//! Android JNI bridge for libp2p peer delivery and the experimental durable
//! relay mailbox protocol. MLS ciphertext remains opaque to the relay; public
//! deployment and real-device end-to-end verification are separate milestones.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{atomic::{AtomicBool, AtomicU64, Ordering}, Mutex, OnceLock},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

mod mls_snapshot;
mod mls_group;

use futures::StreamExt;
use jni::{objects::{JByteArray, JObject, JString}, sys::{jboolean, jbyteArray, jstring, JNI_FALSE, JNI_TRUE}, JNIEnv};
use libp2p::{swarm::SwarmEvent, tcp, yamux, multiaddr::Protocol, Multiaddr, SwarmBuilder};

#[derive(libp2p::swarm::NetworkBehaviour)]
#[behaviour(to_swarm = "MeshxAndroidEvent")]
struct MeshxAndroidBehaviour {
    relay: libp2p::relay::client::Behaviour,
    meshx: meshx_libp2p_transport_spike::MeshxNetworkBehaviour,
    mailbox: meshx_libp2p_transport_spike::MeshxMailboxBehaviour,
}

#[derive(Debug)]
enum MeshxAndroidEvent {
    Relay(libp2p::relay::client::Event),
    Meshx(meshx_libp2p_transport_spike::MeshxEvent),
    Mailbox(libp2p::request_response::Event<
        meshx_libp2p_transport_spike::MailboxRequest,
        meshx_libp2p_transport_spike::MailboxResponse,
    >),
}
impl From<libp2p::relay::client::Event> for MeshxAndroidEvent {
    fn from(event: libp2p::relay::client::Event) -> Self { Self::Relay(event) }
}
impl From<meshx_libp2p_transport_spike::MeshxEvent> for MeshxAndroidEvent {
    fn from(event: meshx_libp2p_transport_spike::MeshxEvent) -> Self { Self::Meshx(event) }
}
impl From<libp2p::request_response::Event<
    meshx_libp2p_transport_spike::MailboxRequest,
    meshx_libp2p_transport_spike::MailboxResponse,
>> for MeshxAndroidEvent {
    fn from(event: libp2p::request_response::Event<
        meshx_libp2p_transport_spike::MailboxRequest,
        meshx_libp2p_transport_spike::MailboxResponse,
    >) -> Self { Self::Mailbox(event) }
}

enum TransportCommand {
    AddBootstrapPeers(Vec<String>),
    AddRelayPeer(String),
    FindPeer(libp2p::PeerId),
    SendCiphertext { peer_id: libp2p::PeerId, ciphertext: Vec<u8> },
    AcknowledgeMailbox { relay_peer: libp2p::PeerId, message_id: [u8; 16] },
}

#[derive(Clone, Copy)]
enum PendingMailboxRequest {
    Fetch,
    Store,
    Acknowledge([u8; 16]),
}

const MAX_PENDING_INCOMING: usize = 128;
static NEXT_MESSAGE_ID: AtomicU64 = AtomicU64::new(1);
static INCOMING_MESSAGES: OnceLock<Mutex<VecDeque<meshx_libp2p_transport_spike::DeliveryEnvelope>>> = OnceLock::new();
static MAILBOX_SOURCES: OnceLock<Mutex<HashMap<[u8; 16], libp2p::PeerId>>> = OnceLock::new();
static MAILBOX_ACK_PENDING: OnceLock<Mutex<HashSet<[u8; 16]>>> = OnceLock::new();

fn mailbox_sources() -> &'static Mutex<HashMap<[u8; 16], libp2p::PeerId>> {
    MAILBOX_SOURCES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn mailbox_ack_pending() -> &'static Mutex<HashSet<[u8; 16]>> {
    MAILBOX_ACK_PENDING.get_or_init(|| Mutex::new(HashSet::new()))
}

fn incoming_messages() -> &'static Mutex<VecDeque<meshx_libp2p_transport_spike::DeliveryEnvelope>> {
    INCOMING_MESSAGES.get_or_init(|| Mutex::new(VecDeque::new()))
}

fn unix_time_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn queue_ciphertext(raw_peer_id: &str, ciphertext: Vec<u8>) -> Result<String, String> {
    if ciphertext.is_empty() || ciphertext.len() > meshx_libp2p_transport_spike::MAX_CIPHERTEXT_BYTES {
        return Err("Encrypted payload must be between 1 byte and 1 MiB.".to_owned());
    }
    let peer_id = parse_peer_id_input(raw_peer_id)?;
    let sender = command_sender_store().lock()
        .map_err(|_| "MESHX network command queue is unavailable".to_owned())?
        .clone()
        .ok_or_else(|| "Start the MESHX network before sending a message.".to_owned())?;
    sender.send(TransportCommand::SendCiphertext { peer_id, ciphertext })
        .map_err(|_| "MESHX network thread is not accepting commands.".to_owned())?;
    Ok("MESHX encrypted payload queued for direct delivery; if a configured mailbox relay is connected, an offline-store request is also sent. This is not a delivered/read receipt.".to_owned())
}

static STARTED: AtomicBool = AtomicBool::new(false);
static STATUS: OnceLock<Mutex<String>> = OnceLock::new();
static COMMAND_SENDER: OnceLock<Mutex<Option<tokio::sync::mpsc::UnboundedSender<TransportCommand>>>> = OnceLock::new();

fn command_sender_store() -> &'static Mutex<Option<tokio::sync::mpsc::UnboundedSender<TransportCommand>>> {
    COMMAND_SENDER.get_or_init(|| Mutex::new(None))
}

fn status_store() -> &'static Mutex<String> {
    STATUS.get_or_init(|| Mutex::new(
        "MESHX libp2p transport is not started".to_owned()
    ))
}

fn set_status(value: impl Into<String>) {
    if let Ok(mut status) = status_store().lock() {
        *status = value.into();
    }
}

fn current_status() -> String {
    status_store().lock()
        .map(|status| status.clone())
        .unwrap_or_else(|_| "MESHX transport status unavailable".to_owned())
}

fn parse_bootstrap_input(raw: &str) -> Result<Vec<String>, String> {
    let addresses: Vec<String> = raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    let address_refs: Vec<&str> = addresses.iter().map(String::as_str).collect();
    let parsed = meshx_libp2p_transport_spike::parse_bootstrap_peers(&address_refs)
        .map_err(|error| format!("Invalid MESHX bootstrap list: {error:?}"))?;
    Ok(parsed.into_iter().map(|peer| peer.address.to_string()).collect())
}

fn parse_relay_address(raw: &str) -> Result<Multiaddr, String> {
    let address = raw.trim().parse::<Multiaddr>()
        .map_err(|_| "Invalid relay multiaddress.".to_owned())?;
    if address.iter().any(|part| matches!(part, Protocol::P2pCircuit)) {
        return Err("Enter the relay server's direct address, without /p2p-circuit.".to_owned());
    }
    if !matches!(address.iter().last(), Some(Protocol::P2p(_))) {
        return Err("Relay address must end with /p2p/RELAY_PEER_ID.".to_owned());
    }
    Ok(address)
}

/// Converts the listener address emitted after a relay reservation into the
/// direct relay address used to build outbound circuit paths.
fn relay_base_from_circuit_listen_address(address: &Multiaddr) -> Option<Multiaddr> {
    let mut relay_address = address.clone();
    match relay_address.pop() {
        Some(Protocol::P2p(_)) => {}
        _ => return None,
    }
    match relay_address.pop() {
        Some(Protocol::P2pCircuit) => Some(relay_address),
        _ => None,
    }
}

fn queue_relay_peer(raw: &str) -> Result<String, String> {
    let address = parse_relay_address(raw)?;
    let sender = command_sender_store().lock()
        .map_err(|_| "MESHX network command queue is unavailable".to_owned())?
        .clone()
        .ok_or_else(|| "Start the MESHX network before adding a relay.".to_owned())?;
    sender.send(TransportCommand::AddRelayPeer(address.to_string()))
        .map_err(|_| "MESHX network thread is not accepting commands.".to_owned())?;
    Ok("MESHX relay connection and reservation request queued; waiting for server confirmation.".to_owned())
}

fn queue_bootstrap_peers(raw: &str) -> Result<String, String> {
    let addresses = parse_bootstrap_input(raw)?;
    if addresses.is_empty() {
        return Err("Enter at least one bootstrap multiaddress.".to_owned());
    }
    let sender = command_sender_store().lock()
        .map_err(|_| "MESHX network command queue is unavailable".to_owned())?
        .clone()
        .ok_or_else(|| "Start the MESHX network before adding bootstrap peers.".to_owned())?;
    let count = addresses.len();
    sender.send(TransportCommand::AddBootstrapPeers(addresses))
        .map_err(|_| "MESHX network thread is not accepting commands.".to_owned())?;
    Ok(format!("MESHX: {count} bootstrap peer(s) queued. Connection and DHT status will update below."))
}

fn parse_peer_id_input(raw: &str) -> Result<libp2p::PeerId, String> {
    raw.trim().parse::<libp2p::PeerId>()
        .map_err(|_| "Invalid MESHX transport Peer ID.".to_owned())
}

fn queue_peer_lookup(raw: &str) -> Result<String, String> {
    let peer_id = parse_peer_id_input(raw)?;
    let sender = command_sender_store().lock()
        .map_err(|_| "MESHX network command queue is unavailable".to_owned())?
        .clone()
        .ok_or_else(|| "Start the MESHX network before searching for contacts.".to_owned())?;
    sender.send(TransportCommand::FindPeer(peer_id))
        .map_err(|_| "MESHX network thread is not accepting commands.".to_owned())?;
    Ok("MESHX DHT peer lookup queued. Results are candidate routing peers, not proof that the contact is online.".to_owned())
}

fn start_swarm(identity_bytes: &[u8]) -> Result<String, String> {
    let keypair = libp2p::identity::Keypair::from_protobuf_encoding(identity_bytes)
        .map_err(|error| format!("MESHX saved transport identity is invalid: {error}"))?;

    if STARTED.swap(true, Ordering::SeqCst) {
        return Ok(current_status());
    }

    let peer_id = keypair.public().to_peer_id();
    let peer_label = peer_id.to_string();
    let thread_peer_label = peer_label.clone();
    let (command_sender, mut command_receiver) = tokio::sync::mpsc::unbounded_channel();
    if let Ok(mut stored_sender) = command_sender_store().lock() {
        *stored_sender = Some(command_sender);
    } else {
        STARTED.store(false, Ordering::SeqCst);
        return Err("MESHX network command queue could not be initialized".to_owned());
    }

    let spawn_result = thread::Builder::new()
        .name("meshx-libp2p".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    set_status(format!("MESHX runtime error: {error}"));
                    STARTED.store(false, Ordering::SeqCst);
                    return;
                }
            };

            runtime.block_on(async move {
                let mut requested_relays: Vec<Multiaddr> = Vec::new();
                let mut active_relays: Vec<Multiaddr> = Vec::new();
                let mut pending_mailbox_stores: Vec<(libp2p::PeerId, meshx_libp2p_transport_spike::DeliveryEnvelope)> = Vec::new();
                let mut pending_mailbox_acks: Vec<(libp2p::PeerId, [u8; 16])> = Vec::new();
                let mut mailbox_fetch_in_flight: HashSet<libp2p::PeerId> = HashSet::new();
                let mut pending_mailbox_requests = HashMap::new();
                let mut mailbox_poll = tokio::time::interval(Duration::from_secs(15));
                let builder = match SwarmBuilder::with_existing_identity(keypair)
                    .with_tokio()
                    .with_tcp(
                        tcp::Config::default(),
                        libp2p::noise::Config::new,
                        yamux::Config::default,
                    ) {
                    Ok(builder) => builder,
                    Err(error) => {
                        set_status(format!("MESHX TCP transport error: {error}"));
                        STARTED.store(false, Ordering::SeqCst);
                        return;
                    }
                };

                let builder = builder.with_quic();

                let builder = match builder
                    .with_relay_client(libp2p::noise::Config::new, yamux::Config::default)
                {
                    Ok(builder) => builder,
                    Err(error) => {
                        set_status(format!("MESHX relay transport setup error: {error}"));
                        STARTED.store(false, Ordering::SeqCst);
                        return;
                    }
                };

                let builder = match builder.with_behaviour(|key, relay| MeshxAndroidBehaviour {
                    relay,
                    meshx: meshx_libp2p_transport_spike::new_network_behaviour(
                        key.public().to_peer_id()
                    ),
                    mailbox: meshx_libp2p_transport_spike::new_mailbox_behaviour(),
                }) {
                    Ok(builder) => builder,
                    Err(error) => {
                        set_status(format!("MESHX behaviour error: {error}"));
                        STARTED.store(false, Ordering::SeqCst);
                        return;
                    }
                };
                let mut swarm = builder.build();

                let listen_address: Multiaddr = match "/ip4/0.0.0.0/tcp/0".parse() {
                    Ok(address) => address,
                    Err(error) => {
                        set_status(format!("MESHX listen address error: {error}"));
                        STARTED.store(false, Ordering::SeqCst);
                        return;
                    }
                };

                if let Err(error) = swarm.listen_on(listen_address) {
                    set_status(format!("MESHX listen failed: {error}"));
                    STARTED.store(false, Ordering::SeqCst);
                    return;
                }

                set_status(format!(
                    "MESHX libp2p swarm starting; peer id {thread_peer_label}; waiting for TCP listener"
                ));

                loop {
                    tokio::select! {
                        _ = mailbox_poll.tick() => {
                            for relay_address in &requested_relays {
                                let relay_peer = match relay_address.iter().last() {
                                    Some(Protocol::P2p(peer)) => peer,
                                    _ => continue,
                                };
                                if swarm.is_connected(&relay_peer) && mailbox_fetch_in_flight.insert(relay_peer) {
                                    let request_id = swarm.behaviour_mut().mailbox.send_request(
                                        &relay_peer,
                                        meshx_libp2p_transport_spike::MailboxRequest::Fetch,
                                    );
                                    pending_mailbox_requests.insert(
                                        request_id,
                                        PendingMailboxRequest::Fetch,
                                    );
                                }
                            }
                        }
                        event = swarm.select_next_some() => {
                            match event {
                                SwarmEvent::NewListenAddr { address, .. } => {
                                    if address.iter().any(|part| matches!(part, Protocol::P2pCircuit)) {
                                        match relay_base_from_circuit_listen_address(&address) {
                                            Some(relay_address) => {
                                                if requested_relays.contains(&relay_address)
                                                    && !active_relays.contains(&relay_address) {
                                                    active_relays.push(relay_address.clone());
                                                }
                                                let relay_peer = relay_address.iter().last()
                                                    .and_then(|part| match part {
                                                        Protocol::P2p(peer) => Some(peer),
                                                        _ => None,
                                                    });
                                                set_status(format!(
                                                    "MESHX relay reservation confirmed for {relay_peer:?}; relay routes are now available; circuit address {address}; local peer id {thread_peer_label}"
                                                ));
                                            }
                                            None => set_status(format!(
                                                "MESHX received an invalid relay listener address: {address}"
                                            )),
                                        }
                                    } else {
                                        set_status(format!(
                                            "MESHX libp2p TCP listener active; peer id {thread_peer_label}; address {address}"
                                        ));
                                    }
                                }
                                SwarmEvent::ListenerError { error, .. } => {
                                    set_status(format!("MESHX listener error: {error}"));
                                }
                                SwarmEvent::ListenerClosed { listener_id, addresses, reason } => {
                                    match reason {
                                        Ok(()) => set_status(format!(
                                            "MESHX listener {listener_id:?} closed without an error; addresses: {addresses:?}. A relay route is active only if a reservation was confirmed."
                                        )),
                                        Err(error) => set_status(format!(
                                            "MESHX listener {listener_id:?} closed: {error}; addresses: {addresses:?}"
                                        )),
                                    }
                                }
                                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                                    set_status(format!(
                                        "MESHX outgoing connection to {peer_id:?} failed: {error}"
                                    ));
                                }
                                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                    set_status(format!(
                                        "MESHX libp2p connected to peer {peer_id}; local peer id {thread_peer_label}"
                                    ));
                                    let is_configured_relay = requested_relays.iter().any(|address| {
                                        matches!(address.iter().last(), Some(Protocol::P2p(id)) if id == peer_id)
                                    });
                                    if is_configured_relay {
                                        if mailbox_fetch_in_flight.insert(peer_id) {
                                            let request_id = swarm.behaviour_mut().mailbox.send_request(
                                                &peer_id,
                                                meshx_libp2p_transport_spike::MailboxRequest::Fetch,
                                            );
                                            pending_mailbox_requests.insert(
                                                request_id,
                                                PendingMailboxRequest::Fetch,
                                            );
                                        }
                                        let mut remaining = Vec::new();
                                        for (relay_peer, envelope) in pending_mailbox_stores.drain(..) {
                                            if relay_peer == peer_id {
                                                let request_id = swarm.behaviour_mut().mailbox.send_request(
                                                    &peer_id,
                                                    meshx_libp2p_transport_spike::MailboxRequest::Store(envelope),
                                                );
                                                pending_mailbox_requests.insert(
                                                    request_id,
                                                    PendingMailboxRequest::Store,
                                                );
                                            } else {
                                                remaining.push((relay_peer, envelope));
                                            }
                                        }
                                        pending_mailbox_stores = remaining;
                                        let mut remaining_acks = Vec::new();
                                        for (relay_peer, message_id) in pending_mailbox_acks.drain(..) {
                                            if relay_peer == peer_id {
                                                let request_id = swarm.behaviour_mut().mailbox.send_request(
                                                    &peer_id,
                                                    meshx_libp2p_transport_spike::MailboxRequest::Acknowledge { message_id },
                                                );
                                                pending_mailbox_requests.insert(
                                                    request_id,
                                                    PendingMailboxRequest::Acknowledge(message_id),
                                                );
                                            } else {
                                                remaining_acks.push((relay_peer, message_id));
                                            }
                                        }
                                        pending_mailbox_acks = remaining_acks;
                                    }
                                }
                                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                                    mailbox_fetch_in_flight.remove(&peer_id);
                                    let relay_closed = active_relays.iter().any(|address| {
                                        address.iter().any(|part| matches!(part, Protocol::P2p(id) if id == peer_id))
                                    });
                                    if relay_closed {
                                        active_relays.retain(|address| {
                                            !address.iter().any(|part| matches!(part, Protocol::P2p(id) if id == peer_id))
                                        });
                                        set_status(format!(
                                            "MESHX relay connection closed: {peer_id}; its circuit route is no longer marked active; local peer id {thread_peer_label}"
                                        ));
                                    } else {
                                        set_status(format!(
                                            "MESHX peer disconnected: {peer_id}; local peer id {thread_peer_label}"
                                        ));
                                    }
                                }
                                SwarmEvent::Behaviour(MeshxAndroidEvent::Meshx(meshx_libp2p_transport_spike::MeshxEvent::Kad(event))) => {
                                    set_status(format!(
                                        "MESHX DHT discovery event: {event:?}; local peer id {thread_peer_label}"
                                    ));
                                }
                                SwarmEvent::Behaviour(MeshxAndroidEvent::Meshx(meshx_libp2p_transport_spike::MeshxEvent::Delivery(event))) => {
                                    use libp2p::request_response::{Event as RequestEvent, Message as RequestMessage};
                                    match event {
                                        RequestEvent::Message { peer, message, .. } => match message {
                                            RequestMessage::Request { request, channel, .. } => {
                                                let now = unix_time_seconds();
                                                let local_id = swarm.local_peer_id().to_bytes();
                                                let sender_matches = request.sender_id == peer.to_bytes();
                                                let recipient_matches = request.recipient_id == local_id;
                                                let valid = request.validate(now).is_ok() && sender_matches && recipient_matches;
                                                let accepted = if valid {
                                                    if let Ok(mut queue) = incoming_messages().lock() {
                                                        if queue.len() < MAX_PENDING_INCOMING {
                                                            queue.push_back(request.clone());
                                                            true
                                                        } else { false }
                                                    } else { false }
                                                } else { false };
                                                let ack = meshx_libp2p_transport_spike::DeliveryAck {
                                                    message_id: request.message_id,
                                                    accepted,
                                                };
                                                let _ = swarm.behaviour_mut().meshx.delivery.send_response(channel, ack);
                                                set_status(if accepted {
                                                    format!("MESHX received encrypted payload from {peer}; queued in volatile app memory. Not yet decrypted or persisted.")
                                                } else {
                                                    format!("MESHX rejected invalid, misaddressed, or over-capacity payload from {peer}.")
                                                });
                                            }
                                            RequestMessage::Response { response, .. } => {
                                                set_status(if response.accepted {
                                                    format!("MESHX peer {peer} accepted the encrypted payload into its volatile receive queue; delivery is not durable.")
                                                } else {
                                                    format!("MESHX peer {peer} rejected the encrypted payload.")
                                                });
                                            }
                                        },
                                        RequestEvent::OutboundFailure { peer, error, .. } => {
                                            set_status(format!("MESHX send to {peer} failed: {error}"));
                                        }
                                        RequestEvent::InboundFailure { peer, error, .. } => {
                                            set_status(format!("MESHX receive from {peer} failed: {error}"));
                                        }
                                        RequestEvent::ResponseSent { peer, .. } => {
                                            set_status(format!("MESHX receive acknowledgement sent to {peer}."));
                                        }
                                    }
                                }
                                SwarmEvent::Behaviour(MeshxAndroidEvent::Mailbox(event)) => {
                                    use libp2p::request_response::{Event as RequestEvent, Message as RequestMessage};
                                    match event {
                                        RequestEvent::Message { peer, message, .. } => match message {
                                            RequestMessage::Response { request_id, response } => {
                                                let pending = pending_mailbox_requests.remove(&request_id);
                                                match response {
                                                    meshx_libp2p_transport_spike::MailboxResponse::Stored { accepted, duplicate } => {
                                                        set_status(format!(
                                                            "MESHX relay mailbox store response from {peer}: accepted={accepted}, duplicate={duplicate}. Server storage is not a recipient delivery receipt."
                                                        ));
                                                    }
                                                    meshx_libp2p_transport_spike::MailboxResponse::Messages { envelopes } => {
                                                        mailbox_fetch_in_flight.remove(&peer);
                                                        let now = unix_time_seconds();
                                                        let local_id = swarm.local_peer_id().to_bytes();
                                                        let mut added = 0usize;
                                                        if let Ok(mut queue) = incoming_messages().lock() {
                                                            if let Ok(mut sources) = mailbox_sources().lock() {
                                                                for envelope in envelopes {
                                                                    if envelope.recipient_id != local_id
                                                                        || envelope.validate(now).is_err()
                                                                        || libp2p::PeerId::from_bytes(&envelope.sender_id).is_err()
                                                                        || queue.iter().any(|queued| queued.message_id == envelope.message_id)
                                                                        || queue.len() >= MAX_PENDING_INCOMING {
                                                                        continue;
                                                                    }
                                                                    sources.insert(envelope.message_id, peer);
                                                                    queue.push_back(envelope);
                                                                    added += 1;
                                                                }
                                                            }
                                                        }
                                                        set_status(format!(
                                                            "MESHX relay mailbox fetched {added} encrypted message(s) from {peer}; messages remain on the server until Android saves and acknowledges them."
                                                        ));
                                                    }
                                                    meshx_libp2p_transport_spike::MailboxResponse::Acknowledged { message_id, removed } => {
                                                        let is_expected_ack = matches!(
                                                            pending,
                                                            Some(PendingMailboxRequest::Acknowledge(expected_id))
                                                                if expected_id == message_id
                                                        );
                                                        if is_expected_ack {
                                                            if let Ok(mut queued) = mailbox_ack_pending().lock() {
                                                                queued.remove(&message_id);
                                                            }
                                                            if let Ok(mut queue) = incoming_messages().lock() {
                                                                queue.retain(|item| item.message_id != message_id);
                                                            }
                                                            if let Ok(mut sources) = mailbox_sources().lock() {
                                                                sources.remove(&message_id);
                                                            }
                                                            set_status(format!(
                                                                "MESHX relay mailbox acknowledgement for {}: server_removed={removed}.",
                                                                message_id.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
                                                            ));
                                                        } else {
                                                            set_status(format!(
                                                                "MESHX relay returned an unexpected acknowledgement for {}.",
                                                                message_id.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
                                                            ));
                                                        }
                                                    }
                                                    meshx_libp2p_transport_spike::MailboxResponse::Rejected { reason } => {
                                                        mailbox_fetch_in_flight.remove(&peer);
                                                        if let Some(PendingMailboxRequest::Acknowledge(message_id)) = pending {
                                                            if let Ok(mut queued) = mailbox_ack_pending().lock() {
                                                                queued.remove(&message_id);
                                                            }
                                                        }
                                                        set_status(format!(
                                                            "MESHX relay mailbox rejected a request from {peer}: {reason:?}"
                                                        ));
                                                    }
                                                }
                                            }
                                            RequestMessage::Request { request: _, channel, .. } => {
                                                let _ = swarm.behaviour_mut().mailbox.send_response(
                                                    channel,
                                                    meshx_libp2p_transport_spike::MailboxResponse::Rejected {
                                                        reason: meshx_libp2p_transport_spike::MailboxRejectReason::Unauthorized,
                                                    },
                                                );
                                            }
                                        },
                                        RequestEvent::OutboundFailure { peer, request_id, error } => {
                                            mailbox_fetch_in_flight.remove(&peer);
                                            if let Some(PendingMailboxRequest::Acknowledge(message_id)) =
                                                pending_mailbox_requests.remove(&request_id) {
                                                if let Ok(mut queued) = mailbox_ack_pending().lock() {
                                                    queued.remove(&message_id);
                                                }
                                            } else {
                                                pending_mailbox_requests.remove(&request_id);
                                            }
                                            set_status(format!("MESHX relay mailbox request to {peer} failed: {error}"));
                                        }
                                        RequestEvent::InboundFailure { peer, error, .. } => {
                                            set_status(format!("MESHX relay mailbox inbound request from {peer} failed: {error}"));
                                        }
                                        RequestEvent::ResponseSent { peer, .. } => {
                                            set_status(format!("MESHX relay mailbox response sent to {peer}."));
                                        }
                                    }
                                }
                                SwarmEvent::Behaviour(MeshxAndroidEvent::Relay(event)) => {
                                    set_status(format!("MESHX circuit-relay event: {event:?}; local peer id {thread_peer_label}"));
                                }
                                _ => {}
                            }
                        }
                        command = command_receiver.recv() => {
                            match command {
                                Some(TransportCommand::AddRelayPeer(raw_address)) => {
                                    match parse_relay_address(&raw_address) {
                                        Ok(relay_address) => {
                                            if requested_relays.contains(&relay_address) {
                                                set_status(format!("MESHX relay {} is already configured; waiting for or using its existing reservation.", relay_address));
                                                continue;
                                            }
                                            let relay_peer = match relay_address.iter().last() {
                                                Some(Protocol::P2p(peer)) => peer,
                                                _ => {
                                                    set_status("MESHX rejected relay address: missing relay Peer ID.".to_owned());
                                                    continue;
                                                }
                                            };
                                            let mut reservation_address = relay_address.clone();
                                            reservation_address.push(Protocol::P2pCircuit);
                                            // The relay-client transport initiates the relay dial
                                            // when listen_on is called. A separate swarm.dial here
                                            // races the reservation and can close the listener.
                                            match swarm.listen_on(reservation_address) {
                                                Ok(listener_id) => {
                                                    if !requested_relays.contains(&relay_address) {
                                                        requested_relays.push(relay_address.clone());
                                                    }
                                                    set_status(format!(
                                                        "MESHX relay {relay_peer}: circuit reservation listener {listener_id:?} requested; waiting for server confirmation."
                                                    ));
                                                }
                                                Err(error) => set_status(format!(
                                                    "MESHX relay reservation request failed for {relay_peer}: {error}"
                                                )),
                                            }
                                        }
                                        Err(error) => set_status(format!("MESHX relay address rejected: {error}")),
                                    }
                                }
                                Some(TransportCommand::AddBootstrapPeers(addresses)) => {
                                    let address_refs: Vec<&str> = addresses.iter().map(String::as_str).collect();
                                    match meshx_libp2p_transport_spike::parse_bootstrap_peers(&address_refs) {
                                        Ok(peers) => {
                                            let dial_results = meshx_libp2p_transport_spike::dial_bootstrap_peers(
                                                &mut swarm,
                                                &peers,
                                            );
                                            let dial_queued = dial_results.iter().filter(|result| result.is_ok()).count();
                                            let dht_peers_added = meshx_libp2p_transport_spike::add_dht_bootstrap_peers(
                                                &mut swarm.behaviour_mut().meshx.kad,
                                                &peers,
                                            );
                                            let bootstrap_result = meshx_libp2p_transport_spike::start_dht_bootstrap(
                                                &mut swarm.behaviour_mut().meshx.kad,
                                            );
                                            match bootstrap_result {
                                                Ok(query_id) => set_status(format!(
                                                    "MESHX bootstrap configured: {} peer(s), {dial_queued} dial(s) queued, {dht_peers_added} DHT address(es); bootstrap query {query_id:?}; local peer id {thread_peer_label}",
                                                    peers.len()
                                                )),
                                                Err(error) => set_status(format!(
                                                    "MESHX bootstrap peers added ({dht_peers_added}) but DHT bootstrap could not start: {error:?}; local peer id {thread_peer_label}"
                                                )),
                                            }
                                        }
                                        Err(error) => set_status(format!(
                                            "MESHX rejected bootstrap list: {error:?}; local peer id {thread_peer_label}"
                                        )),
                                    }
                                }
                                Some(TransportCommand::FindPeer(peer_id)) => {
                                    let query_id = meshx_libp2p_transport_spike::find_closest_peers(
                                        &mut swarm.behaviour_mut().meshx.kad,
                                        peer_id.clone(),
                                    );
                                    set_status(format!(
                                        "MESHX DHT lookup started for {peer_id}; query {query_id:?}; returned peers are only routing candidates, not proof the contact is online; local peer id {thread_peer_label}"
                                    ));
                                }
                                Some(TransportCommand::AcknowledgeMailbox { relay_peer, message_id }) => {
                                    if swarm.is_connected(&relay_peer) {
                                        let request_id = swarm.behaviour_mut().mailbox.send_request(
                                            &relay_peer,
                                            meshx_libp2p_transport_spike::MailboxRequest::Acknowledge { message_id },
                                        );
                                        pending_mailbox_requests.insert(
                                            request_id,
                                            PendingMailboxRequest::Acknowledge(message_id),
                                        );
                                    } else {
                                        pending_mailbox_acks.push((relay_peer, message_id));
                                    }
                                }
                                Some(TransportCommand::SendCiphertext { peer_id, ciphertext }) => {
                                    let now = unix_time_seconds();
                                    let counter = NEXT_MESSAGE_ID.fetch_add(1, Ordering::Relaxed);
                                    let mut message_id = [0u8; 16];
                                    message_id[..8].copy_from_slice(&now.to_be_bytes());
                                    message_id[8..].copy_from_slice(&counter.to_be_bytes());
                                    let envelope = meshx_libp2p_transport_spike::DeliveryEnvelope {
                                        message_id,
                                        sender_id: swarm.local_peer_id().to_bytes(),
                                        recipient_id: peer_id.to_bytes(),
                                        created_at: now,
                                        expires_at: now.saturating_add(24 * 60 * 60),
                                        hop_limit: 8,
                                        ciphertext,
                                    };
                                    match envelope.validate(now) {
                                        Ok(()) => {
                                            for relay_address in &active_relays {
                                                let mut circuit = relay_address.clone();
                                                circuit.push(Protocol::P2pCircuit);
                                                circuit.push(Protocol::P2p(peer_id));
                                                swarm.behaviour_mut().meshx.kad.add_address(&peer_id, circuit.clone());
                                                if !swarm.is_connected(&peer_id) {
                                                    let _ = swarm.dial(circuit);
                                                }
                                            }
                                            swarm.behaviour_mut().meshx.delivery.send_request(&peer_id, envelope.clone());
                                            let mut mailbox_requests = 0usize;
                                            for relay_address in &requested_relays {
                                                let relay_peer = match relay_address.iter().last() {
                                                    Some(Protocol::P2p(relay_peer)) => relay_peer,
                                                    _ => continue,
                                                };
                                                if swarm.is_connected(&relay_peer) {
                                                    let request_id = swarm.behaviour_mut().mailbox.send_request(
                                                        &relay_peer,
                                                        meshx_libp2p_transport_spike::MailboxRequest::Store(envelope.clone()),
                                                    );
                                                    pending_mailbox_requests.insert(
                                                        request_id,
                                                        PendingMailboxRequest::Store,
                                                    );
                                                } else {
                                                    pending_mailbox_stores.push((relay_peer, envelope.clone()));
                                                }
                                                mailbox_requests += 1;
                                            }
                                            set_status(format!("MESHX encrypted-payload request queued for {peer_id}; {} confirmed circuit-relay route(s); {mailbox_requests} offline-mailbox store request(s) queued. Server acceptance is not proof of recipient delivery.", active_relays.len()));
                                        }
                                        Err(error) => set_status(format!("MESHX rejected outgoing encrypted payload: {error:?}")),
                                    }
                                }
                                None => break,
                            }
                        }
                    }
                }
            });
        });

    match spawn_result {
        Ok(_) => {
            let message = format!(
                "MESHX libp2p swarm starting; peer id {peer_label}; TCP listener requested"
            );
            set_status(message.clone());
            Ok(message)
        }
        Err(error) => {
            STARTED.store(false, Ordering::SeqCst);
            if let Ok(mut stored_sender) = command_sender_store().lock() {
                *stored_sender = None;
            }
            let message = format!("MESHX thread start failed: {error}");
            set_status(message.clone());
            Err(message)
        }
    }
}

fn jni_string(env: &mut JNIEnv, value: String) -> jstring {
    env.new_string(value)
        .expect("JNI string allocation")
        .into_raw()
}

/// Kotlin: NativeMeshx.nativeTransportStatus()
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeTransportStatus(
    mut env: JNIEnv,
    _this: JObject,
) -> jstring {
    jni_string(&mut env, current_status())
}

/// Kotlin: NativeMeshx.nativeAddBootstrapPeers(addresses: String)
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeAddBootstrapPeers(
    mut env: JNIEnv,
    _this: JObject,
    raw_addresses: JString,
) -> jstring {
    let result = match env.get_string(&raw_addresses) {
        Ok(value) => queue_bootstrap_peers(&value.to_string_lossy())
            .unwrap_or_else(|error| format!("MESHX bootstrap error: {error}")),
        Err(error) => format!("MESHX bootstrap list could not be read from Android: {error}"),
    };
    jni_string(&mut env, result)
}

/// Kotlin: NativeMeshx.nativeAddRelayPeer(address: String)
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeAddRelayPeer(
    mut env: JNIEnv,
    _this: JObject,
    raw_address: JString,
) -> jstring {
    let result = match env.get_string(&raw_address) {
        Ok(value) => queue_relay_peer(&value.to_string_lossy())
            .unwrap_or_else(|error| format!("MESHX relay error: {error}")),
        Err(error) => format!("MESHX relay error: Relay address could not be read from Android: {error}"),
    };
    jni_string(&mut env, result)
}

/// Kotlin: NativeMeshx.nativeFindPeer(peerId: String)
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeFindPeer(
    mut env: JNIEnv,
    _this: JObject,
    raw_peer_id: JString,
) -> jstring {
    let result = match env.get_string(&raw_peer_id) {
        Ok(value) => queue_peer_lookup(&value.to_string_lossy())
            .unwrap_or_else(|error| format!("MESHX peer discovery error: {error}")),
        Err(error) => format!("MESHX peer discovery error: Peer ID could not be read from Android: {error}"),
    };
    jni_string(&mut env, result)
}


/// Kotlin: NativeMeshx.nativeSendCiphertext(peerId: String, ciphertext: ByteArray)
/// Accepts opaque application ciphertext only; plaintext encryption belongs to the MLS layer.
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeSendCiphertext(
    mut env: JNIEnv,
    _this: JObject,
    raw_peer_id: JString,
    ciphertext: JByteArray,
) -> jstring {
    let peer_id = match env.get_string(&raw_peer_id) {
        Ok(value) => value.to_string_lossy().into_owned(),
        Err(error) => return jni_string(&mut env, format!("MESHX send error: Peer ID could not be read: {error}")),
    };
    let payload = match env.convert_byte_array(&ciphertext) {
        Ok(bytes) => bytes,
        Err(error) => return jni_string(&mut env, format!("MESHX send error: Ciphertext could not be read: {error}")),
    };
    let result = queue_ciphertext(&peer_id, payload)
        .unwrap_or_else(|error| format!("MESHX send error: {error}"));
    jni_string(&mut env, result)
}

/// Kotlin: NativeMeshx.nativePollIncomingCiphertexts()
/// Drains the bounded volatile receive queue as JSON; ciphertext remains opaque.
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativePollIncomingCiphertexts(
    mut env: JNIEnv,
    _this: JObject,
    raw_peer_id: JString,
) -> jstring {
    let peer_id = match env.get_string(&raw_peer_id) {
        Ok(value) => match parse_peer_id_input(&value.to_string_lossy()) {
            Ok(peer_id) => peer_id,
            Err(_) => return jni_string(&mut env, "[]".to_owned()),
        },
        Err(_) => return jni_string(&mut env, "[]".to_owned()),
    };
    let expected_sender = peer_id.to_bytes();
    // Peek rather than drain: Android explicitly acknowledges each message
    // only after MLS authentication and encrypted local persistence succeed.
    let pending_acks = match mailbox_ack_pending().lock() {
        Ok(pending) => pending.clone(),
        Err(_) => return jni_string(&mut env, "[]".to_owned()),
    };
    let messages = match incoming_messages().lock() {
        Ok(queue) => queue.iter()
            .filter(|message| {
                message.sender_id.as_slice() == expected_sender.as_slice()
                    && !pending_acks.contains(&message.message_id)
            })
            .cloned()
            .collect::<Vec<_>>(),
        Err(_) => return jni_string(&mut env, "[]".to_owned()),
    };
    // Expose the authenticated libp2p sender ID beside the opaque MLS bytes so
    // Android can route the payload to the matching saved contact/group.
    let payloads = messages.into_iter().filter_map(|message| {
        let sender_peer_id = libp2p::PeerId::from_bytes(&message.sender_id).ok()?.to_string();
        Some(serde_json::json!({
            "sender_peer_id": sender_peer_id,
            "ciphertext": message.ciphertext,
            "message_id": message.message_id.iter()
                .map(|byte| format!("{byte:02x}")).collect::<String>(),
        }))
    }).collect::<Vec<_>>();
    let json = serde_json::to_string(&payloads).unwrap_or_else(|_| "[]".to_owned());
    jni_string(&mut env, json)
}

/// Kotlin: NativeMeshx.nativeAckIncomingCiphertext(messageId)
/// Removes a received envelope only after Android confirms successful processing.
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeAckIncomingCiphertext(
    mut env: JNIEnv,
    _this: JObject,
    raw_message_id: JString,
) -> jboolean {
    let value = match env.get_string(&raw_message_id) {
        Ok(value) => value.to_string_lossy().into_owned(),
        Err(_) => return JNI_FALSE,
    };
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return JNI_FALSE;
    }
    let mut message_id = [0u8; 16];
    for index in 0..16 {
        match u8::from_str_radix(&value[index * 2..index * 2 + 2], 16) {
            Ok(byte) => message_id[index] = byte,
            Err(_) => return JNI_FALSE,
        }
    }
    let relay_peer = match mailbox_sources().lock() {
        Ok(sources) => sources.get(&message_id).cloned(),
        Err(_) => return JNI_FALSE,
    };
    if let Some(relay_peer) = relay_peer {
        let sender = match command_sender_store().lock() {
            Ok(stored) => match stored.clone() {
                Some(sender) => sender,
                None => return JNI_FALSE,
            },
            Err(_) => return JNI_FALSE,
        };
        match mailbox_ack_pending().lock() {
            Ok(mut pending) => {
                if !pending.insert(message_id) {
                    return JNI_TRUE;
                }
            }
            Err(_) => return JNI_FALSE,
        }
        if sender.send(TransportCommand::AcknowledgeMailbox { relay_peer, message_id }).is_err() {
            if let Ok(mut pending) = mailbox_ack_pending().lock() {
                pending.remove(&message_id);
            }
            return JNI_FALSE;
        }
        // The server response removes the native copy. If the request fails,
        // it becomes visible to polling again so the app can retry.
        JNI_TRUE
    } else {
        // Direct peer messages have no relay mailbox copy to acknowledge.
        match incoming_messages().lock() {
            Ok(mut queue) => {
                let before = queue.len();
                queue.retain(|message| message.message_id != message_id);
                if queue.len() < before { JNI_TRUE } else { JNI_FALSE }
            }
            Err(_) => JNI_FALSE,
        }
    }
}

/// Kotlin: NativeMeshx.nativeGenerateIdentity()
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeGenerateIdentity(
    mut env: JNIEnv,
    _this: JObject,
) -> jbyteArray {
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    match keypair.to_protobuf_encoding() {
        Ok(bytes) => env.byte_array_from_slice(&bytes)
            .map(|array| array.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Kotlin: NativeMeshx.nativeTransportPublicKey(identity: ByteArray)
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeTransportPublicKey(
    mut env: JNIEnv,
    _this: JObject,
    identity: JByteArray,
) -> jbyteArray {
    let result = env.convert_byte_array(&identity)
        .ok()
        .and_then(|bytes| libp2p::identity::Keypair::from_protobuf_encoding(&bytes).ok())
        .map(|keypair| keypair.public().encode_protobuf());
    match result {
        Some(bytes) => env.byte_array_from_slice(&bytes)
            .map(|array| array.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }
}

/// Kotlin: NativeMeshx.nativeTransportPeerId(publicKey: ByteArray)
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeTransportPeerId(
    mut env: JNIEnv,
    _this: JObject,
    public_key: JByteArray,
) -> jstring {
    let result = env.convert_byte_array(&public_key)
        .ok()
        .and_then(|bytes| libp2p::identity::PublicKey::try_decode_protobuf(&bytes).ok())
        .map(|key| key.to_peer_id().to_string())
        .unwrap_or_default();
    jni_string(&mut env, result)
}


/// Kotlin: NativeMeshx.nativeMlsCreateSignerSnapshot()
/// Returns serialized OpenMLS provider state; callers must encrypt it with MlsStateVault.
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeMlsCreateSignerSnapshot(
    mut env: JNIEnv,
    _this: JObject,
) -> jbyteArray {
    match mls_snapshot::create_signer_snapshot() {
        Ok(bytes) => env.byte_array_from_slice(&bytes)
            .map(|array| array.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(error) => {
            set_status(format!("MESHX MLS snapshot error: {error}"));
            std::ptr::null_mut()
        }
    }
}

/// Kotlin: NativeMeshx.nativeMlsValidateSignerSnapshot(snapshot: ByteArray)
/// Validates that the restored provider contains its original MLS private signer.
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeMlsValidateSignerSnapshot(
    mut env: JNIEnv,
    _this: JObject,
    snapshot: JByteArray,
) -> jboolean {
    match env.convert_byte_array(&snapshot) {
        Ok(bytes) if mls_snapshot::validate_signer_snapshot(&bytes).is_ok() => JNI_TRUE,
        _ => JNI_FALSE,
    }
}

/// Kotlin: NativeMeshx.nativeStartTransport(identity: ByteArray)
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeStartTransport(
    mut env: JNIEnv,
    _this: JObject,
    identity: JByteArray,
) -> jstring {
    let result = match env.convert_byte_array(&identity) {
        Ok(bytes) => start_swarm(&bytes).unwrap_or_else(|error| error),
        Err(error) => format!("MESHX identity could not be read from Android: {error}"),
    };
    jni_string(&mut env, result)
}


/// Kotlin: NativeMeshx.nativeMlsCreateGroupSnapshot(identity: ByteArray)
/// Creates an RFC 9420 group and returns opaque state for the encrypted Android vault.
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeMlsCreateGroupSnapshot(
    mut env: JNIEnv,
    _this: JObject,
    identity: JByteArray,
) -> jbyteArray {
    match env.convert_byte_array(&identity)
        .map_err(|error| format!("MLS credential identity could not be read: {error}"))
        .and_then(|bytes| mls_group::create_group_snapshot(&bytes)) {
        Ok(bytes) => env.byte_array_from_slice(&bytes)
            .map(|array| array.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(error) => {
            set_status(format!("MESHX MLS group creation error: {error}"));
            std::ptr::null_mut()
        }
    }
}

/// Kotlin: NativeMeshx.nativeMlsValidateGroupSnapshot(snapshot: ByteArray)
/// Restores the provider and verifies both the MLS group and its signing key.
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeMlsValidateGroupSnapshot(
    mut env: JNIEnv,
    _this: JObject,
    snapshot: JByteArray,
) -> jboolean {
    match env.convert_byte_array(&snapshot) {
        Ok(bytes) if mls_group::validate_group_snapshot(&bytes).is_ok() => JNI_TRUE,
        _ => JNI_FALSE,
    }
}


/// Kotlin: NativeMeshx.nativeMlsTwoMemberRoundTripSelfTest()
/// Exercises independent Alice/Bob MLS providers and a real encrypted app message.
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeMlsTwoMemberRoundTripSelfTest(
    _env: JNIEnv,
    _this: JObject,
) -> jboolean {
    match mls_group::two_member_round_trip_self_test() {
        Ok(()) => JNI_TRUE,
        Err(error) => {
            set_status(format!("MESHX MLS two-member self-test failed: {error}"));
            JNI_FALSE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_identity_restores_the_same_peer_id() {
        let original = libp2p::identity::Keypair::generate_ed25519();
        let expected_peer_id = original.public().to_peer_id();
        let encoded = original.to_protobuf_encoding().expect("encode identity");
        let restored = libp2p::identity::Keypair::from_protobuf_encoding(&encoded)
            .expect("decode saved identity");
        assert_eq!(expected_peer_id, restored.public().to_peer_id());
    }

    #[test]
    fn transport_public_key_is_derived_from_persisted_identity() {
        let original = libp2p::identity::Keypair::generate_ed25519();
        let encoded = original.to_protobuf_encoding().expect("encode identity");
        let restored = libp2p::identity::Keypair::from_protobuf_encoding(&encoded)
            .expect("decode saved identity");
        assert_eq!(
            original.public().encode_protobuf(),
            restored.public().encode_protobuf()
        );
    }

    #[test]
    fn invalid_persisted_identity_is_rejected() {
        assert!(libp2p::identity::Keypair::from_protobuf_encoding(b"not a key").is_err());
    }

    #[test]
    fn bootstrap_input_trims_lines_and_preserves_peer_ids() {
        let peer = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id();
        let address = format!("/ip4/127.0.0.1/tcp/4001/p2p/{peer}");
        let input = format!("  {address}  \n\n");
        let parsed = parse_bootstrap_input(&input).expect("valid bootstrap peer");
        assert_eq!(parsed, vec![address]);
    }

    #[test]
    fn bootstrap_input_rejects_addresses_without_peer_ids() {
        assert!(parse_bootstrap_input("/ip4/127.0.0.1/tcp/4001").is_err());
    }

    #[test]
    fn bootstrap_input_rejects_more_than_thirty_two_peers() {
        let addresses: Vec<String> = (0..33).map(|_| {
            let peer = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id();
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{peer}")
        }).collect();
        assert!(parse_bootstrap_input(&addresses.join("\n")).is_err());
    }

    #[test]
    fn relay_address_requires_a_peer_id_and_rejects_circuit_suffix() {
        let relay_peer = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id();
        let direct = format!("/ip4/127.0.0.1/tcp/4001/p2p/{relay_peer}");
        assert_eq!(parse_relay_address(&direct).unwrap().to_string(), direct);
        assert!(parse_relay_address("/ip4/127.0.0.1/tcp/4001").is_err());
        assert!(parse_relay_address(&format!("{direct}/p2p-circuit")).is_err());
    }

    #[test]
    fn confirmed_circuit_listener_address_maps_to_direct_relay_address() {
        let relay_peer = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id();
        let local_peer = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id();
        let direct = format!("/ip4/127.0.0.1/tcp/4001/p2p/{relay_peer}");
        let circuit: Multiaddr = format!("{direct}/p2p-circuit/p2p/{local_peer}")
            .parse()
            .expect("valid circuit listener address");
        assert_eq!(
            relay_base_from_circuit_listen_address(&circuit).unwrap().to_string(),
            direct
        );
        let malformed: Multiaddr = direct.parse().expect("valid direct address");
        assert!(relay_base_from_circuit_listen_address(&malformed).is_none());
    }

    #[test]
    fn peer_lookup_parser_accepts_real_peer_ids_and_rejects_invalid_input() {
        let expected = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id();
        assert_eq!(parse_peer_id_input(&format!("  {expected}  ")).unwrap(), expected);
        assert!(parse_peer_id_input("").is_err());
        assert!(parse_peer_id_input("not-a-peer-id").is_err());
    }

    #[test]
    fn initial_status_is_honest_about_not_started_transport() {
        assert!(current_status().contains("not started"));
    }
}


/// Kotlin: NativeMeshx.nativeMlsCreateKeyPackageSnapshot(identity: ByteArray)
/// Creates a one-use KeyPackage and returns private provider state for vault encryption.
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeMlsCreateKeyPackageSnapshot(
    mut env: JNIEnv,
    _this: JObject,
    identity: JByteArray,
) -> jbyteArray {
    match env.convert_byte_array(&identity)
        .map_err(|error| format!("MLS identity could not be read: {error}"))
        .and_then(|bytes| mls_group::create_key_package_snapshot(&bytes)) {
        Ok(bytes) => env.byte_array_from_slice(&bytes)
            .map(|array| array.into_raw()).unwrap_or(std::ptr::null_mut()),
        Err(error) => {
            set_status(format!("MESHX MLS KeyPackage error: {error}"));
            std::ptr::null_mut()
        }
    }
}

/// Kotlin: NativeMeshx.nativeMlsExtractKeyPackage(snapshot: ByteArray)
/// Restores and validates the public KeyPackage before it is shared with a contact.
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeMlsExtractKeyPackage(
    mut env: JNIEnv,
    _this: JObject,
    snapshot: JByteArray,
) -> jbyteArray {
    match env.convert_byte_array(&snapshot)
        .map_err(|error| format!("MLS snapshot could not be read: {error}"))
        .and_then(|bytes| mls_group::extract_key_package(&bytes)) {
        Ok(bytes) => env.byte_array_from_slice(&bytes)
            .map(|array| array.into_raw()).unwrap_or(std::ptr::null_mut()),
        Err(error) => {
            set_status(format!("MESHX MLS KeyPackage validation error: {error}"));
            std::ptr::null_mut()
        }
    }
}


/// Kotlin: NativeMeshx.nativeMlsAddMemberToGroup(groupSnapshot, keyPackage)
/// Validates the recipient KeyPackage and returns updated sender state + Welcome.
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeMlsAddMemberToGroup(
    mut env: JNIEnv,
    _this: JObject,
    group_snapshot: JByteArray,
    key_package: JByteArray,
) -> jbyteArray {
    let result = env.convert_byte_array(&group_snapshot)
        .map_err(|error| format!("MLS group snapshot could not be read: {error}"))
        .and_then(|group_bytes| {
            env.convert_byte_array(&key_package)
                .map_err(|error| format!("Recipient KeyPackage could not be read: {error}"))
                .and_then(|package_bytes| {
                    mls_group::add_member_to_group_snapshot(&group_bytes, &package_bytes)
                })
        });
    match result {
        Ok(bytes) => env.byte_array_from_slice(&bytes)
            .map(|array| array.into_raw()).unwrap_or(std::ptr::null_mut()),
        Err(error) => {
            set_status(format!("MESHX MLS member invitation error: {error}"));
            std::ptr::null_mut()
        }
    }
}


/// Kotlin: NativeMeshx.nativeMlsJoinGroupFromWelcome(keyPackageState, welcome, tree)
/// Joins the invitation using the recipient's locally persisted private MLS state.
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeMlsJoinGroupFromWelcome(
    mut env: JNIEnv,
    _this: JObject,
    key_package_state: JByteArray,
    welcome_message: JByteArray,
    ratchet_tree: JByteArray,
) -> jbyteArray {
    let result = env.convert_byte_array(&key_package_state)
        .map_err(|error| format!("Recipient MLS state could not be read: {error}"))
        .and_then(|state| {
            env.convert_byte_array(&welcome_message)
                .map_err(|error| format!("MLS Welcome could not be read: {error}"))
                .and_then(|welcome| {
                    env.convert_byte_array(&ratchet_tree)
                        .map_err(|error| format!("MLS ratchet tree could not be read: {error}"))
                        .and_then(|tree| mls_group::join_group_from_invitation(&state, &welcome, &tree))
                })
        });
    match result {
        Ok(bytes) => env.byte_array_from_slice(&bytes)
            .map(|array| array.into_raw()).unwrap_or(std::ptr::null_mut()),
        Err(error) => {
            set_status(format!("MESHX MLS group join error: {error}"));
            std::ptr::null_mut()
        }
    }
}


/// Kotlin: NativeMeshx.nativeMlsEncryptApplicationMessage(groupSnapshot, plaintext)
/// Returns JSON bundle containing advanced sender state and MLS ciphertext.
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeMlsEncryptApplicationMessage(
    mut env: JNIEnv,
    _this: JObject,
    group_snapshot: JByteArray,
    plaintext: JByteArray,
) -> jbyteArray {
    let result = env.convert_byte_array(&group_snapshot)
        .map_err(|error| format!("MLS group state could not be read: {error}"))
        .and_then(|state| {
            env.convert_byte_array(&plaintext)
                .map_err(|error| format!("Message plaintext could not be read: {error}"))
                .and_then(|message| mls_group::encrypt_group_application_message(&state, &message))
        });
    match result {
        Ok(bytes) => env.byte_array_from_slice(&bytes)
            .map(|array| array.into_raw()).unwrap_or(std::ptr::null_mut()),
        Err(error) => {
            set_status(format!("MESHX MLS encryption error: {error}"));
            std::ptr::null_mut()
        }
    }
}

/// Kotlin: NativeMeshx.nativeMlsDecryptApplicationMessage(groupSnapshot, ciphertext)
/// Returns JSON bundle containing advanced receiver state and authenticated plaintext.
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeMlsDecryptApplicationMessage(
    mut env: JNIEnv,
    _this: JObject,
    group_snapshot: JByteArray,
    ciphertext: JByteArray,
) -> jbyteArray {
    let result = env.convert_byte_array(&group_snapshot)
        .map_err(|error| format!("MLS group state could not be read: {error}"))
        .and_then(|state| {
            env.convert_byte_array(&ciphertext)
                .map_err(|error| format!("MLS ciphertext could not be read: {error}"))
                .and_then(|message| mls_group::decrypt_group_application_message(&state, &message))
        });
    match result {
        Ok(bytes) => env.byte_array_from_slice(&bytes)
            .map(|array| array.into_raw()).unwrap_or(std::ptr::null_mut()),
        Err(error) => {
            set_status(format!("MESHX MLS decryption error: {error}"));
            std::ptr::null_mut()
        }
    }
}
