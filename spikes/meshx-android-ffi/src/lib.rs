//! Android JNI bridge for a libp2p TCP/Noise/Yamux peer and opaque ciphertext
//! request/response delivery. MLS encryption, durable relays, and global delivery
//! are separate unfinished milestones.

use std::{
    collections::VecDeque,
    sync::{atomic::{AtomicBool, AtomicU64, Ordering}, Mutex, OnceLock},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

mod mls_snapshot;
mod mls_group;

use futures::StreamExt;
use jni::{objects::{JByteArray, JObject, JString}, sys::{jboolean, jbyteArray, jstring, JNI_FALSE, JNI_TRUE}, JNIEnv};
use libp2p::{swarm::SwarmEvent, tcp, yamux, Multiaddr, SwarmBuilder};

enum TransportCommand {
    AddBootstrapPeers(Vec<String>),
    FindPeer(libp2p::PeerId),
    SendCiphertext { peer_id: libp2p::PeerId, ciphertext: Vec<u8> },
}

const MAX_PENDING_INCOMING: usize = 128;
static NEXT_MESSAGE_ID: AtomicU64 = AtomicU64::new(1);
static INCOMING_MESSAGES: OnceLock<Mutex<VecDeque<meshx_libp2p_transport_spike::DeliveryEnvelope>>> = OnceLock::new();

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
    Ok("MESHX encrypted payload queued for direct peer delivery. This is not a delivered/read receipt.".to_owned())
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

                let builder = match builder.with_behaviour(|key| {
                    meshx_libp2p_transport_spike::new_network_behaviour(
                        key.public().to_peer_id()
                    )
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
                        event = swarm.select_next_some() => {
                            match event {
                                SwarmEvent::NewListenAddr { address, .. } => {
                                    set_status(format!(
                                        "MESHX libp2p TCP listener active; peer id {thread_peer_label}; address {address}"
                                    ));
                                }
                                SwarmEvent::ListenerError { error, .. } => {
                                    set_status(format!("MESHX listener error: {error}"));
                                }
                                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                    set_status(format!(
                                        "MESHX libp2p connected to peer {peer_id}; local peer id {thread_peer_label}"
                                    ));
                                }
                                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                                    set_status(format!(
                                        "MESHX peer disconnected: {peer_id}; local peer id {thread_peer_label}"
                                    ));
                                }
                                SwarmEvent::Behaviour(meshx_libp2p_transport_spike::MeshxEvent::Kad(event)) => {
                                    set_status(format!(
                                        "MESHX DHT discovery event: {event:?}; local peer id {thread_peer_label}"
                                    ));
                                }
                                SwarmEvent::Behaviour(meshx_libp2p_transport_spike::MeshxEvent::Delivery(event)) => {
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
                                                let _ = swarm.behaviour_mut().delivery.send_response(channel, ack);
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
                                _ => {}
                            }
                        }
                        command = command_receiver.recv() => {
                            match command {
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
                                                &mut swarm.behaviour_mut().kad,
                                                &peers,
                                            );
                                            let bootstrap_result = meshx_libp2p_transport_spike::start_dht_bootstrap(
                                                &mut swarm.behaviour_mut().kad,
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
                                        &mut swarm.behaviour_mut().kad,
                                        peer_id.clone(),
                                    );
                                    set_status(format!(
                                        "MESHX DHT lookup started for {peer_id}; query {query_id:?}; returned peers are only routing candidates, not proof the contact is online; local peer id {thread_peer_label}"
                                    ));
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
                                        hop_limit: 1,
                                        ciphertext,
                                    };
                                    match envelope.validate(now) {
                                        Ok(()) => {
                                            swarm.behaviour_mut().delivery.send_request(&peer_id, envelope);
                                            set_status(format!("MESHX direct encrypted-payload request queued for {peer_id}; waiting for remote acknowledgement. No relay/offline delivery."));
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
    let messages = match incoming_messages().lock() {
        Ok(mut queue) => {
            let mut selected = Vec::new();
            let mut retained = VecDeque::new();
            while let Some(message) = queue.pop_front() {
                if message.sender_id.as_slice() == expected_sender.as_slice() {
                    selected.push(message);
                } else {
                    retained.push_back(message);
                }
            }
            *queue = retained;
            selected
        }
        Err(_) => return jni_string(&mut env, "[]".to_owned()),
    };
    // Expose the authenticated libp2p sender ID beside the opaque MLS bytes so
    // Android can route the payload to the matching saved contact/group.
    let payloads = messages.into_iter().filter_map(|message| {
        let sender_peer_id = libp2p::PeerId::from_bytes(&message.sender_id).ok()?.to_string();
        Some(serde_json::json!({
            "sender_peer_id": sender_peer_id,
            "ciphertext": message.ciphertext,
            "message_id": message.message_id,
        }))
    }).collect::<Vec<_>>();
    let json = serde_json::to_string(&payloads).unwrap_or_else(|_| "[]".to_owned());
    jni_string(&mut env, json)
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
