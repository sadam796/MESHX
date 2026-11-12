//! Self-hostable libp2p circuit-relay v2 node and durable offline mailbox for MESHX.
//! The mailbox stores only end-to-end-encrypted envelopes and authenticates mailbox
//! operations against the libp2p Peer ID established by the Noise connection.
//! This remains an experimental service; public deployment still needs abuse controls.
use futures::StreamExt;
use libp2p::{
    identity,
    relay,
    request_response::{Event as RequestEvent, Message as RequestMessage},
    swarm::{NetworkBehaviour, SwarmEvent},
    SwarmBuilder,
};
use meshx_libp2p_transport_spike::{
    handle_mailbox_request, new_mailbox_behaviour, DiskQueue, MailboxRequest, MailboxResponse,
    MeshxMailboxBehaviour,
};
use std::{error::Error, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "RelayServerEvent")]
struct RelayServerBehaviour {
    circuit: relay::Behaviour,
    mailbox: MeshxMailboxBehaviour,
}

#[derive(Debug)]
enum RelayServerEvent {
    Circuit(relay::Event),
    Mailbox(RequestEvent<MailboxRequest, MailboxResponse>),
}

impl From<relay::Event> for RelayServerEvent {
    fn from(event: relay::Event) -> Self {
        Self::Circuit(event)
    }
}

impl From<RequestEvent<MailboxRequest, MailboxResponse>> for RelayServerEvent {
    fn from(event: RequestEvent<MailboxRequest, MailboxResponse>) -> Self {
        Self::Mailbox(event)
    }
}

fn unix_time_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn load_or_create_identity(path: &PathBuf) -> Result<identity::Keypair, Box<dyn Error>> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        return Ok(identity::Keypair::from_protobuf_encoding(&bytes)?);
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let key = identity::Keypair::generate_ed25519();
    let encoded = key.to_protobuf_encoding()?;
    use std::io::Write;
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&temp)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(temp, path)?;
    Ok(key)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let key_path = PathBuf::from(
        std::env::var("MESHX_RELAY_KEY_FILE")
            .unwrap_or_else(|_| "./data/relay-identity.key".to_string()),
    );
    let mailbox_dir = PathBuf::from(
        std::env::var("MESHX_MAILBOX_DIR")
            .unwrap_or_else(|_| "./data/mailbox".to_string()),
    );
    let mailbox_max_entries = env_usize("MESHX_MAILBOX_MAX_ENTRIES", 1_000);
    let mailbox_max_bytes = env_usize("MESHX_MAILBOX_MAX_BYTES", 512 * 1024 * 1024);
    let mailbox = DiskQueue::open(&mailbox_dir, mailbox_max_entries, mailbox_max_bytes)?;

    let listen_address = std::env::var("MESHX_RELAY_LISTEN")
        .unwrap_or_else(|_| "/ip4/0.0.0.0/tcp/4001".to_string())
        .parse()?;
    let public_address: Option<libp2p::Multiaddr> =
        std::env::var("MESHX_RELAY_PUBLIC_ADDRESS")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.parse::<libp2p::Multiaddr>())
            .transpose()?;

    let identity = load_or_create_identity(&key_path)?;
    let peer_id = identity.public().to_peer_id();
    let mut swarm = SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|_| {
            let mut circuit = relay::Behaviour::new(peer_id, relay::Config::default());
            // This VPS is intentionally operated as a relay. Do not wait for
            // external-address discovery before advertising the HOP protocol.
            circuit.set_status(Some(relay::Status::Enable));
            RelayServerBehaviour {
                circuit,
                mailbox: new_mailbox_behaviour(),
            }
        })?
        .build();

    swarm.listen_on(listen_address)?;
    if let Some(address) = public_address {
        swarm.add_external_address(address.clone());
        println!("Advertised relay address: {address}/p2p/{peer_id}");
    } else {
        println!("No MESHX_RELAY_PUBLIC_ADDRESS set; clients must use the VPS address entered in the app.");
    }
    println!("MESHX relay peer ID: {peer_id}");
    println!("Relay identity file: {}", key_path.display());
    println!(
        "MESHX durable mailbox ready at {}; limits: {} messages / {} bytes",
        mailbox_dir.display(),
        mailbox_max_entries,
        mailbox_max_bytes
    );
    println!(
        "Mailbox protocol: /meshx/mailbox/1; fetch returns at most {} messages per request",
        meshx_libp2p_transport_spike::MAX_MAILBOX_FETCH_MESSAGES
    );

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("Shutdown requested; stopping relay and mailbox service.");
                break;
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("Relay listening on {address}/p2p/{peer_id}");
                    }
                    SwarmEvent::Behaviour(RelayServerEvent::Mailbox(event)) => {
                        match event {
                            RequestEvent::Message { peer, message, .. } => match message {
                                RequestMessage::Request { request, channel, .. } => {
                                    let response = handle_mailbox_request(
                                        &mailbox,
                                        &peer,
                                        request,
                                        unix_time_seconds(),
                                    );
                                    if swarm.behaviour_mut().mailbox.send_response(channel, response).is_err() {
                                        eprintln!("Mailbox response channel closed for authenticated peer {peer}");
                                    }
                                }
                                RequestMessage::Response { .. } => {}
                            },
                            RequestEvent::InboundFailure { peer, error, .. } => {
                                eprintln!("Mailbox request from {peer} failed: {error}");
                            }
                            RequestEvent::OutboundFailure { peer, error, .. } => {
                                eprintln!("Mailbox response to {peer} failed: {error}");
                            }
                            RequestEvent::ResponseSent { .. } => {}
                        }
                    }
                    SwarmEvent::Behaviour(RelayServerEvent::Circuit(_)) => {}
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_key_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "meshx-relay-key-{label}-{}-{nonce}.key",
            std::process::id()
        ))
    }

    #[test]
    fn relay_identity_is_stable_across_restarts() {
        let path = test_key_path("restart");
        let first = load_or_create_identity(&path).expect("create relay identity");
        let first_peer = first.public().to_peer_id();
        drop(first);

        let second = load_or_create_identity(&path).expect("reload relay identity");
        assert_eq!(second.public().to_peer_id(), first_peer);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn relay_identity_file_is_created_with_private_permissions() {
        let path = test_key_path("permissions");
        let _key = load_or_create_identity(&path).expect("create relay identity");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn corrupted_relay_identity_is_not_silently_replaced() {
        let path = test_key_path("corrupt");
        std::fs::write(&path, b"not-a-libp2p-key").expect("write corrupt key");
        assert!(load_or_create_identity(&path).is_err());
        let _ = std::fs::remove_file(path);
    }
}
