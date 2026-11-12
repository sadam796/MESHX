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
use std::{collections::HashMap, error::Error, path::PathBuf, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};

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

/// Per-authenticated-peer fixed-window request limiter with bounded bookkeeping.
struct PeerRateLimiter {
    window: Duration,
    max_requests: usize,
    max_tracked_peers: usize,
    peers: HashMap<libp2p::PeerId, (Instant, usize)>,
}

impl PeerRateLimiter {
    fn new(window: Duration, max_requests: usize, max_tracked_peers: usize) -> Self {
        Self { window, max_requests: max_requests.max(1), max_tracked_peers, peers: HashMap::new() }
    }

    fn allow(&mut self, peer: libp2p::PeerId, now: Instant) -> bool {
        self.peers.retain(|_, (started, _)| now.saturating_duration_since(*started) < self.window);
        if let Some((started, count)) = self.peers.get_mut(&peer) {
            if now.saturating_duration_since(*started) >= self.window {
                *started = now;
                *count = 1;
                return true;
            }
            if *count >= self.max_requests { return false; }
            *count += 1;
            return true;
        }
        if self.peers.len() >= self.max_tracked_peers { return false; }
        self.peers.insert(peer, (now, 1));
        true
    }
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
    let mailbox_requests_per_minute = env_usize("MESHX_MAILBOX_REQUESTS_PER_MINUTE", 120);
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
    println!("Mailbox request limit: {} requests per authenticated peer per 60 seconds", mailbox_requests_per_minute);
    println!(
        "Mailbox protocol: /meshx/mailbox/1; fetch returns at most {} messages per request",
        meshx_libp2p_transport_spike::MAX_MAILBOX_FETCH_MESSAGES
    );

    let mut rate_limiter = PeerRateLimiter::new(Duration::from_secs(60), mailbox_requests_per_minute, 10_000);

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
                                    let response = if rate_limiter.allow(peer, Instant::now()) {
                                        handle_mailbox_request(&mailbox, &peer, request, unix_time_seconds())
                                    } else {
                                        MailboxResponse::Rejected {
                                            reason: meshx_libp2p_transport_spike::MailboxRejectReason::RateLimited,
                                        }
                                    };
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
    fn mailbox_rate_limiter_caps_requests_per_peer_and_resets_window() {
        let peer = identity::Keypair::generate_ed25519().public().to_peer_id();
        let other = identity::Keypair::generate_ed25519().public().to_peer_id();
        let start = Instant::now();
        let mut limiter = PeerRateLimiter::new(Duration::from_secs(60), 2, 10);
        assert!(limiter.allow(peer, start));
        assert!(limiter.allow(peer, start + Duration::from_secs(1)));
        assert!(!limiter.allow(peer, start + Duration::from_secs(2)));
        assert!(limiter.allow(other, start + Duration::from_secs(2)), "limits are per peer");
        assert!(limiter.allow(peer, start + Duration::from_secs(60)), "window resets after 60 seconds");
    }

    #[test]
    fn mailbox_rate_limiter_bounds_tracked_peer_state() {
        let start = Instant::now();
        let mut limiter = PeerRateLimiter::new(Duration::from_secs(60), 10, 1);
        let first = identity::Keypair::generate_ed25519().public().to_peer_id();
        let second = identity::Keypair::generate_ed25519().public().to_peer_id();
        assert!(limiter.allow(first, start));
        assert!(!limiter.allow(second, start), "tracked peer map must remain bounded");
        assert!(limiter.allow(second, start + Duration::from_secs(60)), "expired windows are pruned");
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
