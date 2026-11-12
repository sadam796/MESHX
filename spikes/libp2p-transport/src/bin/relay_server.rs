//! Self-hostable public libp2p circuit-relay v2 node for MESHX.
//! This is a reachable-peer relay only; it does not implement offline mailbox delivery.
use futures::StreamExt;
use libp2p::{identity, relay, swarm::SwarmEvent, SwarmBuilder};
use std::{error::Error, path::PathBuf};

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
    let listen_address = std::env::var("MESHX_RELAY_LISTEN")
        .unwrap_or_else(|_| "/ip4/0.0.0.0/tcp/4001".to_string())
        .parse()?;

    let identity = load_or_create_identity(&key_path)?;
    let peer_id = identity.public().to_peer_id();
    let mut swarm = SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|_| relay::Behaviour::new(peer_id, relay::Config::default()))?
        .build();

    swarm.listen_on(listen_address)?;
    println!("MESHX relay peer ID: {peer_id}");
    println!("Relay identity file: {}", key_path.display());

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("Shutdown requested; stopping relay.");
                break;
            }
            event = swarm.select_next_some() => {
                if let SwarmEvent::NewListenAddr { address, .. } = event {
                    println!("Relay listening on {address}/p2p/{peer_id}");
                }
            }
        }
    }
    Ok(())
}
