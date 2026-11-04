//! Local TCP transport smoke test. This proves only a direct local peer connection
//! and authenticated libp2p ping; it does not test MLS, relays, or global delivery.

use std::time::Duration;

use futures::StreamExt;
use libp2p::{
    noise,
    ping,
    swarm::{Swarm, SwarmEvent},
    tcp, yamux, Multiaddr, SwarmBuilder,
};

fn make_swarm() -> Swarm<ping::Behaviour> {
    SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .expect("TCP transport")
        .with_behaviour(|_| ping::Behaviour::default())
        .expect("ping behaviour")
        .build()
}

#[tokio::test]
async fn two_local_peers_connect_and_ping() {
    let mut alice = make_swarm();
    let mut bob = make_swarm();
    let bob_peer = *bob.local_peer_id();

    bob.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .expect("Bob listens");

    let bob_addr: Multiaddr = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = bob.select_next_some().await {
                break address;
            }
        }
    })
    .await
    .expect("Bob listen address timeout");

    let mut dial_addr = bob_addr;
    dial_addr.push(libp2p::multiaddr::Protocol::P2p(bob_peer));
    alice.dial(dial_addr).expect("Alice dials Bob");

    let ping_seen = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            tokio::select! {
                event = alice.select_next_some() => {
                    if matches!(event, SwarmEvent::Behaviour(ping::Event { result: Ok(_), .. })) {
                        break true;
                    }
                }
                event = bob.select_next_some() => {
                    if matches!(event, SwarmEvent::Behaviour(ping::Event { result: Ok(_), .. })) {
                        break true;
                    }
                }
            }
        }
    })
    .await
    .expect("No successful ping between local peers");

    assert!(ping_seen);
}
