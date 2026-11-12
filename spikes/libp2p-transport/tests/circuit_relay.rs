use std::time::Duration;

use futures::StreamExt;
use libp2p::{
    identity,
    multiaddr::Protocol,
    noise, relay,
    swarm::{Swarm, SwarmEvent},
    tcp, yamux, SwarmBuilder,
};

fn relay_server(key: identity::Keypair) -> Swarm<relay::Behaviour> {
    SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .expect("relay server TCP transport")
        .with_quic()
        .with_behaviour(|key| {
            relay::Behaviour::new(key.public().to_peer_id(), relay::Config::default())
        })
        .expect("relay server behaviour")
        .build()
}

fn relay_client(key: identity::Keypair) -> Swarm<relay::client::Behaviour> {
    SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .expect("relay client TCP transport")
        .with_quic()
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .expect("relay client transport")
        .with_behaviour(|_key, relay| relay)
        .expect("relay client behaviour")
        .build()
}

#[tokio::test]
async fn two_clients_can_connect_through_a_local_circuit_relay() {
    let server_key = identity::Keypair::generate_ed25519();
    let server_peer = server_key.public().to_peer_id();
    let mut server = relay_server(server_key);

    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0"
        .parse()
        .expect("valid loopback listen address");
    server.listen_on(listen).expect("relay server listen");

    let server_address = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = server.select_next_some().await {
                break address.with(Protocol::P2p(server_peer));
            }
        }
    })
    .await
    .expect("relay server did not start listening");

    let client_a_key = identity::Keypair::generate_ed25519();
    let client_a_peer = client_a_key.public().to_peer_id();
    let mut client_a = relay_client(client_a_key);
    client_a.dial(server_address.clone()).expect("client A dial relay");

    let reservation_listener = server_address.clone().with(Protocol::P2pCircuit);
    client_a
        .listen_on(reservation_listener)
        .expect("client A request relay reservation");

    let client_b_key = identity::Keypair::generate_ed25519();
    let mut client_b = relay_client(client_b_key);

    tokio::time::timeout(Duration::from_secs(20), async {
        let mut client_b_dial_started = false;

        loop {
            tokio::select! {
                _ = server.select_next_some() => {}
                event = client_a.select_next_some() => {
                    if let SwarmEvent::NewListenAddr { address, .. } = event {
                        if address.iter().any(|part| matches!(part, Protocol::P2pCircuit)) {
                            assert!(
                                address.iter().any(|part| matches!(part, Protocol::P2p(peer) if *peer == client_a_peer)),
                                "relay reservation address must identify client A"
                            );
                            if !client_b_dial_started {
                                client_b.dial(address).expect("client B dial relayed client A");
                                client_b_dial_started = true;
                            }
                        }
                    }
                }
                event = client_b.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. }
                            if peer_id == client_a_peer =>
                        {
                            assert!(
                                endpoint.get_remote_address().iter().any(|part| matches!(part, Protocol::P2pCircuit)),
                                "connection must use a relay circuit address"
                            );
                            break;
                        }
                        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                            panic!("client B relay dial failed for {peer_id:?}: {error}");
                        }
                        _ => {}
                    }
                }
            }
        }
    })
    .await
    .expect("two peers did not establish a relayed connection");
}
