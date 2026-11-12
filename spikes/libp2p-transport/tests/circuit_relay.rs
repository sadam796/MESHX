use std::time::Duration;

use futures::StreamExt;
use libp2p::{
    identity,
    multiaddr::Protocol,
    noise, relay,
    swarm::{Swarm, SwarmEvent},
    tcp, yamux, SwarmBuilder,
};

#[derive(libp2p::swarm::NetworkBehaviour)]
struct TestRelayServerBehaviour {
    relay: relay::Behaviour,
    ping: libp2p::ping::Behaviour,
}

#[derive(libp2p::swarm::NetworkBehaviour)]
struct TestRelayClientBehaviour {
    relay: relay::client::Behaviour,
    ping: libp2p::ping::Behaviour,
}

fn relay_server(key: identity::Keypair) -> Swarm<TestRelayServerBehaviour> {
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
            let mut relay =
                relay::Behaviour::new(key.public().to_peer_id(), relay::Config::default());
            // Loopback tests have no externally confirmed address, so explicitly
            // enable HOP protocol advertisement for this test relay.
            relay.set_status(Some(relay::Status::Enable));
            TestRelayServerBehaviour {
                relay,
                ping: libp2p::ping::Behaviour::new(libp2p::ping::Config::new()),
            }
        })
        .expect("relay server behaviour")
        .build()
}

fn relay_client(key: identity::Keypair) -> Swarm<TestRelayClientBehaviour> {
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
        .with_behaviour(|_key, relay| TestRelayClientBehaviour {
            relay,
            ping: libp2p::ping::Behaviour::new(libp2p::ping::Config::new()),
        })
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

    // Match a public relay deployment: advertise the transport address
    // without the terminal relay Peer ID (the swarm appends it when needed).
    let mut advertised_address = server_address.clone();
    assert!(matches!(advertised_address.pop(), Some(Protocol::P2p(peer)) if peer == server_peer));
    server.add_external_address(advertised_address);

    let client_a_key = identity::Keypair::generate_ed25519();
    let client_a_peer = client_a_key.public().to_peer_id();
    let mut client_a = relay_client(client_a_key);

    // Listening on the relay circuit address makes the relay-client behaviour
    // dial the relay and request a reservation. Do not race it with a separate
    // manual dial to the same peer.
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
                event = server.select_next_some() => {
                    println!("relay server event: {event:?}");
                }
                event = client_a.select_next_some() => {
                    println!("client A event: {event:?}");
                    if let SwarmEvent::NewListenAddr { address, .. } = event {
                        if address.iter().any(|part| matches!(part, Protocol::P2pCircuit)) {
                            assert!(
                                address.iter().any(|part| matches!(part, Protocol::P2p(peer) if peer == client_a_peer)),
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
                    println!("client B event: {event:?}");
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
