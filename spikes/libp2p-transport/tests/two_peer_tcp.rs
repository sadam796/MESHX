//! Local TCP application-protocol smoke test.
//! This exchanges a bounded delivery-envelope structure, not real MLS ciphertext.
//! It does not provide E2E encryption, discovery, relays, durable delivery, or global reachability.

use std::time::Duration;

use futures::StreamExt;
use libp2p::{
    request_response,
    swarm::{Swarm, SwarmEvent},
    tcp, yamux, Multiaddr, SwarmBuilder,
};
use meshx_libp2p_transport_spike::{
    dial_bootstrap_peers, new_network_behaviour, parse_bootstrap_peers,
    DeliveryAck, DeliveryEnvelope, MeshxNetworkBehaviour,
};

fn make_swarm() -> Swarm<MeshxNetworkBehaviour> {
    SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            libp2p::noise::Config::new,
            yamux::Config::default,
        )
        .expect("TCP transport")
        .with_behaviour(|key| new_network_behaviour(key.public().to_peer_id()))
        .expect("delivery behaviour")
        .build()
}

#[tokio::test]
async fn two_local_peers_exchange_delivery_envelope_and_ack() {
    let mut alice = make_swarm();
    let mut bob = make_swarm();
    let bob_peer = *bob.local_peer_id();
    let outgoing = DeliveryEnvelope {
        message_id: [42; 16],
        sender_id: b"alice-protocol-id".to_vec(),
        recipient_id: b"bob-protocol-id".to_vec(),
        created_at: 100,
        expires_at: 300,
        hop_limit: 8,
        ciphertext: b"opaque-test-bytes-not-real-encryption".to_vec(),
    };
    outgoing.validate(101).expect("valid test envelope");

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

    let bootstrap_address = format!("{bob_addr}/p2p/{bob_peer}");
    let bootstrap_peers = parse_bootstrap_peers(&[&bootstrap_address])
        .expect("valid bootstrap configuration");
    let dial_results = dial_bootstrap_peers(&mut alice, &bootstrap_peers);
    assert_eq!(dial_results.len(), 1);
    assert!(dial_results.into_iter().all(|result| result.is_ok()));

    let mut request_sent = false;
    let mut payload_received = false;
    let mut acknowledgement_received = false;

    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                event = alice.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == bob_peer && !request_sent => {
                            alice.behaviour_mut().delivery.send_request(&bob_peer, outgoing.clone());
                            request_sent = true;
                        }
                        SwarmEvent::Behaviour(MeshxNetworkBehaviourEvent::Delivery(
                            request_response::Event::Message {
                                message: request_response::Message::Response { response, .. },
                                ..
                            }
                        )) => {
                            assert_eq!(response.message_id, outgoing.message_id);
                            assert!(response.accepted);
                            acknowledgement_received = true;
                        }
                        _ => {}
                    }
                }
                event = bob.select_next_some() => {
                    if let SwarmEvent::Behaviour(MeshxNetworkBehaviourEvent::Delivery(
                        request_response::Event::Message {
                            message: request_response::Message::Request { request, channel, .. },
                            ..
                        }
                    )) = event {
                        assert_eq!(request, outgoing);
                        request.validate(101).expect("Bob validates envelope");
                        payload_received = true;
                        bob.behaviour_mut().delivery.send_response(channel, DeliveryAck {
                            message_id: request.message_id,
                            accepted: true,
                        }).expect("send acknowledgement");
                    }
                }
            }

            if payload_received && acknowledgement_received {
                break;
            }
        }
    })
    .await
    .expect("application envelope exchange timed out");

    assert!(request_sent);
    assert!(payload_received);
    assert!(acknowledgement_received);
}
