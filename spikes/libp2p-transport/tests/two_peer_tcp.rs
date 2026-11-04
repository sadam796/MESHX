//! Local TCP application-protocol smoke test.
//! This proves one peer can send an opaque byte payload and receive an acknowledgement.
//! It does not provide E2E encryption, discovery, relays, durable delivery, or global reachability.

use std::time::Duration;

use futures::StreamExt;
use libp2p::{
    request_response,
    swarm::{NetworkBehaviour, Swarm, SwarmEvent},
    tcp, yamux, Multiaddr, StreamProtocol, SwarmBuilder,
};

const DELIVERY_PROTOCOL: &str = "/meshx/delivery/1";
const TEST_CIPHERTEXT: &[u8] = b"opaque-test-ciphertext-not-real-encryption";
const ACK: &[u8] = b"accepted-for-test-only";

#[derive(NetworkBehaviour)]
struct Behaviour {
    delivery: request_response::cbor::Behaviour<Vec<u8>, Vec<u8>>,
}

fn make_swarm() -> Swarm<Behaviour> {
    SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            libp2p::noise::Config::new,
            yamux::Config::default,
        )
        .expect("TCP transport")
        .with_behaviour(|_| Behaviour {
            delivery: request_response::cbor::Behaviour::new(
                [(
                    StreamProtocol::new(DELIVERY_PROTOCOL),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            ),
        })
        .expect("delivery behaviour")
        .build()
}

#[tokio::test]
async fn two_local_peers_exchange_opaque_delivery_payload_and_ack() {
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

    let mut request_sent = false;
    let mut payload_received = false;
    let mut acknowledgement_received = false;

    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                event = alice.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == bob_peer && !request_sent => {
                            alice.behaviour_mut().delivery.send_request(
                                &bob_peer,
                                TEST_CIPHERTEXT.to_vec(),
                            );
                            request_sent = true;
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Delivery(
                            request_response::Event::Message {
                                message: request_response::Message::Response { response, .. },
                                ..
                            }
                        )) => {
                            assert_eq!(response.as_slice(), ACK);
                            acknowledgement_received = true;
                        }
                        _ => {}
                    }
                }
                event = bob.select_next_some() => {
                    if let SwarmEvent::Behaviour(BehaviourEvent::Delivery(
                        request_response::Event::Message {
                            message: request_response::Message::Request { request, channel, .. },
                            ..
                        }
                    )) = event {
                        assert_eq!(request.as_slice(), TEST_CIPHERTEXT);
                        payload_received = true;
                        bob.behaviour_mut().delivery.send_response(channel, ACK.to_vec())
                            .expect("send acknowledgement");
                    }
                }
            }

            if payload_received && acknowledgement_received {
                break;
            }
        }
    })
    .await
    .expect("application payload exchange timed out");

    assert!(request_sent);
    assert!(payload_received);
    assert!(acknowledgement_received);
}
