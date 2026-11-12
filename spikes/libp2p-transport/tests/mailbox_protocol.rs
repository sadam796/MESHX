//! Network-level test for the relay mailbox request/response protocol.
//! This uses loopback TCP and authenticated libp2p Noise peer identities;
//! it does not claim public Internet reachability or Android client integration.

use std::{path::PathBuf, time::{Duration, SystemTime, UNIX_EPOCH}};

use futures::StreamExt;
use libp2p::{
    identity,
    request_response::{Event as RequestEvent, Message as RequestMessage},
    swarm::{Swarm, SwarmEvent},
    tcp, yamux, Multiaddr, SwarmBuilder,
};
use meshx_libp2p_transport_spike::{
    handle_mailbox_request, new_mailbox_behaviour, DeliveryEnvelope, DiskQueue,
    MailboxRequest, MailboxResponse, MeshxMailboxBehaviour,
};

fn make_swarm() -> Swarm<MeshxMailboxBehaviour> {
    SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            libp2p::noise::Config::new,
            yamux::Config::default,
        )
        .expect("TCP transport")
        .with_behaviour(|_| new_mailbox_behaviour())
        .expect("mailbox behaviour")
        .build()
}

fn test_mailbox_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("meshx-mailbox-network-{}-{nonce}", std::process::id()))
}

#[tokio::test]
async fn sender_stores_recipient_fetches_and_acknowledges_over_network() {
    let mut server = make_swarm();
    let server_peer = *server.local_peer_id();
    let mut sender = make_swarm();
    let sender_peer = *sender.local_peer_id();
    let mut recipient = make_swarm();
    let recipient_peer = *recipient.local_peer_id();

    let directory = test_mailbox_dir();
    let queue = DiskQueue::open(&directory, 32, 1024 * 1024).expect("open durable mailbox");

    server
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("loopback address"))
        .expect("server listens");

    let server_address: Multiaddr = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = server.select_next_some().await {
                break address.with(libp2p::multiaddr::Protocol::P2p(server_peer));
            }
        }
    })
    .await
    .expect("mailbox server listen timeout");

    sender.dial(server_address.clone()).expect("sender dials mailbox server");
    recipient.dial(server_address.clone()).expect("recipient dials mailbox server");

    let envelope = DeliveryEnvelope {
        message_id: [77; 16],
        sender_id: sender_peer.to_bytes(),
        recipient_id: recipient_peer.to_bytes(),
        created_at: 100,
        expires_at: 300,
        hop_limit: 8,
        ciphertext: b"opaque-mls-ciphertext".to_vec(),
    };

    let mut store_sent = false;
    let mut stored = false;
    let mut recipient_connected = false;
    let mut fetch_sent = false;
    let mut ack_sent = false;
    let mut acknowledged = false;

    tokio::time::timeout(Duration::from_secs(25), async {
        while !acknowledged {
            tokio::select! {
                event = sender.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            if peer_id == server_peer && !store_sent {
                                sender.behaviour_mut().send_request(
                                    &server_peer,
                                    MailboxRequest::Store(envelope.clone()),
                                );
                                store_sent = true;
                            }
                        }
                        SwarmEvent::Behaviour(RequestEvent::Message {
                            peer,
                            message: RequestMessage::Response { response, .. },
                            ..
                        }) => {
                            assert_eq!(peer, server_peer);
                            assert_eq!(
                                response,
                                MailboxResponse::Stored { accepted: true, duplicate: false }
                            );
                            stored = true;
                        }
                        _ => {}
                    }
                }
                event = recipient.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            if peer_id == server_peer {
                                recipient_connected = true;
                            }
                        }
                        SwarmEvent::Behaviour(RequestEvent::Message {
                            peer,
                            message: RequestMessage::Response { response, .. },
                            ..
                        }) => {
                            assert_eq!(peer, server_peer);
                            match response {
                                MailboxResponse::Messages { envelopes } => {
                                    assert_eq!(envelopes, vec![envelope.clone()]);
                                    assert!(!ack_sent);
                                    recipient.behaviour_mut().send_request(
                                        &server_peer,
                                        MailboxRequest::Acknowledge {
                                            message_id: envelope.message_id,
                                        },
                                    );
                                    ack_sent = true;
                                }
                                MailboxResponse::Acknowledged { message_id, removed } => {
                                    assert_eq!(message_id, envelope.message_id);
                                    assert!(removed, "recipient ack must remove its queued message");
                                    acknowledged = true;
                                }
                                other => panic!("unexpected mailbox response: {other:?}"),
                            }
                        }
                        _ => {}
                    }
                }
                event = server.select_next_some() => {
                    if let SwarmEvent::Behaviour(RequestEvent::Message {
                        peer,
                        message: RequestMessage::Request { request, channel, .. },
                        ..
                    }) = event {
                        let response = handle_mailbox_request(&queue, &peer, request, 101);
                        server.behaviour_mut().send_response(channel, response)
                            .expect("mailbox response channel");
                    }
                }
            }

            if stored && recipient_connected && !fetch_sent {
                recipient.behaviour_mut().send_request(&server_peer, MailboxRequest::Fetch);
                fetch_sent = true;
            }
        }
    })
    .await
    .expect("mailbox store/fetch/ack exchange timed out");

    assert!(store_sent);
    assert!(stored);
    assert!(fetch_sent);
    assert!(ack_sent);
    assert!(queue.is_empty().expect("mailbox queue state"));
    let _ = std::fs::remove_dir_all(directory);
}
