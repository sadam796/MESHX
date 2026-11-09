//! Android JNI bridge that starts a real libp2p TCP/Noise/Yamux swarm.
//! This milestone starts a listening peer; it does not yet implement recipient
//! discovery, MLS sessions, message sending, relays, or global delivery.

use std::{
    sync::{atomic::{AtomicBool, Ordering}, Mutex, OnceLock},
    thread,
};

use futures::StreamExt;
use jni::{objects::{JByteArray, JObject}, sys::{jbyteArray, jstring}, JNIEnv};
use libp2p::{swarm::SwarmEvent, tcp, yamux, Multiaddr, SwarmBuilder};

static STARTED: AtomicBool = AtomicBool::new(false);
static STATUS: OnceLock<Mutex<String>> = OnceLock::new();

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

fn start_swarm(identity_bytes: &[u8]) -> Result<String, String> {
    let keypair = libp2p::identity::Keypair::from_protobuf_encoding(identity_bytes)
        .map_err(|error| format!("MESHX saved transport identity is invalid: {error}"))?;

    if STARTED.swap(true, Ordering::SeqCst) {
        return Ok(current_status());
    }

    let peer_id = keypair.public().to_peer_id();
    let peer_label = peer_id.to_string();
    let thread_peer_label = peer_label.clone();

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
                    match swarm.select_next_some().await {
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
                        _ => {}
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
    fn invalid_persisted_identity_is_rejected() {
        assert!(libp2p::identity::Keypair::from_protobuf_encoding(b"not a key").is_err());
    }

    #[test]
    fn initial_status_is_honest_about_not_started_transport() {
        assert!(current_status().contains("not started"));
    }
}
