//! Android JNI bridge that starts a real libp2p TCP/Noise/Yamux swarm.
//! This milestone starts a listening peer; it does not yet implement recipient
//! discovery, MLS sessions, message sending, relays, or global delivery.

use std::{
    sync::{atomic::{AtomicBool, Ordering}, Mutex, OnceLock},
    thread,
};

use futures::StreamExt;
use jni::{objects::JObject, sys::jstring, JNIEnv};
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

fn start_swarm() -> Result<String, String> {
    if STARTED.swap(true, Ordering::SeqCst) {
        return Ok(current_status());
    }

    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id();
    let peer_label = peer_id.to_string();

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
                let mut swarm = match SwarmBuilder::with_existing_identity(keypair)
                    .with_tokio()
                    .with_tcp(
                        tcp::Config::default(),
                        libp2p::noise::Config::new,
                        yamux::Config::default,
                    )
                    .map_err(|error| format!("MESHX TCP transport error: {error}"))
                    .and_then(|builder| {
                        builder
                            .with_behaviour(|key| {
                                meshx_libp2p_transport_spike::new_network_behaviour(
                                    key.public().to_peer_id()
                                )
                            })
                            .map_err(|error| format!("MESHX behaviour error: {error}"))
                    })
                {
                    Ok(builder) => builder.build(),
                    Err(error) => {
                        set_status(error);
                        STARTED.store(false, Ordering::SeqCst);
                        return;
                    }
                };

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
                    "MESHX libp2p swarm starting; peer id {peer_label}; waiting for TCP listener"
                ));

                loop {
                    match swarm.select_next_some().await {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            set_status(format!(
                                "MESHX libp2p TCP listener active; peer id {peer_label}; address {address}"
                            ));
                        }
                        SwarmEvent::ListenerError { error, .. } => {
                            set_status(format!("MESHX listener error: {error}"));
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            set_status(format!(
                                "MESHX libp2p connected to peer {peer_id}; local peer id {peer_label}"
                            ));
                        }
                        SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            set_status(format!(
                                "MESHX peer disconnected: {peer_id}; local peer id {peer_label}"
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

/// Kotlin: NativeMeshx.nativeStartTransport()
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeStartTransport(
    mut env: JNIEnv,
    _this: JObject,
) -> jstring {
    let result = start_swarm().unwrap_or_else(|error| error);
    jni_string(&mut env, result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_status_is_honest_about_not_started_transport() {
        assert!(current_status().contains("not started"));
    }
}
