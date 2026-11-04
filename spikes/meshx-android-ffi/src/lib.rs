//! Minimal JNI boundary spike for the Android application.
//! This proves the native library can expose a Kotlin-callable JNI symbol.
//! It does not start a libp2p Swarm or deliver messages.

use jni::{
    objects::JObject,
    sys::jstring,
    JNIEnv,
};

const STATUS_PREFIX: &str = "MESHX native bridge loaded; transport not started";

/// Kotlin declaration:
/// `external fun nativeTransportStatus(): String`
/// on `org.meshx.app.NativeMeshx`.
#[no_mangle]
pub extern "system" fn Java_org_meshx_app_NativeMeshx_nativeTransportStatus(
    mut env: JNIEnv,
    _this: JObject,
) -> jstring {
    let status = format!(
        "{STATUS_PREFIX}; max ciphertext {} bytes",
        meshx_libp2p_transport_spike::MAX_CIPHERTEXT_BYTES
    );
    env.new_string(status)
        .expect("JNI string allocation")
        .into_raw()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_status_is_explicit_about_transport_state() {
        assert!(STATUS_PREFIX.contains("transport not started"));
        assert!(meshx_libp2p_transport_spike::MAX_CIPHERTEXT_BYTES > 0);
    }
}
