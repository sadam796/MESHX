//! Isolated compile-only dependency probe for MESHX.
//! This is not wired into the Android app and does not implement messaging.

pub fn openmls_dependency_probe() -> &'static str {
    "OpenMLS dependency linked in isolated spike"
}
