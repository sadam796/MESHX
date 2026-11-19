//! Deterministic key derivation for MESHX's 24-word recovery identity.
//!
//! The mnemonic is converted to a standard BIP-39 seed in the Android layer.
//! This module derives independent, domain-separated transport and P-256
//! signing keys. It never persists or logs seed material.

use hkdf::Hkdf;
use p256::{
    ecdsa::SigningKey,
    pkcs8::{EncodePrivateKey, EncodePublicKey},
};
use sha2::Sha256;

const RECOVERY_SALT: &[u8] = b"MESHX-RECOVERY-KEYS-V1";
const TRANSPORT_INFO: &[u8] = b"MESHX/libp2p-ed25519-transport/v1";
const SIGNING_INFO: &[u8] = b"MESHX/p256-identity-signing/v1";

fn expand(seed: &[u8], info: &[u8], output: &mut [u8]) -> Result<(), String> {
    if seed.len() != 64 {
        return Err("BIP-39 seed must be exactly 64 bytes.".to_owned());
    }
    Hkdf::<Sha256>::new(Some(RECOVERY_SALT), seed)
        .expand(info, output)
        .map_err(|_| "MESHX recovery key derivation failed.".to_owned())
}

pub fn derive_transport_identity(seed: &[u8]) -> Result<Vec<u8>, String> {
    let mut secret = [0u8; 32];
    expand(seed, TRANSPORT_INFO, &mut secret)?;
    let result = libp2p::identity::Keypair::ed25519_from_bytes(&mut secret)
        .map_err(|error| format!("MESHX recovery transport key is invalid: {error}"))
        .and_then(|key| key.to_protobuf_encoding()
            .map_err(|error| format!("MESHX recovery transport key could not be encoded: {error}")));
    secret.fill(0);
    result
}

/// Returns PKCS#8 DER private key bytes. The caller must keep these secret and
/// protect them with the Android Keystore when stored on this device.
pub fn derive_signing_private_key(seed: &[u8]) -> Result<Vec<u8>, String> {
    let mut secret = [0u8; 32];
    // The probability of an invalid P-256 scalar is negligible, but use a
    // counter-based retry rather than silently accepting invalid material.
    for counter in 0u32..256 {
        let mut info = SIGNING_INFO.to_vec();
        info.extend_from_slice(&counter.to_be_bytes());
        expand(seed, &info, &mut secret)?;
        if let Ok(key) = SigningKey::from_slice(&secret) {
            let encoded = key.to_pkcs8_der()
                .map_err(|error| format!("MESHX signing key encoding failed: {error}"))?
                .as_bytes().to_vec();
            secret.fill(0);
            return Ok(encoded);
        }
    }
    secret.fill(0);
    Err("Could not derive a valid MESHX P-256 signing key.".to_owned())
}

/// Returns the X.509 SubjectPublicKeyInfo DER matching the derived private key.
pub fn derive_signing_public_key(seed: &[u8]) -> Result<Vec<u8>, String> {
    let mut secret = [0u8; 32];
    for counter in 0u32..256 {
        let mut info = SIGNING_INFO.to_vec();
        info.extend_from_slice(&counter.to_be_bytes());
        expand(seed, &info, &mut secret)?;
        if let Ok(key) = SigningKey::from_slice(&secret) {
            let encoded = key.verifying_key().to_public_key_der()
                .map_err(|error| format!("MESHX signing public key encoding failed: {error}"))?
                .as_bytes().to_vec();
            secret.fill(0);
            return Ok(encoded);
        }
    }
    secret.fill(0);
    Err("Could not derive a valid MESHX P-256 signing key.".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_restores_identical_transport_and_signing_keys() {
        let seed = [7u8; 64];
        let transport_a = derive_transport_identity(&seed).unwrap();
        let transport_b = derive_transport_identity(&seed).unwrap();
        let signing_private_a = derive_signing_private_key(&seed).unwrap();
        let signing_private_b = derive_signing_private_key(&seed).unwrap();
        let signing_public_a = derive_signing_public_key(&seed).unwrap();
        let signing_public_b = derive_signing_public_key(&seed).unwrap();

        assert_eq!(transport_a, transport_b);
        assert_eq!(signing_private_a, signing_private_b);
        assert_eq!(signing_public_a, signing_public_b);
        let key = libp2p::identity::Keypair::from_protobuf_encoding(&transport_a).unwrap();
        assert_eq!(
            key.public().to_peer_id(),
            libp2p::identity::Keypair::from_protobuf_encoding(&transport_b)
                .unwrap().public().to_peer_id()
        );
    }

    #[test]
    fn different_seeds_produce_different_account_keys() {
        let first = [1u8; 64];
        let second = [2u8; 64];
        assert_ne!(derive_transport_identity(&first).unwrap(), derive_transport_identity(&second).unwrap());
        assert_ne!(derive_signing_public_key(&first).unwrap(), derive_signing_public_key(&second).unwrap());
    }

    #[test]
    fn rejects_non_bip39_seed_lengths() {
        assert!(derive_transport_identity(&[0u8; 32]).is_err());
        assert!(derive_signing_private_key(&[0u8; 65]).is_err());
    }
}
