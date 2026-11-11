//! OpenMLS provider snapshot boundary used by the Android Keystore vault.
//!
//! Snapshots contain MLS signing secrets. They are opaque bytes here and must
//! only be persisted after encryption by MlsStateVault on Android.

use openmls::prelude::{Ciphersuite, OpenMlsProvider};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize, Serialize};

const SNAPSHOT_VERSION: u32 = 1;
const MLS_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

#[derive(Serialize, Deserialize)]
struct ProviderSnapshot {
    version: u32,
    signer_public: Vec<u8>,
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Creates a real OpenMLS provider store containing a generated Ed25519 MLS
/// signing key, then serializes the provider store for the Android vault.
pub fn create_signer_snapshot() -> Result<Vec<u8>, String> {
    let provider = OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(MLS_CIPHERSUITE.signature_algorithm())
        .map_err(|error| format!("MLS signing key generation failed: {error:?}"))?;
    signer.store(provider.storage())
        .map_err(|error| format!("MLS signing key storage failed: {error:?}"))?;

    let entries = provider.storage().values.read()
        .map_err(|_| "OpenMLS provider storage lock is poisoned".to_owned())?
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    serde_json::to_vec(&ProviderSnapshot {
        version: SNAPSHOT_VERSION,
        signer_public: signer.public().to_vec(),
        entries,
    }).map_err(|error| format!("OpenMLS provider snapshot encoding failed: {error}"))
}

/// Restores the provider store and proves that its private MLS signing key can
/// be loaded again. Call only with bytes authenticated by the Android vault.
pub fn validate_signer_snapshot(bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() {
        return Err("MLS provider snapshot is empty".to_owned());
    }
    let snapshot: ProviderSnapshot = serde_json::from_slice(bytes)
        .map_err(|error| format!("MLS provider snapshot is invalid: {error}"))?;
    if snapshot.version != SNAPSHOT_VERSION || snapshot.signer_public.is_empty() {
        return Err("MLS provider snapshot version or signer is invalid".to_owned());
    }

    let provider = OpenMlsRustCrypto::default();
    provider.storage().values.write()
        .map_err(|_| "OpenMLS provider storage lock is poisoned".to_owned())?
        .extend(snapshot.entries);

    SignatureKeyPair::read(
        provider.storage(),
        &snapshot.signer_public,
        MLS_CIPHERSUITE.signature_algorithm(),
    ).ok_or_else(|| "MLS signing key was not found in restored provider storage".to_owned())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_snapshot_restores_the_real_openmls_private_key() {
        let snapshot = create_signer_snapshot().expect("create OpenMLS signer snapshot");
        assert!(!snapshot.is_empty());
        validate_signer_snapshot(&snapshot).expect("restore OpenMLS signer snapshot");
    }

    #[test]
    fn signer_snapshot_rejects_tampering_and_unknown_versions() {
        let snapshot = create_signer_snapshot().expect("create OpenMLS signer snapshot");
        let mut tampered = snapshot.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(validate_signer_snapshot(&tampered).is_err());

        let mut unknown: ProviderSnapshot = serde_json::from_slice(&snapshot).unwrap();
        unknown.version = SNAPSHOT_VERSION + 1;
        let unknown = serde_json::to_vec(&unknown).unwrap();
        assert!(validate_signer_snapshot(&unknown).is_err());
    }
}
