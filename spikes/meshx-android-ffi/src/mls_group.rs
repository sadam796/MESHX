//! Group-scoped OpenMLS state operations for the Android Keystore boundary.
//!
//! The provider snapshot contains private MLS material. It must be encrypted by
//! MlsStateVault before persistence. Credential identity is supplied by the app;
//! binding it to the MESHX identity is a separate, not-yet-completed milestone.

use openmls::prelude::{Ciphersuite, CredentialWithKey, MlsGroup, MlsGroupCreateConfig, OpenMlsProvider, BasicCredential};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize, Serialize};

const SNAPSHOT_VERSION: u32 = 1;
const MLS_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

#[derive(Serialize, Deserialize)]
struct GroupSnapshot {
    version: u32,
    group_id: Vec<u8>,
    signer_public: Vec<u8>,
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Creates an actual RFC 9420 MLS group and returns its provider snapshot.
/// The identity bytes become the MLS BasicCredential identity; callers must
/// encrypt the returned bytes in Android Keystore-backed storage.
pub fn create_group_snapshot(identity: &[u8]) -> Result<Vec<u8>, String> {
    if identity.is_empty() || identity.len() > 256 {
        return Err("MLS credential identity must contain 1 to 256 bytes".to_owned());
    }

    let provider = OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(MLS_CIPHERSUITE.signature_algorithm())
        .map_err(|error| format!("MLS signing key generation failed: {error:?}"))?;
    signer.store(provider.storage())
        .map_err(|error| format!("MLS signing key storage failed: {error:?}"))?;

    let credential = BasicCredential::new(identity.to_vec());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.to_public_vec().into(),
    };
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(MLS_CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();
    let group = MlsGroup::new(&provider, &signer, &config, credential_with_key)
        .map_err(|error| format!("MLS group creation failed: {error:?}"))?;

    let entries = provider.storage().values.read()
        .map_err(|_| "OpenMLS provider storage lock is poisoned".to_owned())?
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    serde_json::to_vec(&GroupSnapshot {
        version: SNAPSHOT_VERSION,
        group_id: group.group_id().as_slice().to_vec(),
        signer_public: signer.public().to_vec(),
        entries,
    }).map_err(|error| format!("OpenMLS group snapshot encoding failed: {error}"))
}

/// Restores the provider and confirms that the saved group and signer both exist.
pub fn validate_group_snapshot(bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() {
        return Err("MLS group snapshot is empty".to_owned());
    }
    let snapshot: GroupSnapshot = serde_json::from_slice(bytes)
        .map_err(|error| format!("MLS group snapshot is invalid: {error}"))?;
    if snapshot.version != SNAPSHOT_VERSION
        || snapshot.group_id.is_empty()
        || snapshot.signer_public.is_empty()
    {
        return Err("MLS group snapshot version or identifiers are invalid".to_owned());
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

    MlsGroup::load(provider.storage(), &snapshot.group_id)
        .map_err(|error| format!("MLS group restore failed: {error:?}"))?
        .ok_or_else(|| "MLS group was not found in restored provider storage".to_owned())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_restores_a_real_mls_group() {
        let snapshot = create_group_snapshot(b"meshx-test-identity")
            .expect("create MLS group snapshot");
        assert!(!snapshot.is_empty());
        validate_group_snapshot(&snapshot).expect("restore MLS group and signer");
    }

    #[test]
    fn rejects_empty_and_tampered_group_snapshots() {
        assert!(create_group_snapshot(b"").is_err());
        let snapshot = create_group_snapshot(b"meshx-test-identity")
            .expect("create MLS group snapshot");
        let mut tampered = snapshot;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(validate_group_snapshot(&tampered).is_err());
    }
}
