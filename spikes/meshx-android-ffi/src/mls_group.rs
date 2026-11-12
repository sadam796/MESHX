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

    MlsGroup::load(provider.storage(), &openmls::prelude::GroupId::from_slice(&snapshot.group_id))
        .map_err(|error| format!("MLS group restore failed: {error:?}"))?
        .ok_or_else(|| "MLS group was not found in restored provider storage".to_owned())?;

    Ok(())
}


/// Runs a real two-member RFC 9420 application-message round trip using two
/// independent providers. This is an on-device cryptographic self-test only;
/// it does not imply network delivery or contact authentication.
pub fn two_member_round_trip_self_test() -> Result<(), String> {
    use openmls::framing::{ProcessedMessageContent, MlsMessageIn};
    use openmls::prelude::{KeyPackage, StagedWelcome};

    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();
    let config = openmls::prelude::MlsGroupCreateConfig::builder()
        .ciphersuite(MLS_CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    let make_member = |identity: &[u8], provider: &OpenMlsRustCrypto| -> Result<_, String> {
        let signer = SignatureKeyPair::new(MLS_CIPHERSUITE.signature_algorithm())
            .map_err(|e| format!("MLS signer generation failed: {e:?}"))?;
        signer.store(provider.storage())
            .map_err(|e| format!("MLS signer storage failed: {e:?}"))?;
        let credential = BasicCredential::new(identity.to_vec());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.to_public_vec().into(),
        };
        Ok((signer, credential_with_key))
    };

    let (alice_signer, alice_credential) = make_member(b"meshx-self-test-alice", &alice_provider)?;
    let (bob_signer, bob_credential) = make_member(b"meshx-self-test-bob", &bob_provider)?;
    let mut alice = MlsGroup::new(&alice_provider, &alice_signer, &config, alice_credential)
        .map_err(|e| format!("Alice MLS group creation failed: {e:?}"))?;
    let bob_key_package = KeyPackage::builder()
        .build(MLS_CIPHERSUITE, &bob_provider, &bob_signer, bob_credential)
        .map_err(|e| format!("Bob KeyPackage creation failed: {e:?}"))?;
    let (_commit, welcome, _group_info) = alice.add_members(
        &alice_provider, &alice_signer, core::slice::from_ref(bob_key_package.key_package())
    ).map_err(|e| format!("Alice could not add Bob: {e:?}"))?;
    alice.merge_pending_commit(&alice_provider)
        .map_err(|e| format!("Alice commit merge failed: {e:?}"))?;

    let welcome: MlsMessageIn = welcome.into();
    let welcome = match welcome.extract() {
        openmls::prelude::MlsMessageBodyIn::Welcome(value) => value,
        _ => return Err("OpenMLS did not produce a Welcome message".to_owned()),
    };
    let mut bob = StagedWelcome::new_from_welcome(
        &bob_provider, &config.join_config(), welcome,
        Some(alice.export_ratchet_tree().into())
    ).map_err(|e| format!("Bob Welcome processing failed: {e:?}"))?
        .into_group(&bob_provider)
        .map_err(|e| format!("Bob MLS group join failed: {e:?}"))?;

    let plaintext = b"MESHX Android MLS self-test";
    let ciphertext = alice.create_message(&alice_provider, &alice_signer, plaintext)
        .map_err(|e| format!("MLS application encryption failed: {e:?}"))?;
    let protocol_message = MlsMessageIn::from(ciphertext).try_into_protocol_message()
        .map_err(|e| format!("MLS ciphertext parsing failed: {e:?}"))?;
    let processed = bob.process_message(&bob_provider, protocol_message)
        .map_err(|e| format!("MLS application decryption failed: {e:?}"))?;
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => { if message.into_bytes() == plaintext { Ok(()) } else { Err("Bob recovered different MLS application plaintext".to_owned()) } },
        _ => Err("Bob did not recover the expected MLS application plaintext".to_owned()),
    }
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

    #[test]
    fn two_member_group_encrypts_and_decrypts_after_provider_restore() {
        use openmls::framing::{ProcessedMessageContent, MlsMessageIn};
        use openmls::prelude::{KeyPackage, StagedWelcome};

        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(MLS_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();

        let make_member = |identity: &[u8], provider: &OpenMlsRustCrypto| {
            let signer = SignatureKeyPair::new(MLS_CIPHERSUITE.signature_algorithm()).unwrap();
            signer.store(provider.storage()).unwrap();
            let credential = BasicCredential::new(identity.to_vec());
            let credential_with_key = CredentialWithKey {
                credential: credential.into(),
                signature_key: signer.to_public_vec().into(),
            };
            (signer, credential_with_key)
        };

        let (alice_signer, alice_credential) = make_member(b"meshx-alice", &alice_provider);
        let (bob_signer, bob_credential) = make_member(b"meshx-bob", &bob_provider);
        let mut alice = MlsGroup::new(&alice_provider, &alice_signer, &config, alice_credential).unwrap();
        let bob_key_package = KeyPackage::builder()
            .build(MLS_CIPHERSUITE, &bob_provider, &bob_signer, bob_credential)
            .unwrap();
        let (_commit, welcome, _group_info) = alice.add_members(
            &alice_provider, &alice_signer, core::slice::from_ref(bob_key_package.key_package())
        ).unwrap();
        alice.merge_pending_commit(&alice_provider).unwrap();

        let welcome: MlsMessageIn = welcome.into();
        let welcome = match welcome.extract() {
            openmls::prelude::MlsMessageBodyIn::Welcome(value) => value,
            _ => panic!("expected MLS Welcome"),
        };
        let bob = StagedWelcome::new_from_welcome(
            &bob_provider, &config.join_config(), welcome,
            Some(alice.export_ratchet_tree().into())
        ).unwrap().into_group(&bob_provider).unwrap();

        let group_id = alice.group_id().clone();
        let alice_entries = alice_provider.storage().values.read().unwrap().iter()
            .map(|(k, v)| (k.clone(), v.clone())).collect::<Vec<_>>();
        let bob_entries = bob_provider.storage().values.read().unwrap().iter()
            .map(|(k, v)| (k.clone(), v.clone())).collect::<Vec<_>>();
        let restored_alice = OpenMlsRustCrypto::default();
        restored_alice.storage().values.write().unwrap().extend(alice_entries);
        let restored_bob = OpenMlsRustCrypto::default();
        restored_bob.storage().values.write().unwrap().extend(bob_entries);

        let mut alice = MlsGroup::load(restored_alice.storage(), &group_id).unwrap().unwrap();
        let mut bob = MlsGroup::load(restored_bob.storage(), bob.group_id()).unwrap().unwrap();
        let signer = SignatureKeyPair::read(
            restored_alice.storage(), alice_signer.public(),
            MLS_CIPHERSUITE.signature_algorithm()
        ).unwrap();

        let plaintext = b"MESHX two-device MLS encrypted message";
        let ciphertext = alice.create_message(&restored_alice, &signer, plaintext).unwrap();
        let processed = bob.process_message(
            &restored_bob,
            MlsMessageIn::from(ciphertext).try_into_protocol_message().unwrap()
        ).unwrap();
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => {
                assert_eq!(message.into_bytes(), plaintext);
            }
            other => panic!("expected application message, got {other:?}"),
        }
    }

}


#[derive(Serialize, Deserialize)]
struct KeyPackageSnapshot {
    version: u32,
    signer_public: Vec<u8>,
    key_package: Vec<u8>,
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Creates a one-use MLS KeyPackage and snapshots its private init/encryption
/// material. The snapshot must be encrypted by the Android Keystore vault.
pub fn create_key_package_snapshot(identity: &[u8]) -> Result<Vec<u8>, String> {
    use openmls::prelude::{KeyPackage, tls_codec::Serialize};

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
    let bundle = KeyPackage::builder()
        .build(MLS_CIPHERSUITE, &provider, &signer, credential_with_key)
        .map_err(|error| format!("MLS KeyPackage creation failed: {error:?}"))?;
    let key_package = bundle.key_package().tls_serialize_detached()
        .map_err(|error| format!("MLS KeyPackage serialization failed: {error:?}"))?;
    let entries = provider.storage().values.read()
        .map_err(|_| "OpenMLS provider storage lock is poisoned".to_owned())?
        .iter().map(|(key, value)| (key.clone(), value.clone())).collect();
    serde_json::to_vec(&KeyPackageSnapshot {
        version: SNAPSHOT_VERSION,
        signer_public: signer.public().to_vec(),
        key_package,
        entries,
    }).map_err(|error| format!("MLS KeyPackage snapshot encoding failed: {error}"))
}

/// Extracts the public one-use KeyPackage from an authenticated vault snapshot.
pub fn extract_key_package(snapshot_bytes: &[u8]) -> Result<Vec<u8>, String> {
    use openmls::prelude::{DeserializeBytes, KeyPackageIn, ProtocolVersion};

    let snapshot: KeyPackageSnapshot = serde_json::from_slice(snapshot_bytes)
        .map_err(|error| format!("MLS KeyPackage snapshot is invalid: {error}"))?;
    if snapshot.version != SNAPSHOT_VERSION || snapshot.key_package.is_empty() {
        return Err("MLS KeyPackage snapshot version or payload is invalid".to_owned());
    }
    let provider = OpenMlsRustCrypto::default();
    provider.storage().values.write()
        .map_err(|_| "OpenMLS provider storage lock is poisoned".to_owned())?
        .extend(snapshot.entries);
    SignatureKeyPair::read(provider.storage(), &snapshot.signer_public,
        MLS_CIPHERSUITE.signature_algorithm())
        .ok_or_else(|| "MLS KeyPackage signer was not restored".to_owned())?;
    let input = KeyPackageIn::tls_deserialize_exact_bytes(&snapshot.key_package)
        .map_err(|error| format!("MLS KeyPackage decoding failed: {error:?}"))?;
    input.validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|error| format!("MLS KeyPackage signature validation failed: {error:?}"))?;
    Ok(snapshot.key_package)
}

#[cfg(test)]
mod key_package_tests {
    use super::*;

    #[test]
    fn creates_persists_and_revalidates_one_use_contact_key_package() {
        let snapshot = create_key_package_snapshot(b"meshx-contact-test")
            .expect("create contact KeyPackage snapshot");
        let public_package = extract_key_package(&snapshot)
            .expect("restore and validate public KeyPackage");
        assert!(!public_package.is_empty());
        let restored_public_package = extract_key_package(&snapshot)
            .expect("repeat validation from same saved private state");
        assert_eq!(public_package, restored_public_package);
    }
}


#[derive(Serialize, Deserialize)]
pub struct GroupInvitationSnapshot {
    pub version: u32,
    pub updated_group_snapshot: Vec<u8>,
    pub welcome_message: Vec<u8>,
    pub ratchet_tree: Vec<u8>,
}

/// Adds a verified remote KeyPackage to an existing MLS group. Returns the
/// updated sender state plus the Welcome and ratchet tree the recipient needs.
pub fn add_member_to_group_snapshot(
    group_snapshot_bytes: &[u8],
    key_package_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    use openmls::prelude::{DeserializeBytes, KeyPackageIn, ProtocolVersion};
    use openmls::prelude::tls_codec::Serialize;

    if group_snapshot_bytes.is_empty() || key_package_bytes.is_empty() {
        return Err("MLS group snapshot and recipient KeyPackage are required".to_owned());
    }
    let snapshot: GroupSnapshot = serde_json::from_slice(group_snapshot_bytes)
        .map_err(|error| format!("MLS group snapshot is invalid: {error}"))?;
    if snapshot.version != SNAPSHOT_VERSION || snapshot.group_id.is_empty() {
        return Err("MLS group snapshot version or group ID is invalid".to_owned());
    }
    let provider = OpenMlsRustCrypto::default();
    provider.storage().values.write()
        .map_err(|_| "OpenMLS provider storage lock is poisoned".to_owned())?
        .extend(snapshot.entries);
    let signer = SignatureKeyPair::read(
        provider.storage(), &snapshot.signer_public, MLS_CIPHERSUITE.signature_algorithm()
    ).ok_or_else(|| "MLS group signing key is missing".to_owned())?;
    let group_id = openmls::prelude::GroupId::from_slice(&snapshot.group_id);
    let mut group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(|error| format!("MLS group restore failed: {error:?}"))?
        .ok_or_else(|| "MLS group was not found".to_owned())?;
    let package_in = KeyPackageIn::tls_deserialize_exact_bytes(key_package_bytes)
        .map_err(|error| format!("Recipient KeyPackage decoding failed: {error:?}"))?;
    let package = package_in.validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|error| format!("Recipient KeyPackage signature validation failed: {error:?}"))?;
    let (_commit, welcome, _group_info) = group.add_members(
        &provider, &signer, core::slice::from_ref(&package)
    ).map_err(|error| format!("MLS member addition failed: {error:?}"))?;
    group.merge_pending_commit(&provider)
        .map_err(|error| format!("MLS membership commit failed: {error:?}"))?;

    let welcome_message = welcome.tls_serialize_detached()
        .map_err(|error| format!("MLS Welcome serialization failed: {error:?}"))?;
    let ratchet_tree = group.export_ratchet_tree().tls_serialize_detached()
        .map_err(|error| format!("MLS ratchet tree serialization failed: {error:?}"))?;
    let entries = provider.storage().values.read()
        .map_err(|_| "OpenMLS provider storage lock is poisoned".to_owned())?
        .iter().map(|(key, value)| (key.clone(), value.clone())).collect();
    let updated_group_snapshot = serde_json::to_vec(&GroupSnapshot {
        version: SNAPSHOT_VERSION,
        group_id: group.group_id().as_slice().to_vec(),
        signer_public: signer.public().to_vec(),
        entries,
    }).map_err(|error| format!("Updated MLS group snapshot encoding failed: {error}"))?;
    serde_json::to_vec(&GroupInvitationSnapshot {
        version: SNAPSHOT_VERSION,
        updated_group_snapshot,
        welcome_message,
        ratchet_tree,
    }).map_err(|error| format!("MLS invitation encoding failed: {error}"))
}


#[cfg(test)]
mod invitation_tests {
    use super::*;

    #[test]
    fn persisted_group_accepts_verified_contact_key_package_and_exports_welcome() {
        let alice_group = create_group_snapshot(b"meshx-invite-alice")
            .expect("create sender group");
        let bob_key_package_snapshot = create_key_package_snapshot(b"meshx-invite-bob")
            .expect("create recipient KeyPackage snapshot");
        let bob_public_key_package = extract_key_package(&bob_key_package_snapshot)
            .expect("extract verified recipient KeyPackage");
        let invitation = add_member_to_group_snapshot(&alice_group, &bob_public_key_package)
            .expect("add recipient and export invitation");
        let invitation: GroupInvitationSnapshot = serde_json::from_slice(&invitation)
            .expect("decode invitation bundle");
        assert_eq!(invitation.version, SNAPSHOT_VERSION);
        assert!(!invitation.welcome_message.is_empty());
        assert!(!invitation.ratchet_tree.is_empty());
        validate_group_snapshot(&invitation.updated_group_snapshot)
            .expect("updated sender group remains restorable");
    }
}
