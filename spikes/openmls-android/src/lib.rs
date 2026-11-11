//! MESHX OpenMLS group engine spike.
//!
//! This crate exercises RFC 9420 group setup and application-message encryption.
//! Android JNI and the Keystore-backed storage adapter are separate integration
//! steps; this test uses OpenMLS' in-memory provider and snapshots it to simulate
//! persistence without writing plaintext test state to disk.

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

const TEST_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

#[cfg(test)]
mod tests {
    use super::*;
    use openmls::framing::ProcessedMessageContent;
    use openmls_traits::OpenMlsProvider;

    /// Serialize the complete OpenMLS provider store for the encrypted Android
    /// persistence boundary. The returned bytes contain secrets and must be
    /// encrypted before they are written to disk.
    fn snapshot_provider(provider: &OpenMlsRustCrypto) -> Vec<u8> {
        let entries: Vec<(Vec<u8>, Vec<u8>)> = provider
            .storage()
            .values
            .read()
            .expect("OpenMLS storage read lock")
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        serde_json::to_vec(&entries).expect("serialize OpenMLS provider store")
    }
    
    /// Restore an OpenMLS provider from bytes obtained from the encrypted Android
    /// state vault. Callers must never pass plaintext files or untrusted snapshots.
    fn restore_provider(snapshot: &[u8]) -> OpenMlsRustCrypto {
        let entries: Vec<(Vec<u8>, Vec<u8>)> =
            serde_json::from_slice(snapshot).expect("deserialize OpenMLS provider store");
        let provider = OpenMlsRustCrypto::default();
        provider
            .storage()
            .values
            .write()
            .expect("OpenMLS storage write lock")
            .extend(entries);
        provider
    }
    
    
    fn new_member(
        identity: &[u8],
        provider: &OpenMlsRustCrypto,
    ) -> (CredentialWithKey, SignatureKeyPair) {
        let credential = BasicCredential::new(identity.to_vec());
        let signer = SignatureKeyPair::new(TEST_CIPHERSUITE.signature_algorithm())
            .expect("generate MLS signing key");
        signer.store(provider.storage()).expect("store MLS signing key");
        (
            CredentialWithKey {
                credential: credential.into(),
                signature_key: signer.to_public_vec().into(),
            },
            signer,
        )
    }

    #[test]
    fn two_member_mls_message_survives_encrypted_store_boundary_round_trip() {
        // Independent providers model two Android devices.
        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();

        let (alice_credential, alice_signer) = new_member(b"meshx-alice", &alice_provider);
        let (bob_credential, bob_signer) = new_member(b"meshx-bob", &bob_provider);

        let create_config = MlsGroupCreateConfig::builder()
            .ciphersuite(TEST_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();

        let mut alice_group = MlsGroup::new(
            &alice_provider,
            &alice_signer,
            &create_config,
            alice_credential,
        )
        .expect("Alice creates MLS group");

        let bob_key_package = KeyPackage::builder()
            .build(
                TEST_CIPHERSUITE,
                &bob_provider,
                &bob_signer,
                bob_credential,
            )
            .expect("Bob creates KeyPackage");

        let (_commit, welcome, _group_info) = alice_group
            .add_members(
                &alice_provider,
                &alice_signer,
                core::slice::from_ref(bob_key_package.key_package()),
            )
            .expect("Alice adds Bob");
        alice_group
            .merge_pending_commit(&alice_provider)
            .expect("Alice merges add-member commit");

        let welcome: MlsMessageIn = welcome.into();
        let welcome = welcome.into_welcome().expect("Welcome message");
        let mut bob_group = StagedWelcome::new_from_welcome(
            &bob_provider,
            &create_config.join_config(),
            welcome,
            Some(alice_group.export_ratchet_tree().into()),
        )
        .expect("Bob stages Welcome")
        .into_group(&bob_provider)
        .expect("Bob joins MLS group");

        assert_eq!(alice_group.members().count(), 2);
        assert_eq!(bob_group.members().count(), 2);

        // This models the Android Keystore vault boundary: the complete provider
        // snapshots are handed to Kotlin, encrypted there, then restored here.
        // No plaintext snapshot is written to disk by this test.
        let alice_snapshot = snapshot_provider(&alice_provider);
        let bob_snapshot = snapshot_provider(&bob_provider);
        let restored_alice_provider = restore_provider(&alice_snapshot);
        let restored_bob_provider = restore_provider(&bob_snapshot);

        let mut restored_alice_group = MlsGroup::load(
            restored_alice_provider.storage(),
            alice_group.group_id(),
        )
        .expect("load Alice MLS group")
        .expect("Alice MLS group exists");
        let mut restored_bob_group = MlsGroup::load(
            restored_bob_provider.storage(),
            bob_group.group_id(),
        )
        .expect("load Bob MLS group")
        .expect("Bob MLS group exists");

        let restored_alice_signer = SignatureKeyPair::read(
            restored_alice_provider.storage(),
            alice_signer.public(),
            TEST_CIPHERSUITE.signature_algorithm(),
        )
        .expect("restore Alice MLS signer");
        let plaintext = b"MESHX MLS end-to-end test message";
        let encrypted = restored_alice_group
            .create_message(&restored_alice_provider, &restored_alice_signer, plaintext)
            .expect("Alice encrypts MLS application message");

        let processed = restored_bob_group
            .process_message(
                &restored_bob_provider,
                encrypted.into_protocol_message().expect("MLS protocol message"),
            )
            .expect("Bob authenticates and decrypts MLS message");

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => {
                assert_eq!(message.into_bytes(), plaintext);
            }
            other => panic!("Expected an MLS application message, got {other:?}"),
        }
    }
}

/// Exposes a compile-time marker for the RFC 9420 engine spike. This does not
/// imply that the engine is wired into the Android app or network transport.
pub fn openmls_engine_status() -> &'static str {
    "OpenMLS 0.9.2 RFC 9420 group engine spike; Android bridge pending"
}
