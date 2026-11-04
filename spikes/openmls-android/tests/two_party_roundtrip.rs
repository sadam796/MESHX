use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

fn make_identity(
    identity: &[u8],
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = BasicCredential::new(identity.to_vec());
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
        .expect("create signature key");
    signer.store(provider.storage()).expect("store signature key");

    (
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        },
        signer,
    )
}

#[test]
fn two_members_exchange_encrypted_application_message() {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();

    let (alice_credential, alice_signer) =
        make_identity(b"Alice", ciphersuite, &alice_provider);
    let (bob_credential, bob_signer) =
        make_identity(b"Bob", ciphersuite, &bob_provider);

    let bob_key_package = KeyPackage::builder()
        .build(ciphersuite, &bob_provider, &bob_signer, bob_credential)
        .expect("build Bob key package");

    let mut alice_group = MlsGroup::new(
        &alice_provider,
        &alice_signer,
        &MlsGroupCreateConfig::default(),
        alice_credential,
    )
    .expect("create Alice group");

    let (_add_commit, welcome_out, _group_info) = alice_group
        .add_members(
            &alice_provider,
            &alice_signer,
            core::slice::from_ref(bob_key_package.key_package()),
        )
        .expect("add Bob to group");
    alice_group
        .merge_pending_commit(&alice_provider)
        .expect("merge Alice add-member commit");

    // Transfer the Welcome as serialized bytes, as a delivery service would.
    let welcome_bytes = welcome_out
        .tls_serialize_detached()
        .expect("serialize Welcome");
    let welcome_message =
        MlsMessageIn::tls_deserialize_exact(&welcome_bytes).expect("parse Welcome");
    let welcome = match welcome_message.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => panic!("expected MLS Welcome"),
    };

    let staged_join = StagedWelcome::new_from_welcome(
        &bob_provider,
        &MlsGroupJoinConfig::default(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("stage Bob group join");
    let mut bob_group = staged_join
        .into_group(&bob_provider)
        .expect("Bob joins group");

    assert_eq!(alice_group.members().count(), 2);
    assert_eq!(bob_group.members().count(), 2);

    // Alice encrypts an application message; Bob receives only the MLS ciphertext.
    let plaintext = b"MESHX encrypted hello";
    let encrypted = alice_group
        .create_message(&alice_provider, &alice_signer, plaintext)
        .expect("encrypt Alice message");
    let encrypted_bytes = encrypted
        .tls_serialize_detached()
        .expect("serialize encrypted message");
    let incoming =
        MlsMessageIn::tls_deserialize_exact(&encrypted_bytes).expect("parse encrypted message");
    let protocol_message = incoming
        .try_into_protocol_message()
        .expect("convert to MLS protocol message");
    let processed = bob_group
        .process_message(&bob_provider, protocol_message)
        .expect("Bob decrypts and authenticates message");

    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => {
            assert_eq!(message.into_bytes(), plaintext);
        }
        _ => panic!("expected an authenticated application message"),
    }
}
