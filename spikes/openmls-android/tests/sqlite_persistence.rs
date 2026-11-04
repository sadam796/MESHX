use openmls::prelude::{tls_codec::*, *};
use openmls::storage::OpenMlsProvider;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use serde::{de::DeserializeOwned, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

struct PersistentProvider {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<JsonCodec, Connection>,
}

impl OpenMlsProvider for PersistentProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, Connection>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

fn open_provider(path: &Path) -> PersistentProvider {
    let connection = Connection::open(path).expect("open SQLite database");
    let mut storage = SqliteStorageProvider::<JsonCodec, _>::new(connection);
    storage.run_migrations().expect("initialize OpenMLS SQLite schema");

    PersistentProvider {
        crypto: RustCrypto::default(),
        storage,
    }
}

fn database_path(label: &str) -> PathBuf {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "meshx-openmls-{label}-{}-{}.sqlite",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ))
}

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
fn two_members_resume_encrypted_chat_after_database_reopen() {
    let alice_db = database_path("alice");
    let bob_db = database_path("bob");
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    let alice_group_id;
    let bob_group_id;
    let alice_signer;
    let bob_signer;
    let first_message_bytes;

    {
        let alice_provider = open_provider(&alice_db);
        let bob_provider = open_provider(&bob_db);

        let (alice_credential, signer_a) =
            make_identity(b"Alice-persistent", ciphersuite, &alice_provider);
        let (bob_credential, signer_b) =
            make_identity(b"Bob-persistent", ciphersuite, &bob_provider);
        alice_signer = signer_a;
        bob_signer = signer_b;

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

        let (_commit, welcome_out, _group_info) = alice_group
            .add_members(
                &alice_provider,
                &alice_signer,
                core::slice::from_ref(bob_key_package.key_package()),
            )
            .expect("add Bob");
        alice_group
            .merge_pending_commit(&alice_provider)
            .expect("merge Alice add-member commit");

        let welcome_bytes = welcome_out.tls_serialize_detached().expect("serialize Welcome");
        let welcome = match MlsMessageIn::tls_deserialize_exact(&welcome_bytes)
            .expect("parse Welcome")
            .extract()
        {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => panic!("expected Welcome"),
        };
        let staged = StagedWelcome::new_from_welcome(
            &bob_provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            Some(alice_group.export_ratchet_tree().into()),
        )
        .expect("stage Bob join");
        let mut bob_group = staged.into_group(&bob_provider).expect("Bob joins");

        alice_group_id = alice_group.group_id().clone();
        bob_group_id = bob_group.group_id().clone();

        first_message_bytes = alice_group
            .create_message(&alice_provider, &alice_signer, b"before restart")
            .expect("encrypt first message")
            .tls_serialize_detached()
            .expect("serialize first message");
        let incoming = MlsMessageIn::tls_deserialize_exact(&first_message_bytes).expect("parse first message");
        let protocol = incoming
            .try_into_protocol_message()
            .expect("convert first message");
        let processed = bob_group
            .process_message(&bob_provider, protocol)
            .expect("Bob decrypts first message");
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => {
                assert_eq!(message.into_bytes(), b"before restart");
            }
            _ => panic!("expected application message"),
        }
    } // Drop both groups, providers and SQLite connections to simulate process restart.

    {
        let alice_provider = open_provider(&alice_db);
        let bob_provider = open_provider(&bob_db);

        let mut alice_group = MlsGroup::load(alice_provider.storage(), &alice_group_id)
            .expect("load Alice group state")
            .expect("Alice group must survive restart");
        let mut bob_group = MlsGroup::load(bob_provider.storage(), &bob_group_id)
            .expect("load Bob group state")
            .expect("Bob group must survive restart");

        let second = alice_group
            .create_message(&alice_provider, &alice_signer, b"after restart")
            .expect("encrypt second message after restart")
            .tls_serialize_detached()
            .expect("serialize second message");
        let incoming = MlsMessageIn::tls_deserialize_exact(&second).expect("parse second message");
        let protocol = incoming
            .try_into_protocol_message()
            .expect("convert second message");
        let processed = bob_group
            .process_message(&bob_provider, protocol)
            .expect("Bob decrypts after restart");

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => {
                assert_eq!(message.into_bytes(), b"after restart");
            }
            _ => panic!("expected application message"),
        }

        // The replay window must also survive a process restart.
        let replay = MlsMessageIn::tls_deserialize_exact(&first_message_bytes)
            .expect("parse replay after restart")
            .try_into_protocol_message()
            .expect("convert replay after restart");
        assert!(
            bob_group.process_message(&bob_provider, replay).is_err(),
            "Bob must reject a previously processed message after restart"
        );

        assert_eq!(alice_group.epoch(), bob_group.epoch());
    }

    let _ = std::fs::remove_file(alice_db);
    let _ = std::fs::remove_file(bob_db);
}
