# MESHX OpenMLS Persistence Evaluation

## Status: isolated host test implemented; production storage not approved

The official OpenMLS SQLite storage provider has been identified: `openmls_sqlite_storage` 0.3.0, from the OpenMLS project, paired with the OpenMLS 0.9.x storage API. The spike now contains a custom `OpenMlsProvider` that keeps OpenMLS RustCrypto and swaps only the storage provider.

The host integration test creates Alice and Bob groups in separate SQLite databases, exchanges an encrypted message, drops the groups/providers/connections, reopens both databases, reloads the groups, exchanges another encrypted message, and checks that the first message is still rejected as a replay.

**Important:** the spike uses a JSON codec and ordinary SQLite only to test persistence mechanics. It does not encrypt the SQLite database. MLS private state can therefore be readable from these test database files. They are temporary test fixtures, deleted at test end, and must never be used for real user data.

Do not connect this spike to the Android app yet.

## Required production approach

1. Select an encrypted database strategy that is compatible with Android, Rust, and the chosen OpenMLS storage provider. The current ordinary SQLite provider is not sufficient by itself.
2. Keep database files in app-private storage. Protect the database key with Android Keystore; never store that key, MLS private keys, or recovery phrase in plaintext.
3. Evaluate SQLCipher or a reviewed application-layer encryption design, including key lifecycle, memory handling, migrations, backup/restore, and crash consistency. Do not assume a plain SQLite file is encrypted because Android app storage is private.
4. Use atomic transactions and safe database migration/versioning.
5. Do not log database contents, serialized private state, key material, or message plaintext.
6. Review the provider and storage implementation before production use; a passing test is not a security audit.

## Automated tests

- [x] Create Alice/Bob identities and a two-member group using persistent storage.
- [x] Send and decrypt an application message.
- [x] Drop both provider instances to simulate process shutdown.
- [x] Reopen the same storage using fresh provider instances and reload each MLS group by its group ID.
- [x] Exchange a second encrypted message after reload.
- [x] Verify the first message cannot be replayed after reload.
- [ ] Verify a corrupted/truncated database fails closed without silently creating a new identity or group.
- [ ] Verify wrong/missing database key fails closed (requires encrypted database strategy).
- [x] Use separate databases for independent users and verify their group state remains separate.
- [ ] Run the SQLite provider and persistence tests as part of Android ARM64 cross-compilation.
- [ ] Verify Android runtime persistence on physical devices.
- [ ] Verify iOS storage separately if iOS support is pursued.

## Acceptance gate

Host persistence tests are passing. This is only a protocol/storage-mechanics proof. The Android cross-compile must include test/dev dependencies, and physical-device behavior must be tested. Persistence is not production-ready until encrypted database handling, crash consistency, corruption handling, recovery, and security review are complete.

## Current honest status

- Two-party MLS message exchange: tested in isolated tests.
- Modified ciphertext rejection: tested.
- Replay rejection in one process: tested.
- Non-member rejection: tested.
- SQLite group-state persistence after provider/database reopen: tested on host CI.
- Replay rejection after database reopen: tested on host CI.
- Encrypted database / Android Keystore database key: not implemented.
- Android app integration and network transport: not implemented.
