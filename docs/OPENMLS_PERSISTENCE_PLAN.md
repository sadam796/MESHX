# MESHX OpenMLS Persistence Evaluation

## Status: design gate — not implemented

The current two-party tests use `OpenMlsRustCrypto::default()`, whose bundled test storage is in-memory. Those tests prove protocol behavior only while each test process is alive. They do not prove that an MLS group can be safely restored after an app/process restart.

Do not connect this spike to the Android app yet.

## Required approach

1. Evaluate the OpenMLS-maintained SQLite storage provider that matches the pinned OpenMLS release. Confirm its exact crate version, Rust version, Android NDK compatibility, licence, maintenance status, and supported storage APIs before adding it.
2. Keep the RustCrypto cryptographic provider; replace only the storage backend through a correctly implemented `OpenMlsProvider`. Do not write a custom crypto provider.
3. Store the database only in app-private storage. Protect the database key with Android Keystore; never store that key, MLS private keys, or recovery phrase in plaintext.
4. Use atomic transactions and safe database migration/versioning. Define backup/restore behavior before release.
5. Do not log database contents, serialized private state, key material, or message plaintext.

## Required automated tests

- Create Alice/Bob identities and a two-member group using persistent storage.
- Send and decrypt one application message.
- Drop both provider instances to simulate process shutdown.
- Reopen the same storage using fresh provider instances and reload each MLS group by its group ID.
- Exchange a second encrypted message after reload and verify its plaintext.
- Verify the first message cannot be replayed after reload.
- Verify a corrupted/truncated database fails closed without silently creating a new identity or group.
- Verify wrong/missing database key fails closed.
- Verify independent users' databases cannot open each other's group state.

## Acceptance gate

Persistence is not accepted until the tests above pass on host CI and the storage crate builds for Android ARM64. iOS is a separate target check. A successful cross-compile is not proof of Android runtime correctness or a security audit.

## Current honest status

- Two-party MLS message exchange: tested in an isolated in-memory test.
- Modified ciphertext rejection: tested.
- Replay rejection: tested within the same process.
- Non-member rejection: tested.
- Process restart / durable MLS state: not yet tested.
- Android app integration and network transport: not implemented.
