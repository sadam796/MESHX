# MESHX MLS state storage boundary

## Status

This is the Android persistence foundation for the OpenMLS engine. It is **not yet** an OpenMLS `StorageProvider` and is not wired to the Android JNI transport. A separate Rust spike now exercises a two-member RFC 9420 flow (create group, add member, Welcome join, encrypted application message, provider snapshot/restore, decrypt). That Rust test uses an in-memory provider and serialized snapshots; it does not call this Android vault or write plaintext snapshots to disk.

## Storage contract

```text
OpenMLS group state bytes
        |
        v
MlsStateVault.save(groupId, opaqueBytes)
        |
        v
AES-256-GCM (Android Keystore key: meshx_mls_state_aes_v1)
        |
        v
App-private file: files/meshx_mls_state_v1/<SHA-256(groupId)>.mls
```

- AES-256-GCM uses a fresh randomized 96-bit IV for each save and a 128-bit authentication tag.
- The group ID is included as authenticated additional data (AAD), so a snapshot cannot be moved to a different group ID and still decrypt.
- File names are SHA-256 hashes of group IDs; the raw group ID is not written into the file name.
- Writes use a temporary file, `fsync`, and atomic rename so an interrupted write does not replace the previous complete snapshot.
- Reads fail closed if the Keystore key is missing, the format/size is invalid, or AES-GCM authentication fails. A failed read does not silently erase or replace the stored file.
- Snapshots are capped at 16 MiB per group. The vault uses app-private internal storage.
- Android app backup is disabled in the manifest (`android:allowBackup="false"`); a Keystore-bound ciphertext must not be copied to another device without a deliberate recovery design.

## Next integration work

1. Connect the Rust provider snapshot/restore boundary to this Android vault so the serialized OpenMLS provider store is encrypted before every disk write and authenticated before restore.
2. Bind the MLS credential signing key to a deliberate MESHX identity model; the existing MESHX2 transport-key signature is not automatically an MLS credential.
3. Extend the Rust two-member test with tamper/replay and non-member rejection, and add an Android restart test that exercises the real Rust-to-vault bridge.
4. Only then connect MLS ciphertext to libp2p request/response delivery. Noise remains hop-by-hop transport security; MLS provides group end-to-end protection.
