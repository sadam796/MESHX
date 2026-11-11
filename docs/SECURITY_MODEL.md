# MESHX Security Model

## Contact transport-key changes

For a saved MESHX2 identity, importing the same identity fingerprint with a different signed transport Peer ID raises a warning and requires explicit confirmation before replacing the saved binding. Importing unsigned MESHX1 over an existing signed MESHX2 binding is rejected as a downgrade. This is a local key-change safeguard, not proof of a person's real-world identity; users must still compare fingerprints over an independent trusted channel. Identity-key changes produce a different fingerprint and are not automatically linked to the old contact.

## Status: design document, not a security audit

MESHX is an early Android prototype. The app can create a device identity, create/import MESHX2 signed identity-to-transport bindings, and save local prototype chat records using Android Keystore AES-GCM. Android emulator CI verifies that a valid MESHX2 binding imports and that changing its transport key without a new identity signature is rejected. An isolated Rust/OpenMLS test suite exercises two-member MLS message encryption, tampering rejection, replay rejection, non-member rejection, and SQLite group-state restoration after a simulated restart. This test code is not connected to the Android app. Its temporary SQLite fixture is unencrypted and must not hold real user data. The app itself does **not** yet provide end-to-end encrypted communication, MLS-authenticated messaging sessions, Internet message delivery, relay routing, or recovery. Do not use the prototype for sensitive conversations.

## Current protections and limitations

- The current device identity uses an Android Keystore EC key pair. The private key is intended to remain in that device's Keystore.
- A MESHX2 QR carries the EC identity public key, the libp2p Ed25519 transport public key, the derived Peer ID, and an ECDSA/SHA-256 signature over a domain-separated transport key. Import verifies the signature and checks that the Peer ID matches the transport public key. The EC signing private key remains in Android Keystore; the transport private key is separately encrypted with an Android Keystore AES-GCM key. MESHX1 QR import is retained for compatibility but carries no signed transport binding.
- MESHX2 proves that the holder of the identity private key authorized the included transport key; it does **not** prove a real-world person's identity. Users must still compare the 128-bit SHA-256 fingerprint through a separate trusted channel. The manual verification marker is a user assertion, not a cryptographic handshake.
- Automatic identity-change warnings and explicit transport-key rotation confirmation are not implemented yet. MESHX2 is not an MLS credential and does not authenticate chat messages.
- Local prototype chat records are encrypted at rest with AES-GCM using a key held by Android Keystore. This protects stored records against some forms of file extraction, but it is not end-to-end encryption and does not protect a compromised or unlocked device.
- The current local message format and UI are prototype-only. No message is transmitted to a contact or relay.
- Losing or resetting the device may make the local encryption key unavailable. Recovery and encrypted backup are not implemented.

## Required one-to-one end-to-end design

Before real message sending is enabled:

1. Integrate a maintained, independently reviewed messaging protocol implementation. Do not invent a handshake, ratchet, cipher suite, random-number generator, or key derivation scheme.
2. Evaluate a maintained Signal Protocol-compatible implementation and its Android support, licensing, maintenance status, API stability, and security review before selecting a dependency.
3. Use separate protocol-managed identity and signed pre-key / one-time pre-key material as required by the selected protocol. Do not repurpose the current QR EC key as an encryption key without a protocol-reviewed migration.
4. Bind the MESHX2 identity to the selected protocol's credential using reviewed APIs. Authenticate contact identity through a stable safety number or equivalent fingerprint derived exactly as specified by the selected protocol. Provide a clear in-person / trusted-channel verification flow and warn when a contact identity or transport key changes.
5. Encrypt and authenticate every message on the sender device. Only the intended recipient device(s) may decrypt it. Relays must never receive message plaintext or decryption keys.
6. Support replay protection, message identifiers, duplicate suppression, authenticated receipts, key rotation, pre-key replenishment, and safe handling of device reinstall or lost state.
7. Keep network metadata minimal. Explain that IP addresses, timing, relay use, and traffic volume may still reveal information even when message content is encrypted.

## Relay and global delivery requirements

- Direct peer connections may be attempted when possible. NAT/firewall restrictions and mobile background limits mean direct connectivity will not always work.
- Independent, replaceable relay operators may store and forward ciphertext only. A relay must not be trusted with plaintext or session secrets.
- Queued messages need authenticated envelopes, expiry, size limits, hop limits, quotas, duplicate suppression, and deletion after expiry or confirmed delivery according to user policy.
- Delivery is best-effort. A message can remain queued or fail when the recipient is offline, no route exists, or networks are blocked.
- No single mandatory relay, discovery provider, or company server should control the entire network. Multiple independent providers and community-operated nodes should be supported.

## Recovery and backups

- The planned recovery choice is a user-held 12/24-word recovery phrase plus encrypted backup.
- Recovery words and private keys must never be sent to relays or stored in plaintext on a server.
- Backup encryption must use a well-reviewed password/key derivation and authenticated encryption design selected during implementation, with clear warnings about weak recovery secrets and loss of access.
- Test restore on a clean device before describing recovery as working.

## Media and nearby mode

- Photo, video, and voice files must be encrypted on the sender device before upload or relay transfer, split into authenticated chunks, and verified after download.
- Bluetooth and Wi-Fi Direct are local nearby transports only. They cannot directly deliver a message across distant cities or countries. They may carry encrypted bundles between nearby participating devices as an optional store-and-forward path.

## Release gates

Do not label MESHX production-ready until all of the following are complete:

- Protocol and dependency selection reviewed and documented.
- End-to-end sessions tested between separate devices, including contact identity verification and identity-change warnings.
- Relay operators demonstrably cannot decrypt messages.
- Replay, tampering, duplicate, expiry, offline queue, and key-loss tests pass.
- Recovery and encrypted backup restore tests pass.
- Independent security review and privacy review completed.
- Clear delivery states and limitations are visible in the app.

