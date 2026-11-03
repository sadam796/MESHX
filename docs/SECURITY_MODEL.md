# MESHX Security Model

## Status: design document, not a security audit

MESHX is an early Android prototype. The current app can create a device identity, import a contact's public identity, and save local prototype chat records using Android Keystore AES-GCM. It does **not** yet provide end-to-end encrypted communication, authenticated key agreement, Internet delivery, relay routing, or recovery. Do not use the prototype for sensitive conversations.

## Current protections and limitations

- The current device identity uses an Android Keystore EC key pair. The private key is intended to remain in that device's Keystore.
- A contact QR currently carries a public key only. Importing it does not prove that the person is who they claim to be. Verify fingerprints with the contact through a separate trusted channel before trusting an identity.
- Local prototype chat records are encrypted at rest with AES-GCM using a key held by Android Keystore. This protects stored records against some forms of file extraction, but it is not end-to-end encryption and does not protect a compromised or unlocked device.
- The current local message format and UI are prototype-only. No message is transmitted to a contact or relay.
- Losing or resetting the device may make the local encryption key unavailable. Recovery and encrypted backup are not implemented.

## Required one-to-one end-to-end design

Before real message sending is enabled:

1. Integrate a maintained, independently reviewed messaging protocol implementation. Do not invent a handshake, ratchet, cipher suite, random-number generator, or key derivation scheme.
2. Evaluate a maintained Signal Protocol-compatible implementation and its Android support, licensing, maintenance status, API stability, and security review before selecting a dependency.
3. Use separate protocol-managed identity and signed pre-key / one-time pre-key material as required by the selected protocol. Do not repurpose the current QR EC key as an encryption key without a protocol-reviewed migration.
4. Authenticate contact identity through a stable safety number or equivalent fingerprint derived exactly as specified by the selected protocol. Provide a clear in-person / trusted-channel verification flow and warn when a contact identity changes.
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

