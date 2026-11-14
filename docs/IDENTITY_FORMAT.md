# MESHX identity QR formats

## MESHX2 — signed identity-to-transport binding

MESHX2 is the current QR format. The payload is prefixed with `MESHX2:` and followed by Base64-encoded UTF-8 JSON:

- `version`: integer `2`.
- `identity_public_key`: Base64-encoded X.509 EC public key (the Android Keystore identity key).
- `transport_public_key`: Base64-encoded libp2p protobuf Ed25519 public key.
- `transport_peer_id`: the libp2p Peer ID derived from `transport_public_key`.
- `binding_signature`: Base64-encoded ECDSA/SHA-256 signature made by the identity private key.

The signature input is the UTF-8 domain separator `MESHX-TRANSPORT-BINDING-V2:` followed by the exact decoded transport public-key bytes. On import, the app verifies the ECDSA signature using `identity_public_key`, derives the Peer ID from `transport_public_key` through the native libp2p library, and rejects a mismatch.

The identity private key remains in Android Keystore. The separate libp2p transport private key is stored encrypted with AES-GCM under a key held by Android Keystore. Neither private key is included in the QR payload.

## MESHX1 — legacy identity-only QR

MESHX1 is retained for older contacts. It contains only the Base64-encoded X.509 EC public key. It has no transport public key, Peer ID, or signed binding, so it cannot identify a libp2p transport peer.

## Signed MLS setup envelopes

The Android prototype uses two additional, versioned setup-envelope formats:

- `MESHXK1:` wraps a serialized one-use OpenMLS KeyPackage, the sender's signed MESHX2 public identity, and an ECDSA/SHA-256 signature made by that identity's Android Keystore private key.
- `MESHXI1:` wraps the MLS Welcome message and ratchet tree, the inviter's signed MESHX2 public identity, and an ECDSA/SHA-256 signature.

The signature input uses a distinct domain separator for each envelope type and length-prefixed fields containing the identity public key and exact serialized MLS bytes. The receiver verifies the MESHX2 transport binding, requires the exact identity public key, fingerprint, and Peer ID to match the saved contact, and verifies the identity signature before passing the KeyPackage or Welcome to OpenMLS. MLS setup also requires the user to mark the contact as fingerprint-verified after an independent trusted-channel comparison. Legacy MESHX1 contacts cannot be used for this signed MLS exchange.

The envelopes contain public setup material only. MLS private KeyPackage state remains in the Android Keystore-backed encrypted vault. Each binary envelope part is limited to 1 MiB.

The app now offers send/receive controls for these envelopes through its native direct-ciphertext and experimental relay-mailbox path; manual copy/paste remains a fallback. The receiver polls while the contact chat is open, verifies the signed envelope, and stores it locally before acknowledging it. The transport path is wired but successful delivery across separate networks or through a deployed public relay has not been verified. These signatures bind the exact MLS setup bytes to a MESHX2 key, but do not prove a real-world person's identity or constitute an independent security review.

## Trust and limitations

- A valid MESHX2 signature proves that the corresponding identity private key authorized the included transport key. It does not prove who controls that identity in the real world.
- Users must compare the displayed identity fingerprint with the contact over a separate trusted channel.
- Transport-key change warnings and explicit replacement confirmation are implemented in local contact import. Identity-key changes produce a new fingerprint and are not automatically linked to the old contact.
- This format does not replace MLS credentials, establish an end-to-end encrypted session, or authenticate application messages.
- MESHX2 is an experimental project format and has not received an independent security review.
