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

## Trust and limitations

- A valid MESHX2 signature proves that the corresponding identity private key authorized the included transport key. It does not prove who controls that identity in the real world.
- Users must compare the displayed identity fingerprint with the contact over a separate trusted channel.
- Automatic warnings and explicit confirmation for identity or transport-key changes are not implemented yet.
- This format does not replace MLS credentials, establish an end-to-end encrypted session, or authenticate application messages.
- MESHX2 is an experimental project format and has not received an independent security review.
