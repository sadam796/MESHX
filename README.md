# MESHX

**Global-first, private messaging for Android.**

MESHX is an experimental decentralized-messaging project. Worldwide Internet messaging is the primary goal; Bluetooth and Wi-Fi Direct are complementary nearby transports.

## Current Android prototype

Implemented in code and covered by automated checks:

- Device-local EC identity protected by Android Keystore, plus a separate libp2p Ed25519 transport identity encrypted with an Android Keystore AES-GCM key.
- Signed MESHX2 QR identity binding the EC identity to its libp2p transport public key and Peer ID. Legacy MESHX1 import remains available for compatibility.
- OpenMLS through a Rust JNI bridge: create a group, create a one-use KeyPackage, add a member, join from Welcome, and encrypt/decrypt application messages.
- MLS state snapshots stored through an Android Keystore AES-GCM vault.
- Signed `MESHXK1:` KeyPackage and `MESHXI1:` Welcome/ratchet-tree envelopes. The MESHX2 identity key signs the exact setup bytes; the receiver checks the saved contact fingerprint and signed transport binding before accepting them. MLS setup requires the user to mark the contact as fingerprint-verified after an independent comparison.
- Android instrumentation coverage for two-repository MLS exchange, signed setup-envelope verification, tamper rejection, contact mismatch rejection, and rejection of legacy MESHX1 for signed MLS setup.
- Native libp2p TCP/Noise/Yamux startup, configurable bootstrap peers, direct ciphertext send, and an experimental relay mailbox client.
- Nearby Wi-Fi Direct and Bluetooth ciphertext transport prototypes.

## Not yet verified or complete

- KeyPackage and Welcome setup still use manual copy/paste; automatic Internet exchange is not implemented.
- Public bootstrap reachability, public relay deployment, Android-to-public-relay exchange, and successful delivery between phones on different networks have not been verified.
- Real two-phone Bluetooth and Wi-Fi Direct testing remains pending.
- Durable authenticated Internet delivery receipts/retries, encrypted media transfer, recovery phrase, encrypted backup, and iPhone app remain incomplete.
- The project has not received an independent security review and is not ready for sensitive or production communications.

A passing emulator or CI test is not proof of real-world cross-network delivery or physical-radio operation. Relays and bootstrap nodes may observe routing metadata such as peer identifiers, timing, and ciphertext size. Delivery is best-effort, not guaranteed.

## Product principles

- No phone-number or email registration.
- Worldwide Internet messaging is the primary goal; users do not need to be physically nearby.
- Avoid dependence on one mandatory central operator. Discovery and relay services should be replaceable and independently operated where practical.
- Use established cryptographic protocols and libraries; do not invent cryptography.
- Relays should forward ciphertext, never message plaintext or decryption keys.
- Nearby Bluetooth/Wi-Fi Direct delivery is only for devices within radio range.
- Never put message contents, media, private keys, or recovery phrases on-chain.

## Repository map

- `android/` — Android application.
- `spikes/meshx-android-ffi/` — Rust JNI bridge, libp2p transport, and OpenMLS operations.
- `spikes/openmls-android/` — OpenMLS storage and protocol evaluation tests.
- `spikes/libp2p-transport/` — libp2p peer-connectivity, relay server, and experimental durable mailbox protocol.
- `docs/ROADMAP.md` — staged implementation plan.
- `docs/SECURITY_MODEL.md` — current protections, limitations, and release gates.
- `docs/IDENTITY_FORMAT.md` — MESHX1/MESHX2 identities and signed MLS setup envelopes.
- `docs/RELAY_DEPLOYMENT.md` — experimental relay deployment guide.
- `.github/workflows/` — Android and Rust CI checks.

## Build

GitHub Actions builds a debug APK and runs Android emulator instrumentation tests. Open the **Actions** tab and select **Android debug build**. The APK is uploaded as a workflow artifact when the run succeeds.

MESHX is experimental and is not production-ready.
