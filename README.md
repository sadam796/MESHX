# MESHX

**Global-first, private messaging for Android.**

MESHX is an early-stage project exploring decentralized messaging over the Internet, with nearby offline delivery as an additional capability.

## Current project status

The Android prototype currently supports:
- Device-local EC contact identity plus a separate libp2p Ed25519 transport identity.
- The libp2p transport private key is encrypted with an Android Keystore AES-GCM key; Android emulator CI verifies that the same Peer ID survives app force-stop and relaunch.
- Android emulator CI verifies the native TCP/Noise/Yamux listener starts without an app crash.
- User-configurable, bounded bootstrap multiaddresses are wired through Kotlin/JNI to outbound dial requests and Kademlia bootstrap initiation. This is configuration and startup wiring, not proof that a public bootstrap node is reachable.
- Signed MESHX2 QR binding the Android Keystore EC identity to the libp2p Ed25519 transport public key; import verifies the signature and derived Peer ID, and Android emulator CI rejects a tampered binding. Legacy MESHX1 import remains available without a transport-key binding.
- A local-only chat prototype; messages do not reach another device.
- Local prototype chat records encrypted at rest using an Android Keystore AES-GCM key.
- An isolated OpenMLS evaluation with passing tests for two-member message encryption, ciphertext tampering, replay rejection, and non-member rejection.
- An isolated SQLite persistence test showing MLS group state can be reopened after simulated process restart on host CI.
- An isolated libp2p localhost test for two authenticated peers over TCP/Noise/Yamux, subject to CI verification.
- A bounded in-memory queue and a disk-backed ciphertext mailbox queue prototype with expiry, replay markers, capacity limits, and acknowledgement-before-delete tests.
- A self-hostable libp2p circuit-relay v2 server binary with persistent relay identity, explicit HOP protocol enablement, configurable public address advertisement, and a Docker Compose deployment recipe (`docs/RELAY_DEPLOYMENT.md`).
- An experimental network mailbox protocol (`/meshx/mailbox/1`) integrated into the relay server: sender-authenticated store, recipient-scoped fetch, recipient-only acknowledgement, bounded batches, disk persistence, expiry, replay markers, and restrictive Unix file permissions.
- Android UI/JNI wiring for an optional circuit-relay client, including a saved relay multiaddress, reservation status reporting, and use of relay routes only after a reservation is confirmed.

The OpenMLS/SQLite spike and mailbox client remain isolated from the Android app. The relay server now has an experimental disk-backed mailbox API, but the Android app does not call it yet. A public relay has not been deployed and an Android-to-public-relay connection has not yet been verified. The circuit-relay server forwards live peer traffic; the separate mailbox API can hold encrypted envelopes for offline recipients once clients are integrated.

**Not implemented or not yet verified:** identity-change warnings and transport-key rotation confirmation, successful discovery through a reachable public bootstrap node, deployment of a public relay, successful Android-to-public-relay connection, real cross-network message delivery, remotely accessible authenticated offline mailbox service, production end-to-end encrypted chats, encrypted media, Bluetooth/Wi-Fi Direct delivery, recovery phrase, encrypted backup, and iPhone app.

## Product principles

- Worldwide Internet messaging is the primary goal; users do not need to be physically nearby.
- Avoid dependence on one mandatory central operator. Discovery and relay services should be replaceable and independently operated where practical.
- Use end-to-end encryption with established, reviewed cryptographic protocols and libraries.
- Relay devices and nodes should forward ciphertext, not read message contents.
- Nearby Bluetooth/Wi-Fi Direct delivery is a complementary feature for devices in radio range; it does not by itself connect distant cities or countries.
- No guaranteed delivery: connectivity, routing peers, recipient availability, Android background limits, and network restrictions affect delivery.
- Never put message contents, media, private keys, or recovery phrases on-chain.

## Recovery

The planned recovery approach is a user-held 12- or 24-word recovery phrase, with optional encrypted backup. The phrase and private keys must never be uploaded in plaintext or stored by a relay.

## Repository map

- `android/` — Android application scaffold and local prototype.
- `spikes/openmls-android/` — isolated OpenMLS protocol and persistence evaluation; not wired into the app.
- `spikes/libp2p-transport/` — libp2p peer-connectivity, relay server, and experimental durable mailbox protocol; the Android mailbox client is not yet wired.
- `docs/ARCHITECTURE.md` — architecture and security boundaries.
- `docs/ROADMAP.md` — staged implementation plan.
- `docs/SECURITY_MODEL.md` — current protections, limitations, and release gates.
- `docs/IDENTITY_FORMAT.md` — MESHX1 legacy and signed MESHX2 QR format.
- `docs/TRANSPORT_DECISION.md` — Rust libp2p global transport evaluation and test gates.
- `docs/RELAY_DEPLOYMENT.md` — experimental self-hosted relay deployment guide.
- `.github/workflows/` — cloud Android and Rust spike checks.

## Build

A GitHub Actions workflow builds a debug APK in the cloud. Open the **Actions** tab, select **Android debug build**, and run it manually, or push a commit to `main`. The APK is published as a workflow artifact when the build succeeds.

This project is experimental and is not ready for real private communications or production use.
