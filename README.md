# MESHX

**Global-first, private messaging for Android.**

MESHX is an early-stage project exploring decentralized messaging over the Internet, with nearby offline delivery as an additional capability.

## Current project status

The Android prototype currently supports:
- Device-local identity creation using Android Keystore.
- Public identity QR generation and contact import.
- A local-only chat prototype; messages do not reach another device.
- Local prototype chat records encrypted at rest using an Android Keystore AES-GCM key.
- An isolated OpenMLS evaluation with passing tests for two-member message encryption, ciphertext tampering, replay rejection, and non-member rejection.
- An isolated SQLite persistence test showing MLS group state can be reopened after simulated process restart on host CI.

The OpenMLS/SQLite spike is not integrated into the Android app. Its test database uses ordinary, unencrypted SQLite and is only a temporary CI fixture. It is not safe for real user data.

**Not implemented:** worldwide Internet message transport, peer discovery, independent relays, offline store-and-forward, production end-to-end encrypted chats, encrypted media, Bluetooth/Wi-Fi Direct delivery, recovery phrase, encrypted backup, and iPhone app.

## Product principles

- Worldwide Internet messaging is the primary goal; users do not need to be physically nearby.
- Avoid dependence on one mandatory central operator. Discovery and relay services should be replaceable and independently operated where practical.
- Use end-to-end encryption with established, reviewed cryptographic protocols and libraries.
- Relay devices and nodes should forward ciphertext, not read message contents.
- Nearby Bluetooth/Wi-Fi Direct delivery is a complementary feature for devices in radio range; it does not by itself connect distant cities or countries.
- No guaranteed delivery: connectivity, routing peers, recipient availability, Android background limits, and network restrictions affect delivery.
- Never put message contents, media, private keys, or recovery phrases on a blockchain.

## Recovery

The planned recovery approach is a user-held 12- or 24-word recovery phrase, with optional encrypted backup. The phrase and private keys must never be uploaded in plaintext or stored by a relay.

## Repository map

- `android/` — Android application scaffold and local prototype.
- `spikes/openmls-android/` — isolated OpenMLS protocol and persistence evaluation; not wired into the app.
- `spikes/libp2p-transport/` — isolated libp2p networking dependency/target-compatibility probe; not wired into the app.
- `docs/ARCHITECTURE.md` — architecture and security boundaries.
- `docs/ROADMAP.md` — staged implementation plan.
- `docs/SECURITY_MODEL.md` — current protections, limitations, and release gates.
- `docs/TRANSPORT_DECISION.md` — Rust libp2p global transport evaluation and test gates.
- `.github/workflows/` — cloud Android and Rust spike checks.

## Build

A GitHub Actions workflow builds a debug APK in the cloud. Open the **Actions** tab, select **Android debug build**, and run it manually, or push a commit to `main`. The APK is published as a workflow artifact when the build succeeds.

This project is experimental and is not ready for real private communications or production use.
