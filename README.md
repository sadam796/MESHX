# MESHX

**Global-first, private messaging for Android.**

MESHX is an early-stage project exploring decentralized messaging over the Internet, with nearby offline delivery as an additional capability.

## Project status

The Android app currently contains a starter screen only. Internet peer discovery, message transport, end-to-end encryption, media transfer, recovery, and nearby offline relaying are **not implemented yet**.

## Product principles

- Worldwide Internet messaging is the primary goal; users do not need to be physically nearby.
- Avoid dependence on one mandatory central operator. Discovery and relay services should be replaceable and independently operated where practical.
- Use end-to-end encryption with established, audited cryptographic protocols and libraries.
- Relay devices and nodes should forward ciphertext, not read message contents.
- Nearby Bluetooth/Wi-Fi Direct delivery is a complementary feature for devices in radio range; it does not by itself connect distant cities or countries.
- No guaranteed delivery: connectivity, routing peers, recipient availability, Android background limits, and network restrictions affect delivery.
- Never put message contents, media, private keys, or recovery phrases on a blockchain.

## Recovery

The planned recovery approach is a user-held 12- or 24-word recovery phrase, with optional encrypted backup. The phrase and private keys must never be uploaded in plaintext or stored by a relay.

## Repository map

- `android/` — Android application scaffold.
- `docs/ARCHITECTURE.md` — architecture and security boundaries.
- `docs/ROADMAP.md` — staged implementation plan.
- `.github/workflows/android-build.yml` — cloud Android build workflow.

## Build

A GitHub Actions workflow can build a debug APK in the cloud. Open the **Actions** tab, select **Android debug build**, and run it manually, or push a commit to `main`. The APK is published as a workflow artifact when the build succeeds.

This project is experimental and is not ready for real private communications or production use.
