# MESHX OpenMLS Evaluation Spike

## Status: plan only — no cryptography dependency added

This is an isolated evaluation plan. It does not change the Android app, current identity keys, local chat, or network behavior.

## Why test OpenMLS

OpenMLS is an implementation of IETF MLS (RFC 9420). The current published crate documentation identifies version 0.9.2. Its CI builds Android and iOS Rust targets, but labels them unsupported/not tested; only Linux, Windows and macOS targets are listed as built and tested. Therefore, a successful cross-compile is only an initial engineering signal, not proof of mobile readiness.

References:
- https://docs.rs/crate/openmls/latest
- https://github.com/openmls/openmls
- https://latest.openmls.tech/book/

## Evaluation sequence

### Gate 1 — isolated native build
- Pin OpenMLS and every crypto-provider dependency to exact versions.
- Record the full dependency tree, licence notices, checksums and Rust toolchain.
- Build a tiny Rust library on the host CI runner.
- Do not add the library to the production Android app.

### Gate 2 — mobile cross-compilation
- Build Android arm64 first using a pinned Android NDK and Rust target.
- Then test Android x86_64 for emulator coverage.
- Build the iOS arm64 target in a macOS CI runner.
- Record that cross-compilation is not runtime support or a security audit.
- Keep generated native binaries out of the Git repository; publish only CI artifacts if needed.

### Gate 3 — protocol behavior
Use two independent test identities and test the MLS two-member group flow:
1. Create credentials and key packages using protocol-defined APIs.
2. Exchange key packages through a deliberately simple test transport.
3. Create a group, add the second member, and process the commit.
4. Exchange encrypted application messages in both directions.
5. Persist and reload each member's MLS state, then repeat message exchange.
6. Test malformed messages, replayed messages, stale epochs, duplicate delivery, member removal and identity/key changes.

No hand-written cryptographic primitives or custom session protocol are allowed.

### Gate 4 — MESHX fit
Before any adoption, design how MESHX will provide:
- authenticated credentials and human-verifiable contact identity;
- key-package publication and retrieval over multiple independent relays;
- offline store-and-forward of opaque protocol messages;
- replay/duplicate handling, expiry, rate limits and abuse resistance;
- encrypted media key distribution;
- backup and recovery without exposing private keys to relays.

MLS is an encryption/group-key protocol, not a peer-discovery or transport network. It does not by itself solve global routing, relay availability, push notifications or offline delivery.

## Explicit non-goals

- Do not replace the existing prototype EC QR identity yet.
- Do not enable network sending or receiving.
- Do not describe local AES-GCM storage as end-to-end encryption.
- Do not add the third-party Dart/Flutter OpenMLS wrapper to this Kotlin/Compose app merely to avoid writing bindings. A framework migration would be a separate product decision and needs its own maintenance, licence and audit review.
- Do not expose debug features that print cryptographic secrets or protocol key material.

## Pass criteria

The spike passes only if reproducible Android and iOS builds succeed, the two-device protocol tests pass including state reload, the exact dependency and licence set is reviewed, and the design fits MESHX's multi-relay model. Passing this spike still does not authorize production use; independent security review and a migration plan are required.

## Current result

Not started. This document records the next bounded engineering task. No OpenMLS dependency is installed in the MESHX app.
