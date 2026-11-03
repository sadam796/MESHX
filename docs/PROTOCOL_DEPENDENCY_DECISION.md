# MESHX Protocol Dependency Decision

## Decision status: candidate identified; integration blocked pending licence and support review

### Candidate: Signal libsignal

The official `signalapp/libsignal` repository contains the Signal Protocol implementation, including Double Ratchet, and exposes Java/Android packages. Its README explicitly says the library is used by Signal clients and that use outside Signal is unsupported; its APIs and bridge layers may change without notice. The repository is licensed AGPL-3.0. These are material product and maintenance risks for MESHX, not details to ignore.

Official references:
- Repository and README: https://github.com/signalapp/libsignal
- Published Android artifact metadata: https://central.sonatype.com/artifact/org.signal/libsignal-android

### Why MESHX is not adding a dependency yet

1. **Licence review:** AGPL-3.0 obligations may affect distribution of the Android app and any network service. Obtain qualified legal advice and decide whether MESHX will comply with AGPL or choose a different implementation. Do not assume that merely using a library has no source-disclosure implications.
2. **Support boundary:** libsignal states that use outside Signal is unsupported. MESHX must not treat it as a supported third-party SDK or assume stable public APIs.
3. **Version and toolchain:** the current official repository documents JDK 21 for its Android build, while this prototype's CI currently uses JDK 17. A dependency trial needs a deliberate toolchain/compatibility change and reproducible CI.
4. **API design:** a protocol implementation needs persistent protocol stores for identities, signed pre-keys, one-time pre-keys, sessions, and sender/receiver state. Merely adding an AAR does not create secure messaging.
5. **Platform interoperability:** Android is first, but MESHX plans iOS later. The chosen protocol and wire format must have a viable, maintained implementation on both platforms.

### Required evaluation before implementation

- Review licence obligations with counsel and choose an explicit distribution strategy.
- Compare maintained, audited protocol implementations with Android and iOS support; reject abandoned forks and unofficial repackaging.
- Pin exact versions and checksums; document provenance and update policy.
- Build a throwaway CI dependency proof before touching production chat code.
- Implement protocol-defined identity and pre-key exchange, persistent stores, safety-number verification, identity-change warnings, and two-device test vectors.
- Never use the current EC QR key directly as a session key. Design a versioned migration and protocol-native identity exchange.
- Do not claim E2E security until two independent devices pass interoperability, tampering, replay, identity-change, and persistence tests and the design receives independent review.

## Current prototype status

- Android Keystore identity and public-key QR: prototype only.
- Contact import and local public-key storage: prototype only.
- Local chat records encrypted at rest with Android Keystore AES-GCM: prototype only.
- End-to-end sessions, remote message transport, relays, delivery receipts, media encryption, recovery and iOS: not implemented.

**Release rule:** No real network messaging should be enabled until the protocol dependency, licence, key lifecycle, and security review gates are resolved.


## Alternative comparison (research update: 2026-11-03)

### 1. OpenMLS — strongest protocol candidate to prototype next

OpenMLS is a Rust implementation of the IETF Messaging Layer Security protocol (RFC 9420). It is designed for end-to-end encrypted group messaging and can support a group of two as well as larger groups. Its source repository documents Android and iOS Rust targets as buildable in CI but explicitly lists those targets as unsupported/not tested. That distinction matters: cross-compilation is not the same as a supported mobile SDK.

- Licence: Apache-2.0 in the OpenMLS repository.
- Strengths: open standard (RFC 9420), Rust core, suitable group key management, multiple cipher suites.
- Risks: MESHX would need its own Kotlin/Swift bindings or a carefully maintained binding layer, persistent storage, credential/identity verification, key-package discovery and delivery-service logic. MLS does not itself provide a decentralized network, contact directory, push delivery, offline queue or media transport.
- Audit note: Phoenix R&D reported an SRLabs audit on 2026-05-27: eight issues were found, one High; seven fixes were merged, and the remaining Low issue was still being addressed in that report. We must inspect the full report and verify the status of every finding against the exact version before selecting a release.
- Current status: **prototype candidate only; not approved for production**.

References:
- https://github.com/openmls/openmls
- https://docs.rs/crate/openmls/latest
- https://blog.phnx.im/openmls-independent-security-audit/

### 2. Matrix Rust SDK / vodozemac — mature mobile reference, but tied to Matrix architecture

The Matrix Rust SDK is Apache-2.0, maintained by Element, described by its maintainers as production-ready, and used by Element X on Android and iOS. It has Kotlin and Swift bindings. Its crypto component can operate without network I/O, and vodozemac is the Rust implementation of Matrix Olm/Megolm cryptographic ratchets. vodozemac reports an audit by Least Authority with no significant findings.

- Strengths: real Android/iOS client deployments, maintained Rust code, mature device verification and key-backup concepts, permissive Apache-2.0 licence for the SDK.
- Risks: the full SDK is a Matrix client-server SDK. Using it as a complete solution would bring Matrix account, room, sync and homeserver assumptions, which do not match MESHX's goal of independent peer/community relays without one mandatory central service. Using only its crypto component means adopting Matrix's Olm/Megolm protocol/state model, not simply taking a generic plug-in.
- Binding APIs can change; follow the current Element X integration rather than copying old snippets.
- Current status: **use as a design and implementation reference; do not adopt the full Matrix network stack for MESHX at this stage**.

References:
- https://github.com/matrix-org/matrix-rust-sdk
- https://github.com/matrix-org/vodozemac
- https://matrix.org/ecosystem/sdks/

### 3. Small third-party Kotlin wrappers — reject for now

A small community Kotlin wrapper around OpenMLS exists, but its own repository warns that it has not had a formal security audit. A young wrapper is not a substitute for a reviewed protocol implementation and stable mobile maintenance.

Reference:
- https://github.com/zeroxv6/kotlin-mls

## Current recommendation

1. **Do not add Signal libsignal** until its AGPL-3.0 and unsupported external-use issues are resolved.
2. **Do not add an unofficial wrapper** just because it makes Android integration look easy.
3. **Next engineering experiment: OpenMLS in an isolated branch or throwaway CI module**, with no changes to the current chat UI or identity keys. First prove Android compilation, iOS target feasibility, encrypted state persistence, two-device add/commit/message flow, and exact dependency licence notices.
4. In parallel, study Matrix Rust SDK and vodozemac for device verification, cross-signing and recovery UX; do not import Matrix homeserver dependence into MESHX's network architecture.
5. Keep protocol identity separate from the current prototype EC QR identity until a reviewed migration and user-verification flow exist.

### Important protocol/network distinction

MLS encrypts and authenticates group messages; it does not make a network decentralized by itself. MESHX still needs a separate transport design for peer discovery, key-package publication, message forwarding, offline store-and-forward, spam resistance and metadata minimization. A relay should only handle protocol ciphertext, and the protocol's delivery-service assumptions must be explicitly checked against MESHX's multi-relay design.

**Decision remains provisional:** OpenMLS is the next candidate to test, not a final production selection. No E2E claim or real network messaging is authorized by this research alone.
