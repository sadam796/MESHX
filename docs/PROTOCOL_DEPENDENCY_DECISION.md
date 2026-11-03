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
