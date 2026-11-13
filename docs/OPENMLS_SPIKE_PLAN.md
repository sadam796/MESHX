# MESHX OpenMLS evaluation and Apple compatibility

## Task #47 — iPhone / iOS compatibility

This is an isolated compatibility and protocol-validation task. It does not yet make the Android application an iOS application, and it does not claim that an iPhone can message an Android phone in the current app.

### What this task verifies
- The same pinned OpenMLS Rust crate and MESHX MLS test code compile for physical iPhone ARM64.
- The same code compiles for Apple Silicon iOS Simulator ARM64.
- The two-member MLS protocol, ciphertext authentication/decryption, replay rejection, and persistent-state reload tests run on the macOS host.
- Android and iOS use the same MLS ciphersuite and wire format in this isolated Rust core.

### CI
Workflow: `.github/workflows/openmls-ios-spike.yml`
- macOS host protocol and persistence tests.
- `aarch64-apple-ios` compile check for physical iPhones.
- `aarch64-apple-ios-sim` compile check for Apple Silicon simulator.

The iOS targets require Xcode-provided SDKs. A successful cross-compile is not an iPhone runtime test. Rust's iOS targets are Tier 2 without host tools; tests must ultimately run in an iOS app or simulator. OpenMLS upstream documents iOS as built on CI but unsupported/not tested by its own CI. References:
- https://doc.rust-lang.org/stable/rustc/platform-support/apple-ios.html
- https://docs.rs/crate/openmls/latest
- https://github.com/openmls/openmls

### Explicitly not complete in #47
- No Swift/SwiftUI iOS application or Xcode project exists yet.
- No iOS Keychain-backed OpenMLS storage adapter exists yet.
- No iPhone runtime/simulator execution has been performed by this workflow.
- No Android-to-iPhone app-to-app message exchange has been performed.
- No App Store signing, TestFlight, push notification, or background delivery work is included.
- The OpenMLS crate remains an isolated spike and is not installed in the production Android app.

### Pass criteria
The automated part of #47 passes only when all three CI jobs succeed: host MLS tests, physical-device ARM64 compile, and Apple Silicon simulator compile. The full cross-platform product milestone remains open until an iOS app wrapper, Keychain storage, runtime tests, and a real Android–iPhone encrypted message exchange are completed.

## OpenMLS implementation constraints
OpenMLS implements IETF MLS (RFC 9420). It is an encryption/group-key protocol, not peer discovery or transport. It does not itself provide global routing, relay availability, push notifications, or offline delivery.

- Keep OpenMLS and crypto-provider versions pinned.
- Do not implement custom cryptographic primitives.
- Do not expose debug features that print secrets or key material.
- Do not claim local at-rest encryption alone is end-to-end encryption.
- Do not add a third-party Dart/Flutter wrapper to the Kotlin/Compose app without a separate framework decision and maintenance/security review.
- Before production adoption, review dependency licences, threat model, storage integration, key backup/recovery, relay fit, and obtain independent security review.
