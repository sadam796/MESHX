# MESHX implementation roadmap

A planned feature is not implemented until it has working tests on the intended platform. Physical-phone testing is intentionally deferred until the code-side work is ready.

## Stage 0 — foundation
- [x] Create Android/Kotlin/Jetpack Compose starter project.
- [x] Document global-first architecture and security boundaries.
- [x] Build a debug APK in GitHub Actions.
- [ ] Install and test the app on two physical Android phones (deferred by user).

## Stage 1 — local identity and safe foundations
- [x] Generate a device-local EC identity using Android Keystore (prototype identity only).
- [x] Add public identity QR generation and contact import.
- [x] Add a local-only chat prototype.
- [x] Encrypt local prototype chat records at rest with an Android Keystore AES-GCM key.
- [x] Evaluate OpenMLS in an isolated Rust spike; host tests cover two-party encrypted messages, tampering, replay, and non-member rejection.
- [x] Prove OpenMLS group-state persistence and replay rejection across provider/database reopen in a host-only SQLite test.
- [x] Compile the OpenMLS SQLite provider and persistence test code for Android ARM64 in CI.
- [ ] Select and implement encrypted persistent MLS storage suitable for Android.
- [x] Add interim 128-bit contact fingerprint display and manual verification marker (not protocol authentication).
- [ ] Replace interim marker with protocol-authenticated verification and identity-change warnings.
- [ ] Do not add phone-number or email registration.

## Stage 2 — first worldwide Internet messaging prototype
- [x] Select libp2p 0.57.1 as the isolated transport candidate and compile-check Android/iOS targets.
- [x] Add a local two-peer TCP/Noise/Yamux connection and request/response exchange test (host CI only; not app messaging).
- [x] Add a bounded in-memory opaque delivery-envelope queue prototype with expiry, duplicate-ID, hop-limit, ciphertext-size, entry-count, and aggregate-byte validation.
- [x] Add a bounded parser for replaceable bootstrap multiaddresses with required peer identities, malformed/duplicate rejection, and a 32-endpoint cap (configuration parser only; no live discovery yet).
- [ ] Implement live peer discovery/bootstrap connections that can use multiple replaceable endpoints.
- [ ] Integrate the reviewed MLS/session layer into the Android app.
- [ ] Bind the app's human identity to protocol credentials with authenticated contact verification and identity-change warnings.
- [ ] Add authenticated delivery receipts, bounded retry, and durable message status.
- [ ] Test between two phones on different networks, not only on the same Wi-Fi (deferred until code-side readiness).
- [ ] Document what bootstrap, STUN, or relay infrastructure can observe.

## Stage 3 — decentralized routing and resilience
- [ ] Add independent community-operated relays and/or a suitable peer-routing layer.
- [ ] Replace the in-memory queue with durable, encrypted store-and-forward storage.
- [ ] Add abuse controls, rate limits, spam resistance, and relay opt-in controls.
- [ ] Test relay failure and switching between independent routes.
- [ ] Never claim that a route-free or offline recipient can receive immediately.

## Stage 4 — media and nearby offline mode
- [ ] Add encrypted photo, voice, and video transfer with size limits and resumable chunks.
- [ ] Add nearby Bluetooth/Wi-Fi Direct transport for devices within radio range.
- [ ] Add opt-in nearby store-and-forward with hop limits, expiry, and duplicate suppression.
- [ ] Clearly distinguish local radio delivery from worldwide Internet delivery.

## Stage 5 — recovery, review, and release
- [ ] Implement user-held 12/24-word recovery phrase and optional client-side encrypted backup.
- [ ] Commission independent security review and penetration testing.
- [ ] Add privacy-preserving diagnostics, accessibility, localization, and release signing.
- [ ] Publish transparent threat model, limitations, and incident response process.

## Non-negotiable security rules
- Do not invent cryptography; use audited protocols and maintained libraries.
- Do not store message contents, media, private keys, or recovery phrases on-chain.
- Treat all relays and bootstrap services as potentially observable/untrusted.
- Do not promise guaranteed delivery, anonymity, or uninterrupted operation.
- Do not ship real-user messaging until the threat model and security review are complete.
