# MESHX implementation roadmap

A planned feature is not implemented until it has working tests on the intended platform. Physical-phone testing is intentionally deferred until the code-side work is ready.

## Stage 0 — foundation
- [x] Create Android/Kotlin/Jetpack Compose starter project.
- [x] Document global-first architecture and security boundaries.
- [x] Build a debug APK in GitHub Actions.
- [ ] Install and test the app on two physical Android phones (deferred by user).

## Stage 1 — local identity and safe foundations
- [x] Generate a device-local EC identity using Android Keystore (prototype identity only).
- [x] Persist the separate libp2p Ed25519 transport identity encrypted with Android Keystore AES-GCM; emulator CI confirms the Peer ID remains identical after app force-stop and relaunch.
- [x] Add signed MESHX2 QR binding the Android Keystore EC identity to the libp2p Ed25519 transport key; verify the signature and derived Peer ID on import, with Android emulator tamper-rejection coverage.
- [x] Preserve legacy MESHX1 contact import without treating it as a signed transport binding.
- [x] Add a local-only chat prototype.
- [x] Encrypt local prototype chat records at rest with an Android Keystore AES-GCM key.
- [x] Evaluate OpenMLS in an isolated Rust spike; host tests cover two-party encrypted messages, tampering, replay, and non-member rejection.
- [x] Prove OpenMLS group-state persistence and replay rejection across provider/database reopen in a host-only SQLite test.
- [x] Compile the OpenMLS SQLite provider and persistence test code for Android ARM64 in CI.
- [ ] Select and implement encrypted persistent MLS storage suitable for Android.
- [x] Add 128-bit contact fingerprint display and manual out-of-band comparison marker.
- [x] Detect changed signed transport Peer IDs for the same identity fingerprint; require explicit confirmation before replacement and reject signed-to-legacy downgrade (Android CI tests policy decisions).
- [ ] Do not add phone-number or email registration.

## Stage 2 — first worldwide Internet messaging prototype
- [x] Select libp2p 0.57.1 as the isolated transport candidate and compile-check Android/iOS targets.
- [x] Pass the local two-peer TCP/Noise/Yamux connection and request/response exchange test in host CI (local protocol smoke test only; not app messaging or worldwide delivery).
- [x] Add a bounded in-memory opaque delivery-envelope queue prototype with expiry, duplicate-ID, hop-limit, ciphertext-size, entry-count, and aggregate-byte validation.
- [x] Add a bounded parser for replaceable bootstrap multiaddresses with required peer identities, malformed/duplicate rejection, and a 32-endpoint cap (configuration parser only; no live discovery yet).
- [x] Add a user-triggered Kademlia closest-peer lookup for a signed contact Peer ID (query can be queued; live public discovery is not yet verified).
- [ ] Verify live peer discovery/bootstrap connections against reachable, replaceable nodes and test successful peer discovery across different networks.
- [x] Verify the Rust-to-Kotlin JNI startup bridge on Android ARM64 and x86_64 emulator CI; APK packaging, app launch, native listener startup, and restart identity check pass.
- [x] Wire bounded user-configurable bootstrap multiaddresses through the Android UI/JNI to outbound dial requests and Kademlia bootstrap initiation (live peer reachability is not yet verified).
- [ ] Integrate the reviewed MLS/session layer into the Android app.
- [ ] Verify native libp2p Swarm startup on a physical ARM64 Android device. Current code starts a TCP/Noise/Yamux listener; it does not yet discover peers or send app messages.
- [ ] Bind MESHX2 contact identities to MLS protocol credentials and authenticate identity changes in the messaging session.
- [ ] Add authenticated delivery receipts, bounded retry, and durable message status.
- [ ] Test between two phones on different networks, not only on the same Wi-Fi (deferred until code-side readiness).
- [ ] Document what bootstrap, STUN, or relay infrastructure can observe.

## Stage 3 — decentralized routing and resilience
- [ ] Add independent community-operated relays and/or a suitable peer-routing layer.
- [ ] Replace the in-memory queue with durable, encrypted store-and-forward storage.
- [ ] Complete abuse controls, storage quotas, spam resistance, and relay opt-in controls (basic per-authenticated-peer mailbox request rate limiting is implemented; broader protections remain).
- [ ] Test relay failure and switching between independent routes.
- [ ] Never claim that a route-free or offline recipient can receive immediately.

## Stage 4 — media and nearby offline mode
- [ ] Add encrypted photo, voice, and video transfer with size limits and resumable chunks.
- [ ] Complete and physically verify nearby Bluetooth/Wi-Fi Direct transport for devices within radio range.
- [x] Add a Wi-Fi Direct discovery/connection and ciphertext-only socket UI prototype; Android CI validation and physical-phone radio testing are tracked separately.
- [x] Connect the nearby Wi-Fi Direct panel to the active MLS chat: send generated MLS ciphertext directly and authenticate/decrypt incoming frames before saving plaintext locally (automated build/test and physical-device verification tracked separately).
- [x] Add message-ID acknowledgements and duplicate-safe same-session retry for nearby Wi-Fi Direct delivery; receiver persists the authenticated message and processed ID before acknowledging (physical two-phone verification remains pending).
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


## Task #47 — nearby delivery acknowledgement
- [x] Add a random 128-bit message ID to each nearby encrypted message frame.
- [x] Require a matching receiver acknowledgement before showing nearby send as delivered.
- [x] Persist authenticated plaintext and processed message ID before sending the acknowledgement.
- [x] Recognize same-session retries by message ID and acknowledge duplicates without decrypting twice.
- [x] Add Android instrumentation tests for frame bounds, truncation, ID matching, and acknowledgement validation.
- [ ] Persist outgoing retry IDs across app restarts and test retries after process death.
- [ ] Verify delivery acknowledgement and duplicate retry on two physical Android phones.
