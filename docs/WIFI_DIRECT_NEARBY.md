# MESHX Wi-Fi Direct nearby transport (task #45)

## Scope
Wi-Fi Direct is a nearby-only Android transport. It does not require internet after
the Android devices establish a Wi-Fi P2P group. It does not provide delivery between
distant cities; worldwide messaging remains a separate Internet/libp2p path.

## Current prototype
- Uses Android WifiP2pManager peer discovery and connection negotiation.
- Requests NEARBY_WIFI_DEVICES on Android 13+ and fine location on Android 12 and
  earlier, where the platform requires it for peer discovery.
- The group owner listens on a dedicated TCP port; the group client sends one frame.
- Frames use a 4-byte big-endian length prefix and enforce a 1-byte to 1-MiB payload cap.
- The transport accepts opaque bytes only. Callers must encrypt and authenticate
  application messages with the correct MLS group before sending.
- Blocking socket operations run on Dispatchers.IO.
- The panel exposes manual Base64 ciphertext send/receive for the prototype.

## Limitations
- The prototype handles one transfer per receive session and requires both phones to
  stay awake with the app screen open.
- The app does not yet route messages automatically into the MLS chat screen.
- No foreground/background delivery, retry queue, media transfer, or automatic
  reconnection is implemented.
- The Android connection request and role negotiation depend on device/vendor support.
- A successful frame codec test or emulator build is not proof of radio connectivity.

## Verification still required
1. Build and run Android emulator instrumentation tests in CI.
2. Test peer discovery, group formation, and ciphertext transfer on two physical phones.
3. Verify received ciphertext with the matching MLS group before displaying plaintext.
4. Test connection loss, timeout, duplicate delivery, and recovery behavior.


## Task #46 — MLS chat integration

- The nearby panel is bound to the currently open contact chat.
- The existing chat composer creates MLS application ciphertext; the nearby client sends
  those bytes directly without asking the user to copy/paste Base64.
- The group-owner receiver passes the frame to the matching saved MLS group. Only after
  MLS authentication and decryption succeeds is plaintext written to the encrypted local
  message store and shown in chat history.
- Wrong-group, modified, or replayed ciphertext is rejected by the MLS state machine and
  is not added to local chat history.
- Group-state mutations in the app-facing repository are synchronized to avoid concurrent
  local relay and Wi-Fi Direct receive operations racing over the same saved group snapshot.
- Current Wi-Fi Direct prototype is one-way per group (client sends, owner receives);
  reconnect with roles reversed for a reply. Background service, automatic role negotiation,
  delivery acknowledgements/retries, and two-physical-phone validation remain future work.


## Task #47 — acknowledged nearby delivery and duplicate-safe retry

- Every Wi-Fi Direct message frame now carries a random 128-bit message ID followed by
  the MLS ciphertext. The ciphertext remains opaque to the transport.
- The sender waits for an acknowledgement containing the exact same message ID. A send
  is reported as delivered only after that acknowledgement is received.
- The receiver writes the authenticated plaintext and encrypted processed-ID marker to
  local storage in one synchronous preference commit before acknowledging.
- If an acknowledgement is lost, the sender can retry the same ciphertext while the chat
  remains open. The stable ID lets the receiver recognize the duplicate and acknowledge
  it without attempting to decrypt the same MLS ciphertext a second time.
- Instrumentation coverage checks message framing, ID validation, payload bounds,
  truncated frames, and matching/mismatching acknowledgements.
- This is a foreground, one-transfer prototype, not a durable background retry queue.
  A process restart may generate a new outgoing ID; cross-restart retry persistence and
  physical two-phone testing are not yet verified.
