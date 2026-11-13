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
