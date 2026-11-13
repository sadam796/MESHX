# MESHX Bluetooth nearby transport (task #44)

## Scope
This is a nearby-only Android transport. It does not replace Internet delivery and
cannot connect distant cities. Wi-Fi Direct is tracked separately as task #45.

## Current implementation
- Secure RFCOMM sockets are used for paired Bluetooth devices.
- The transport accepts and sends only opaque ciphertext byte arrays; chat plaintext
  must be encrypted/authenticated by the MLS layer before this transport is called.
- Frames use a 4-byte big-endian length prefix and enforce a 1-byte to 1-MiB payload cap.
- Socket operations are blocking and must run off the Android main thread, e.g. on Dispatchers.IO.
- The Bluetooth feature is optional; devices without Bluetooth can still use MESHX. The Compose panel lists already-paired devices and supports a manual one-frame send/receive session; it is not a background service or automatic MLS chat integration.
- Android 12+ requires runtime BLUETOOTH_CONNECT permission for socket operations.
  Scanning/discovery requires BLUETOOTH_SCAN; advertising/discoverability requires
  BLUETOOTH_ADVERTISE. The current transport primitive does not yet implement the
  permission UI, device discovery/pairing flow, background service, or chat-screen
  integration.

## Verification
The frame codec has instrumentation coverage for valid round trips, empty/oversized
frames, invalid lengths, and truncated payloads. A successful codec test is not proof
of Bluetooth radio connectivity or two-phone delivery.

## Remaining work
1. Add runtime permission handling and nearby-device discovery/pairing UI.
2. Add a cancellable foreground receive service and explicit user opt-in.
3. Connect the transport to the MLS ciphertext path; never send plaintext.
4. Test send/receive on two physical Android phones with Bluetooth enabled.
