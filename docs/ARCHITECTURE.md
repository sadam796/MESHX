# MESHX — Initial Architecture

## First milestone
Build a native Android prototype that exchanges encrypted text between two nearby Android phones. After that, test a third phone relaying ciphertext.

## Design principles
- No phone number or email registration.
- Locally generated public/private-key identity; share public identity by QR code.
- End-to-end encryption using a maintained, independently reviewed protocol/library. Do not invent cryptography.
- Nearby transport using Android-supported nearby connectivity, Bluetooth, or Wi-Fi Direct, depending on device support.
- Store-and-forward relays carry ciphertext only, with message IDs, expiry, hop limits, sender authentication, and duplicate suppression.
- Later add Internet peer discovery and independently operated community relays. Avoid dependence on one mandatory operator.
- Recovery uses a user-held 12/24-word phrase and encrypted backup. Never upload recovery words or private keys in plaintext.
- Never store messages, media, contacts, or private keys on a blockchain.

## Important delivery limits
Bluetooth and Wi-Fi Direct only connect nearby devices. They cannot directly deliver from Hyderabad to Mumbai. Long-distance delivery needs Internet access and a route through peers/community nodes, or a continuous chain of participating devices. Without a route, delivery waits. Android background limits, battery, radio range, shutdowns, and unavailable relays can prevent delivery.

## Security requirements
1. Use established cryptographic protocols and maintained libraries.
2. Relay devices must not have decryption keys.
3. Protect against replay, tampering, spam, and duplicate delivery.
4. Distinguish sent, relayed, delivered, and read states; never promise guaranteed delivery.
5. Obtain independent security review before public release.

## Roadmap
1. Android app shell and local identity.
2. Audited encryption and two-phone nearby text exchange.
3. Three-device ciphertext relay.
4. Internet P2P discovery and community relays.
5. Photo, video, and voice attachments.
6. QR contacts, recovery, and security review.

This repository is a prototype plan, not yet a functioning messenger.