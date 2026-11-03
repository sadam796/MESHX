# MESHX — Global Decentralized Messaging Architecture

## Product goal

MESHX is intended to be a worldwide private messenger. A person in Hyderabad must be able to message a person in Mumbai, New York, London, Lagos, or anywhere else with Internet connectivity, without both users needing to be nearby and without depending on one mandatory company server.

Nearby offline communication is an additional capability, not the primary architecture.

## Global-first network

- **Identity:** locally generated cryptographic identity; no phone number or email required. Contacts can be added by sharing a QR code or public identity link.
- **End-to-end messaging:** use a maintained, independently reviewed encryption protocol/library. Only the intended recipient devices can decrypt message content.
- **Peer discovery:** use a distributed, replaceable discovery/rendezvous design so users can find peers without one permanent central directory. Bootstrap services may help new devices join, but must be replaceable and independently operated.
- **Internet transport:** connect peers directly when possible. When direct connectivity is blocked by NAT, firewalls, or devices being offline, use optional independently operated relay nodes that forward ciphertext only.
- **Resilient delivery:** queue encrypted messages on the sender's device and, where the user opts in, on relay nodes with expiry, size limits, message IDs, hop limits, authenticated sender metadata, and duplicate suppression. Delivery is best-effort, not guaranteed.
- **Offline nearby mode:** add Android nearby connectivity, Bluetooth, or Wi-Fi Direct as a separate transport for nearby devices. Nearby radios do not replace global Internet routing.
- **Media:** later support encrypted photo, video, and voice attachments, with chunking, integrity checks, and limits.
- **Recovery:** user-held 12/24-word recovery phrase plus encrypted backup. Never upload recovery words or private keys in plaintext.
- **Blockchain:** not required for message delivery. Never store messages, media, contacts, or private keys on-chain. If public identity verification is ever added, keep it optional and minimize permanent, linkable metadata.

## How Hyderabad-to-Mumbai and worldwide delivery works

If both users have Internet access, MESHX should route an end-to-end encrypted message over the Internet using peer connections and/or independent ciphertext relays. The users do not need to be physically close.

If the recipient is offline, the encrypted message can wait on the sender's device or an opted-in relay until the recipient reconnects. If the sender has no Internet, nearby offline transfer can pass ciphertext to participating devices; delivery across a city or country then requires a chain of willing devices or a later Internet connection. Bluetooth/Wi-Fi Direct alone cannot bridge distant cities or continents.

## No single point of control

The design should avoid a mandatory single operator for identity, discovery, routing, or relaying. Support multiple independent discovery/bootstrap providers and relay operators, and allow community-run infrastructure. Decentralization reduces single-provider dependence but cannot prevent Internet shutdowns, censorship, network outages, hostile infrastructure, or lack of available routes.

## Security and privacy requirements

1. Use established cryptographic protocols and maintained libraries; never design custom cryptography.
2. Relay nodes must not possess message decryption keys.
3. Protect against replay, tampering, impersonation, spam, metadata leakage, and duplicate delivery.
4. Clearly distinguish queued, sent, relayed, delivered, and read states. Never claim guaranteed delivery.
5. Minimize metadata and retention; apply expiry and user controls to queued messages.
6. Obtain independent security review before public release.

## Implementation order

1. Define and threat-model the global-first peer discovery, Internet transport, and relay architecture.
2. Build Android identity and encrypted one-to-one messaging.
3. Implement Internet P2P connections and independent ciphertext relays; test between geographically distant networks.
4. Add offline queueing and delivery receipts.
5. Add nearby offline transport and multi-device store-and-forward as complementary features.
6. Add encrypted photo, video, and voice attachments.
7. Add QR contact exchange, recovery phrase plus encrypted backup, abuse protections, and security review.

This repository is an early project scaffold and architecture plan, not yet a functioning messenger.