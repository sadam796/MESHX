# MESHX Internet Transport Evaluation

## Status: recommended candidate; not integrated

MESHX needs an Internet transport for global communication. The current Android app has no network message delivery.

**Recommended candidate for an isolated prototype: Rust libp2p 0.57.1.** It is modular and provides Rust implementations of TCP, QUIC, peer identity/security handshakes, circuit relays, rendezvous, Kademlia, AutoNAT, and request/response protocols. This makes it a better starting point than writing a custom peer network. The version is pinned for the spike; re-check maintenance, advisories, API changes, and Android/iOS builds before production adoption.

Official references:
- Rust libp2p crate: https://docs.rs/libp2p/0.57.1/
- Connectivity and NAT traversal: https://libp2p.io/connectivity/
- Standalone connectivity: https://libp2p.io/docs/standalone-connectivity/

## Proposed network shape

1. **Bootstrap:** ship a small, replaceable list of community bootstrap peers. Support adding/removing independent peers. No single bootstrap provider is authoritative.
2. **Discovery:** evaluate Kademlia DHT and/or independent rendezvous servers. Do not publish phone numbers, contact lists, or plaintext identities in public discovery records.
3. **Transport:** attempt QUIC when UDP is available and TCP as a fallback. Use the relay path when direct inbound connectivity is blocked.
4. **Relay:** support Circuit Relay v2 and multiple independent relay operators. Relay nodes forward opaque encrypted packets and must not hold MLS keys.
5. **Peer authentication:** use libp2p peer identity for transport-level peer authentication, but do not treat it as proof that a peer is the intended human contact. Human-contact verification remains a separate MESHX identity/fingerprint process.
6. **Message protection:** MLS is the separate end-to-end security layer. libp2p transport encryption protects a connection hop; it does not replace MESHX end-to-end encryption.
7. **Message envelope:** use a bounded request/response protocol for delivery envelopes. Include message ID, sender/recipient protocol identity, expiry, hop limit, ciphertext, and authenticated receipt metadata. Do not broadcast private messages through a public pubsub topic.
8. **Offline queue:** implement an explicit encrypted store-and-forward queue with expiry, quotas, duplicate suppression, and user opt-in. A relay can store only ciphertext. Delivery remains best-effort.

## Important mobile/NAT limitation

Many mobile devices are behind carrier-grade NAT and cannot accept arbitrary inbound connections. QUIC uses UDP, which some networks block. TCP fallback and independent relay paths are therefore required. Rust libp2p's documented private-to-private hole-punching support has limitations; do not assume direct phone-to-phone connectivity will work on every carrier. Relay delivery is the baseline fallback, not an exceptional edge case.

A peer-to-peer architecture still needs bootstrap/discovery peers and reachable relays to help devices find one another. The goal is multiple replaceable operators, not the unrealistic promise of zero infrastructure.

## Security and privacy boundaries

- Relays can observe network metadata such as peer identifiers, IP addresses, timing, packet sizes, and traffic volume even when payloads are encrypted.
- Do not claim anonymity from end-to-end encryption or from use of relays.
- Do not store plaintext messages, media, MLS private state, recovery phrases, or contact lists on relay nodes.
- Authenticate all application-level delivery receipts; transport connection success is not message delivery.
- Apply rate limits, quotas, expiry, and abuse controls to prevent relay exhaustion and spam.
- Avoid a single hard-coded relay, DHT bootstrap, rendezvous service, or operator.

## Required prototype tests

- [ ] Compile the pinned libp2p stack for Android ARM64 and iOS ARM64.
- [ ] Establish two authenticated peer connections on separate networks.
- [ ] Test QUIC and TCP fallback, including UDP-blocked networks.
- [ ] Deliver an MLS ciphertext over a direct connection.
- [ ] Deliver the same ciphertext through an independent relay.
- [ ] Verify relay operators cannot decrypt the payload.
- [ ] Test multiple bootstrap and relay operators; disable one and reconnect through another.
- [ ] Measure battery use, background behavior, reconnection, and data usage on physical Android devices.
- [ ] Test expiry, duplicate suppression, quotas, and offline queue behavior.
- [ ] Review metadata leakage and abuse resistance.

## Acceptance gate

Do not integrate libp2p into the user-facing Android app until the isolated Android/iOS build and two-device network tests pass. Do not describe MESHX as globally connected until real delivery works between geographically separate devices and through relay fallback.
