//! Isolated compile-only probe for the proposed MESHX Internet transport.
//! No swarm, peer discovery, relay, or message delivery is implemented here.

/// Keeps the selected libp2p peer identity type in the public probe surface.
pub fn peer_id_type_probe() -> Option<libp2p::PeerId> {
    None
}
