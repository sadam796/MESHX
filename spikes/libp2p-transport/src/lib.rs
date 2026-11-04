//! Isolated foundations for MESHX delivery envelopes and transport experiments.
//! This crate is not wired into the Android app and does not provide global delivery.

use std::collections::HashMap;

pub const MAX_CIPHERTEXT_BYTES: usize = 1024 * 1024;
pub const MAX_ID_BYTES: usize = 128;
pub const MAX_HOP_LIMIT: u8 = 16;
pub const MAX_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Opaque application ciphertext plus bounded routing metadata.
/// The sender must encrypt and authenticate the payload before creating this envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryEnvelope {
    pub message_id: [u8; 16],
    pub sender_id: Vec<u8>,
    pub recipient_id: Vec<u8>,
    pub created_at: u64,
    pub expires_at: u64,
    pub hop_limit: u8,
    pub ciphertext: Vec<u8>,
}

impl DeliveryEnvelope {
    pub fn validate(&self, now: u64) -> Result<(), EnvelopeError> {
        if self.sender_id.is_empty() || self.sender_id.len() > MAX_ID_BYTES
            || self.recipient_id.is_empty() || self.recipient_id.len() > MAX_ID_BYTES {
            return Err(EnvelopeError::InvalidIdentity);
        }
        if self.ciphertext.is_empty() || self.ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(EnvelopeError::InvalidCiphertextSize);
        }
        if self.hop_limit == 0 || self.hop_limit > MAX_HOP_LIMIT {
            return Err(EnvelopeError::InvalidHopLimit);
        }
        if self.expires_at <= self.created_at
            || self.expires_at.saturating_sub(self.created_at) > MAX_TTL_SECONDS {
            return Err(EnvelopeError::InvalidExpiry);
        }
        if now >= self.expires_at {
            return Err(EnvelopeError::Expired);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    InvalidIdentity,
    InvalidCiphertextSize,
    InvalidHopLimit,
    InvalidExpiry,
    Expired,
    QueueFull,
}

/// Bounded in-memory queue for ciphertext envelopes. It is a testable prototype,
/// not durable storage; production relays need encrypted-at-rest persistence,
/// operator quotas, authentication, and abuse controls.
pub struct MemoryQueue {
    entries: HashMap<[u8; 16], DeliveryEnvelope>,
    max_entries: usize,
    max_bytes: usize,
    used_bytes: usize,
}

impl MemoryQueue {
    /// Creates a queue with an entry limit and a byte limit derived from the
    /// maximum envelope size. Prefer with_limits when configuring a relay.
    pub fn new(max_entries: usize) -> Self {
        Self::with_limits(max_entries, max_entries.saturating_mul(MAX_CIPHERTEXT_BYTES))
    }

    /// Creates a queue bounded by both message count and total ciphertext bytes.
    pub fn with_limits(max_entries: usize, max_bytes: usize) -> Self {
        Self { entries: HashMap::new(), max_entries, max_bytes, used_bytes: 0 }
    }

    /// Returns true when inserted, false for an already queued message ID.
    pub fn enqueue(&mut self, envelope: DeliveryEnvelope, now: u64) -> Result<bool, EnvelopeError> {
        envelope.validate(now)?;
        if self.entries.contains_key(&envelope.message_id) {
            return Ok(false);
        }
        if self.entries.len() >= self.max_entries
            || self.used_bytes.saturating_add(envelope.ciphertext.len()) > self.max_bytes {
            return Err(EnvelopeError::QueueFull);
        }
        self.used_bytes += envelope.ciphertext.len();
        self.entries.insert(envelope.message_id, envelope);
        Ok(true)
    }

    pub fn take_for(&mut self, recipient: &[u8], now: u64) -> Vec<DeliveryEnvelope> {
        self.expire(now);
        let ids: Vec<[u8; 16]> = self.entries.iter()
            .filter(|(_, item)| item.recipient_id == recipient)
            .map(|(id, _)| *id)
            .collect();
        ids.into_iter().filter_map(|id| {
            self.entries.remove(&id).map(|item| {
                self.used_bytes = self.used_bytes.saturating_sub(item.ciphertext.len());
                item
            })
        }).collect()
    }

    pub fn expire(&mut self, now: u64) {
        self.entries.retain(|_, item| now < item.expires_at);
        self.used_bytes = self.entries.values()
            .map(|item| item.ciphertext.len())
            .sum();
    }

    pub fn len(&self) -> usize { self.entries.len() }

    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    pub fn used_bytes(&self) -> usize { self.used_bytes }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(id: u8, recipient: &[u8], expiry: u64) -> DeliveryEnvelope {
        DeliveryEnvelope {
            message_id: [id; 16],
            sender_id: b"alice".to_vec(),
            recipient_id: recipient.to_vec(),
            created_at: 100,
            expires_at: expiry,
            hop_limit: 8,
            ciphertext: b"opaque-ciphertext".to_vec(),
        }
    }

    #[test]
    fn queue_deduplicates_and_routes_only_to_recipient() {
        let mut queue = MemoryQueue::new(4);
        let item = envelope(1, b"bob", 500);
        assert_eq!(queue.enqueue(item.clone(), 101), Ok(true));
        assert_eq!(queue.enqueue(item, 101), Ok(false));
        assert_eq!(queue.take_for(b"carol", 102).len(), 0);
        assert_eq!(queue.take_for(b"bob", 102).len(), 1);
        assert!(queue.is_empty());
    }

    #[test]
    fn expired_envelopes_are_rejected_and_removed() {
        let mut queue = MemoryQueue::new(4);
        assert_eq!(queue.enqueue(envelope(2, b"bob", 110), 110), Err(EnvelopeError::Expired));
        assert!(queue.is_empty());
    }

    #[test]
    fn queue_has_a_hard_entry_limit() {
        let mut queue = MemoryQueue::new(1);
        assert_eq!(queue.enqueue(envelope(3, b"bob", 500), 101), Ok(true));
        assert_eq!(queue.enqueue(envelope(4, b"bob", 500), 101), Err(EnvelopeError::QueueFull));
    }

    #[test]
    fn invalid_hop_limit_is_rejected() {
        let mut item = envelope(5, b"bob", 500);
        item.hop_limit = 0;
        assert_eq!(item.validate(101), Err(EnvelopeError::InvalidHopLimit));
    }

    #[test]
    fn queue_enforces_total_byte_limit() {
        let mut queue = MemoryQueue::with_limits(10, 20);
        let mut first = envelope(6, b"bob", 500);
        first.ciphertext = vec![1; 12];
        let mut second = envelope(7, b"bob", 500);
        second.ciphertext = vec![2; 9];

        assert_eq!(queue.enqueue(first, 101), Ok(true));
        assert_eq!(queue.used_bytes(), 12);
        assert_eq!(queue.enqueue(second, 101), Err(EnvelopeError::QueueFull));
        assert_eq!(queue.used_bytes(), 12);
    }

    #[test]
    fn taking_and_expiring_messages_releases_byte_quota() {
        let mut queue = MemoryQueue::with_limits(10, 30);
        let mut for_bob = envelope(8, b"bob", 500);
        for_bob.ciphertext = vec![1; 10];
        let mut for_carol = envelope(9, b"carol", 110);
        for_carol.ciphertext = vec![2; 7];

        assert_eq!(queue.enqueue(for_bob, 101), Ok(true));
        assert_eq!(queue.enqueue(for_carol, 101), Ok(true));
        assert_eq!(queue.used_bytes(), 17);
        assert_eq!(queue.take_for(b"bob", 102).len(), 1);
        assert_eq!(queue.used_bytes(), 7);
        queue.expire(110);
        assert_eq!(queue.used_bytes(), 0);
        assert!(queue.is_empty());
    }
}
