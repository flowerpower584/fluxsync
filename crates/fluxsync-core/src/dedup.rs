//! 50-entry content dedup ring.
//!
//! Implementation: `VecDeque<[u8; 32]>` keyed by BLAKE3 of the payload.
//! `O(n)` lookup is fine at n=50, and the deque preserves insertion order
//! so we can drop the oldest hash when the buffer is full.
//!
//! A `HashSet` would lose ordering and force more bookkeeping for the
//! 50-item bound; a `VecDeque` is the smaller, less-surprising primitive.

use std::collections::VecDeque;

/// Default dedup capacity. The frontend exposes 5 history entries; we keep
/// 50 in RAM to absorb burst-mode reconnects without re-sending duplicates.
pub const DEDUP_CAPACITY: usize = 50;

/// SE-14: a 32-byte BLAKE3 content digest. Constructible only via
/// [`DedupRing::hash`] (or [`ContentHash::from_blake3`] for explicit
/// migration paths) so a caller cannot pass an attacker-controlled
/// `ClipboardItem.hash` straight into [`DedupRing::observe`] — that
/// transposition would let a peer pick which hash keys the dedup ring,
/// poisoning history with a chosen-collision payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    /// Borrow the raw digest bytes for wire serialization / tracing.
    /// **Do not** round-trip a foreign `[u8;32]` back into `ContentHash`
    /// through this — go through [`DedupRing::hash`].
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Explicit constructor for the rare callers that already hold a
    /// BLAKE3 digest computed by [`DedupRing::hash`] (e.g. tests that
    /// reuse a fixed seed array). Mirrors the same invariant: the
    /// caller asserts these bytes ARE a BLAKE3 of some payload.
    #[must_use]
    pub fn from_blake3(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Consume the newtype and return the raw 32 digest bytes — for
    /// daemon-side uses that have to write the hash into a wire field
    /// (`ClipboardItem.hash`, `peer_id`, etc.).
    #[must_use]
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Debug, Clone)]
pub struct DedupRing {
    capacity: usize,
    inner: VecDeque<ContentHash>,
}

impl Default for DedupRing {
    fn default() -> Self {
        Self::new(DEDUP_CAPACITY)
    }
}

impl DedupRing {
    /// Build an empty ring with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            inner: VecDeque::with_capacity(capacity.max(1)),
        }
    }

    /// Try to record `hash`. Returns:
    ///   * `true` — newly inserted; caller should treat the item as fresh.
    ///   * `false` — already present in the last `capacity` items; caller
    ///     should drop / ack the duplicate.
    ///
    /// Accepts only [`ContentHash`] (SE-14) so a caller cannot smuggle a
    /// peer-controlled `[u8; 32]` (e.g. `ClipboardItem.hash`) in here.
    pub fn observe(&mut self, hash: ContentHash) -> bool {
        if self.inner.contains(&hash) {
            return false;
        }
        if self.inner.len() == self.capacity {
            self.inner.pop_front();
        }
        self.inner.push_back(hash);
        true
    }

    #[must_use]
    pub fn contains(&self, hash: &ContentHash) -> bool {
        self.inner.contains(hash)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Compute a BLAKE3 hash of `bytes` for use with `observe`. Centralized
    /// so producers can't accidentally use a different hash.
    #[must_use]
    pub fn hash(bytes: &[u8]) -> ContentHash {
        ContentHash(*blake3::hash(bytes).as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(seed: u8) -> ContentHash {
        ContentHash::from_blake3([seed; 32])
    }

    #[test]
    fn observe_first_time_returns_true() {
        let mut r = DedupRing::default();
        assert!(r.observe(h(1)));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn observe_same_twice_returns_false_second_time() {
        let mut r = DedupRing::default();
        assert!(r.observe(h(1)));
        assert!(!r.observe(h(1)));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn ring_evicts_oldest_at_capacity() {
        let mut r = DedupRing::new(3);
        assert!(r.observe(h(1)));
        assert!(r.observe(h(2)));
        assert!(r.observe(h(3)));
        assert!(r.observe(h(4))); // evicts h(1)
        assert!(!r.contains(&h(1)));
        assert!(r.contains(&h(2)));
        assert!(r.contains(&h(3)));
        assert!(r.contains(&h(4)));
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn evicted_hash_can_be_re_observed() {
        let mut r = DedupRing::new(2);
        r.observe(h(1));
        r.observe(h(2));
        r.observe(h(3)); // evicts h(1)
        assert!(r.observe(h(1))); // h(1) is fresh again — that's the design
    }

    #[test]
    fn default_is_50_items() {
        let r = DedupRing::default();
        assert_eq!(r.capacity, 50);
        assert!(r.is_empty());
    }

    #[test]
    fn hash_is_deterministic_blake3() {
        let a = DedupRing::hash(b"hello");
        let b = DedupRing::hash(b"hello");
        let c = DedupRing::hash(b"world");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn se14_cannot_observe_peer_controlled_array_directly() {
        // SE-14 regression: `DedupRing::observe` MUST refuse a raw
        // `[u8; 32]` from a peer wire frame. The type signature is the
        // enforcement here — this test exists to fail the build (not at
        // runtime) the day someone deletes the newtype.
        let mut r = DedupRing::default();
        let peer_supplied: [u8; 32] = [0xAA; 32];
        // The next line MUST NOT compile if uncommented:
        // r.observe(peer_supplied);
        // The right shape — caller has to acknowledge "this is a digest":
        assert!(r.observe(ContentHash::from_blake3(peer_supplied)));
    }
}
