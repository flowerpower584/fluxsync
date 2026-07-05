//! In-memory resend buffer for the resync-on-reconnect feature.
//!
//! `State.history` (see `fluxsync-core`) only keeps *previews* of recent
//! clipboard items — enough for the UI, not enough to re-send. When a peer
//! reconnects after a drop, the daemon wants to re-offer the handful of
//! items it might have missed, which means holding onto the full payload
//! bytes for a short while after the item is first sent. That is this
//! module's only job: a small, capped, TTL'd, purely in-memory cache of
//! recent outbound items, keyed by content hash.
//!
//! # Security invariant
//!
//! **Sensitive items MUST NOT be inserted here.** The whole point of
//! `sensitive` clipboard items (per the firewall / at-rest vault policy
//! elsewhere in the daemon) is that they are never persisted and never
//! retained beyond the immediate in-flight send. This buffer is in-memory
//! only (never written to disk) and bounded by [`MAX_AGE`], but it is still
//! retention beyond the single send — callers must filter `sensitive` items
//! out before calling [`Outbox::insert`]. This module does not and cannot
//! enforce that itself; it trusts the caller.
//!
//! **This buffer only ever holds items already admitted to history.** A
//! clipboard firewall (`Ask`/`Block`) decision runs before an item is
//! recorded to `State.history` (see `fluxsync_core::App::handle`); callers
//! must mirror that gate here — insert on an immediate `Pass`, or on a
//! deferred `Ask` item only once the user approves it via
//! `ResolvePending{allow: true}`, and never for a `Block`/denied item. See
//! `driver.rs`'s `complete_reassembled_item`, `dispatch_inbound_frame`, and
//! `CmdOp::ResolvePending` handling for where that gate is enforced, and
//! `Outbox::insert`'s doc comment below for the exact contract.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Maximum number of items retained at once. Oldest (by insertion order)
/// evicted first once exceeded.
pub const MAX_ITEMS: usize = 16;

/// Maximum combined payload bytes retained at once. Oldest evicted first
/// once exceeded, same as [`MAX_ITEMS`]. Must be >= `fluxsync_proto::MAX_PAYLOAD`
/// — otherwise a single legal max-size item would immediately self-evict via
/// `evict_over_caps` right after its own insert, silently breaking resync for
/// every item near the size cap.
pub const MAX_TOTAL_BYTES: usize = 2 * fluxsync_proto::MAX_PAYLOAD;

/// Default retention window: an item older than this is dropped lazily
/// (on the next insert or read) rather than proactively. 24 hours — long
/// enough to cover a reconnect after an overnight sleep, short enough that
/// this is clearly a resend cache, not a history store.
pub const MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// One buffered outbound item: enough to rebuild the exact wire frames
/// `driver.rs` would have sent the first time (see `build_item_frames` /
/// `Action::SendItem` handling), so a re-offer is byte-for-byte identical
/// to the original send.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Full clipboard payload bytes (already capped upstream at
    /// `fluxsync_proto::MAX_PAYLOAD` by the same producers that feed
    /// `Action::SendItem`).
    pub payload: Vec<u8>,
    /// Wire item kind, matching `ClipboardItem.kind`.
    pub kind: fluxsync_proto::Kind,
    /// `EventId.origin` this item was originally stamped with —
    /// `ClipboardItem.origin` on the wire.
    pub origin: [u8; 32],
    /// `EventId.seq` this item was originally stamped with —
    /// `ClipboardItem.event_seq` on the wire. Re-offering with the
    /// original `(origin, seq)` lets the peer's mesh anti-loop guard
    /// recognize a resend as the same event, not a new one.
    pub seq: u64,
    /// When this entry was inserted (or last refreshed). Drives TTL
    /// eviction against [`Outbox::max_age`].
    pub created: Instant,
}

/// Bounded, TTL'd, in-memory buffer of recent outbound clipboard items,
/// keyed by content hash. See the module doc for the security invariant.
#[derive(Debug)]
pub struct Outbox {
    /// Insertion order, oldest first. A re-insert of an existing hash
    /// removes and re-appends it, so this always reflects "most recently
    /// (re-)inserted" order.
    order: VecDeque<[u8; 32]>,
    entries: HashMap<[u8; 32], Entry>,
    total_bytes: usize,
    /// TTL, normally [`MAX_AGE`]; a field (not just the constant) so tests
    /// can shrink it to exercise expiry without real or simulated sleeps
    /// spanning a full day.
    max_age: Duration,
}

impl Outbox {
    /// New, empty outbox with the production [`MAX_AGE`] TTL.
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_age(MAX_AGE)
    }

    /// New, empty outbox with a caller-supplied TTL. Exposed for tests that
    /// need a short TTL to exercise expiry deterministically.
    #[must_use]
    pub fn with_max_age(max_age: Duration) -> Self {
        Self {
            order: VecDeque::new(),
            entries: HashMap::new(),
            total_bytes: 0,
            max_age,
        }
    }

    /// Insert (or refresh) an entry under `hash`.
    ///
    /// Lazily purges expired entries first, then — if `hash` already has an
    /// entry — removes it (so the re-insert both replaces the entry and
    /// moves it to newest), then appends the new entry and evicts the
    /// oldest entries until both [`MAX_ITEMS`] and [`MAX_TOTAL_BYTES`] hold.
    ///
    /// Contract (see the module doc's security invariant): callers must only
    /// call this for an item already admitted to `State.history` — an
    /// immediate firewall `Pass`, or a parked `Ask` item once the user
    /// approves it. Never call this for a `Block`ed or denied item.
    pub fn insert(&mut self, hash: [u8; 32], entry: Entry) {
        self.purge_expired();
        self.remove(hash);
        self.total_bytes = self.total_bytes.saturating_add(entry.payload.len());
        self.order.push_back(hash);
        self.entries.insert(hash, entry);
        self.evict_over_caps();
    }

    /// Look up a still-live entry by hash. Returns `None` for a missing
    /// hash or one whose entry has expired (lazy TTL purge on read).
    #[must_use]
    pub fn get(&self, hash: [u8; 32]) -> Option<&Entry> {
        let now = Instant::now();
        self.entries
            .get(&hash)
            .filter(|e| !Self::is_expired(e, self.max_age, now))
    }

    /// Every still-live hash, newest (most recently inserted/refreshed)
    /// first. Lazily excludes expired entries without removing them.
    #[must_use]
    pub fn hashes(&self) -> Vec<[u8; 32]> {
        let now = Instant::now();
        self.order
            .iter()
            .rev()
            .filter(|h| {
                self.entries
                    .get(*h)
                    .is_some_and(|e| !Self::is_expired(e, self.max_age, now))
            })
            .copied()
            .collect()
    }

    /// Count of still-live entries (post lazy TTL purge).
    #[must_use]
    pub fn len(&self) -> usize {
        let now = Instant::now();
        self.entries
            .values()
            .filter(|e| !Self::is_expired(e, self.max_age, now))
            .count()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn is_expired(entry: &Entry, max_age: Duration, now: Instant) -> bool {
        now.saturating_duration_since(entry.created) > max_age
    }

    /// Purge every hash in `hashes` from the outbox. Used by "clear
    /// clipboard history" so a cleared item cannot silently come back into
    /// history via a later resync/pull — a missing hash is a no-op.
    pub fn remove_many(&mut self, hashes: &[[u8; 32]]) {
        for hash in hashes {
            self.remove(*hash);
        }
    }

    /// Remove `hash` (if present), keeping `order` and `total_bytes` in sync.
    fn remove(&mut self, hash: [u8; 32]) {
        if let Some(old) = self.entries.remove(&hash) {
            self.total_bytes = self.total_bytes.saturating_sub(old.payload.len());
            if let Some(pos) = self.order.iter().position(|h| *h == hash) {
                self.order.remove(pos);
            }
        }
    }

    /// Physically drop every expired entry. Called on every insert so the
    /// cap-eviction pass below always works from a live set.
    fn purge_expired(&mut self) {
        let now = Instant::now();
        let max_age = self.max_age;
        let expired: Vec<[u8; 32]> = self
            .entries
            .iter()
            .filter(|(_, e)| Self::is_expired(e, max_age, now))
            .map(|(h, _)| *h)
            .collect();
        for hash in expired {
            self.remove(hash);
        }
    }

    /// Evict oldest-first until both caps hold.
    fn evict_over_caps(&mut self) {
        while self.order.len() > MAX_ITEMS || self.total_bytes > MAX_TOTAL_BYTES {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some(e) = self.entries.remove(&oldest) {
                self.total_bytes = self.total_bytes.saturating_sub(e.payload.len());
                tracing::debug!(
                    hash = ?hex::encode(oldest),
                    bytes = e.payload.len(),
                    remaining = self.order.len(),
                    "outbox: evicted oldest entry over cap"
                );
            }
        }
    }

    /// Unconditionally drop every entry. Used on a security wipe
    /// (untrusted-peer, ghost-timeout, peer-swap) — see `driver.rs`'s
    /// `vault_wipe_gen` handling — where the whole outbox must not outlive
    /// the in-memory/on-disk history it mirrors, not just the hashes that
    /// happened to be in `State.history` at the time.
    pub fn clear_all(&mut self) {
        self.order.clear();
        self.entries.clear();
        self.total_bytes = 0;
    }
}

impl Default for Outbox {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{Entry, Outbox, MAX_ITEMS, MAX_TOTAL_BYTES};
    use fluxsync_proto::Kind;
    use std::time::{Duration, Instant};

    fn hash(n: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = n;
        h
    }

    fn entry(payload_len: usize, seq: u64, created: Instant) -> Entry {
        Entry {
            payload: vec![0u8; payload_len],
            kind: Kind::Text,
            origin: [9u8; 32],
            seq,
            created,
        }
    }

    #[test]
    fn cap_eviction_evicts_oldest_by_insertion_order() {
        let mut ob = Outbox::new();
        let last = u8::try_from(MAX_ITEMS + 2).unwrap();
        for i in 0..(MAX_ITEMS + 3) {
            let n = u8::try_from(i).unwrap();
            ob.insert(hash(n), entry(1, u64::from(n), Instant::now()));
        }
        assert_eq!(ob.len(), MAX_ITEMS);
        let hs = ob.hashes();
        assert_eq!(hs.len(), MAX_ITEMS);
        // Newest first: the very last inserted hash leads.
        assert_eq!(hs[0], hash(last));
        // The three oldest were evicted.
        assert!(ob.get(hash(0)).is_none());
        assert!(ob.get(hash(1)).is_none());
        assert!(ob.get(hash(2)).is_none());
        // The rest survive.
        assert!(ob.get(hash(3)).is_some());
        assert!(ob.get(hash(last)).is_some());
    }

    #[test]
    fn byte_cap_evicts_oldest_first() {
        let mut ob = Outbox::new();
        let big = MAX_TOTAL_BYTES / 2 + 1;
        ob.insert(hash(1), entry(big, 1, Instant::now()));
        ob.insert(hash(2), entry(big, 2, Instant::now())); // pushes over cap: evicts hash(1)
        ob.insert(hash(3), entry(big, 3, Instant::now())); // pushes over cap: evicts hash(2)

        assert!(ob.get(hash(1)).is_none(), "hash(1) must be byte-cap evicted");
        assert!(ob.get(hash(2)).is_none(), "hash(2) must be byte-cap evicted");
        assert!(ob.get(hash(3)).is_some());
        assert_eq!(ob.len(), 1);
    }

    #[test]
    fn ttl_purge_drops_expired_entries_lazily() {
        let mut ob = Outbox::with_max_age(Duration::from_millis(20));
        let old_created = Instant::now()
            .checked_sub(Duration::from_millis(50))
            .expect("test machine uptime exceeds 50ms");
        ob.insert(hash(1), entry(1, 1, old_created));

        // Purged on read even before another insert runs the mutating purge.
        assert!(ob.get(hash(1)).is_none());
        assert!(ob.hashes().is_empty());
        assert_eq!(ob.len(), 0);

        // A fresh insert triggers the mutating purge path too.
        ob.insert(hash(2), entry(1, 2, Instant::now()));
        assert_eq!(ob.len(), 1);
        assert_eq!(ob.hashes(), vec![hash(2)]);
    }

    #[test]
    fn reinsert_refreshes_hash_to_newest_and_replaces_entry() {
        let mut ob = Outbox::new();
        ob.insert(hash(1), entry(1, 1, Instant::now()));
        ob.insert(hash(2), entry(1, 2, Instant::now()));
        ob.insert(hash(1), entry(5, 99, Instant::now())); // refresh

        assert_eq!(ob.len(), 2);
        let hs = ob.hashes();
        assert_eq!(hs[0], hash(1), "refreshed hash must move to newest");
        assert_eq!(hs[1], hash(2));

        let got = ob.get(hash(1)).expect("refreshed entry must exist");
        assert_eq!(got.seq, 99);
        assert_eq!(got.payload.len(), 5);
    }

    #[test]
    fn remove_many_purges_given_hashes_and_leaves_the_rest() {
        let mut ob = Outbox::new();
        ob.insert(hash(1), entry(1, 1, Instant::now()));
        ob.insert(hash(2), entry(1, 2, Instant::now()));
        ob.insert(hash(3), entry(1, 3, Instant::now()));

        ob.remove_many(&[hash(1), hash(3), hash(99)]); // hash(99) absent: no-op

        assert!(ob.get(hash(1)).is_none());
        assert!(ob.get(hash(3)).is_none());
        assert!(ob.get(hash(2)).is_some());
        assert_eq!(ob.len(), 1);
    }

    #[test]
    fn empty_outbox_reports_empty() {
        let ob = Outbox::new();
        assert!(ob.is_empty());
        assert_eq!(ob.len(), 0);
        assert!(ob.hashes().is_empty());
        assert!(ob.get(hash(1)).is_none());
    }
}
