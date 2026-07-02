//! FS-058: per-source-IP rate-limit for handshake initiation.
//!
//! A remote attacker on the LAN can spam `HandshakeInit` datagrams during
//! the TOFU pairing window to:
//!   1. flood `PendingSet` (M2),
//!   2. burn CPU on Noise responder work,
//!   3. flood `peers.json` on disk via newly-trusted TOFU entries (V1).
//!
//! This module enforces a token bucket per source `IpAddr`. The bucket is
//! conservative (low burst, low refill) because the legitimate workload is
//! ~1 handshake per peer per session.
//!
//! The store is bounded (`MAX_TRACKED_SOURCES`) and entries idle for more
//! than `IDLE_EVICT` are dropped on the next `check` call, so the limiter
//! itself cannot be turned into a memory amplifier.
//!
//! Closes FS-058 partial: V1+V2+M2 share the same DoS surface and this is
//! the single choke point in front of the responder.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Max tokens a single source can accumulate. One token = one accepted
/// `HandshakeInit`. Tight burst so a hostile peer cannot front-load a
/// flood, but high enough to absorb a couple of legitimate retries.
pub const BUCKET_CAPACITY: u32 = 5;

/// Sustained refill interval: one token regenerated per this duration.
/// DIR-P1-02: the reconnect backoff's at-cap jitter floor
/// (`backoff::STEADY_STATE_FLOOR`) is derived from this constant and must
/// stay strictly above it, so our own steady-state redials can never
/// outpace the peer's limiter — a guard test in `backoff.rs`
/// (`steady_floor_outpaces_limiter_refill`) fails if either constant is
/// retuned in a way that reintroduces the storm.
pub const REFILL_INTERVAL: Duration = Duration::from_secs(6);

/// Tokens regenerated per second (derived from [`REFILL_INTERVAL`] —
/// single source of truth). ~1 every 6s → after the burst is spent,
/// the attacker is rate-limited to ~10 handshakes/minute per source IP.
#[allow(clippy::cast_precision_loss)] // 6 is exactly representable
pub const REFILL_PER_SEC: f64 = 1.0 / REFILL_INTERVAL.as_secs() as f64;

/// Maximum number of distinct source IPs we track. If the table is full we
/// evict the oldest-seen entry before inserting a new one — this prevents
/// the limiter from being amplifier-bombed by spoofed sources.
pub const MAX_TRACKED_SOURCES: usize = 1024;

/// Source IPs idle for longer than this are dropped on the next sweep.
pub const IDLE_EVICT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl Bucket {
    fn new(now: Instant) -> Self {
        Self {
            tokens: f64::from(BUCKET_CAPACITY),
            last_refill: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_refill);
        let add = elapsed.as_secs_f64() * REFILL_PER_SEC;
        self.tokens = (self.tokens + add).min(f64::from(BUCKET_CAPACITY));
        self.last_refill = now;
    }

    fn try_consume(&mut self) -> bool {
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Bounded token-bucket limiter keyed by source `IpAddr`.
#[derive(Debug, Default)]
pub struct HandshakeRateLimiter {
    buckets: HashMap<IpAddr, Bucket>,
}

impl HandshakeRateLimiter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buckets: HashMap::new(),
        }
    }

    /// `true` if the source may proceed with one handshake right now.
    /// Side effect: refills the bucket and consumes one token on success.
    pub fn check(&mut self, src: IpAddr) -> bool {
        self.check_at(src, Instant::now())
    }

    /// Test seam: explicit `now`.
    pub fn check_at(&mut self, src: IpAddr, now: Instant) -> bool {
        self.sweep(now);

        // Cap the table BEFORE insert so a flood of unique sources cannot
        // grow it unbounded.
        if !self.buckets.contains_key(&src) && self.buckets.len() >= MAX_TRACKED_SOURCES {
            if let Some(victim) = self
                .buckets
                .iter()
                .min_by_key(|(_, b)| b.last_refill)
                .map(|(k, _)| *k)
            {
                self.buckets.remove(&victim);
            }
        }

        let bucket = self.buckets.entry(src).or_insert_with(|| Bucket::new(now));
        bucket.refill(now);
        bucket.try_consume()
    }

    fn sweep(&mut self, now: Instant) {
        self.buckets
            .retain(|_, b| now.saturating_duration_since(b.last_refill) < IDLE_EVICT);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, n))
    }

    #[test]
    fn allows_burst_up_to_capacity() {
        let mut l = HandshakeRateLimiter::new();
        let now = Instant::now();
        for _ in 0..BUCKET_CAPACITY {
            assert!(l.check_at(ip(1), now));
        }
        assert!(!l.check_at(ip(1), now), "must reject once bucket drained");
    }

    #[test]
    fn refills_over_time() {
        let mut l = HandshakeRateLimiter::new();
        let t0 = Instant::now();
        for _ in 0..BUCKET_CAPACITY {
            assert!(l.check_at(ip(1), t0));
        }
        // 12s later → ~2 tokens refilled.
        let t1 = t0 + Duration::from_secs(12);
        assert!(l.check_at(ip(1), t1));
        assert!(l.check_at(ip(1), t1));
        assert!(!l.check_at(ip(1), t1));
    }

    #[test]
    fn per_source_independent() {
        let mut l = HandshakeRateLimiter::new();
        let now = Instant::now();
        for _ in 0..BUCKET_CAPACITY {
            assert!(l.check_at(ip(1), now));
        }
        assert!(!l.check_at(ip(1), now));
        // A different IP has its own bucket.
        assert!(l.check_at(ip(2), now));
    }

    #[test]
    fn table_cap_evicts_oldest() {
        let mut l = HandshakeRateLimiter::new();
        let mut now = Instant::now();
        // Fill the table.
        for i in 0..MAX_TRACKED_SOURCES {
            let octets = u32::try_from(i).unwrap().to_be_bytes();
            let addr = IpAddr::V4(Ipv4Addr::new(10, octets[1], octets[2], octets[3]));
            assert!(l.check_at(addr, now));
            now += Duration::from_millis(1);
        }
        assert_eq!(l.len(), MAX_TRACKED_SOURCES);
        // One more distinct source → still capped.
        assert!(l.check_at(ip(99), now));
        assert!(l.len() <= MAX_TRACKED_SOURCES);
    }

    #[test]
    fn idle_entries_swept() {
        let mut l = HandshakeRateLimiter::new();
        let t0 = Instant::now();
        assert!(l.check_at(ip(1), t0));
        assert_eq!(l.len(), 1);
        // Long after IDLE_EVICT: next call sweeps the stale entry before
        // inserting the new one.
        let t1 = t0 + IDLE_EVICT + Duration::from_secs(1);
        assert!(l.check_at(ip(2), t1));
        assert_eq!(l.len(), 1, "stale ip(1) must have been evicted");
    }
}
