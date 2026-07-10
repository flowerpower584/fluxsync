//! DIR-P1-02: per-peer exponential backoff with full jitter for the
//! blind cache-redial reconnect path.
//!
//! Before this, a dropped session was redialed on a fixed cadence
//! forever — a flapping network or a dead peer produced a steady
//! handshake-init storm that could saturate the peer's own inbound
//! [`crate::rate_limit::HandshakeRateLimiter`]. This module tracks,
//! per peer-id, when the next blind redial is allowed.
//!
//! Deliberately pure and clock-injected: every method takes `now` as
//! an explicit [`Instant`] rather than reading the clock itself, so
//! the whole state machine is deterministic and testable without any
//! real or virtual sleeping. Jitter is likewise injected via a
//! generic [`RngCore`] — production callers use `rand_core::OsRng`;
//! tests use a fixed seed.
//!
//! Timing state lives here in the daemon, never in `fluxsync-core`
//! (which stays sync/pure and IO-free) — see `.agents/learnings/error-log.md`.

use rand_core::RngCore;
use std::time::{Duration, Instant};

/// Base (pre-jitter) delay for the first retry. Jittered into
/// `[250ms, 500ms]` by [`full_jitter`] — this is the "first retry
/// fast" requirement.
pub const INITIAL_BASE: Duration = Duration::from_millis(500);

/// Hard ceiling on the pre-jitter base delay. Product KPI: reconnect
/// p95 < 10s after network recovery. mDNS re-announcing a peer
/// bypasses this backoff entirely (see the `DiscoveryEvent::Resolved`
/// handler in `driver.rs`), so this cap only bounds the blind
/// cache-redial path; 8s leaves comfortable headroom under the 10s
/// budget even for a single worst-case wait.
pub const CAP: Duration = Duration::from_secs(8);

/// Attempt index at which the pre-jitter base first reaches [`CAP`]:
/// `500ms << 4 == 8000ms == CAP`. Attempts beyond this stay capped.
const MAX_SHIFT: u32 = 4;

/// M6: minimum session uptime before [`PeerBackoff::on_session_ended`]
/// treats a drop as "was stable" and resets `attempt`. Set comfortably
/// above the ~9s heartbeat-timeout floor (3 missed pings * 3s, see
/// `driver.rs`'s `heartbeat_loop`) so a session that dies on its very
/// first missed-heartbeat cycle can never look stable by accident.
pub const MIN_STABLE: Duration = Duration::from_secs(15);

/// Safety margin added on top of the peer's handshake rate-limiter
/// sustained refill interval to form [`STEADY_STATE_FLOOR`].
const FLOOR_MARGIN: Duration = Duration::from_millis(500);

/// Jitter floor once the base has reached [`CAP`]. Plain `[base/2, base]`
/// full jitter would allow an at-cap redial cadence of one per 4s — faster
/// than the peer's inbound `HandshakeRateLimiter` regenerates tokens (one
/// per [`crate::rate_limit::REFILL_INTERVAL`], 6s), so a long outage would
/// slowly drain the peer's bucket with our own retries. Clamping the at-cap
/// jitter window to `[REFILL_INTERVAL + margin, CAP]` keeps every
/// steady-state redial strictly slower than the refill, so the limiter can
/// never be saturated by us. Pre-cap attempts keep the fast `[base/2, base]`
/// window — the limiter's burst capacity absorbs the whole exponential ramp
/// (proven against the real limiter in `tests/backoff_chaos.rs`, not
/// asserted in prose). The `steady_floor_outpaces_limiter_refill` test
/// below fails if a future retune of either constant reopens the gap.
pub const STEADY_STATE_FLOOR: Duration =
    crate::rate_limit::REFILL_INTERVAL.saturating_add(FLOOR_MARGIN);

/// Backoff state for a single peer. Lives in a
/// `HashMap<[u8; 32], PeerBackoff>` in the daemon (see `BackoffMap` in
/// `driver.rs`), keyed by peer-id, pruned wherever the discovery
/// cache is pruned (unpair / revoke / vault wipe).
#[derive(Debug, Clone, Copy)]
pub struct PeerBackoff {
    attempt: u32,
    next_ready_at: Option<Instant>,
}

impl Default for PeerBackoff {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerBackoff {
    #[must_use]
    pub fn new() -> Self {
        Self {
            attempt: 0,
            next_ready_at: None,
        }
    }

    /// True if a blind redial is allowed at `now` — either no attempt
    /// has failed yet, or the jittered backoff window from the last
    /// failure has elapsed.
    #[must_use]
    pub fn ready(&self, now: Instant) -> bool {
        match self.next_ready_at {
            None => true,
            Some(t) => now >= t,
        }
    }

    /// Record a failed dial attempt: schedule the next allowed retry
    /// using exponential backoff with full jitter, then advance the
    /// attempt counter.
    pub fn on_attempt_failed<R: RngCore>(&mut self, now: Instant, rng: &mut R) {
        let delay = full_jitter(base_delay_for_attempt(self.attempt), rng);
        self.next_ready_at = Some(now + delay);
        self.attempt = self.attempt.saturating_add(1);
    }

    /// A *completed* handshake (not a mere UDP send / TCP connect)
    /// resets state, so the next drop starts fresh at the fast initial
    /// retry instead of wherever the counter last was.
    ///
    /// M6: kept as a manual/explicit reset primitive, but `driver.rs` no
    /// longer calls this the instant a handshake completes — a link that
    /// completes then immediately drops, repeatedly, would reset straight
    /// back to the fast retry on every flap, defeating this module's whole
    /// purpose. See [`Self::on_session_ended`], which driver.rs calls
    /// instead at actual teardown, gated on proven stability.
    pub fn on_handshake_ok(&mut self) {
        self.attempt = 0;
        self.next_ready_at = None;
    }

    /// M6: reset backoff only if the just-ended session stayed up at least
    /// [`MIN_STABLE`] — otherwise keep the escalated `attempt`, since a
    /// session shorter than that is a flap, not a recovery. Called from
    /// `driver.rs`'s teardown paths (heartbeat timeout, `Msg::Bye`, a
    /// completed rekey) with the dead session's uptime.
    pub fn on_session_ended(&mut self, uptime: Duration) {
        if uptime >= MIN_STABLE {
            self.attempt = 0;
            self.next_ready_at = None;
        }
    }
}

/// Pre-jitter base delay for the given (0-indexed) failed-attempt
/// count: `INITIAL_BASE * 2^attempt`, capped at [`CAP`].
fn base_delay_for_attempt(attempt: u32) -> Duration {
    let shift = attempt.min(MAX_SHIFT);
    Duration::from_millis(u64::try_from(INITIAL_BASE.as_millis()).unwrap_or(u64::MAX) << shift)
}

/// Lower bound of the jitter window for a given base delay: `base/2`
/// while ramping (fast first retry, still de-synchronized), clamped up
/// to [`STEADY_STATE_FLOOR`] once the base has reached [`CAP`] so the
/// steady-state redial cadence never outpaces the peer's rate-limiter
/// refill (see `STEADY_STATE_FLOOR`).
fn jitter_floor(base: Duration) -> Duration {
    if base >= CAP {
        STEADY_STATE_FLOOR
    } else {
        base / 2
    }
}

/// Full jitter: uniform-random in `[jitter_floor(base), base]` — i.e.
/// `[base/2, base]` while ramping (a non-zero floor, unlike AWS-style
/// `[0, base]`, keeps the very first retry meaningfully fast at ~250ms),
/// tightening to `[STEADY_STATE_FLOOR, CAP]` once capped.
///
/// Samples via a widening multiply (`(rng_u64 * range) >> 64`) rather
/// than `%`, so the result is unbiased across the whole `u64` space
/// and `rng.next_u64() == u64::MAX` deterministically maps to the top
/// of the range — useful for pinning exact bounds in tests.
fn full_jitter<R: RngCore>(base: Duration, rng: &mut R) -> Duration {
    let base_ms = u64::try_from(base.as_millis()).unwrap_or(u64::MAX);
    let floor_ms = u64::try_from(jitter_floor(base).as_millis()).unwrap_or(u64::MAX);
    let span = base_ms.saturating_sub(floor_ms);
    let extra = if span == 0 {
        0
    } else {
        ((u128::from(rng.next_u64()) * u128::from(span + 1)) >> 64) as u64
    };
    Duration::from_millis(floor_ms + extra)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic RngCore for tests — splitmix64, no external
    /// dependency. Not cryptographic; jitter is a scheduling nicety,
    /// not a security boundary.
    struct SplitMix64(u64);

    impl RngCore for SplitMix64 {
        #[allow(clippy::cast_possible_truncation)] // low 32 bits of splitmix64 is fine for test jitter
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            rand_core::impls::fill_bytes_via_next(self, dest);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    /// Always returns 0 — jitter collapses to exactly `base/2`. Used
    /// to pin down the lower bound of the growth sequence.
    struct MinRng;
    impl RngCore for MinRng {
        fn next_u32(&mut self) -> u32 {
            0
        }
        fn next_u64(&mut self) -> u64 {
            0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    /// Always returns `u64::MAX` — jitter collapses to exactly `base`.
    /// Used to pin down the upper bound of the growth sequence.
    struct MaxRng;
    impl RngCore for MaxRng {
        fn next_u32(&mut self) -> u32 {
            u32::MAX
        }
        fn next_u64(&mut self) -> u64 {
            u64::MAX
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0xFF);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn growth_sequence_min_jitter_follows_floor() {
        // MinRng pins jitter to the window floor: base/2 while ramping
        // (250, 500, 1000, 2000), then — once base hits CAP — the
        // steady-state floor (6500 = limiter refill 6000 + 500 margin)
        // forever, NOT CAP/2 = 4000: at-cap redials must stay slower
        // than the peer's rate-limiter refill.
        let mut pb = PeerBackoff::new();
        let mut rng = MinRng;
        let now = Instant::now();
        let floor_ms = u64::try_from(STEADY_STATE_FLOOR.as_millis()).unwrap();
        let expected = [250, 500, 1000, 2000, floor_ms, floor_ms, floor_ms];
        let mut cursor = now;
        for &exp in &expected {
            pb.on_attempt_failed(cursor, &mut rng);
            let scheduled = pb.next_ready_at.expect("scheduled after failure");
            assert_eq!(scheduled - cursor, ms(exp));
            cursor = scheduled;
        }
    }

    #[test]
    fn growth_sequence_max_jitter_never_exceeds_cap() {
        // MaxRng pins jitter to exactly base: 500, 1000, 2000, 4000,
        // 8000, then capped at 8000 (== CAP) forever — the cap must
        // never push a wait past CAP, which is the p95<10s KPI guard.
        let mut pb = PeerBackoff::new();
        let mut rng = MaxRng;
        let now = Instant::now();
        let expected = [500, 1000, 2000, 4000, 8000, 8000, 8000];
        let mut cursor = now;
        for &exp in &expected {
            pb.on_attempt_failed(cursor, &mut rng);
            let scheduled = pb.next_ready_at.expect("scheduled after failure");
            let delay = scheduled - cursor;
            assert_eq!(delay, ms(exp));
            assert!(delay <= CAP, "delay {delay:?} exceeded CAP {CAP:?}");
            cursor = scheduled;
        }
    }

    #[test]
    fn jitter_stays_within_floor_to_base_bounds() {
        for seed in 0..64u64 {
            let mut rng = SplitMix64(seed);
            for attempt in 0..8u32 {
                let base = base_delay_for_attempt(attempt);
                let floor = jitter_floor(base);
                let delay = full_jitter(base, &mut rng);
                assert!(
                    delay >= floor && delay <= base,
                    "seed {seed} attempt {attempt}: delay {delay:?} out of [{floor:?}, {base:?}]"
                );
                assert!(base <= CAP);
            }
        }
    }

    /// Guard invariant: the at-cap jitter floor must stay strictly above
    /// the handshake rate-limiter's sustained refill interval. If a
    /// future retune of either constant (backoff CAP/floor, limiter
    /// refill) breaks this, our own steady-state redials would drain the
    /// peer's token bucket faster than it refills — silently
    /// reintroducing the self-inflicted handshake storm DIR-P1-02
    /// exists to prevent. Fail here, loudly, instead.
    #[test]
    fn steady_floor_outpaces_limiter_refill() {
        assert!(
            STEADY_STATE_FLOOR > crate::rate_limit::REFILL_INTERVAL,
            "at-cap redial floor ({STEADY_STATE_FLOOR:?}) must exceed the limiter's \
             sustained refill interval ({:?})",
            crate::rate_limit::REFILL_INTERVAL
        );
        assert!(
            STEADY_STATE_FLOOR < CAP,
            "at-cap jitter window [{STEADY_STATE_FLOOR:?}, {CAP:?}] must be non-empty \
             (floor >= CAP would kill jitter entirely at steady state)"
        );
        // REFILL_PER_SEC is derived from REFILL_INTERVAL in rate_limit.rs;
        // re-check the derivation so the two can never drift apart.
        let derived = 1.0 / crate::rate_limit::REFILL_INTERVAL.as_secs_f64();
        assert!(
            (crate::rate_limit::REFILL_PER_SEC - derived).abs() < f64::EPSILON,
            "REFILL_PER_SEC must remain derived from REFILL_INTERVAL"
        );
    }

    #[test]
    fn ready_gates_until_scheduled_time_then_opens() {
        let mut pb = PeerBackoff::new();
        let now = Instant::now();
        assert!(pb.ready(now), "fresh backoff must be immediately ready");

        let mut rng = MaxRng; // delay == base == 500ms for attempt 0
        pb.on_attempt_failed(now, &mut rng);
        assert!(
            !pb.ready(now),
            "must not be ready immediately after a failure"
        );
        assert!(!pb.ready(now + ms(499)));
        assert!(pb.ready(now + ms(500)));
        assert!(pb.ready(now + ms(501)));
    }

    #[test]
    fn reset_on_success_returns_to_fast_initial_retry() {
        let mut pb = PeerBackoff::new();
        let mut rng = MaxRng;
        let now = Instant::now();
        for _ in 0..5 {
            pb.on_attempt_failed(now, &mut rng);
        }
        assert!(!pb.ready(now));

        pb.on_handshake_ok();
        assert!(pb.ready(now), "reset must clear the pending wait");
        assert_eq!(pb.attempt, 0);

        // Next failure after a reset schedules the fast initial delay
        // again, not wherever the counter left off.
        pb.on_attempt_failed(now, &mut rng);
        assert_eq!(pb.next_ready_at.unwrap() - now, ms(500));
    }

    /// M6: a session that dropped before proving itself stable (< `MIN_STABLE`)
    /// must keep its escalated `attempt` — resetting here is exactly the
    /// flap-storm bug this fix closes.
    #[test]
    fn on_session_ended_keeps_escalated_attempt_when_short_lived() {
        let mut pb = PeerBackoff::new();
        let mut rng = MaxRng;
        let now = Instant::now();
        for _ in 0..3 {
            pb.on_attempt_failed(now, &mut rng);
        }
        assert_eq!(pb.attempt, 3);
        pb.on_session_ended(MIN_STABLE.checked_sub(Duration::from_millis(1)).unwrap());
        assert_eq!(
            pb.attempt, 3,
            "a short-lived session must not reset backoff"
        );
        assert!(
            !pb.ready(now),
            "the pending wait must survive the short-lived session"
        );
    }

    /// M6: a session that stayed up at least `MIN_STABLE` resets backoff on
    /// end, so a legitimate reconnect after real stability isn't slowed by a
    /// stale escalated `attempt`.
    #[test]
    fn on_session_ended_resets_when_stable() {
        let mut pb = PeerBackoff::new();
        let mut rng = MaxRng;
        let now = Instant::now();
        for _ in 0..3 {
            pb.on_attempt_failed(now, &mut rng);
        }
        assert_eq!(pb.attempt, 3);
        pb.on_session_ended(MIN_STABLE);
        assert_eq!(
            pb.attempt, 0,
            "a session that reached MIN_STABLE must reset backoff"
        );
        assert!(pb.ready(now), "reset must clear the pending wait");
    }

    #[test]
    fn peers_are_independent() {
        let mut a = PeerBackoff::new();
        let mut b = PeerBackoff::new();
        let mut rng = MaxRng;
        let now = Instant::now();

        a.on_attempt_failed(now, &mut rng);
        a.on_attempt_failed(now, &mut rng);
        assert!(!a.ready(now));
        assert!(
            b.ready(now),
            "peer b must be unaffected by peer a's failures"
        );

        b.on_attempt_failed(now, &mut rng);
        assert_eq!(a.attempt, 2);
        assert_eq!(b.attempt, 1);
    }
}
