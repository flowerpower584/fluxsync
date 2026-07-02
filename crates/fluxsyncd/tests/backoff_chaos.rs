//! DIR-P1-02 chaos test: exponential backoff must turn 50 consecutive
//! connection failures into a bounded, decaying sequence of dial
//! attempts — not a storm — and must not hand the peer's own inbound
//! `HandshakeRateLimiter` (rate_limit.rs) more load than it can absorb.
//!
//! Scope note (why this isn't a full daemon-to-daemon run like
//! `zero_day_net.rs`): `PeerBackoff` never reads the clock itself —
//! every method takes `now` as an explicit `Instant` — specifically so
//! this property is provable with pure `Duration` arithmetic instead
//! of actually waiting out up to 50 * 8s of either wall-clock or
//! `tokio::time::pause()`-advanced virtual time through a real 5s
//! per-hint UDP handshake timeout. That keeps this test fast and
//! immune to timing flakiness while still exercising the two real
//! production types end to end: `fluxsyncd::backoff::PeerBackoff` and
//! `fluxsyncd::rate_limit::HandshakeRateLimiter`.
//!
//! Adversarial framing: every simulated failure uses the *fastest*
//! legal jitter draw (the exact floor of the jitter window — `base/2`
//! while ramping, `STEADY_STATE_FLOOR` once capped), i.e. the worst
//! case for both storm-avoidance and rate-limiter pressure. Real
//! jitter is uniform-random over `[floor, base]`, so any real run is
//! only ever slower / gentler than what's asserted here — the bounds
//! below hold a fortiori.

use fluxsyncd::backoff::{PeerBackoff, CAP, INITIAL_BASE, STEADY_STATE_FLOOR};
use fluxsyncd::rate_limit::{HandshakeRateLimiter, BUCKET_CAPACITY};
use rand_core::RngCore;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

const ATTEMPTS: usize = 50;

/// Always yields 0 — `full_jitter` collapses to the exact floor of
/// its window, the fastest legal retry cadence. See the module doc
/// for why this is the right adversarial choice, not a weakening of
/// the test.
struct FastestJitterRng;

impl RngCore for FastestJitterRng {
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

/// Drives `ATTEMPTS` consecutive forced failures through a fresh
/// `PeerBackoff`, polling `ready()` the same way `driver.rs`'s
/// reconnect loop does (instead of reaching into private state), and
/// returns the `Instant` each dial attempt actually happened at.
fn simulate_forced_failures() -> Vec<Instant> {
    let mut pb = PeerBackoff::new();
    let mut rng = FastestJitterRng;
    let mut now = Instant::now();
    // 25ms evenly divides every delay this schedule ever produces
    // (250/500/1000/2000ms ramping, 6500ms at cap), so polling never
    // overshoots a boundary — the recorded gaps below are exact, not
    // approximate.
    let poll_step = Duration::from_millis(25);

    let mut attempt_times = Vec::with_capacity(ATTEMPTS);
    for _ in 0..ATTEMPTS {
        while !pb.ready(now) {
            now += poll_step;
        }
        attempt_times.push(now);
        pb.on_attempt_failed(now, &mut rng);
    }
    attempt_times
}

#[test]
fn fifty_forced_failures_stay_log_shaped_not_a_storm() {
    let times = simulate_forced_failures();
    assert_eq!(times.len(), ATTEMPTS);

    // No single wait ever exceeds CAP — the product KPI guard (p95 <
    // 10s reconnect) the architect specified. Structurally guaranteed
    // by `full_jitter` returning at most `base <= CAP`, but assert it
    // black-box here too since it's the one invariant a caller must
    // never observe broken.
    for pair in times.windows(2) {
        let gap = pair[1] - pair[0];
        assert!(
            gap <= CAP,
            "a single backoff wait ({gap:?}) exceeded the CAP ({CAP:?}) KPI guard"
        );
    }

    // The very first retry is fast, per DIR-P1-02's "~250-500ms"
    // requirement — even at the jitter floor it's at least base/2.
    let first_gap = times[1] - times[0];
    assert_eq!(first_gap, INITIAL_BASE / 2);

    // Genuine exponential growth happened, not a flat fast retry: by
    // the time we've reached the steady (capped) state, gaps have
    // grown to the at-cap floor — STEADY_STATE_FLOOR, the limiter's
    // sustained refill interval plus margin, NOT CAP/2 (see
    // backoff.rs: plain half-jitter at cap could outpace the refill).
    let steady_gap = times[ATTEMPTS - 1] - times[ATTEMPTS - 2];
    assert_eq!(steady_gap, STEADY_STATE_FLOOR);

    // 50 back-to-back failures must NOT complete anywhere near
    // "storm" speed. Even under the fastest legal jitter, the
    // exponential ramp alone pushes total elapsed time into the
    // minutes; a broken/no-op backoff (or the pre-fix flat, unbacked
    // retry) would burn through 50 attempts in well under a second at
    // the 200ms discovery-dispatcher poll granularity.
    let total = times[ATTEMPTS - 1] - times[0];
    assert!(
        total >= Duration::from_secs(60),
        "50 forced failures completed in {total:?} — that's a storm, not backoff"
    );

    // Bounded/log-shaped, concretely: reaching the 11th attempt must
    // take real time (double-digit seconds), not a handful of
    // milliseconds.
    let to_11th = times[10] - times[0];
    assert!(
        to_11th >= Duration::from_secs(20),
        "10 backoff cycles collapsed to {to_11th:?} — growth isn't happening"
    );
}

#[test]
fn fifty_forced_failures_do_not_overwhelm_the_real_rate_limiter() {
    // Same peer's inbound limiter would see our own retries as
    // repeated `HandshakeInit`s from one source IP — reuse the real,
    // production `HandshakeRateLimiter` (rate_limit.rs) rather than
    // reimplementing its token-bucket math here.
    let times = simulate_forced_failures();
    let src: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut limiter = HandshakeRateLimiter::new();

    let mut allowed = 0usize;
    let mut throttled = 0usize;
    for &t in &times {
        if limiter.check_at(src, t) {
            allowed += 1;
        } else {
            throttled += 1;
        }
    }

    // Binding AC: the limiter is NEVER tripped by our own retries,
    // even under the fastest legal jitter. This holds by construction:
    // the exponential ramp fits inside the burst capacity (asserted
    // below), and every at-cap redial is spaced at least
    // STEADY_STATE_FLOOR apart — strictly more than one refill
    // interval (guarded by `steady_floor_outpaces_limiter_refill` in
    // backoff.rs) — so the bucket regains at least one token between
    // consecutive steady-state attempts and never runs dry.
    assert_eq!(
        throttled, 0,
        "rate limiter throttled {throttled}/{ATTEMPTS} of our own retries — \
         the backoff schedule must never saturate the peer's limiter"
    );
    assert_eq!(allowed, ATTEMPTS);

    // "Burst absorbs the ramp", verified rather than asserted in
    // prose: count the attempts fired before the schedule first
    // reaches its at-cap spacing (i.e. everything in the fast
    // exponential ramp) and check they fit within the limiter's burst
    // capacity — refill during the ramp is a bonus on top, not needed
    // for correctness.
    let ramp_attempts = times
        .windows(2)
        .take_while(|w| w[1] - w[0] < STEADY_STATE_FLOOR)
        .count()
        + 1; // gaps -> attempts: N short gaps cover N+1 leading dials
    assert!(
        ramp_attempts <= BUCKET_CAPACITY as usize,
        "the pre-cap exponential ramp fired {ramp_attempts} dials — more than the \
         limiter's burst capacity ({BUCKET_CAPACITY}); the ramp would trip the limiter"
    );
}
