//! Battery / link policy.
//!
//! `status_for` is the **single source of truth** for the `status` field
//! exposed in the IPC state JSON. No other code in the workspace recomputes
//! `status` independently — the field is set from this function's output
//! after every state mutation.
//!
//! Rule (worse-of-both: if either side wants to pause, both pause):
//!
//! ```text
//! inactive  if !on
//! critical  if min(self_battery, peer_battery) <= 5
//! paused    if (self_below_threshold && !self_charging)
//!           || (peer_below_threshold && !peer_charging)
//! syncing   otherwise
//! ```
//!
//! `charge_override` (default true) hides the "below threshold" condition
//! when the *low* device is plugged in — covered implicitly by the
//! `!*_charging` checks above.

use crate::state::{State, Status};

/// Critical-battery cutoff. At or below this level the device is too low
/// to keep the link alive, regardless of threshold.
pub const CRITICAL_LEVEL: u8 = 5;

/// Compute the [`Status`] for a snapshot of [`State`].
#[must_use]
pub fn status_for(state: &State) -> Status {
    if !state.on {
        return Status::Inactive;
    }
    if state.peer_battery <= CRITICAL_LEVEL || state.battery_level <= CRITICAL_LEVEL {
        return Status::Critical;
    }
    let peer_below = state.peer_battery <= state.battery_threshold && !state.peer_charging;
    let self_below = state.battery_level <= state.battery_threshold && !state.charging;
    if peer_below || self_below {
        return Status::Paused;
    }
    Status::Syncing
}

/// Convenience: would this state be considered halted (i.e. `Critical`)?
#[must_use]
pub fn is_halted(state: &State) -> bool {
    state.on && (state.peer_battery <= CRITICAL_LEVEL || state.battery_level <= CRITICAL_LEVEL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{Config, State};

    fn st(on: bool, self_b: u8, self_c: bool, peer_b: u8, peer_c: bool, thr: u8) -> State {
        let mut s = State::initial(&Config::default());
        s.on = on;
        s.battery_level = self_b;
        s.charging = self_c;
        s.peer_battery = peer_b;
        s.peer_charging = peer_c;
        s.battery_threshold = thr;
        s
    }

    // ── Inactive ─────────────────────────────────────────────────────────
    #[test]
    fn inactive_when_off_regardless() {
        for self_b in [0u8, 5, 50, 100] {
            for peer_b in [0u8, 5, 50, 100] {
                let s = st(false, self_b, false, peer_b, false, 15);
                assert_eq!(status_for(&s), Status::Inactive, "{self_b}/{peer_b}");
            }
        }
    }

    // ── Critical: peer ────────────────────────────────────────────────────
    #[test]
    fn critical_when_peer_at_or_below_5() {
        for peer_b in 0u8..=5 {
            let s = st(true, 80, false, peer_b, false, 15);
            assert_eq!(status_for(&s), Status::Critical, "peer={peer_b}");
        }
    }

    #[test]
    fn not_critical_when_peer_above_5() {
        let s = st(true, 80, false, 6, false, 15);
        assert_ne!(status_for(&s), Status::Critical);
    }

    // ── Critical: self ────────────────────────────────────────────────────
    #[test]
    fn critical_when_self_at_or_below_5() {
        for self_b in 0u8..=5 {
            let s = st(true, self_b, false, 80, false, 15);
            assert_eq!(status_for(&s), Status::Critical, "self={self_b}");
        }
    }

    #[test]
    fn critical_overrides_charging() {
        // Even if charging, ≤5% is critical. We don't risk losing the link.
        let s = st(true, 3, true, 80, false, 15);
        assert_eq!(status_for(&s), Status::Critical);
    }

    // ── Paused: peer-side ─────────────────────────────────────────────────
    #[test]
    fn paused_when_peer_at_or_below_threshold_not_charging() {
        let thr = 15;
        for peer_b in 6..=thr {
            let s = st(true, 80, false, peer_b, false, thr);
            assert_eq!(status_for(&s), Status::Paused, "peer={peer_b}");
        }
    }

    #[test]
    fn not_paused_when_peer_at_threshold_plus_one() {
        let s = st(true, 80, false, 16, false, 15);
        assert_eq!(status_for(&s), Status::Syncing);
    }

    #[test]
    fn not_paused_when_peer_below_threshold_but_charging() {
        let s = st(true, 80, false, 10, true, 15);
        assert_eq!(status_for(&s), Status::Syncing);
    }

    // ── Paused: self-side ─────────────────────────────────────────────────
    #[test]
    fn paused_when_self_at_or_below_threshold_not_charging() {
        let thr = 20;
        for self_b in 6..=thr {
            let s = st(true, self_b, false, 80, false, thr);
            assert_eq!(status_for(&s), Status::Paused, "self={self_b}");
        }
    }

    #[test]
    fn not_paused_when_self_at_threshold_plus_one() {
        let s = st(true, 21, false, 80, false, 20);
        assert_eq!(status_for(&s), Status::Syncing);
    }

    #[test]
    fn not_paused_when_self_below_threshold_but_charging() {
        let s = st(true, 10, true, 80, false, 15);
        assert_eq!(status_for(&s), Status::Syncing);
    }

    // ── Syncing baseline ──────────────────────────────────────────────────
    #[test]
    fn syncing_when_both_above_threshold() {
        for self_b in [16u8, 50, 100] {
            for peer_b in [16u8, 50, 100] {
                let s = st(true, self_b, false, peer_b, false, 15);
                assert_eq!(status_for(&s), Status::Syncing, "{self_b}/{peer_b}");
            }
        }
    }

    // ── Exhaustive boundary table at threshold = 15 ───────────────────────
    #[test]
    fn boundary_table_threshold_15() {
        let thr = 15;
        // (self_b, self_c, peer_b, peer_c, expected)
        let cases = [
            (100u8, false, 100u8, false, Status::Syncing),
            (100, false, 16, false, Status::Syncing),
            (100, false, 15, false, Status::Paused),
            (100, false, 15, true, Status::Syncing),
            (100, false, 6, false, Status::Paused),
            (100, false, 6, true, Status::Syncing),
            (100, false, 5, false, Status::Critical),
            (100, false, 5, true, Status::Critical),
            (100, false, 0, false, Status::Critical),
            (16, false, 100, false, Status::Syncing),
            (15, false, 100, false, Status::Paused),
            (15, true, 100, false, Status::Syncing),
            (6, false, 100, false, Status::Paused),
            (6, true, 100, false, Status::Syncing),
            (5, false, 100, false, Status::Critical),
            (5, true, 100, false, Status::Critical),
            (0, false, 100, false, Status::Critical),
        ];
        for (sb, sc, pb, pc, exp) in cases {
            let s = st(true, sb, sc, pb, pc, thr);
            assert_eq!(
                status_for(&s),
                exp,
                "self={sb}/{sc}, peer={pb}/{pc}, thr={thr}"
            );
        }
    }

    #[test]
    fn is_halted_only_when_on_and_below_critical() {
        assert!(!is_halted(&st(false, 0, false, 0, false, 15)));
        assert!(is_halted(&st(true, 100, false, 4, false, 15)));
        assert!(is_halted(&st(true, 4, false, 100, false, 15)));
        assert!(!is_halted(&st(true, 6, false, 6, false, 15)));
    }
}
