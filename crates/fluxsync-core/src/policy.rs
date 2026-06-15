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
use fluxsync_proto::Kind;
use serde::{Deserialize, Serialize};

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
    // M-CORE-01: `charge_override` (default true) is the "keep syncing while
    // the low device is plugged in" exemption. When the user turns it OFF, a
    // device below threshold must pause *even while charging* — so the charging
    // exemption only applies when `charge_override` is set. Previously this
    // field was never read and the toggle did nothing.
    let charge_exempts = state.charge_override;
    let peer_below =
        state.peer_battery <= state.battery_threshold && !(charge_exempts && state.peer_charging);
    let self_below =
        state.battery_level <= state.battery_threshold && !(charge_exempts && state.charging);
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

// ── Clipboard Firewall (chantier A) ───────────────────────────────────────
//
// Per-content-type policy gating both directions: which inbound items get
// applied to the OS clipboard, and which locally-copied items get broadcast.
// The UI labels are Always / Ask / Never; internally `Rule::{Allow, Ask,
// Deny}` so the decision verbs (`Pass`/`Defer`/`Block`) read distinctly.
//
// This is the proper fix for the by-design-but-ungated secrets path: a
// `sensitive` rule can force "Ask"/"Never" on detected secrets without the
// user having to lock down a whole content type.

/// What the firewall does with one content type. UI: Always / Ask / Never.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Rule {
    /// Always — sync without prompting.
    Allow,
    /// Ask — hold the item until the user confirms (defer apply / confirm send).
    Ask,
    /// Never — drop the item silently.
    Deny,
}

impl Rule {
    /// Order Allow < Ask < Deny so we can take the stricter of two rules.
    fn severity(self) -> u8 {
        match self {
            Rule::Allow => 0,
            Rule::Ask => 1,
            Rule::Deny => 2,
        }
    }

    /// The more restrictive of two rules. Used so the `sensitive` override can
    /// only tighten a content type's rule, never loosen it.
    #[must_use]
    fn stricter(self, other: Rule) -> Rule {
        if other.severity() > self.severity() {
            other
        } else {
            self
        }
    }
}

/// Which way a clipboard item is flowing when the firewall judges it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Arriving from a peer, about to be written to this device's clipboard.
    Inbound,
    /// Locally copied, about to be broadcast to peers.
    Outbound,
}

/// The firewall's verdict for one item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Sync it now.
    Pass,
    /// Hold it; surface an Ask prompt and apply/send only once confirmed.
    Defer,
    /// Drop it silently.
    Block,
}

/// Per-content-type clipboard policy. Default is `disabled` (every item
/// `Pass`es) so an unconfigured daemon behaves exactly as before the firewall
/// existed — opt-in only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FirewallPolicy {
    /// Master switch. While false, [`FirewallPolicy::decide`] always returns
    /// [`Decision::Pass`] regardless of the rules below.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "rule_allow")]
    pub text: Rule,
    #[serde(default = "rule_allow")]
    pub url: Rule,
    #[serde(default = "rule_allow")]
    pub code: Rule,
    #[serde(default = "rule_allow")]
    pub image: Rule,
    /// Applied on top of the per-kind rule when the item is flagged sensitive
    /// (a detected secret). Can only make the verdict stricter, never looser —
    /// so a secret is never auto-allowed because its content type was Always.
    #[serde(default = "rule_ask")]
    pub sensitive: Rule,
}

fn rule_allow() -> Rule {
    Rule::Allow
}

fn rule_ask() -> Rule {
    Rule::Ask
}

impl Default for FirewallPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            text: Rule::Allow,
            url: Rule::Allow,
            code: Rule::Allow,
            image: Rule::Allow,
            sensitive: Rule::Ask,
        }
    }
}

impl FirewallPolicy {
    /// The rule for one content type, before the sensitive override.
    fn rule_for(&self, kind: Kind) -> Rule {
        match kind {
            Kind::Text => self.text,
            Kind::Url => self.url,
            Kind::Code => self.code,
            Kind::Image => self.image,
        }
    }

    /// Decide what to do with an item of `kind`, whether or not it is
    /// `sensitive`, flowing in `dir`. `dir` is informational for now (both
    /// directions share one rule table); the daemon uses it to know whether a
    /// `Defer` means "hold the apply" or "hold the send".
    #[must_use]
    pub fn decide(&self, kind: Kind, sensitive: bool, dir: Direction) -> Decision {
        let _ = dir;
        if !self.enabled {
            return Decision::Pass;
        }
        let mut rule = self.rule_for(kind);
        if sensitive {
            rule = rule.stricter(self.sensitive);
        }
        match rule {
            Rule::Allow => Decision::Pass,
            Rule::Ask => Decision::Defer,
            Rule::Deny => Decision::Block,
        }
    }
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

#[cfg(test)]
mod firewall_tests {
    use super::{Decision, Direction, FirewallPolicy, Rule};
    use fluxsync_proto::Kind;

    const KINDS: [Kind; 4] = [Kind::Text, Kind::Url, Kind::Code, Kind::Image];
    const DIRS: [Direction; 2] = [Direction::Inbound, Direction::Outbound];

    #[test]
    fn default_is_disabled_and_passes_everything() {
        let p = FirewallPolicy::default();
        assert!(!p.enabled);
        for k in KINDS {
            for d in DIRS {
                assert_eq!(p.decide(k, false, d), Decision::Pass);
                // Even a secret passes while the firewall is OFF — identical to
                // pre-firewall behaviour (the secrets path was ungated by design).
                assert_eq!(p.decide(k, true, d), Decision::Pass);
            }
        }
    }

    #[test]
    fn enabled_with_allow_rules_still_passes() {
        let p = FirewallPolicy {
            enabled: true, // rules all Allow, sensitive Ask
            ..FirewallPolicy::default()
        };
        for k in KINDS {
            assert_eq!(p.decide(k, false, Direction::Inbound), Decision::Pass);
        }
    }

    #[test]
    fn per_kind_rules_map_to_verdicts() {
        let p = FirewallPolicy {
            enabled: true,
            text: Rule::Allow,
            url: Rule::Ask,
            code: Rule::Deny,
            image: Rule::Ask,
            sensitive: Rule::Allow,
        };
        assert_eq!(p.decide(Kind::Text, false, Direction::Outbound), Decision::Pass);
        assert_eq!(p.decide(Kind::Url, false, Direction::Outbound), Decision::Defer);
        assert_eq!(p.decide(Kind::Code, false, Direction::Outbound), Decision::Block);
        assert_eq!(p.decide(Kind::Image, false, Direction::Inbound), Decision::Defer);
    }

    #[test]
    fn sensitive_override_only_tightens() {
        // Kind says Always, but the item is a secret and sensitive=Ask → Ask wins.
        let p = FirewallPolicy {
            enabled: true,
            text: Rule::Allow,
            url: Rule::Allow,
            code: Rule::Allow,
            image: Rule::Allow,
            sensitive: Rule::Ask,
        };
        assert_eq!(p.decide(Kind::Text, false, Direction::Outbound), Decision::Pass);
        assert_eq!(p.decide(Kind::Text, true, Direction::Outbound), Decision::Defer);
    }

    #[test]
    fn sensitive_override_never_loosens() {
        // Kind says Never, item is sensitive with a laxer sensitive=Ask: the
        // stricter Never must still win — a secret can't slip past a denied kind.
        let p = FirewallPolicy {
            enabled: true,
            text: Rule::Deny,
            url: Rule::Allow,
            code: Rule::Allow,
            image: Rule::Allow,
            sensitive: Rule::Ask,
        };
        assert_eq!(p.decide(Kind::Text, true, Direction::Outbound), Decision::Block);
    }

    #[test]
    fn deny_sensitive_blocks_secret_of_any_kind() {
        let p = FirewallPolicy {
            enabled: true,
            text: Rule::Allow,
            url: Rule::Allow,
            code: Rule::Allow,
            image: Rule::Allow,
            sensitive: Rule::Deny,
        };
        for k in KINDS {
            assert_eq!(p.decide(k, true, Direction::Outbound), Decision::Block);
            assert_eq!(p.decide(k, false, Direction::Outbound), Decision::Pass);
        }
    }

    #[test]
    fn rule_serde_roundtrip_lowercase() {
        assert_eq!(serde_json::to_string(&Rule::Allow).unwrap(), "\"allow\"");
        assert_eq!(serde_json::to_string(&Rule::Ask).unwrap(), "\"ask\"");
        assert_eq!(serde_json::to_string(&Rule::Deny).unwrap(), "\"deny\"");
        let r: Rule = serde_json::from_str("\"deny\"").unwrap();
        assert_eq!(r, Rule::Deny);
    }

    #[test]
    fn policy_deserializes_from_partial_json_with_defaults() {
        // An old/partial config that only flips `enabled` must fill the rest
        // with the safe defaults (kinds Allow, sensitive Ask).
        let p: FirewallPolicy = serde_json::from_str(r#"{"enabled":true}"#).unwrap();
        assert!(p.enabled);
        assert_eq!(p.text, Rule::Allow);
        assert_eq!(p.sensitive, Rule::Ask);
        assert_eq!(p.decide(Kind::Text, true, Direction::Outbound), Decision::Defer);
    }
}
