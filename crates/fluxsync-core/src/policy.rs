//! Link status + clipboard firewall policy.
//!
//! `status_for` is the **single source of truth** for the `status` field
//! exposed in the IPC state JSON. No other code in the workspace recomputes
//! `status` independently — the field is set from this function's output
//! after every state mutation.

use crate::state::{State, Status};
use fluxsync_proto::Kind;
use serde::{Deserialize, Serialize};

/// Compute the [`Status`] for a snapshot of [`State`]: syncing while the
/// user has sync switched on, inactive otherwise. Battery level is shown,
/// never acted on: FluxSync only sends when something is copied, so there
/// is nothing to save by pausing.
#[must_use]
pub fn status_for(state: &State) -> Status {
    if state.on {
        Status::Syncing
    } else {
        Status::Inactive
    }
}

// ── Clipboard Firewall (chantier A) ───────────────────────────────────────
//
// Per-content-type policy gating both directions: which inbound items get
// applied to the OS clipboard, and which locally-copied items get broadcast.
// The UI labels are Always / Never; internally `Rule::{Allow, Deny}` so the
// decision verbs (`Pass`/`Block`) read distinctly. `Rule::Ask` is no longer
// offered — a question at every copy breaks "sync without thinking about
// it" — and [`FirewallPolicy::normalized`] turns one found in an older saved
// policy into `Deny`, so nothing passes that the user wanted to hold back.
//
// This is the proper fix for the by-design-but-ungated secrets path: a
// `sensitive` rule can force "Never" on detected secrets without the user
// having to lock down a whole content type.

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

/// Which way a clipboard item is flowing when the firewall judges it. Also
/// stored on a deferred [`crate::state::PendingItem`] so the UI can show
/// whether an awaiting item is incoming or outgoing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
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
    #[serde(default = "rule_deny")]
    pub sensitive: Rule,
}

fn rule_allow() -> Rule {
    Rule::Allow
}

fn rule_deny() -> Rule {
    Rule::Deny
}

impl Default for FirewallPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            text: Rule::Allow,
            url: Rule::Allow,
            code: Rule::Allow,
            image: Rule::Allow,
            sensitive: Rule::Deny,
        }
    }
}

impl FirewallPolicy {
    /// This policy with every `Ask` rule (only an older saved policy can
    /// hold one) turned into `Deny`.
    #[must_use]
    pub fn normalized(mut self) -> Self {
        for rule in [
            &mut self.text,
            &mut self.url,
            &mut self.code,
            &mut self.image,
            &mut self.sensitive,
        ] {
            if *rule == Rule::Ask {
                *rule = Rule::Deny;
            }
        }
        self
    }

    /// The rule for one content type, before the sensitive override.
    fn rule_for(&self, kind: Kind) -> Rule {
        match kind {
            Kind::Text => self.text,
            Kind::Url => self.url,
            Kind::Code => self.code,
            // Files follow the binary-content rule ("Images & files").
            Kind::Image | Kind::File => self.image,
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
            enabled: true, // rules all Allow, sensitive Deny
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
        assert_eq!(
            p.decide(Kind::Text, false, Direction::Outbound),
            Decision::Pass
        );
        assert_eq!(
            p.decide(Kind::Url, false, Direction::Outbound),
            Decision::Defer
        );
        assert_eq!(
            p.decide(Kind::Code, false, Direction::Outbound),
            Decision::Block
        );
        assert_eq!(
            p.decide(Kind::Image, false, Direction::Inbound),
            Decision::Defer
        );
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
        assert_eq!(
            p.decide(Kind::Text, false, Direction::Outbound),
            Decision::Pass
        );
        assert_eq!(
            p.decide(Kind::Text, true, Direction::Outbound),
            Decision::Defer
        );
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
        assert_eq!(
            p.decide(Kind::Text, true, Direction::Outbound),
            Decision::Block
        );
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
        // with the safe defaults (kinds Allow, sensitive Deny).
        let p: FirewallPolicy = serde_json::from_str(r#"{"enabled":true}"#).unwrap();
        assert!(p.enabled);
        assert_eq!(p.text, Rule::Allow);
        assert_eq!(p.sensitive, Rule::Deny);
        assert_eq!(
            p.decide(Kind::Text, true, Direction::Outbound),
            Decision::Block
        );
    }

    #[test]
    fn normalized_turns_ask_into_deny() {
        let p = FirewallPolicy {
            enabled: true,
            text: Rule::Ask,
            sensitive: Rule::Ask,
            ..FirewallPolicy::default()
        }
        .normalized();
        assert_eq!(
            (p.text, p.url, p.sensitive),
            (Rule::Deny, Rule::Allow, Rule::Deny)
        );
    }
}
