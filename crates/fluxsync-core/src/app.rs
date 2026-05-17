//! Composes the FSM, state, dedup ring, Lamport clock, and policy into one
//! object the daemon can drive event-by-event.
//!
//! The daemon owns one `App`. Every external nudge becomes an `Event`;
//! `App::handle` returns the list of `Action`s the daemon must execute.
//!
//! `App` is `Send + Sync`-free on purpose: the daemon runs it inside a
//! single tokio task. That removes a whole class of races at zero runtime
//! cost.

use crate::clock::{Clock, LamportClock, WallClock};
use crate::dedup::DedupRing;
use crate::events::{Action, Event, LogEntry};
use crate::fsm::{transition, Phase};
use crate::policy::status_for;
use crate::state::{Config, HistoryItem, State};

const HISTORY_SOFT_CAP: usize = 50;

pub struct App {
    pub phase: Phase,
    pub state: State,
    pub clock: LamportClock,
    pub dedup: DedupRing,
    config: Config,
    /// Peer id of the last peer this app paired with. Survives `ManualUnpair`
    /// (which zeroes `state.peer_id`) so a later re-pair can tell whether the
    /// new peer is the same device or a different one — see FS-046.
    last_paired_peer_id: [u8; 32],
}

impl App {
    #[must_use]
    pub fn new(config: Config) -> Self {
        let state = State::initial(&config);
        Self {
            phase: Phase::Idle,
            state,
            clock: LamportClock::new(),
            dedup: DedupRing::default(),
            config,
            last_paired_peer_id: [0u8; 32],
        }
    }

    /// Read-only snapshot. Cheap; no allocation.
    #[must_use]
    pub fn snapshot(&self) -> &State {
        &self.state
    }

    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn set_metrics(&mut self, m: Option<crate::state::ConnectionMetrics>) {
        self.state.metrics = m;
    }

    pub fn set_latency(&mut self, ms: u32) {
        self.state.link_latency_ms = ms;
    }

    pub fn set_charge_override(&mut self, value: bool) {
        self.config.charge_override = value;
        self.state.charge_override = value;
    }

    /// Drive the state machine with one event. Returns the side-effect
    /// commands the daemon must execute, in order.
    ///
    /// `wall` is `?Sized` so callers may pass either a concrete value
    /// (`&StubWallClock` in tests) or a trait object (`&dyn WallClock`
    /// in the daemon, which holds an `Arc<dyn WallClock + Send + Sync>`).
    #[allow(clippy::needless_pass_by_value)] // Event is consumed by design; callers lose ownership.
    #[allow(clippy::too_many_lines)] // One match arm per event; splitting the dispatch hurts readability.
    pub fn handle<W: WallClock + ?Sized>(&mut self, event: Event, wall: &W) -> Vec<Action> {
        // [FIX] Optimization: Removed expensive state.clone().
        // Instead, we manually track if we need to EmitState.

        // ── Pre-transition state mutations ──────────────────────────────
        // (everything that is "data the FSM expects to already be in state")
        let mut suppress_action = false;
        match &event {
            Event::ToggleOn => self.state.on = true,
            Event::ToggleOff => self.state.on = false,
            Event::PeerSeen { name, peer_id } => {
                if self.is_peer_mismatch(*peer_id) {
                    // [REMEDIATION] Completely abort the process.
                    // DO NOT transition, DO NOT return any actions.
                    return vec![];
                }
                self.state.peer_name.clone_from(name);
                // Don't overwrite peer_id with placeholder
                if *peer_id != [0u8; 32] {
                    // FS-046: a re-pair with a *different* peer must drop the
                    // previous peer's clipboard history. ManualUnpair keeps the
                    // history (same-device reconnect is expected to resume it),
                    // but without this a new peer would inherit — and could
                    // BurstReplay — the prior peer's secrets.
                    if self.last_paired_peer_id != [0u8; 32] && *peer_id != self.last_paired_peer_id
                    {
                        self.state.history.clear();
                    }
                    self.last_paired_peer_id = *peer_id;
                    self.state.peer_id = *peer_id;
                }
            }
            Event::BatteryChangedSelf { level, charging } => {
                self.state.battery_level = *level;
                self.state.charging = *charging;
            }
            Event::BatteryChangedPeer { level, charging } => {
                self.state.peer_battery = *level;
                self.state.peer_charging = *charging;
            }
            Event::LocalClipboardChange {
                hash,
                kind,
                preview,
                sensitive,
                lamport,
            } => {
                let preview = preview.trim();
                self.clock.observe(*lamport);
                if !self.dedup.observe(*hash) {
                    suppress_action = true; // saw it from peer already, don't echo
                } else if !sensitive {
                    self.push_history(HistoryItem {
                        kind: *kind,
                        preview: preview.to_string(),
                        time: wall.hhmm(),
                        source: crate::state::HistorySource::Local,
                        sensitive: *sensitive,
                        lamport: *lamport,
                    });
                }
            }
            Event::FrameReceivedClipboard {
                hash,
                kind,
                preview,
                sensitive,
                lamport,
            } => {
                // On nettoie le texte (espaces inutiles aux extrémités)
                let preview = preview.trim();

                // On synchronise notre horloge logique (Lamport) avec celle de l'Android
                self.clock.observe(*lamport);

                // Dedup by content hash. `observe` returns false when this
                // hash was already seen — that covers three cases at once:
                // an echo of our own local copy, a duplicate retransmit, and
                // a malicious peer reusing a hash to poison history. In every
                // case we drop the frame and only send an Ack.
                if !self.dedup.observe(*hash) {
                    suppress_action = true;
                } else if !sensitive {
                    self.push_history(HistoryItem {
                        kind: *kind,
                        preview: preview.to_string(),
                        time: wall.hhmm(),
                        source: crate::state::HistorySource::Remote,
                        sensitive: *sensitive,
                        lamport: *lamport,
                    });
                }
            }
            Event::PeerLost => {
                self.state.peer_battery = 100;
                self.state.peer_charging = false;
            }
            Event::UntrustedPeerSeen { .. } => {
                self.state.peer_name.clear();
                self.state.peer_id = [0u8; 32];
                self.state.peer_battery = 100;
                self.state.peer_charging = false;
                self.state.history.clear();
            }
            Event::GhostTimeout
                if !matches!(self.phase, Phase::Linked | Phase::Paused | Phase::Halted) =>
            {
                self.state.peer_name.clear();
                self.state.peer_id = [0u8; 32];
                self.state.peer_battery = 100;
                self.state.peer_charging = false;
                self.state.history.clear();
            }
            Event::ManualUnpair => {
                self.state.on = false;
                self.state.peer_name.clear();
                self.state.peer_id = [0u8; 32];
                self.state.trusted_peer_name = None;
                self.state.peer_battery = 100;
                self.state.peer_charging = false;
            }
            Event::SetTrustedPeer { name } => {
                self.state.trusted_peer_name = Some(name.clone());
            }
            _ => {}
        }

        if suppress_action {
            // [REMEDIATION] If suppressed (duplicate/replay), we skip the FSM transition entirely.
            // However, for incoming clipboard frames, we still MUST send an Ack to stop the peer's retransmission.
            if let Event::FrameReceivedClipboard { hash, .. } = &event {
                return vec![Action::AckItem { hash: *hash }];
            }
            return vec![];
        }

        // ── Run the pure transition ─────────────────────────────────────
        let (next, mut actions) = transition(self.phase, &event);

        // Battery-policy phase override (post-transition)
        // [FIX] Force Halted/Paused even in Discovering/Handshaking if battery is bad.
        self.phase = match next {
            Phase::Idle => Phase::Idle,
            _ => self.phase_for_policy_ext(next),
        };

        // Sync phase name into the serializable State so Android/macOS
        // can read the actual FSM phase from the JSON.
        self.state.phase = match self.phase {
            Phase::Idle => "idle",
            Phase::Discovering => "discovering",
            Phase::Handshaking => "handshaking",
            Phase::Linked => "linked",
            Phase::Paused => "paused",
            Phase::Halted => "halted",
        }
        .to_string();

        // Recompute derived `status` field after every event, then make
        // sure subscribers are notified if it actually changed.
        let new_status = status_for(&self.state);
        if self.state.status != new_status {
            self.state.status = new_status;
            if !actions.contains(&Action::EmitState) {
                actions.push(Action::EmitState);
            }
        }

        // Catch-all: Ensure EmitState is present if any significant state changed.
        // We unconditionally add it for events that mutate state.
        if matches!(
            event,
            Event::ToggleOn
                | Event::ToggleOff
                | Event::BatteryChangedSelf { .. }
                | Event::BatteryChangedPeer { .. }
                | Event::PeerSeen { .. }
                | Event::PeerLost
                | Event::ManualUnpair
                | Event::UntrustedPeerSeen { .. }
                | Event::GhostTimeout
                | Event::SetTrustedPeer { .. }
                | Event::FrameReceivedClipboard { .. }
                | Event::LocalClipboardChange { .. }
        ) && !actions.contains(&Action::EmitState)
        {
            actions.push(Action::EmitState);
        }

        actions
    }

    #[must_use]
    pub fn is_peer_mismatch(&self, other_id: [u8; 32]) -> bool {
        // If we are already handshaking or linked with someone else
        if !self.state.peer_name.is_empty() && self.state.peer_id != other_id {
            // We only care about mismatches if we are NOT in Idle or Discovering
            return !matches!(self.phase, Phase::Idle | Phase::Discovering);
        }
        false
    }

    fn push_history(&mut self, item: HistoryItem) {
        // [FIX] Zero-Day: Lamport clocks reset to 0 when the daemon restarts, causing
        // new items from the Mac to be sorted to the BOTTOM of the Android's history.
        // Android Kotlin code only checks the FIRST item to update the OS clipboard,
        // so it silently ignored new copies.
        // By inserting at index 0 and NOT sorting by Lamport, we guarantee the
        // newest item is always at the top of the history.
        self.state.history.insert(0, item);

        if self.state.history.len() > HISTORY_SOFT_CAP {
            self.state.history.truncate(HISTORY_SOFT_CAP);
        }
    }

    fn phase_for_policy_ext(&self, fsm_next: Phase) -> Phase {
        use crate::state::Status;
        match status_for(&self.state) {
            Status::Critical => {
                // Critical battery: force Halted ONLY if we're in a
                // connected phase. Never override Discovering/Handshaking
                // — the FSM needs those to reconnect.
                match fsm_next {
                    Phase::Linked | Phase::Paused | Phase::Halted => Phase::Halted,
                    other => other,
                }
            }
            Status::Paused => {
                // If FSM wants to be Linked/Paused/Halted, we obey battery.
                // If it wants to be Discovering/Handshaking, we let it stay there
                // unless it's Critical.
                match fsm_next {
                    Phase::Linked | Phase::Paused | Phase::Halted => Phase::Paused,
                    other => other,
                }
            }
            Status::Syncing | Status::Inactive => {
                // Battery is healthy: upgrade Paused/Halted back to Linked.
                // NEVER promote Discovering/Handshaking to Linked — that
                // would trap the FSM with a dead session after PeerLost.
                match fsm_next {
                    Phase::Paused | Phase::Halted => Phase::Linked,
                    other => other,
                }
            }
        }
    }

    /// Logger helper for the daemon — wraps a manual `EmitLog` in a single
    /// place so the friendly text stays consistent with what the FSM emits.
    #[must_use]
    pub fn log(level_msg: LogEntry) -> Action {
        Action::EmitLog(level_msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::StubWallClock;
    use crate::events::LogLevel;
    use crate::state::Status;
    use fluxsync_proto::Kind;

    fn wall() -> StubWallClock {
        StubWallClock::new("14:32", 1_700_000_000_000)
    }

    fn boot() -> App {
        App::new(Config::default())
    }

    #[test]
    fn fresh_app_is_idle_inactive() {
        let app = boot();
        assert_eq!(app.phase, Phase::Idle);
        assert_eq!(app.state.status, Status::Inactive);
        assert!(!app.state.on);
    }

    #[test]
    fn toggle_on_marks_on_and_starts_discovery() {
        let mut app = boot();
        let actions = app.handle(Event::ToggleOn, &wall());
        assert!(app.state.on);
        assert_eq!(app.phase, Phase::Discovering);
        assert!(actions.iter().any(|a| matches!(a, Action::StartDiscovery)));
    }

    #[test]
    fn full_happy_path_to_linked() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy S21 Ultra".into(),
            },
            &wall(),
        );
        let _ = app.handle(Event::HandshakeOk, &wall());
        // After HandshakeOk, with both batteries healthy, status should be Syncing
        // and phase should be Linked.
        app.state.battery_level = 80;
        app.state.peer_battery = 70;
        let _ = app.handle(
            Event::BatteryChangedSelf {
                level: 80,
                charging: false,
            },
            &wall(),
        );
        assert_eq!(app.state.status, Status::Syncing);
        assert_eq!(app.phase, Phase::Linked);
        assert_eq!(app.state.peer_name, "Galaxy S21 Ultra");
    }

    #[test]
    fn fs043_zero_peer_id_is_a_mismatch_while_handshaking() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        assert_eq!(app.phase, Phase::Handshaking);
        // An all-zero peer_id must NOT be treated as a trusted sentinel.
        assert!(app.is_peer_mismatch([0u8; 32]));
        // A different real peer_id is still a mismatch.
        assert!(app.is_peer_mismatch([9u8; 32]));
        // The actual paired peer is not a mismatch.
        assert!(!app.is_peer_mismatch([7u8; 32]));
    }

    #[test]
    fn battery_drop_below_threshold_pauses_phase_and_status() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::BatteryChangedPeer {
                level: 80,
                charging: false,
            },
            &wall(),
        );
        // Now drop peer to below threshold.
        app.handle(
            Event::BatteryChangedPeer {
                level: 10,
                charging: false,
            },
            &wall(),
        );
        assert_eq!(app.state.status, Status::Paused);
        assert_eq!(app.phase, Phase::Paused);
    }

    #[test]
    fn critical_battery_halts_phase_and_status() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::BatteryChangedPeer {
                level: 4,
                charging: false,
            },
            &wall(),
        );
        assert_eq!(app.state.status, Status::Critical);
        assert_eq!(app.phase, Phase::Halted);
    }

    #[test]
    fn local_clipboard_change_pushes_history_and_emits_send_item() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::BatteryChangedPeer {
                level: 80,
                charging: false,
            },
            &wall(),
        );
        let actions = app.handle(
            Event::LocalClipboardChange {
                hash: [1; 32],
                kind: Kind::Url,
                preview: "https://github.com".into(),
                sensitive: false,
                lamport: 1,
            },
            &wall(),
        );
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SendItem { hash, .. } if hash == &[1u8; 32])));
        assert_eq!(app.state.history.len(), 1);
        assert_eq!(app.state.history[0].preview, "https://github.com");
        assert_eq!(app.state.history[0].time, "14:32");
    }

    #[test]
    fn fs046_manual_unpair_keeps_history() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::LocalClipboardChange {
                hash: [1; 32],
                kind: Kind::Url,
                preview: "https://github.com".into(),
                sensitive: false,
                lamport: 1,
            },
            &wall(),
        );
        assert_eq!(app.state.history.len(), 1);

        app.handle(Event::ManualUnpair, &wall());

        // Unpair disconnects the peer but must not wipe local history (FS-046).
        assert_eq!(app.state.history.len(), 1);
        assert_eq!(app.state.history[0].preview, "https://github.com");
        assert!(!app.state.on);
        assert_eq!(app.state.peer_id, [0u8; 32]);
        assert_eq!(app.state.trusted_peer_name, None);
    }

    #[test]
    fn fs046_repair_with_a_different_peer_clears_history() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Phone A".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::LocalClipboardChange {
                hash: [1; 32],
                kind: Kind::Text,
                preview: "MY_PASSWORD".into(),
                sensitive: false,
                lamport: 1,
            },
            &wall(),
        );
        assert_eq!(app.state.history.len(), 1);

        // Unpair keeps the history (FS-046).
        app.handle(Event::ManualUnpair, &wall());
        assert_eq!(app.state.history.len(), 1);

        // Re-pair with a DIFFERENT peer: the old secret must be gone, or it
        // would leak to the new peer on a BurstReplay.
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [0xB; 32],
                name: "Phone B".into(),
            },
            &wall(),
        );
        assert!(
            app.state.history.is_empty(),
            "different-peer re-pair leaked prior history: {:?}",
            app.state.history
        );
    }

    #[test]
    fn fs046_repair_with_the_same_peer_keeps_history() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Phone A".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::LocalClipboardChange {
                hash: [1; 32],
                kind: Kind::Url,
                preview: "https://github.com".into(),
                sensitive: false,
                lamport: 1,
            },
            &wall(),
        );
        assert_eq!(app.state.history.len(), 1);

        // Reconnect the SAME peer — history stays (FS-046 intent).
        app.handle(Event::ManualUnpair, &wall());
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Phone A".into(),
            },
            &wall(),
        );
        assert_eq!(app.state.history.len(), 1);
        assert_eq!(app.state.history[0].preview, "https://github.com");
    }

    #[test]
    fn sensitive_clipboard_does_not_persist_to_history() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::BatteryChangedPeer {
                level: 80,
                charging: false,
            },
            &wall(),
        );
        app.handle(
            Event::LocalClipboardChange {
                hash: [9; 32],
                kind: Kind::Text,
                preview: "sk_live_aaaaaaaaaaaaaaaaaaaaaaaa".into(),
                sensitive: true,
                lamport: 1,
            },
            &wall(),
        );
        assert!(app.state.history.is_empty());
    }

    #[test]
    fn duplicate_local_clipboard_suppresses_send_item() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::BatteryChangedPeer {
                level: 80,
                charging: false,
            },
            &wall(),
        );
        // First copy: emit send.
        let a1 = app.handle(
            Event::LocalClipboardChange {
                hash: [3; 32],
                kind: Kind::Text,
                preview: "x".into(),
                sensitive: false,
                lamport: 1,
            },
            &wall(),
        );
        assert!(a1.iter().any(|a| matches!(a, Action::SendItem { .. })));
        // Same hash again: suppressed.
        let a2 = app.handle(
            Event::LocalClipboardChange {
                hash: [3; 32],
                kind: Kind::Text,
                preview: "x".into(),
                sensitive: false,
                lamport: 2,
            },
            &wall(),
        );
        assert!(!a2.iter().any(|a| matches!(a, Action::SendItem { .. })));
    }

    #[test]
    fn frame_received_writes_clipboard_and_pushes_history() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::BatteryChangedPeer {
                level: 80,
                charging: false,
            },
            &wall(),
        );
        let actions = app.handle(
            Event::FrameReceivedClipboard {
                hash: [4; 32],
                kind: Kind::Text,
                preview: "Bonjour".into(),
                lamport: 5,
                sensitive: false,
            },
            &wall(),
        );
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::WriteClipboard { .. })));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::AckItem { hash } if hash == &[4u8; 32])));
        assert_eq!(app.state.history[0].preview, "Bonjour");
    }

    #[test]
    fn fs045_old_lamport_retransmit_is_still_accepted() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::BatteryChangedPeer {
                level: 80,
                charging: false,
            },
            &wall(),
        );
        // A first frame advances our Lamport clock far ahead.
        app.handle(
            Event::FrameReceivedClipboard {
                hash: [1; 32],
                kind: Kind::Text,
                preview: "recent".into(),
                lamport: 500,
                sensitive: false,
            },
            &wall(),
        );
        // A legitimate retransmit carrying an old Lamport stamp (peer
        // restarted and re-sent earlier history). It must still be
        // accepted — Noise nonces and content-hash dedup cover replay.
        let actions = app.handle(
            Event::FrameReceivedClipboard {
                hash: [2; 32],
                kind: Kind::Text,
                preview: "old retransmit".into(),
                lamport: 3,
                sensitive: false,
            },
            &wall(),
        );
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::WriteClipboard { .. })));
        assert!(app
            .state
            .history
            .iter()
            .any(|h| h.preview == "old retransmit"));
    }

    #[test]
    fn history_capped_at_soft_cap() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::BatteryChangedPeer {
                level: 80,
                charging: false,
            },
            &wall(),
        );
        // Push 60 distinct items.
        for i in 0..60u8 {
            app.handle(
                Event::FrameReceivedClipboard {
                    hash: [i; 32],
                    kind: Kind::Text,
                    preview: format!("item-{i}"),
                    lamport: u64::from(i),
                    sensitive: false,
                },
                &wall(),
            );
        }
        assert_eq!(app.state.history.len(), HISTORY_SOFT_CAP);
        // Most-recent at index 0.
        assert_eq!(app.state.history[0].preview, "item-59");
    }

    #[test]
    fn toggle_off_clears_phase_and_emits_state() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        let actions = app.handle(Event::ToggleOff, &wall());
        assert!(!app.state.on);
        assert_eq!(app.phase, Phase::Idle);
        assert_eq!(app.state.status, Status::Inactive);
        assert!(actions.iter().any(|a| matches!(a, Action::EmitState)));
    }

    #[test]
    fn handshake_timeout_emits_warn_log_and_falls_back() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        let actions = app.handle(Event::HandshakeTimeout, &wall());
        assert_eq!(app.phase, Phase::Discovering);
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::EmitLog(LogEntry {
                level: LogLevel::Warn,
                ..
            })
        )));
    }

    #[test]
    fn log_helper_constructs_emit_log_action() {
        let a = App::log(LogEntry::ok("hello"));
        assert_eq!(
            a,
            Action::EmitLog(LogEntry {
                level: LogLevel::Ok,
                msg: "hello".into()
            })
        );
    }
}
