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

    /// Drive the state machine with one event. Returns the side-effect
    /// commands the daemon must execute, in order.
    ///
    /// `wall` is `?Sized` so callers may pass either a concrete value
    /// (`&StubWallClock` in tests) or a trait object (`&dyn WallClock`
    /// in the daemon, which holds an `Arc<dyn WallClock + Send + Sync>`).
    pub fn handle<W: WallClock + ?Sized>(&mut self, event: Event, wall: &W) -> Vec<Action> {
        // Snapshot so we can detect any state mutation (not just `status`)
        // and notify subscribers. Without this, e.g. a `LocalClipboardChange`
        // that grew `history` but did not flip `status` would silently
        // skip the observer fan-out.
        let pre_snapshot = self.state.clone();

        // ── Pre-transition state mutations ──────────────────────────────
        // (everything that is "data the FSM expects to already be in state")
        let mut suppress_action = false;
        match &event {
            Event::ToggleOn => self.state.on = true,
            Event::ToggleOff => self.state.on = false,
            Event::PeerSeen { name, .. } => self.state.peer_name = name.clone(),
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
                self.clock.observe(*lamport);
                if !self.dedup.observe(*hash) {
                    suppress_action = true; // saw it from peer already, don't echo
                }
                if !sensitive {
                    self.push_history(HistoryItem {
                        kind: *kind,
                        preview: preview.clone(),
                        time: wall.hhmm(),
                    });
                }
            }
            Event::FrameReceivedClipboard {
                hash,
                kind,
                preview,
                lamport,
            } => {
                self.clock.observe(*lamport);
                if !self.dedup.observe(*hash) {
                    suppress_action = true; // duplicate, ack-only
                }
                self.push_history(HistoryItem {
                    kind: *kind,
                    preview: preview.clone(),
                    time: wall.hhmm(),
                });
            }
            _ => {}
        }

        // ── Run the pure transition ─────────────────────────────────────
        let (next, mut actions) = transition(self.phase, &event);

        // ── Battery-policy phase override (post-transition) ──────────────
        // status_for() is the single source of truth for `state.status`;
        // the FSM phase mirrors it for Linked / Paused / Halted but not for
        // Idle / Discovering / Handshaking, which are protocol-driven.
        self.phase = match next {
            Phase::Linked | Phase::Paused | Phase::Halted => self.phase_for_policy(),
            other => other,
        };

        // Recompute derived `status` field after every event, then make
        // sure subscribers are notified if it actually changed.
        let new_status = status_for(&self.state);
        if self.state.status != new_status {
            self.state.status = new_status;
            if !actions.contains(&Action::EmitState) {
                actions.push(Action::EmitState);
            }
        }

        if suppress_action {
            // Drop SendItem actions for items we already saw from the peer.
            actions.retain(|a| !matches!(a, Action::SendItem { .. }));
        }

        // Catch-all: anything that mutated `state` without producing an
        // explicit `EmitState` (e.g. a history append while phase was
        // Idle) still fans out so observers stay in sync.
        if pre_snapshot != self.state && !actions.contains(&Action::EmitState) {
            actions.push(Action::EmitState);
        }

        actions
    }

    fn push_history(&mut self, item: HistoryItem) {
        self.state.history.insert(0, item);
        if self.state.history.len() > HISTORY_SOFT_CAP {
            self.state.history.truncate(HISTORY_SOFT_CAP);
        }
    }

    fn phase_for_policy(&self) -> Phase {
        use crate::state::Status;
        match status_for(&self.state) {
            Status::Critical => Phase::Halted,
            Status::Paused => Phase::Paused,
            Status::Syncing | Status::Inactive => Phase::Linked,
        }
    }

    /// Logger helper for the daemon — wraps a manual `EmitLog` in a single
    /// place so the friendly text stays consistent with what the FSM emits.
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
