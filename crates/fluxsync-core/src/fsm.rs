//! Pure FSM transition function.
//!
//! See `docs/PROTOCOL.md` §2 for the canonical state-transition table. The
//! function below mirrors that table line-for-line. It is deliberately
//! pure: takes the current `Phase` + an `Event`, returns the next `Phase` +
//! a list of `Action`s. No state mutation here — the caller (`App`) owns
//! state and applies actions.
//!
//! Unmodelled (Phase, Event) pairs are no-ops returning the same phase and
//! an empty action list (with a `DEBUG`-level log via the caller, if any).

use crate::events::{Action, Event, LogEntry};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Discovering,
    Handshaking,
    Linked,
    Paused,
    Halted,
}

/// Compute the next phase + action list for a `(phase, event)` pair.
#[must_use]
pub fn transition(phase: Phase, event: &Event) -> (Phase, Vec<Action>) {
    use Action as A;
    use Event as E;
    use Phase as P;

    match (phase, event) {
        // Global: ToggleOff cleanly returns to Idle from any phase.
        (_, E::ToggleOff) => (
            P::Idle,
            vec![
                A::CloseSession,
                A::StopDiscovery,
                A::EmitState,
                A::EmitLog(LogEntry::info("Sync turned off.")),
            ],
        ),

        // Idle → Discovering on ToggleOn.
        (P::Idle, E::ToggleOn) => (
            P::Discovering,
            vec![
                A::StartDiscovery,
                A::EmitState,
                A::EmitLog(LogEntry::info("Sync turned on. Looking for peers.")),
            ],
        ),

        // Discovering → Handshaking on PeerSeen.
        (P::Discovering, E::PeerSeen { peer_id, name }) => (
            P::Handshaking,
            vec![
                A::SendHandshake { peer_id: *peer_id },
                A::EmitLog(LogEntry::info(format!("Discovered peer \"{name}\"."))),
            ],
        ),

        // Discovering on NetworkChanged: keep phase, restart discovery.
        (P::Discovering, E::NetworkChanged) => (
            P::Discovering,
            vec![
                A::StopDiscovery,
                A::StartDiscovery,
                A::EmitLog(LogEntry::warn("Network changed. Searching again.")),
            ],
        ),

        // Handshaking → Linked on HandshakeOk.
        (P::Handshaking, E::HandshakeOk) => (
            P::Linked,
            vec![
                A::OpenSession,
                A::BurstReplay,
                A::EmitState,
                A::EmitLog(LogEntry::ok("Handshake complete. Link is live.")),
            ],
        ),

        // Handshaking → Discovering on timeout.
        (P::Handshaking, E::HandshakeTimeout) => (
            P::Discovering,
            vec![
                A::EmitLog(LogEntry::warn("Handshake timed out. Retrying.")),
                A::StartDiscovery,
            ],
        ),

        // Linked: outbound clipboard.
        (
            P::Linked,
            E::LocalClipboardChange {
                hash,
                kind,
                preview,
                sensitive,
                ..
            },
        ) => (
            P::Linked,
            vec![A::SendItem {
                hash: *hash,
                kind: *kind,
                preview: preview.clone(),
                sensitive: *sensitive,
            }],
        ),

        // Linked: inbound clipboard.
        (
            P::Linked,
            E::FrameReceivedClipboard {
                hash,
                kind: _,
                preview,
                ..
            },
        ) => (
            P::Linked,
            vec![
                A::WriteClipboard {
                    preview: preview.clone(),
                },
                A::AckItem { hash: *hash },
                A::EmitState,
                A::EmitLog(LogEntry::ok(format!(
                    "Clipboard updated — {} chars from peer.",
                    preview.chars().count()
                ))),
            ],
        ),

        // Linked → Discovering on PeerLost.
        (P::Linked, E::PeerLost) => (
            P::Discovering,
            vec![
                A::CloseSession,
                A::EmitState,
                A::EmitLog(LogEntry::warn("Peer offline. Searching again.")),
                A::StartDiscovery,
            ],
        ),

        // Linked + battery change: handled at App layer (status recompute);
        // the transition stays in Linked but the App may flip self.phase to
        // Paused or Halted using `transition` again with a synthesized event.
        (P::Linked, E::BatteryChangedSelf { .. } | E::BatteryChangedPeer { .. }) => {
            (P::Linked, vec![A::EmitState])
        }

        // Paused: a fresh battery sample may bring us back to Linked.
        // The App layer decides; the FSM only acknowledges.
        (P::Paused, E::BatteryChangedSelf { .. } | E::BatteryChangedPeer { .. }) => {
            (P::Paused, vec![A::EmitState])
        }

        // Halted: same — App decides when to come back.
        (P::Halted, E::BatteryChangedSelf { .. } | E::BatteryChangedPeer { .. }) => {
            (P::Halted, vec![A::EmitState])
        }

        // Reconnect after offline → burst replay (handled in Linked).
        (P::Linked, E::Reconnect) => (P::Linked, vec![A::BurstReplay]),

        // Anything else: no-op. The App emits a DEBUG log if it wants.
        _ => (phase, vec![]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Action as A;
    use crate::events::LogLevel;
    use fluxsync_proto::Kind;

    fn peer_seen() -> Event {
        Event::PeerSeen {
            peer_id: [9; 32],
            name: "Galaxy S21 Ultra".into(),
        }
    }

    #[test]
    fn idle_toggle_on_starts_discovery() {
        let (p, a) = transition(Phase::Idle, &Event::ToggleOn);
        assert_eq!(p, Phase::Discovering);
        assert!(a.contains(&A::StartDiscovery));
        assert!(a.contains(&A::EmitState));
    }

    #[test]
    fn toggle_off_from_any_phase_returns_to_idle() {
        for phase in [
            Phase::Idle,
            Phase::Discovering,
            Phase::Handshaking,
            Phase::Linked,
            Phase::Paused,
            Phase::Halted,
        ] {
            let (p, a) = transition(phase, &Event::ToggleOff);
            assert_eq!(p, Phase::Idle, "from {phase:?}");
            assert!(a.contains(&A::CloseSession));
            assert!(a.contains(&A::StopDiscovery));
            assert!(a.contains(&A::EmitState));
        }
    }

    #[test]
    fn discovering_peer_seen_sends_handshake() {
        let (p, a) = transition(Phase::Discovering, &peer_seen());
        assert_eq!(p, Phase::Handshaking);
        assert!(a.iter().any(|x| matches!(x, A::SendHandshake { .. })));
    }

    #[test]
    fn discovering_network_changed_restarts_discovery_in_place() {
        let (p, a) = transition(Phase::Discovering, &Event::NetworkChanged);
        assert_eq!(p, Phase::Discovering);
        assert!(a.contains(&A::StopDiscovery));
        assert!(a.contains(&A::StartDiscovery));
    }

    #[test]
    fn handshaking_ok_advances_to_linked_with_burst_replay() {
        let (p, a) = transition(Phase::Handshaking, &Event::HandshakeOk);
        assert_eq!(p, Phase::Linked);
        assert!(a.contains(&A::OpenSession));
        assert!(a.contains(&A::BurstReplay));
        assert!(a.iter().any(|x| matches!(
            x,
            A::EmitLog(super::LogEntry {
                level: LogLevel::Ok,
                ..
            })
        )));
    }

    #[test]
    fn handshaking_timeout_falls_back_to_discovering() {
        let (p, a) = transition(Phase::Handshaking, &Event::HandshakeTimeout);
        assert_eq!(p, Phase::Discovering);
        assert!(a.contains(&A::StartDiscovery));
    }

    #[test]
    fn linked_local_clipboard_emits_send_item() {
        let ev = Event::LocalClipboardChange {
            hash: [1; 32],
            kind: Kind::Url,
            preview: "https://github.com".into(),
            sensitive: false,
            lamport: 7,
        };
        let (p, a) = transition(Phase::Linked, &ev);
        assert_eq!(p, Phase::Linked);
        assert_eq!(
            a,
            vec![A::SendItem {
                hash: [1; 32],
                kind: Kind::Url,
                preview: "https://github.com".into(),
                sensitive: false,
            }]
        );
    }

    #[test]
    fn linked_frame_received_writes_clipboard_and_acks() {
        let ev = Event::FrameReceivedClipboard {
            hash: [2; 32],
            kind: Kind::Text,
            preview: "Bonjour".into(),
            lamport: 11,
        };
        let (p, a) = transition(Phase::Linked, &ev);
        assert_eq!(p, Phase::Linked);
        assert!(a.iter().any(|x| matches!(x, A::WriteClipboard { .. })));
        assert!(a
            .iter()
            .any(|x| matches!(x, A::AckItem { hash } if hash == &[2u8; 32])));
        assert!(a.contains(&A::EmitState));
    }

    #[test]
    fn linked_peer_lost_returns_to_discovering() {
        let (p, a) = transition(Phase::Linked, &Event::PeerLost);
        assert_eq!(p, Phase::Discovering);
        assert!(a.contains(&A::CloseSession));
        assert!(a.contains(&A::StartDiscovery));
    }

    #[test]
    fn linked_battery_change_emits_state() {
        let (p, a) = transition(
            Phase::Linked,
            &Event::BatteryChangedPeer {
                level: 50,
                charging: false,
            },
        );
        assert_eq!(p, Phase::Linked);
        assert!(a.contains(&A::EmitState));
    }

    #[test]
    fn paused_battery_change_stays_paused_emits_state() {
        let (p, a) = transition(
            Phase::Paused,
            &Event::BatteryChangedSelf {
                level: 80,
                charging: true,
            },
        );
        assert_eq!(p, Phase::Paused);
        assert!(a.contains(&A::EmitState));
    }

    #[test]
    fn halted_battery_change_stays_halted_emits_state() {
        let (p, a) = transition(
            Phase::Halted,
            &Event::BatteryChangedPeer {
                level: 6,
                charging: false,
            },
        );
        assert_eq!(p, Phase::Halted);
        assert!(a.contains(&A::EmitState));
    }

    #[test]
    fn reconnect_in_linked_triggers_burst_replay() {
        let (p, a) = transition(Phase::Linked, &Event::Reconnect);
        assert_eq!(p, Phase::Linked);
        assert!(a.contains(&A::BurstReplay));
    }

    #[test]
    fn unknown_pair_is_noop() {
        let (p, a) = transition(Phase::Idle, &Event::HandshakeOk);
        assert_eq!(p, Phase::Idle);
        assert!(a.is_empty());
    }
}
