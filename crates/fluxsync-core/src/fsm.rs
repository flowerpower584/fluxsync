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

/// Build the friendly log line for an inbound clipboard frame. Text-like
/// kinds report a character count off the `preview`; images report a byte
/// size, since their `payload` is binary and has no meaningful char count.
fn received_label(kind: fluxsync_proto::Kind, payload: &[u8], preview: &str) -> String {
    match kind {
        fluxsync_proto::Kind::Image => {
            let kib = payload.len().div_ceil(1024);
            format!("Clipboard updated — image, {kib} KB from peer.")
        }
        _ => format!(
            "Clipboard updated — {} chars from peer.",
            preview.chars().count()
        ),
    }
}

/// Compute the next phase + action list for a `(phase, event)` pair.
#[must_use]
#[allow(clippy::too_many_lines)]
#[allow(clippy::match_same_arms)] // FSM table mirrors PROTOCOL.md line-for-line; keep one arm per pair.
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

        // Global: Manual unpair instantly drops the peer and goes to Idle.
        (_, E::ManualUnpair) => (
            P::Idle,
            vec![
                A::CloseSession,
                A::StopDiscovery,
                A::DropPeer,
                A::EmitState,
                A::EmitLog(LogEntry::info("Unpaired from peer.")),
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

        // Zero-Day Feature: Cryptographic Reset Detection
        // Handle globally to ensure we escape any stuck phase (Handshaking, etc)
        (_, E::UntrustedPeerSeen { .. }) => (
            P::Discovering,
            vec![
                A::DropPeer,
                A::EmitState,
                A::EmitLog(LogEntry::warn(
                    "Peer cryptographic mismatch detected. Unpairing.",
                )),
                A::StartDiscovery,
            ],
        ),

        // Ghost Timeout: 10 minutes elapsed without seeing the peer.
        // Rescues from stuck Discovery/Handshake. Does NOT affect Linked session.
        (P::Discovering | P::Handshaking, E::GhostTimeout) => (
            P::Discovering,
            vec![
                A::DropPeer,
                A::EmitState,
                A::EmitLog(LogEntry::warn(
                    "Reconnection timeout. Returning to scan mode.",
                )),
                A::StartDiscovery,
            ],
        ),

        // Handshaking → Linked on HandshakeOk.
        (P::Handshaking, E::HandshakeOk) => (
            P::Linked,
            vec![
                A::OpenSession,
                A::BurstReplay,
                A::SendBattery {
                    level: 100, // Placeholder; App will overwrite with real level immediately
                    charging: false,
                },
                A::EmitState,
                A::EmitLog(LogEntry::ok("Handshake complete. Link is live.")),
            ],
        ),

        // Handshaking → Discovering on timeout or peer lost.
        (P::Handshaking, E::HandshakeTimeout | E::PeerLost) => (
            P::Discovering,
            vec![
                A::EmitLog(LogEntry::warn(
                    "Handshake interrupted or timed out. Retrying.",
                )),
                A::StartDiscovery,
            ],
        ),

        // ❌ FAILLE #1 FIX: Handshaking + PeerSeen.
        // Logic in app.rs will have already checked if it's a mismatch.
        // If we reach here, it's either the SAME peer or we're allowing it.
        (P::Handshaking, E::PeerSeen { .. }) => (P::Handshaking, vec![]),

        // Linked: outbound clipboard.
        (
            P::Linked,
            E::LocalClipboardChange {
                hash,
                kind,
                payload,
                sensitive,
                ..
            },
        ) => (
            P::Linked,
            vec![A::SendItem {
                hash: *hash,
                kind: *kind,
                payload: payload.clone(),
                sensitive: *sensitive,
            }],
        ),

        // Linked: inbound clipboard.
        (
            P::Linked,
            E::FrameReceivedClipboard {
                hash,
                kind,
                payload,
                preview,
                ..
            },
        ) => (
            P::Linked,
            vec![
                A::WriteClipboard {
                    kind: *kind,
                    payload: payload.clone(),
                },
                A::AckItem { hash: *hash },
                A::EmitState,
                A::EmitLog(LogEntry::ok(received_label(*kind, payload, preview))),
            ],
        ),

        // Linked: peer name update (Hello exchange after handshake).
        (P::Linked, E::PeerSeen { .. }) => (
            P::Linked,
            vec![
                A::EmitState,
                A::EmitLog(LogEntry::ok("Peer identity confirmed.")),
            ],
        ),

        // Linked/Paused/Halted → Discovering on PeerLost.
        (P::Linked | P::Paused | P::Halted, E::PeerLost) => (
            P::Discovering,
            vec![
                A::CloseSession,
                A::EmitState,
                A::EmitLog(LogEntry::warn("Peer offline. Searching again.")),
                A::StartDiscovery,
            ],
        ),

        // Battery changes: always update state. In Linked phase, also sync to peer.
        (P::Linked, E::BatteryChangedSelf { level, charging }) => (
            P::Linked,
            vec![
                A::SendBattery {
                    level: *level,
                    charging: *charging,
                },
                A::EmitState,
            ],
        ),
        (phase, E::BatteryChangedSelf { .. } | E::BatteryChangedPeer { .. }) => {
            (phase, vec![A::EmitState])
        }
        // Peer platform learned from Hello — push it to the UI, no phase change.
        (phase, E::PeerPlatform { .. }) => (phase, vec![A::EmitState]),

        // DIR-P1-01: negotiated capability set learned from Hello — push it
        // to the UI, no phase change. Unknown caps never reach here (already
        // filtered by `negotiate_caps` before this event is raised).
        (phase, E::PeerCaps { .. }) => (phase, vec![A::EmitState]),

        // FluxMesh Phase 3: a non-primary mesh peer changed — re-emit State so
        // the daemon rebuilds the `peers` list. No phase change, single-peer
        // State untouched.
        (phase, E::MeshPeersChanged) => (phase, vec![A::EmitState]),

        // FluxMesh robustness: primary failover keeps the current phase
        // (Linked when the daemon emits it) and just re-projects State onto the
        // freshly-promoted peer. The identity rebind happens pre-transition in
        // `App::handle`; the FSM only needs to publish.
        (phase, E::PrimaryFailover { .. }) => (phase, vec![A::EmitState]),

        // Reconnect events.
        (P::Linked, E::Reconnect) => (P::Linked, vec![A::BurstReplay]),
        (P::Discovering, E::Reconnect) => (P::Discovering, vec![A::StartDiscovery]),
        (P::Handshaking, E::Reconnect) => (P::Handshaking, vec![]),

        // Network changes in other phases.
        (P::Linked, E::NetworkChanged) => (P::Linked, vec![]), // Handled by socket layer roaming
        (P::Handshaking, E::NetworkChanged) => (P::Discovering, vec![A::StartDiscovery]),

        // Inbound clipboard outside Linked: don't apply it, but still ack so
        // the sender stops retransmitting. Without this it hit the fallback
        // below and was dropped silently, causing an infinite resend loop.
        (phase, E::FrameReceivedClipboard { hash, .. }) => (
            phase,
            vec![
                A::AckItem { hash: *hash },
                A::EmitLog(LogEntry::warn(
                    "Clipboard frame received before link established — acked, not applied.",
                )),
            ],
        ),

        // Fallback for all other undefined transitions.
        (phase, event) => {
            // Only warn on events that should technically change phase but aren't handled.
            // Battery changes and clipboard events in Idle are common and don't need warnings.
            if !matches!(
                event,
                E::BatteryChangedSelf { .. } | E::BatteryChangedPeer { .. }
            ) {
                tracing::debug!("Undefined FSM transition: ({:?}, {:?})", phase, event);
            }
            (phase, vec![])
        }
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
            payload: "https://github.com".to_string().into_bytes(),
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
                payload: b"https://github.com".to_vec(),
                sensitive: false,
            }]
        );
    }

    #[test]
    fn linked_frame_received_writes_clipboard_and_acks() {
        let ev = Event::FrameReceivedClipboard {
            hash: [2; 32],
            kind: Kind::Text,
            payload: "Bonjour".to_string().into_bytes(),
            preview: "Bonjour".into(),
            lamport: 11,
            sensitive: false,
            resync: false,
        };
        let (p, a) = transition(Phase::Linked, &ev);
        assert_eq!(p, Phase::Linked);
        assert!(a.iter().any(|x| matches!(x, A::WriteClipboard { .. })));
        assert!(a
            .iter()
            .any(|x| matches!(x, A::AckItem { hash } if hash == &[2u8; 32])));
        assert!(a.contains(&A::EmitState));
    }

    /// FS-044: a clipboard frame arriving before the link is established
    /// (e.g. in Handshaking) must still be acked so the sender stops
    /// retransmitting. On `main` it hit the empty fallback and was dropped.
    #[test]
    fn non_linked_frame_received_still_acks() {
        let ev = Event::FrameReceivedClipboard {
            hash: [7; 32],
            kind: Kind::Text,
            payload: "early".to_string().into_bytes(),
            preview: "early".into(),
            lamport: 3,
            sensitive: false,
            resync: false,
        };
        let (p, a) = transition(Phase::Handshaking, &ev);
        assert_eq!(p, Phase::Handshaking, "phase must not change");
        assert!(
            a.iter()
                .any(|x| matches!(x, A::AckItem { hash } if hash == &[7u8; 32])),
            "frame must be acked even outside Linked"
        );
        assert!(
            !a.iter().any(|x| matches!(x, A::WriteClipboard { .. })),
            "clipboard must not be applied outside Linked"
        );
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
