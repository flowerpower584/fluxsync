//! Pair Connectivity Tests — 20 real-world scenarios between Peer A and Peer B.
//!
//! These tests operate at the FSM / App level (pure logic, no network).
//! Each test simulates the EXACT sequence of events that would happen
//! between a Mac (Peer A) and an Android phone (Peer B) in a real
//! session. Every test that was missing is a bug that could ship.
//!
//! The bug that triggered this suite: User puts phone offline while
//! linked → Mac still says "linked". User brings phone back online →
//! phone says "searching" but Mac still says "linked". Dead session.

use fluxsync_core::events::{Action, Event, LogEntry};
use fluxsync_core::fsm::Phase;
use fluxsync_core::state::{Config, Status};
use fluxsync_core::*;
use fluxsync_proto::Kind;

// ── Helpers ─────────────────────────────────────────────────────────

fn wall() -> StubWallClock {
    StubWallClock::new("14:32", 1_700_000_000_000)
}

const PEER_ID_B: [u8; 32] = [0xBB; 32];
const PEER_ID_A: [u8; 32] = [0xAA; 32];

/// Create a fresh App simulating one side of the pair.
fn make_app(name: &str) -> App {
    App::new(Config {
        peer_name_self: name.into(),
        charge_override: true,
        version: "0.4.2-test".into(),
        build_id: "test".into(),
        cipher: "chacha20-poly1305".into(),
        firewall: fluxsync_core::FirewallPolicy::default(),
    })
}

/// Drive an App from Idle → Linked in one shot (happy path).
fn link_up(app: &mut App, peer_id: [u8; 32], peer_name: &str) {
    app.handle(Event::ToggleOn, &wall());
    app.handle(
        Event::PeerSeen {
            peer_id,
            name: peer_name.into(),
        },
        &wall(),
    );
    app.handle(Event::HandshakeOk, &wall());
    // Set healthy batteries so we don't get Paused/Halted.
    app.handle(
        Event::BatteryChangedSelf {
            level: 80,
            charging: false,
        },
        &wall(),
    );
    app.handle(
        Event::BatteryChangedPeer {
            level: 75,
            charging: false,
        },
        &wall(),
    );
    assert_eq!(app.phase, Phase::Linked);
    assert_eq!(app.snapshot().status, Status::Syncing);
}

/// Simulate a clean link-up between two apps (both sides).
fn link_pair() -> (App, App) {
    let mut a = make_app("MacBook Pro");
    let mut b = make_app("Galaxy S21");
    link_up(&mut a, PEER_ID_B, "Galaxy S21");
    link_up(&mut b, PEER_ID_A, "MacBook Pro");
    (a, b)
}

fn has_action(actions: &[Action], f: impl Fn(&Action) -> bool) -> bool {
    actions.iter().any(f)
}

// =============================================================================
// CATEGORY 1: OFFLINE / ONLINE DETECTION
// =============================================================================

/// TEST 01: Peer B goes offline — Peer A should detect via PeerLost
/// and transition from Linked → Discovering.
#[test]
fn test_01_peer_b_goes_offline_a_detects() {
    let (mut a, _b) = link_pair();
    assert_eq!(a.phase, Phase::Linked);

    // B disappears. The heartbeat loop eventually fires PeerLost on A.
    let actions = a.handle(Event::PeerLost, &wall());
    assert_eq!(a.phase, Phase::Discovering);
    assert!(has_action(&actions, |a| matches!(a, Action::CloseSession)));
    assert!(has_action(&actions, |a| matches!(
        a,
        Action::StartDiscovery
    )));
    assert!(has_action(&actions, |a| {
        matches!(a, Action::EmitLog(LogEntry { msg, .. }) if msg.contains("Peer offline"))
    }));
}

/// TEST 02: THE EXACT BUG — Peer B goes offline and comes back.
/// After PeerLost on A, a fresh PeerSeen should start a NEW handshake,
/// not stay in Linked with a dead session.
#[test]
fn test_02_peer_b_offline_then_online_reconnects() {
    let (mut a, _b) = link_pair();

    // B disappears.
    a.handle(Event::PeerLost, &wall());
    assert_eq!(a.phase, Phase::Discovering);

    // B comes back — mDNS fires PeerSeen again.
    let actions = a.handle(
        Event::PeerSeen {
            peer_id: PEER_ID_B,
            name: "Galaxy S21".into(),
        },
        &wall(),
    );
    assert_eq!(a.phase, Phase::Handshaking);
    assert!(has_action(&actions, |a| {
        matches!(a, Action::SendHandshake { .. })
    }));
}

/// TEST 03: THE EXACT BUG (other side) — Peer A never fires PeerLost.
/// If A is still in Linked when B re-discovers and sends PeerSeen,
/// A must handle it gracefully (stay Linked, emit state update).
#[test]
fn test_03_peer_b_rediscovered_while_a_still_linked() {
    let (mut a, _b) = link_pair();
    assert_eq!(a.phase, Phase::Linked);

    // B briefly disappears but A's heartbeat hasn't fired PeerLost yet.
    // B comes back and mDNS fires PeerSeen on A while A is still Linked.
    let actions = a.handle(
        Event::PeerSeen {
            peer_id: PEER_ID_B,
            name: "Galaxy S21".into(),
        },
        &wall(),
    );

    // According to fsm.rs line 183-188: (Linked, PeerSeen) → stay Linked, EmitState.
    assert_eq!(a.phase, Phase::Linked);
    assert!(has_action(&actions, |a| matches!(a, Action::EmitState)));
}

/// TEST 04: Both peers go offline simultaneously. Both should end up
/// in Discovering after PeerLost.
#[test]
fn test_04_both_peers_go_offline_simultaneously() {
    let (mut a, mut b) = link_pair();

    a.handle(Event::PeerLost, &wall());
    b.handle(Event::PeerLost, &wall());

    assert_eq!(a.phase, Phase::Discovering);
    assert_eq!(b.phase, Phase::Discovering);

    // Both come back — both should try to handshake.
    a.handle(
        Event::PeerSeen {
            peer_id: PEER_ID_B,
            name: "Galaxy S21".into(),
        },
        &wall(),
    );
    b.handle(
        Event::PeerSeen {
            peer_id: PEER_ID_A,
            name: "MacBook Pro".into(),
        },
        &wall(),
    );
    assert_eq!(a.phase, Phase::Handshaking);
    assert_eq!(b.phase, Phase::Handshaking);

    // Both complete handshake.
    a.handle(Event::HandshakeOk, &wall());
    b.handle(Event::HandshakeOk, &wall());
    assert_eq!(a.phase, Phase::Linked);
    assert_eq!(b.phase, Phase::Linked);
}

/// TEST 05: Rapid disconnect/reconnect cycle — 5 times in a row.
/// The FSM must survive rapid PeerLost → PeerSeen → HandshakeOk loops.
#[test]
fn test_05_rapid_disconnect_reconnect_5x() {
    let (mut a, _b) = link_pair();

    for round in 0..5 {
        // Drop.
        a.handle(Event::PeerLost, &wall());
        assert_eq!(a.phase, Phase::Discovering, "round {round} after PeerLost");

        // Rediscover.
        a.handle(
            Event::PeerSeen {
                peer_id: PEER_ID_B,
                name: "Galaxy S21".into(),
            },
            &wall(),
        );
        assert_eq!(a.phase, Phase::Handshaking, "round {round} after PeerSeen");

        // Handshake completes.
        a.handle(Event::HandshakeOk, &wall());
        // Re-set batteries so policy doesn't pause.
        a.handle(
            Event::BatteryChangedSelf {
                level: 80,
                charging: false,
            },
            &wall(),
        );
        a.handle(
            Event::BatteryChangedPeer {
                level: 75,
                charging: false,
            },
            &wall(),
        );
        assert_eq!(a.phase, Phase::Linked, "round {round} after HandshakeOk");
    }
}

// =============================================================================
// CATEGORY 2: HANDSHAKE EDGE CASES
// =============================================================================

/// TEST 06: Handshake timeout during reconnect. A was Linked, B went
/// offline, A saw PeerSeen, started handshake, but handshake times out.
/// A should fall back to Discovering (not Idle or Linked with dead session).
#[test]
fn test_06_handshake_timeout_during_reconnect() {
    let (mut a, _b) = link_pair();

    a.handle(Event::PeerLost, &wall());
    a.handle(
        Event::PeerSeen {
            peer_id: PEER_ID_B,
            name: "Galaxy S21".into(),
        },
        &wall(),
    );
    assert_eq!(a.phase, Phase::Handshaking);

    // Handshake times out.
    let actions = a.handle(Event::HandshakeTimeout, &wall());
    assert_eq!(a.phase, Phase::Discovering);
    assert!(has_action(&actions, |a| {
        matches!(a, Action::StartDiscovery)
    }));
    // Must NOT be Idle — we're still trying to reconnect.
    assert_ne!(a.phase, Phase::Idle);
}

/// TEST 07: PeerLost during handshake. We see the peer, start
/// handshaking, but the peer vanishes before completing.
#[test]
fn test_07_peer_lost_during_handshake() {
    let mut a = make_app("MacBook Pro");
    a.handle(Event::ToggleOn, &wall());
    a.handle(
        Event::PeerSeen {
            peer_id: PEER_ID_B,
            name: "Galaxy S21".into(),
        },
        &wall(),
    );
    assert_eq!(a.phase, Phase::Handshaking);

    let actions = a.handle(Event::PeerLost, &wall());
    assert_eq!(a.phase, Phase::Discovering);
    assert!(has_action(&actions, |a| {
        matches!(a, Action::StartDiscovery)
    }));
}

/// TEST 08: Double HandshakeOk — if the handshake fires twice
/// (race condition in mDNS), the FSM must not crash or duplicate sessions.
#[test]
fn test_08_double_handshake_ok_ignored() {
    let mut a = make_app("MacBook Pro");
    a.handle(Event::ToggleOn, &wall());
    a.handle(
        Event::PeerSeen {
            peer_id: PEER_ID_B,
            name: "Galaxy S21".into(),
        },
        &wall(),
    );

    // First HandshakeOk → Linked.
    let actions1 = a.handle(Event::HandshakeOk, &wall());
    assert_eq!(a.phase, Phase::Linked);
    assert!(has_action(&actions1, |a| matches!(a, Action::OpenSession)));

    // Second HandshakeOk → no-op (already Linked).
    let actions2 = a.handle(Event::HandshakeOk, &wall());
    assert_eq!(a.phase, Phase::Linked);
    // The fallthrough `_ => (phase, vec![])` in fsm.rs should fire.
    assert!(actions2.is_empty() || !has_action(&actions2, |a| matches!(a, Action::OpenSession)));
}

/// TEST 09: PeerSeen with a DIFFERENT peer_id while linked to the
/// first peer. The FSM should stay Linked with the current peer.
#[test]
fn test_09_different_peer_seen_while_linked() {
    let (mut a, _b) = link_pair();

    let intruder_id = [0xCC; 32];
    let actions = a.handle(
        Event::PeerSeen {
            peer_id: intruder_id,
            name: "Unknown Device".into(),
        },
        &wall(),
    );
    // The FSM now (v0.5.0-hardened) ignores PeerSeen from a different ID
    // while Linked, to prevent session hijacking/spoofing.
    assert_eq!(a.phase, Phase::Linked);
    assert!(actions.is_empty());
    // Name must NOT update.
    assert_eq!(a.snapshot().peer_name, "Galaxy S21");
}

/// TEST 10: Ghost timeout — stuck in Discovering for 10 minutes
/// with a known peer that never reconnects. Should drop the peer.
#[test]
fn test_10_ghost_timeout_drops_stale_peer() {
    let mut a = make_app("MacBook Pro");
    a.handle(Event::ToggleOn, &wall());
    a.handle(
        Event::PeerSeen {
            peer_id: PEER_ID_B,
            name: "Galaxy S21".into(),
        },
        &wall(),
    );
    a.handle(Event::HandshakeOk, &wall());
    // Now linked. Peer goes offline.
    a.handle(Event::PeerLost, &wall());
    assert_eq!(a.phase, Phase::Discovering);

    // 10 minutes pass without reconnection.
    let actions = a.handle(Event::GhostTimeout, &wall());
    assert_eq!(a.phase, Phase::Discovering);
    assert!(has_action(&actions, |a| matches!(a, Action::DropPeer)));
    // Peer name should be cleared.
    assert!(a.snapshot().peer_name.is_empty());
}

// =============================================================================
// CATEGORY 3: TOGGLE ON/OFF DURING SESSIONS
// =============================================================================

/// TEST 11: ToggleOff while linked should cleanly close everything.
#[test]
fn test_11_toggle_off_while_linked_closes_cleanly() {
    let (mut a, _b) = link_pair();

    let actions = a.handle(Event::ToggleOff, &wall());
    assert_eq!(a.phase, Phase::Idle);
    assert!(!a.snapshot().on);
    assert!(has_action(&actions, |a| matches!(a, Action::CloseSession)));
    assert!(has_action(&actions, |a| matches!(a, Action::StopDiscovery)));
}

/// TEST 12: ToggleOff then ToggleOn — full restart should go through
/// Idle → Discovering cleanly.
#[test]
fn test_12_toggle_off_then_on_restarts_cleanly() {
    let (mut a, _b) = link_pair();

    a.handle(Event::ToggleOff, &wall());
    assert_eq!(a.phase, Phase::Idle);

    let actions = a.handle(Event::ToggleOn, &wall());
    assert_eq!(a.phase, Phase::Discovering);
    assert!(has_action(&actions, |a| {
        matches!(a, Action::StartDiscovery)
    }));
}

/// TEST 13: ToggleOff while handshaking — should NOT leave a dangling
/// handshake state.
#[test]
fn test_13_toggle_off_during_handshake() {
    let mut a = make_app("MacBook Pro");
    a.handle(Event::ToggleOn, &wall());
    a.handle(
        Event::PeerSeen {
            peer_id: PEER_ID_B,
            name: "Galaxy S21".into(),
        },
        &wall(),
    );
    assert_eq!(a.phase, Phase::Handshaking);

    let actions = a.handle(Event::ToggleOff, &wall());
    assert_eq!(a.phase, Phase::Idle);
    assert!(has_action(&actions, |a| matches!(a, Action::CloseSession)));
}

/// TEST 14: Rapid ToggleOn/Off — 10 times. The FSM must not leak state.
#[test]
fn test_14_rapid_toggle_10x() {
    let mut a = make_app("MacBook Pro");
    for i in 0..10 {
        a.handle(Event::ToggleOn, &wall());
        assert!(a.snapshot().on, "round {i}");
        assert_eq!(a.phase, Phase::Discovering, "round {i}");

        a.handle(Event::ToggleOff, &wall());
        assert!(!a.snapshot().on, "round {i}");
        assert_eq!(a.phase, Phase::Idle, "round {i}");
    }
}

// =============================================================================
// CATEGORY 4: BATTERY POLICY DURING CONNECTIVITY CHANGES
// =============================================================================

/// TEST 15: Peer battery drops to critical WHILE linked — should
/// transition to Halted, not disconnect.
#[test]
fn test_15_peer_battery_critical_while_linked() {
    let (mut a, _b) = link_pair();

    a.handle(
        Event::BatteryChangedPeer {
            level: 4,
            charging: false,
        },
        &wall(),
    );
    assert_eq!(a.phase, Phase::Halted);
    assert_eq!(a.snapshot().status, Status::Critical);
    // Important: NOT Discovering. We don't drop the link, we halt it.
    assert_ne!(a.phase, Phase::Discovering);
}

/// TEST 16: Peer battery recovers from critical — should resume Linked.
#[test]
fn test_16_peer_battery_recovers_from_critical() {
    let (mut a, _b) = link_pair();

    // Drop to critical.
    a.handle(
        Event::BatteryChangedPeer {
            level: 3,
            charging: false,
        },
        &wall(),
    );
    assert_eq!(a.phase, Phase::Halted);

    // Battery recovers.
    a.handle(
        Event::BatteryChangedPeer {
            level: 50,
            charging: false,
        },
        &wall(),
    );
    assert_eq!(a.phase, Phase::Linked);
    assert_eq!(a.snapshot().status, Status::Syncing);
}

/// TEST 17: Self battery drops below threshold while Linked — should Pause.
#[test]
fn test_17_self_battery_drops_below_threshold_pauses() {
    let (mut a, _b) = link_pair();

    a.handle(
        Event::BatteryChangedSelf {
            level: 10,
            charging: false,
        },
        &wall(),
    );
    assert_eq!(a.phase, Phase::Paused);
    assert_eq!(a.snapshot().status, Status::Paused);
}

/// TEST 18: PeerLost while battery is critical — should go to Discovering,
/// NOT stay in Halted with a dead session.
#[test]
fn test_18_peer_lost_while_halted() {
    let (mut a, _b) = link_pair();

    // Battery critical → Halted.
    a.handle(
        Event::BatteryChangedPeer {
            level: 3,
            charging: false,
        },
        &wall(),
    );
    assert_eq!(a.phase, Phase::Halted);

    // Now the peer actually disconnects.
    let actions = a.handle(Event::PeerLost, &wall());
    // PeerLost resets peer_battery to 100, which should un-halt.
    // FSM says (Linked|Paused|Halted → Discovering on PeerLost)
    // But policy recalculates with peer_battery=100, so we should be Discovering.
    assert_eq!(a.phase, Phase::Discovering);
    assert!(has_action(&actions, |a| matches!(a, Action::CloseSession)));
}

// =============================================================================
// CATEGORY 5: DATA INTEGRITY DURING CONNECTIVITY CHANGES
// =============================================================================

/// TEST 19: Clipboard data sent while peer is offline — the send action
/// should still fire (the transport layer handles the actual failure).
/// The FSM doesn't know about transport failures.
#[test]
fn test_19_clipboard_push_while_linked_fires_send() {
    let (mut a, _b) = link_pair();

    let actions = a.handle(
        Event::LocalClipboardChange {
            hash: [0x42; 32],
            kind: Kind::Text,
            payload: "hello from mac".to_string().into_bytes(),
            preview: "hello from mac".into(),
            sensitive: false,
            lamport: 1,
        },
        &wall(),
    );
    assert!(has_action(&actions, |a| matches!(
        a,
        Action::SendItem { .. }
    )));
    assert_eq!(a.snapshot().history[0].preview, "hello from mac");
}

/// TEST 20: Full end-to-end scenario simulating the EXACT user bug.
///
/// Timeline:
///   1. A and B are linked (happy path)
///   2. B goes offline (airplane mode)
///   3. A still thinks it's linked (heartbeat hasn't fired yet)
///   4. A sends clipboard data — should succeed at FSM level
///   5. Eventually A fires PeerLost → Discovering
///   6. B comes back online → PeerSeen on A
///   7. Handshake completes → Both Linked again
///   8. B sends clipboard data → A receives it
///
/// This is the EXACT flow that was broken.
#[test]
#[allow(clippy::too_many_lines)]
fn test_20_full_offline_online_cycle_end_to_end() {
    let (mut a, mut b) = link_pair();
    assert_eq!(a.phase, Phase::Linked);
    assert_eq!(b.phase, Phase::Linked);

    // ── Step 1: B goes into airplane mode ──
    // On B's side, the daemon stops and restarts later.
    // Nothing happens on A yet (heartbeat hasn't fired).

    // ── Step 2: A sends clipboard while B is gone ──
    // This should succeed at FSM level (transport will fail silently).
    let actions = a.handle(
        Event::LocalClipboardChange {
            hash: [0x01; 32],
            kind: Kind::Url,
            payload: "https://github.com/fluxsync".to_string().into_bytes(),
            preview: "https://github.com/fluxsync".into(),
            sensitive: false,
            lamport: 1,
        },
        &wall(),
    );
    assert!(has_action(&actions, |a| matches!(
        a,
        Action::SendItem { .. }
    )));
    assert_eq!(a.phase, Phase::Linked); // Still linked (doesn't know B is gone)

    // ── Step 3: A's heartbeat fires PeerLost ──
    a.handle(Event::PeerLost, &wall());
    assert_eq!(a.phase, Phase::Discovering);
    assert_eq!(a.snapshot().peer_name, "Galaxy S21"); // Name preserved for reconnection

    // ── Step 4: B comes back online ──
    // B's daemon restarts fresh.
    b = make_app("Galaxy S21");
    b.handle(Event::ToggleOn, &wall());
    assert_eq!(b.phase, Phase::Discovering);

    // ── Step 5: mDNS fires PeerSeen on both sides ──
    a.handle(
        Event::PeerSeen {
            peer_id: PEER_ID_B,
            name: "Galaxy S21".into(),
        },
        &wall(),
    );
    b.handle(
        Event::PeerSeen {
            peer_id: PEER_ID_A,
            name: "MacBook Pro".into(),
        },
        &wall(),
    );
    assert_eq!(a.phase, Phase::Handshaking);
    assert_eq!(b.phase, Phase::Handshaking);

    // ── Step 6: Handshake completes ──
    a.handle(Event::HandshakeOk, &wall());
    b.handle(Event::HandshakeOk, &wall());

    // Re-sync battery info.
    a.handle(
        Event::BatteryChangedSelf {
            level: 80,
            charging: false,
        },
        &wall(),
    );
    a.handle(
        Event::BatteryChangedPeer {
            level: 75,
            charging: false,
        },
        &wall(),
    );
    b.handle(
        Event::BatteryChangedSelf {
            level: 75,
            charging: false,
        },
        &wall(),
    );
    b.handle(
        Event::BatteryChangedPeer {
            level: 80,
            charging: false,
        },
        &wall(),
    );

    assert_eq!(a.phase, Phase::Linked);
    assert_eq!(b.phase, Phase::Linked);
    assert_eq!(a.snapshot().status, Status::Syncing);
    assert_eq!(b.snapshot().status, Status::Syncing);

    // ── Step 7: B sends clipboard data → A receives it ──
    let b_actions = b.handle(
        Event::LocalClipboardChange {
            hash: [0x02; 32],
            kind: Kind::Text,
            payload: "from android".to_string().into_bytes(),
            preview: "from android".into(),
            sensitive: false,
            lamport: 2,
        },
        &wall(),
    );
    assert!(has_action(&b_actions, |a| matches!(
        a,
        Action::SendItem { .. }
    )));

    let a_actions = a.handle(
        Event::FrameReceivedClipboard {
            hash: [0x02; 32],
            kind: Kind::Text,
            payload: "from android".to_string().into_bytes(),
            preview: "from android".into(),
            lamport: 2,
            sensitive: false,
        },
        &wall(),
    );
    assert!(has_action(&a_actions, |a| {
        matches!(a, Action::WriteClipboard { payload, .. } if payload == b"from android")
    }));
    assert_eq!(a.snapshot().history[0].preview, "from android");
}
