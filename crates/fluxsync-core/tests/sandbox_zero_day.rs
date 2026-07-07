use fluxsync_core::app::App;
use fluxsync_core::clock::StubWallClock;
use fluxsync_core::events::{Action, Event};
use fluxsync_core::fsm::Phase;
use fluxsync_core::state::Config;

// ──────────────────────────────────────────────────────────────
// Helper: spin up a fresh App and pair it to a fake Mac.
// ──────────────────────────────────────────────────────────────
fn paired_app() -> (App, StubWallClock) {
    let mut app = App::new(Config::default());
    let wall = StubWallClock::new("12:00", 0);

    app.handle(Event::ToggleOn, &wall);
    assert_eq!(app.phase, Phase::Discovering);

    app.handle(
        Event::PeerSeen {
            peer_id: [1; 32],
            name: "MacBook-Pro".into(),
        },
        &wall,
    );
    assert_eq!(app.phase, Phase::Handshaking);
    assert_eq!(app.state.peer_name, "MacBook-Pro");

    app.handle(Event::HandshakeOk, &wall);
    assert!(
        matches!(app.phase, Phase::Linked | Phase::Paused | Phase::Halted),
        "should be Linked (or policy override), got {:?}",
        app.phase
    );
    assert_eq!(app.state.peer_name, "MacBook-Pro");

    (app, wall)
}

// ══════════════════════════════════════════════════════════════
// Scenario 1: Cryptographic Reset Detection (UntrustedPeerSeen)
// ══════════════════════════════════════════════════════════════
//
// The Mac was wiped / reinstalled. Its mDNS name is still "MacBook-Pro"
// but the Noise static key changed. The discovery layer sees this as an
// untrusted peer and emits `UntrustedPeerSeen { name }`.
//
// Expected: peer_name is cleared => Android navigates to QR scan.
#[test]
fn untrusted_peer_seen_clears_peer_name() {
    let (mut app, wall) = paired_app();

    // Simulate the Mac going away.
    app.handle(Event::PeerLost { peer_id: [1; 32] }, &wall);
    assert_eq!(app.phase, Phase::Discovering);
    assert_eq!(
        app.state.peer_name, "MacBook-Pro",
        "peer_name should stay after PeerLost (for reconnect UI)"
    );

    // Now the mDNS layer sees a Mac with the same name but different keys.
    let actions = app.handle(
        Event::UntrustedPeerSeen {
            name: "MacBook-Pro".into(),
        },
        &wall,
    );

    // peer_name MUST be cleared.
    assert_eq!(
        app.state.peer_name, "",
        "peer_name should be empty after UntrustedPeerSeen"
    );
    assert_eq!(app.phase, Phase::Discovering);

    // FSM must have emitted DropPeer + EmitState.
    assert!(
        actions.iter().any(|a| matches!(a, Action::DropPeer)),
        "expected DropPeer action, got: {actions:?}"
    );
    assert!(
        actions.iter().any(|a| matches!(a, Action::EmitState)),
        "expected EmitState action, got: {actions:?}"
    );
}

// ══════════════════════════════════════════════════════════════
// Scenario 2: Ghost Timeout (10-minute watchdog)
// ══════════════════════════════════════════════════════════════
//
// The Mac is completely gone (uninstalled, dead, etc). After 10 minutes
// the watchdog fires `GhostTimeout`.
//
// Expected: peer_name is cleared => Android navigates to QR scan.
#[test]
fn ghost_timeout_clears_peer_name() {
    let (mut app, wall) = paired_app();

    // Simulate the Mac going away.
    app.handle(Event::PeerLost { peer_id: [1; 32] }, &wall);
    assert_eq!(app.phase, Phase::Discovering);
    assert_eq!(app.state.peer_name, "MacBook-Pro");

    // 10 minutes later, the driver fires GhostTimeout.
    let actions = app.handle(Event::GhostTimeout, &wall);

    assert_eq!(
        app.state.peer_name, "",
        "peer_name should be empty after GhostTimeout"
    );
    assert_eq!(app.phase, Phase::Discovering);

    assert!(
        actions.iter().any(|a| matches!(a, Action::DropPeer)),
        "expected DropPeer action"
    );
}

// ══════════════════════════════════════════════════════════════
// Scenario 3: Manual Unpair (UI failsafe button)
// ══════════════════════════════════════════════════════════════
//
// The user taps "Unpair & re-scan" on the Android UI.
//
// Expected: peer_name is cleared, FSM goes to Idle, session closed.
#[test]
fn manual_unpair_resets_everything() {
    let (mut app, wall) = paired_app();

    // Unpair while still linked!
    let actions = app.handle(Event::ManualUnpair, &wall);

    assert_eq!(
        app.state.peer_name, "",
        "peer_name should be empty after ManualUnpair"
    );
    assert_eq!(
        app.phase,
        Phase::Idle,
        "FSM should go to Idle after ManualUnpair"
    );
    assert!(
        !app.state.on,
        "on should be false after ManualUnpair (Idle)"
    );

    assert!(
        actions.iter().any(|a| matches!(a, Action::DropPeer)),
        "expected DropPeer action"
    );
    assert!(
        actions.iter().any(|a| matches!(a, Action::CloseSession)),
        "expected CloseSession action"
    );
}

// ══════════════════════════════════════════════════════════════
// Scenario 4: Normal reconnect (Wi-Fi blip) — NO false positive
// ══════════════════════════════════════════════════════════════
//
// The Mac temporarily disappears (Wi-Fi hiccup). It comes back 5s later.
// We should NOT clear peer_name during the brief gap.
#[test]
fn wifi_blip_does_not_clear_peer() {
    let (mut app, wall) = paired_app();

    // Mac goes away.
    app.handle(Event::PeerLost { peer_id: [1; 32] }, &wall);
    assert_eq!(app.phase, Phase::Discovering);
    assert_eq!(app.state.peer_name, "MacBook-Pro");

    // 5 seconds later, the Mac reappears with the SAME keys (trusted).
    app.handle(
        Event::PeerSeen {
            peer_id: [1; 32],
            name: "MacBook-Pro".into(),
        },
        &wall,
    );
    assert_eq!(app.phase, Phase::Handshaking);
    assert_eq!(
        app.state.peer_name, "MacBook-Pro",
        "peer_name should still be set"
    );

    // Handshake completes.
    app.handle(Event::HandshakeOk, &wall);
    assert!(
        matches!(app.phase, Phase::Linked | Phase::Paused | Phase::Halted),
        "should be back to Linked"
    );
}

// ══════════════════════════════════════════════════════════════
// Scenario 5: UntrustedPeerSeen with DIFFERENT name is a no-op
// ══════════════════════════════════════════════════════════════
//
// If we see an untrusted peer with a completely different name, the
// FSM should still drop (the peer_name is cleared regardless because
// the FSM doesn't check name matching — that's up to the driver).
#[test]
fn untrusted_peer_different_name_still_drops() {
    let (mut app, wall) = paired_app();
    app.handle(Event::PeerLost { peer_id: [1; 32] }, &wall);

    let actions = app.handle(
        Event::UntrustedPeerSeen {
            name: "SomeOtherMac".into(),
        },
        &wall,
    );

    // The FSM unconditionally drops on UntrustedPeerSeen.
    // The driver is responsible for only emitting this event when
    // the name actually matches.
    assert_eq!(app.state.peer_name, "");
    assert!(actions.iter().any(|a| matches!(a, Action::DropPeer)));
}

// ══════════════════════════════════════════════════════════════
// Scenario 6: ManualUnpair from Discovering (stuck state)
// ══════════════════════════════════════════════════════════════
#[test]
fn manual_unpair_from_discovering() {
    let (mut app, wall) = paired_app();
    app.handle(Event::PeerLost { peer_id: [1; 32] }, &wall);
    assert_eq!(app.phase, Phase::Discovering);

    let actions = app.handle(Event::ManualUnpair, &wall);
    assert_eq!(app.phase, Phase::Idle);
    assert_eq!(app.state.peer_name, "");
    assert!(actions.iter().any(|a| matches!(a, Action::DropPeer)));
}
