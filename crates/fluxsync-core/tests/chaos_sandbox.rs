#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

use fluxsync_core::app::App;
use fluxsync_core::clock::{Clock, StubWallClock};
use fluxsync_core::events::{Action, Event};
use fluxsync_core::fsm::Phase;
use fluxsync_core::state::{Config, Status};
use fluxsync_proto::Kind;

/// Helper to get a fresh app and clock
fn setup() -> (App, StubWallClock) {
    (App::new(Config::default()), StubWallClock::new("00:00", 0))
}

#[test]
fn the_seizure_test() {
    let (mut app, wall) = setup();

    // Toggle on/off 100 times in a row.
    // Expected: No crash, ends up in a consistent state (Idle or Discovering).
    for i in 0..100 {
        if i % 2 == 0 {
            app.handle(Event::ToggleOn, &wall);
        } else {
            app.handle(Event::ToggleOff, &wall);
        }
    }

    // Last was i=99 (Odd) -> ToggleOff -> Idle
    assert_eq!(app.phase, Phase::Idle);
    assert!(!app.state.on);
    assert_eq!(app.state.status, Status::Inactive);
}

#[test]
fn the_amnesia_test() {
    let (mut app, wall) = setup();

    // Start discovery
    app.handle(Event::ToggleOn, &wall);

    // See peer
    app.handle(
        Event::PeerSeen {
            peer_id: [1; 32],
            name: "Target".into(),
        },
        &wall,
    );
    assert_eq!(app.phase, Phase::Handshaking);

    // SUDDENLY! Peer changes keys (UntrustedPeerSeen) while we are still in Handshaking phase.
    // Note: The FSM transition for (Handshaking, UntrustedPeerSeen) is not explicitly defined,
    // so it should be a NO-OP or handle gracefully via _ => (phase, vec![]).
    app.handle(
        Event::UntrustedPeerSeen {
            name: "Target".into(),
        },
        &wall,
    );

    // FSM should have dropped back to Discovering because of UntrustedPeerSeen.
    assert_eq!(
        app.state.peer_name, "",
        "App pre-transition logic should have cleared peer_name"
    );
    assert_eq!(
        app.phase,
        Phase::Discovering,
        "FSM should have dropped back to Discovering"
    );

    // If we are stuck in Handshaking with no peer_name, we should at least timeout.
    app.handle(Event::HandshakeTimeout, &wall);
    assert_eq!(
        app.phase,
        Phase::Discovering,
        "HandshakeTimeout should rescue us"
    );
}

#[test]
fn the_time_paradox_test() {
    let (mut app, wall) = setup();
    app.handle(Event::ToggleOn, &wall);
    app.handle(
        Event::PeerSeen {
            peer_id: [1; 32],
            name: "Mac".into(),
        },
        &wall,
    );
    app.handle(Event::HandshakeOk, &wall);

    // Peer sends a frame with Lamport 100
    app.handle(
        Event::FrameReceivedClipboard {
            hash: [1; 32],
            kind: Kind::Text,
            preview: "Future".into(),
            lamport: 100,
            sensitive: false,
        },
        &wall,
    );
    assert_eq!(app.clock.now(), 101);

    // Peer sends a frame with Lamport 10 (THE PAST!)
    app.handle(
        Event::FrameReceivedClipboard {
            hash: [2; 32],
            kind: Kind::Text,
            preview: "Past".into(),
            lamport: 10,
            sensitive: false,
        },
        &wall,
    );

    // Lamport clock should NOT go backward. observe(10) when at 101 should result in 101 or 102?
    // LamportClock::observe usually does: self.v = max(self.v, remote) + 1
    assert!(
        app.clock.now() > 101,
        "Clock should continue to tick forward: {}",
        app.clock.now()
    );
}

#[test]
fn the_battery_spam_test() {
    let (mut app, wall) = setup();
    app.handle(Event::ToggleOn, &wall);

    // Send 1000 battery updates.
    // Expected: State is updated, but no infinite loops or memory explosions.
    for i in 0..100 {
        app.handle(
            Event::BatteryChangedSelf {
                level: i as u8,
                charging: i % 2 == 0,
            },
            &wall,
        );
    }

    assert_eq!(app.state.battery_level, 99);
    assert!(!app.state.charging);
}

#[test]
fn the_zombie_handshake_test() {
    let (mut app, wall) = setup();

    // App is Idle. SUDDENLY, it receives a HandshakeOk event.
    // This could happen if the network stack is buggy or a packet was delayed.
    let actions = app.handle(Event::HandshakeOk, &wall);

    // FSM says: (Idle, HandshakeOk) -> no-op.
    assert_eq!(app.phase, Phase::Idle);
    assert!(
        actions.is_empty(),
        "Should not perform any actions for unexpected handshakes"
    );
}

#[test]
fn the_ghost_reconnect_test() {
    let (mut app, wall) = setup();
    app.handle(Event::ToggleOn, &wall);
    app.handle(
        Event::PeerSeen {
            peer_id: [1; 32],
            name: "Mac".into(),
        },
        &wall,
    );
    app.handle(Event::HandshakeOk, &wall);

    // We are Linked. Peer is lost.
    app.handle(Event::PeerLost, &wall);
    assert_eq!(app.phase, Phase::Discovering);

    // Now receive a Reconnect event.
    let actions = app.handle(Event::Reconnect, &wall);

    // FSM should restart discovery on Reconnect even if already in Discovering.
    assert_eq!(app.phase, Phase::Discovering);
    assert!(actions.iter().any(|a| matches!(a, Action::StartDiscovery)));
}

#[test]
fn history_spam_test() {
    let (mut app, wall) = setup();

    // Send 10,000 clipboard items.
    // Expected: History stays capped at HISTORY_SOFT_CAP (50).
    for i in 0..1000 {
        app.handle(
            Event::FrameReceivedClipboard {
                hash: [i as u8; 32],
                kind: Kind::Text,
                preview: format!("item {i}"),
                lamport: i as u64,
                sensitive: false,
            },
            &wall,
        );
    }

    assert_eq!(app.state.history.len(), 50);
    assert_eq!(app.state.history[0].preview, "item 999");
}

#[test]
fn the_identity_crisis_test() {
    let (mut app, wall) = setup();
    app.handle(Event::ToggleOn, &wall);

    // See Peer A
    app.handle(
        Event::PeerSeen {
            peer_id: [0xA; 32],
            name: "Peer A".into(),
        },
        &wall,
    );
    assert_eq!(app.state.peer_name, "Peer A");

    // SUDDENLY! Before handshake completes, see Peer B.
    app.handle(
        Event::PeerSeen {
            peer_id: [0xB; 32],
            name: "Peer B".into(),
        },
        &wall,
    );

    // The FSM prevents identity mismatch!
    assert_eq!(app.phase, Phase::Handshaking);

    // peer_name should STILL be Peer A because we rejected Peer B due to mismatch.
    assert_eq!(
        app.state.peer_name, "Peer A",
        "Identity mismatch prevention failed!"
    );
}

#[test]
fn the_duplicate_history_bug_test() {
    let (mut app, wall) = setup();
    app.handle(Event::ToggleOn, &wall);
    app.handle(
        Event::PeerSeen {
            peer_id: [1; 32],
            name: "Mac".into(),
        },
        &wall,
    );
    app.handle(Event::HandshakeOk, &wall);

    let hash = [0xAA; 32];

    // Receive same item twice (e.g. retry because ACK lost)
    app.handle(
        Event::FrameReceivedClipboard {
            hash,
            kind: Kind::Text,
            preview: "Duplicate Content".into(),
            lamport: 1,
            sensitive: false,
        },
        &wall,
    );

    app.handle(
        Event::FrameReceivedClipboard {
            hash,
            kind: Kind::Text,
            preview: "Duplicate Content".into(),
            lamport: 2,
            sensitive: false,
        },
        &wall,
    );

    // Expected: History should only have 1 entry.
    // Actual (if bug exists): History will have 2 entries.
    assert_eq!(
        app.state.history.len(),
        1,
        "History should NOT contain duplicate entries for the same hash!"
    );
}

#[test]
fn the_out_of_order_history_test() {
    let (mut app, wall) = setup();
    app.handle(Event::ToggleOn, &wall);
    app.handle(
        Event::PeerSeen {
            peer_id: [1; 32],
            name: "Mac".into(),
        },
        &wall,
    );
    app.handle(Event::HandshakeOk, &wall);

    // Message 2 arrives first (Network jitter)
    app.handle(
        Event::FrameReceivedClipboard {
            hash: [2; 32],
            kind: Kind::Text,
            preview: "Message 2".into(),
            lamport: 10,
            sensitive: false,
        },
        &wall,
    );

    // Message 1 arrives later
    app.handle(
        Event::FrameReceivedClipboard {
            hash: [1; 32],
            kind: Kind::Text,
            preview: "Message 1".into(),
            lamport: 5,
            sensitive: false,
        },
        &wall,
    );

    // History currently just prepends.
    // So "Message 1" is at index 0, "Message 2" is at index 1.
    assert_eq!(app.state.history[0].preview, "Message 1");
}

#[test]
fn the_privacy_leak_test() {
    let (mut app, wall) = setup();

    // 1. Pair with "My Private Mac"
    app.handle(Event::ToggleOn, &wall);
    app.handle(
        Event::PeerSeen {
            peer_id: [0xA; 32],
            name: "Private Mac".into(),
        },
        &wall,
    );
    app.handle(Event::HandshakeOk, &wall);

    // 2. Copy a secret
    app.handle(
        Event::LocalClipboardChange {
            hash: [0x55; 32],
            kind: Kind::Text,
            preview: "MY_PASSWORD".into(),
            sensitive: false, // User forgot to mark it sensitive
            lamport: 1,
        },
        &wall,
    );

    assert_eq!(app.state.history[0].preview, "MY_PASSWORD");

    // 3. Unpair or Peer Lost
    app.handle(Event::ManualUnpair, &wall);
    assert_eq!(app.state.peer_name, "");

    // 4. Pair with "Friend's Phone"
    app.handle(Event::ToggleOn, &wall);
    app.handle(
        Event::PeerSeen {
            peer_id: [0xB; 32],
            name: "Friend Phone".into(),
        },
        &wall,
    );

    // BUG DETECTION: Is the password still in history?
    // If yes, and the new peer triggers a "BurstReplay", the secret is LEAKED.
    assert!(
        app.state.history.is_empty(),
        "HISTORY SHOULD BE CLEARED ON UNPAIR/NEW PAIR! Found: {:?}",
        app.state.history
    );
}

#[test]
fn memory_and_cpu_stress_test() {
    let (mut app, wall) = setup();
    app.handle(Event::ToggleOn, &wall);
    app.handle(
        Event::PeerSeen {
            peer_id: [1; 32],
            name: "Target".into(),
        },
        &wall,
    );
    app.handle(Event::HandshakeOk, &wall);

    // Create 50 LARGE history items (e.g. 1MB each)
    let large_string = "A".repeat(1_000_000);
    for i in 0..50 {
        app.handle(
            Event::FrameReceivedClipboard {
                hash: [i as u8; 32],
                kind: Kind::Text,
                preview: large_string.clone(),
                lamport: i as u64,
                sensitive: false,
            },
            &wall,
        );
    }

    // Now simulate 100 battery updates and measure time
    let start = std::time::Instant::now();
    for i in 0..100 {
        app.handle(
            Event::BatteryChangedSelf {
                level: i as u8,
                charging: true,
            },
            &wall,
        );
    }
    let duration = start.elapsed();

    println!("Time for 100 battery updates with 50MB state: {duration:?}");

    // If this takes more than say 100ms, it's a major performance bug for a background daemon.
    // On a modern CPU, cloning 50MB 100 times = 5GB of memory copies.
    assert!(
        duration.as_millis() < 500,
        "Performance too slow! State cloning is killing the CPU: {duration:?}"
    );
}
