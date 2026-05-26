//! INDESTRUCTIBLE TEST SUITE — FluxSync Core
//! Tests every critical path to prevent future bugs.
#![allow(clippy::cast_possible_truncation)]

use fluxsync_core::*;
use fluxsync_proto::Kind;

fn wall() -> StubWallClock {
    StubWallClock::new("14:32", 1_700_000_000_000)
}
fn boot() -> App {
    App::new(Config::default())
}
fn h(seed: u8) -> [u8; 32] {
    [seed; 32]
}
fn ch(seed: u8) -> ContentHash {
    ContentHash::from_blake3([seed; 32])
}

fn linked_app() -> App {
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
        Event::BatteryChangedSelf {
            level: 80,
            charging: false,
        },
        &wall(),
    );
    app.handle(
        Event::BatteryChangedPeer {
            level: 80,
            charging: false,
        },
        &wall(),
    );
    app
}

// ═══════════════════════════════════════════════════════════════════
// 1. LIFECYCLE: Boot → Pair → Link → Disconnect → Reconnect
// ═══════════════════════════════════════════════════════════════════

#[test]
fn lifecycle_full_happy_path() {
    let mut app = boot();
    assert_eq!(app.phase, Phase::Idle);
    assert_eq!(app.snapshot().status, Status::Inactive);
    assert!(!app.snapshot().on);

    let a = app.handle(Event::ToggleOn, &wall());
    assert_eq!(app.phase, Phase::Discovering);
    assert!(a.iter().any(|x| matches!(x, Action::StartDiscovery)));

    let a = app.handle(
        Event::PeerSeen {
            peer_id: [1; 32],
            name: "SM-G998N".into(),
        },
        &wall(),
    );
    assert_eq!(app.phase, Phase::Handshaking);
    assert!(a.iter().any(|x| matches!(x, Action::SendHandshake { .. })));
    assert_eq!(app.snapshot().peer_name, "SM-G998N");

    let a = app.handle(Event::HandshakeOk, &wall());
    assert!(a.contains(&Action::OpenSession));
    assert!(a.contains(&Action::BurstReplay));

    app.handle(
        Event::BatteryChangedSelf {
            level: 80,
            charging: false,
        },
        &wall(),
    );
    assert_eq!(app.snapshot().status, Status::Syncing);
    assert_eq!(app.phase, Phase::Linked);
}

#[test]
fn lifecycle_peer_lost_then_rediscovery() {
    let mut app = linked_app();
    let a = app.handle(Event::PeerLost, &wall());
    assert_eq!(app.phase, Phase::Discovering);
    assert!(a.contains(&Action::CloseSession));
    assert!(a.contains(&Action::StartDiscovery));
    // peer_name is intentionally PERSISTENT across PeerLost events.
    // This prevents the Android UI from flashing back to the QR code screen.
    assert!(!app.snapshot().peer_name.is_empty());

    app.handle(
        Event::PeerSeen {
            peer_id: [7; 32],
            name: "Galaxy".into(),
        },
        &wall(),
    );
    assert_eq!(app.phase, Phase::Handshaking);
    app.handle(Event::HandshakeOk, &wall());
    app.handle(
        Event::BatteryChangedSelf {
            level: 80,
            charging: false,
        },
        &wall(),
    );
    assert_eq!(app.phase, Phase::Linked);
}

#[test]
fn lifecycle_handshake_timeout_retries() {
    let mut app = boot();
    app.handle(Event::ToggleOn, &wall());
    app.handle(
        Event::PeerSeen {
            peer_id: [1; 32],
            name: "P".into(),
        },
        &wall(),
    );
    assert_eq!(app.phase, Phase::Handshaking);

    let a = app.handle(Event::HandshakeTimeout, &wall());
    assert_eq!(app.phase, Phase::Discovering);
    assert!(a
        .iter()
        .any(|x| matches!(x, Action::EmitLog(e) if e.level == LogLevel::Warn)));
}

// ═══════════════════════════════════════════════════════════════════
// 2. TOGGLE STRESS — rapid on/off must never crash or deadlock
// ═══════════════════════════════════════════════════════════════════

#[test]
fn toggle_stress_100_cycles() {
    let mut app = boot();
    for _ in 0..100 {
        app.handle(Event::ToggleOn, &wall());
        assert!(app.snapshot().on);
        app.handle(Event::ToggleOff, &wall());
        assert!(!app.snapshot().on);
        assert_eq!(app.phase, Phase::Idle);
        assert_eq!(app.snapshot().status, Status::Inactive);
    }
}

#[test]
fn toggle_off_from_every_phase() {
    for start_phase in [
        Phase::Idle,
        Phase::Discovering,
        Phase::Handshaking,
        Phase::Linked,
        Phase::Paused,
        Phase::Halted,
    ] {
        let (next, actions) = transition(start_phase, &Event::ToggleOff);
        assert_eq!(next, Phase::Idle, "ToggleOff from {start_phase:?}");
        assert!(actions.contains(&Action::CloseSession));
        assert!(actions.contains(&Action::StopDiscovery));
    }
}

// ═══════════════════════════════════════════════════════════════════
// 3. BATTERY POLICY — exhaustive boundary testing
// ═══════════════════════════════════════════════════════════════════

fn make_state(on: bool, sb: u8, sc: bool, pb: u8, pc: bool, thr: u8) -> State {
    let mut s = State::initial(&Config::default());
    s.on = on;
    s.battery_level = sb;
    s.charging = sc;
    s.peer_battery = pb;
    s.peer_charging = pc;
    s.battery_threshold = thr;
    s
}

#[test]
fn policy_inactive_always_when_off() {
    for b in [0, 5, 15, 50, 100] {
        assert_eq!(
            status_for(&make_state(false, b, false, b, false, 20)),
            Status::Inactive
        );
    }
}

#[test]
fn policy_critical_at_5_or_below_either_side() {
    for lvl in 0..=5u8 {
        assert_eq!(
            status_for(&make_state(true, lvl, false, 80, false, 20)),
            Status::Critical
        );
        assert_eq!(
            status_for(&make_state(true, 80, false, lvl, false, 20)),
            Status::Critical
        );
        // Critical even when charging
        assert_eq!(
            status_for(&make_state(true, lvl, true, 80, false, 20)),
            Status::Critical
        );
    }
}

#[test]
fn policy_paused_at_threshold_boundary() {
    let thr = 20u8;
    // At threshold = Paused
    assert_eq!(
        status_for(&make_state(true, thr, false, 80, false, thr)),
        Status::Paused
    );
    // One above = Syncing
    assert_eq!(
        status_for(&make_state(true, thr + 1, false, 80, false, thr)),
        Status::Syncing
    );
    // Same for peer side
    assert_eq!(
        status_for(&make_state(true, 80, false, thr, false, thr)),
        Status::Paused
    );
    assert_eq!(
        status_for(&make_state(true, 80, false, thr + 1, false, thr)),
        Status::Syncing
    );
}

#[test]
fn policy_charging_overrides_pause() {
    assert_eq!(
        status_for(&make_state(true, 10, true, 80, false, 20)),
        Status::Syncing
    );
    assert_eq!(
        status_for(&make_state(true, 80, false, 10, true, 20)),
        Status::Syncing
    );
}

#[test]
fn policy_both_below_still_paused() {
    assert_eq!(
        status_for(&make_state(true, 15, false, 15, false, 20)),
        Status::Paused
    );
}

#[test]
fn policy_phase_mirrors_status_after_link() {
    let mut app = linked_app();
    // Set threshold to 20 so level=10 triggers pause
    app.state.battery_threshold = 20;

    // Drop to paused (10 <= 20, not charging)
    app.handle(
        Event::BatteryChangedSelf {
            level: 10,
            charging: false,
        },
        &wall(),
    );
    assert_eq!(app.snapshot().status, Status::Paused);
    assert_eq!(app.phase, Phase::Paused);

    // Charge → back to linked
    app.handle(
        Event::BatteryChangedSelf {
            level: 10,
            charging: true,
        },
        &wall(),
    );
    assert_eq!(app.snapshot().status, Status::Syncing);
    assert_eq!(app.phase, Phase::Linked);

    // Drop to critical
    app.handle(
        Event::BatteryChangedSelf {
            level: 3,
            charging: false,
        },
        &wall(),
    );
    assert_eq!(app.snapshot().status, Status::Critical);
    assert_eq!(app.phase, Phase::Halted);
}

// ═══════════════════════════════════════════════════════════════════
// 4. CLIPBOARD SYNC — dedup, echo, history, ordering
// ═══════════════════════════════════════════════════════════════════

#[test]
fn clipboard_local_to_peer_emits_send() {
    let mut app = linked_app();
    let a = app.handle(
        Event::LocalClipboardChange {
            hash: h(1),
            kind: Kind::Text,
            payload: "Salam".to_string().into_bytes(),
            preview: "Salam".into(),
            sensitive: false,
            lamport: 1,
        },
        &wall(),
    );
    assert!(a
        .iter()
        .any(|x| matches!(x, Action::SendItem { hash, .. } if *hash == h(1))));
    assert_eq!(app.snapshot().history[0].preview, "Salam");
}

#[test]
fn clipboard_peer_to_local_writes_and_acks() {
    let mut app = linked_app();
    let a = app.handle(
        Event::FrameReceivedClipboard {
            hash: h(2),
            kind: Kind::Text,
            payload: "Bonjour".to_string().into_bytes(),
            preview: "Bonjour".into(),
            lamport: 5,
            sensitive: false,
        },
        &wall(),
    );
    assert!(a
        .iter()
        .any(|x| matches!(x, Action::WriteClipboard { payload, .. } if payload == b"Bonjour")));
    assert!(a
        .iter()
        .any(|x| matches!(x, Action::AckItem { hash } if *hash == h(2))));
    assert_eq!(app.snapshot().history[0].preview, "Bonjour");
}

#[test]
fn clipboard_dedup_suppresses_echo() {
    let mut app = linked_app();
    let a1 = app.handle(
        Event::LocalClipboardChange {
            hash: h(10),
            kind: Kind::Text,
            payload: "x".to_string().into_bytes(),
            preview: "x".into(),
            sensitive: false,
            lamport: 1,
        },
        &wall(),
    );
    assert!(a1.iter().any(|x| matches!(x, Action::SendItem { .. })));

    // Same hash = suppressed
    let a2 = app.handle(
        Event::LocalClipboardChange {
            hash: h(10),
            kind: Kind::Text,
            payload: "x".to_string().into_bytes(),
            preview: "x".into(),
            sensitive: false,
            lamport: 2,
        },
        &wall(),
    );
    assert!(!a2.iter().any(|x| matches!(x, Action::SendItem { .. })));
}

#[test]
fn clipboard_cross_dedup_peer_then_local() {
    // SE-14: dedup is keyed on the digest of the actual payload, not on
    // the sender-supplied `hash` field, so we use the real BLAKE3 of
    // "echo" on both sides — the daemon code does the same.
    let real = DedupRing::hash(b"echo").into_bytes();
    let mut app = linked_app();
    // Receive from peer
    app.handle(
        Event::FrameReceivedClipboard {
            hash: real,
            kind: Kind::Text,
            payload: "echo".to_string().into_bytes(),
            preview: "echo".into(),
            lamport: 1,
            sensitive: false,
        },
        &wall(),
    );
    // Now local clipboard fires with same hash (OS echo)
    let a = app.handle(
        Event::LocalClipboardChange {
            hash: real,
            kind: Kind::Text,
            payload: "echo".to_string().into_bytes(),
            preview: "echo".into(),
            sensitive: false,
            lamport: 2,
        },
        &wall(),
    );
    // Must NOT send it back
    assert!(!a.iter().any(|x| matches!(x, Action::SendItem { .. })));
}

#[test]
fn se14_peer_supplied_hash_does_not_key_dedup() {
    // SE-14 regression: a peer that lies about `ClipboardItem.hash`
    // cannot pin a slot in the dedup ring. We feed a frame whose `hash`
    // is `[0xAA; 32]` but whose payload is "real". The app must dedup
    // against `blake3("real")`, not `[0xAA; 32]`.
    let mut app = linked_app();
    app.handle(
        Event::FrameReceivedClipboard {
            hash: [0xAA; 32], // hostile peer-supplied
            kind: Kind::Text,
            payload: b"real".to_vec(),
            preview: "real".into(),
            lamport: 1,
            sensitive: false,
        },
        &wall(),
    );
    // Sending "fake" with the same poisoned hash MUST still go through —
    // dedup is keyed by payload digest now.
    let a = app.handle(
        Event::FrameReceivedClipboard {
            hash: [0xAA; 32],
            kind: Kind::Text,
            payload: b"fake".to_vec(),
            preview: "fake".into(),
            lamport: 2,
            sensitive: false,
        },
        &wall(),
    );
    assert!(
        a.iter().any(|x| matches!(x, Action::AckItem { .. })),
        "second frame with same poisoned hash but different payload must NOT be deduped"
    );
}

#[test]
fn clipboard_sensitive_not_in_history() {
    let mut app = linked_app();
    app.handle(
        Event::LocalClipboardChange {
            hash: h(30),
            kind: Kind::Text,
            payload: "sk_live_aBcDeFgHiJkLmNoPqRsTuVwX".to_string().into_bytes(),
            preview: "sk_live_aBcDeFgHiJkLmNoPqRsTuVwX".into(),
            sensitive: true,
            lamport: 1,
        },
        &wall(),
    );
    assert!(app.snapshot().history.is_empty());
}

#[test]
fn clipboard_history_capped_at_50() {
    let mut app = linked_app();
    for i in 0..60u8 {
        app.handle(
            Event::FrameReceivedClipboard {
                hash: h(i),
                kind: Kind::Text,
                payload: format!("item-{i}").into_bytes(),
                preview: format!("item-{i}"),
                lamport: u64::from(i),
                sensitive: false,
            },
            &wall(),
        );
    }
    assert_eq!(app.snapshot().history.len(), 50);
    assert_eq!(app.snapshot().history[0].preview, "item-59");
}

#[test]
fn clipboard_history_newest_first() {
    let mut app = linked_app();
    for i in 0..5u8 {
        app.handle(
            Event::FrameReceivedClipboard {
                hash: h(i),
                kind: Kind::Text,
                payload: format!("msg-{i}").into_bytes(),
                preview: format!("msg-{i}"),
                lamport: u64::from(i),
                sensitive: false,
            },
            &wall(),
        );
    }
    assert_eq!(app.snapshot().history[0].preview, "msg-4");
    assert_eq!(app.snapshot().history[4].preview, "msg-0");
}

// ═══════════════════════════════════════════════════════════════════
// 5. DEDUP RING — isolation tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn dedup_ring_eviction_cycle() {
    let mut ring = DedupRing::new(3);
    assert!(ring.observe(ch(1)));
    assert!(ring.observe(ch(2)));
    assert!(ring.observe(ch(3)));
    // Full → evicts oldest
    assert!(ring.observe(ch(4)));
    assert!(!ring.contains(&ch(1)));
    assert!(ring.contains(&ch(4)));
    // Evicted item is fresh again
    assert!(ring.observe(ch(1)));
}

#[test]
fn dedup_ring_stress_1000_items() {
    let mut ring = DedupRing::new(50);
    for i in 0..1000u16 {
        let mut hash = [0u8; 32];
        hash[0] = (i & 0xFF) as u8;
        hash[1] = (i >> 8) as u8;
        ring.observe(ContentHash::from_blake3(hash));
    }
    assert_eq!(ring.len(), 50);
}

// ═══════════════════════════════════════════════════════════════════
// 6. LAMPORT CLOCK — ordering guarantees
// ═══════════════════════════════════════════════════════════════════

#[test]
fn lamport_monotonic_and_observe() {
    let mut c = LamportClock::new();
    assert_eq!(c.tick(), 1);
    assert_eq!(c.tick(), 2);
    assert_eq!(c.observe(100), 101);
    assert_eq!(c.tick(), 102);
    // Smaller observe still bumps
    assert_eq!(c.observe(50), 103);
}

#[test]
fn lamport_clamps_hostile_peer_value() {
    // SE-08: a hostile peer that sends `lamport: u64::MAX` must NOT
    // pin our counter at MAX. `observe` clamps `seen` to
    // LAMPORT_OBSERVE_MAX so subsequent ticks still order distinctly.
    use fluxsync_core::clock::LAMPORT_OBSERVE_MAX;
    let mut c = LamportClock::new();
    let after = c.observe(u64::MAX);
    assert!(after <= LAMPORT_OBSERVE_MAX + 1);
    assert!(c.tick() > after);
}

// ═══════════════════════════════════════════════════════════════════
// 7. STATE SERIALIZATION — JSON contract with Android & macOS
// ═══════════════════════════════════════════════════════════════════

#[test]
fn state_json_has_all_required_keys() {
    let s = State::initial(&Config::default());
    let j = serde_json::to_value(&s).unwrap();
    // These exact keys are read by Android DaemonState.kt and macOS app.js
    for key in [
        "on",
        "battery_level",
        "battery_threshold",
        "charging",
        "peer_name",
        "peer_battery",
        "peer_charging",
        "history",
        "status",
        "version",
        "link_latency_ms",
        "cipher",
    ] {
        assert!(j.get(key).is_some(), "missing JSON key: {key}");
    }
}

#[test]
fn state_status_serializes_lowercase() {
    assert_eq!(serde_json::to_value(Status::Inactive).unwrap(), "inactive");
    assert_eq!(serde_json::to_value(Status::Syncing).unwrap(), "syncing");
    assert_eq!(serde_json::to_value(Status::Paused).unwrap(), "paused");
    assert_eq!(serde_json::to_value(Status::Critical).unwrap(), "critical");
}

#[test]
fn state_history_item_serializes_snake_case() {
    let item = HistoryItem {
        kind: Kind::Url,
        preview: "https://x.com".into(),
        time: "14:32".into(),
        source: HistorySource::Local,
        sensitive: false,
        lamport: 0,
        hash: String::new(),
    };
    let j = serde_json::to_value(&item).unwrap();
    assert!(j.get("kind").is_some());
    assert!(j.get("preview").is_some());
    assert!(j.get("time").is_some());
    assert!(j.get("hash").is_some());
}

#[test]
fn state_roundtrip_json() {
    let s = State::initial(&Config::default());
    let json = serde_json::to_string(&s).unwrap();
    let s2: State = serde_json::from_str(&json).unwrap();
    assert_eq!(s, s2);
}

// ═══════════════════════════════════════════════════════════════════
// 8. THRESHOLD VALIDATION
// ═══════════════════════════════════════════════════════════════════

#[test]
fn threshold_range_5_to_50_inclusive() {
    let mut s = State::initial(&Config::default());
    assert!(s.set_threshold(5).is_ok());
    assert!(s.set_threshold(50).is_ok());
    assert!(s.set_threshold(4).is_err());
    assert!(s.set_threshold(51).is_err());
    assert!(s.set_threshold(0).is_err());
    assert!(s.set_threshold(255).is_err());
}

#[test]
fn battery_level_rejects_over_100() {
    let mut s = State::initial(&Config::default());
    assert!(s.set_self_battery(100, false).is_ok());
    assert!(s.set_self_battery(101, false).is_err());
}

// ═══════════════════════════════════════════════════════════════════
// 9. CLASSIFIER — kind_of and is_sensitive
// ═══════════════════════════════════════════════════════════════════

#[test]
fn classify_urls() {
    assert_eq!(kind_of("https://github.com"), Kind::Url);
    assert_eq!(kind_of("http://localhost:3000"), Kind::Url);
    assert_eq!(kind_of("www.google.com"), Kind::Text); // no scheme
}

#[test]
fn classify_code() {
    assert_eq!(kind_of("fn main() {\n  println!(\"hi\");\n}"), Kind::Code);
    assert_eq!(kind_of("import os\nimport sys"), Kind::Code);
    assert_eq!(kind_of("fn main()"), Kind::Text); // single line
}

#[test]
fn sensitive_detects_all_patterns() {
    assert!(is_sensitive("sk_test_4eC39HqLyjWDarjtT1zdp7dc"));
    assert!(is_sensitive("sk_live_aBcDeFgHiJkLmNoPqRsTuVwX"));
    assert!(is_sensitive("ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"));
    assert!(is_sensitive("AKIAIOSFODNN7EXAMPLE"));
    assert!(is_sensitive("sk-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"));
    assert!(!is_sensitive("Hello, world"));
    assert!(!is_sensitive("https://github.com"));
}

// ═══════════════════════════════════════════════════════════════════
// 10. FSM EDGE CASES — events in wrong phases
// ═══════════════════════════════════════════════════════════════════

#[test]
fn fsm_noop_for_invalid_transitions() {
    // HandshakeOk in Idle = no-op
    let (p, a) = transition(Phase::Idle, &Event::HandshakeOk);
    assert_eq!(p, Phase::Idle);
    assert!(a.is_empty());

    // PeerSeen in Idle = no-op
    let (p, a) = transition(
        Phase::Idle,
        &Event::PeerSeen {
            peer_id: [1; 32],
            name: "X".into(),
        },
    );
    assert_eq!(p, Phase::Idle);
    assert!(a.is_empty());

    // Reconnect in Idle = no-op
    let (p, a) = transition(Phase::Idle, &Event::Reconnect);
    assert_eq!(p, Phase::Idle);
    assert!(a.is_empty());
}

#[test]
fn fsm_network_change_restarts_discovery() {
    let (p, a) = transition(Phase::Discovering, &Event::NetworkChanged);
    assert_eq!(p, Phase::Discovering);
    assert!(a.contains(&Action::StopDiscovery));
    assert!(a.contains(&Action::StartDiscovery));
}

#[test]
fn fsm_reconnect_triggers_burst_replay() {
    let (p, a) = transition(Phase::Linked, &Event::Reconnect);
    assert_eq!(p, Phase::Linked);
    assert!(a.contains(&Action::BurstReplay));
}

#[test]
fn fsm_peer_seen_in_linked_emits_state() {
    let (p, a) = transition(
        Phase::Linked,
        &Event::PeerSeen {
            peer_id: [1; 32],
            name: "X".into(),
        },
    );
    assert_eq!(p, Phase::Linked);
    assert!(a.contains(&Action::EmitState));
}

// ═══════════════════════════════════════════════════════════════════
// 11. EMIT STATE — every mutation fans out
// ═══════════════════════════════════════════════════════════════════

#[test]
fn emit_state_on_every_meaningful_event() {
    let mut app = linked_app();

    let a = app.handle(
        Event::BatteryChangedSelf {
            level: 50,
            charging: false,
        },
        &wall(),
    );
    assert!(a.contains(&Action::EmitState), "battery change must emit");

    let a = app.handle(
        Event::FrameReceivedClipboard {
            hash: h(99),
            kind: Kind::Text,
            payload: "test".to_string().into_bytes(),
            preview: "test".into(),
            lamport: 1,
            sensitive: false,
        },
        &wall(),
    );
    assert!(
        a.contains(&Action::EmitState),
        "clipboard receive must emit"
    );

    let a = app.handle(Event::PeerLost, &wall());
    assert!(a.contains(&Action::EmitState), "peer lost must emit");
}

// ═══════════════════════════════════════════════════════════════════
// 12. STRESS SCENARIO — rapid clipboard + battery interleaving
// ═══════════════════════════════════════════════════════════════════

#[test]
fn stress_interleaved_clipboard_and_battery() {
    let mut app = linked_app();
    for i in 0..200u16 {
        let mut hash = [0u8; 32];
        hash[0] = (i & 0xFF) as u8;
        hash[1] = (i >> 8) as u8;

        if i % 3 == 0 {
            app.handle(
                Event::BatteryChangedSelf {
                    level: ((i % 95) + 6) as u8,
                    charging: i % 7 == 0,
                },
                &wall(),
            );
        } else if i % 3 == 1 {
            app.handle(
                Event::LocalClipboardChange {
                    hash,
                    kind: Kind::Text,
                    payload: format!("local-{i}").into_bytes(),
                    preview: format!("local-{i}"),
                    sensitive: false,
                    lamport: u64::from(i),
                },
                &wall(),
            );
        } else {
            app.handle(
                Event::FrameReceivedClipboard {
                    hash,
                    kind: Kind::Text,
                    payload: format!("remote-{i}").into_bytes(),
                    preview: format!("remote-{i}"),
                    lamport: u64::from(i),
                    sensitive: false,
                },
                &wall(),
            );
        }
    }
    // App must still be coherent
    assert!(app.snapshot().history.len() <= 50);
    assert!(app.snapshot().battery_level <= 100);
}

#[test]
fn stress_peer_bounce_10_cycles() {
    let mut app = boot();
    app.handle(Event::ToggleOn, &wall());

    for i in 0..10u8 {
        app.handle(
            Event::PeerSeen {
                peer_id: [i; 32],
                name: format!("Peer-{i}"),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::BatteryChangedSelf {
                level: 80,
                charging: false,
            },
            &wall(),
        );
        assert_eq!(app.phase, Phase::Linked);
        assert_eq!(app.snapshot().peer_name, format!("Peer-{i}"));

        app.handle(Event::PeerLost, &wall());
        assert_eq!(app.phase, Phase::Discovering);
        // peer_name stays persistent across PeerLost (by design)
        assert!(!app.snapshot().peer_name.is_empty());
    }
}
