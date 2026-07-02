//! REGRESSION C3: `Event::ManualUnpair` must clear parked firewall `Ask`
//! items (both halves) while deliberately KEEPING clipboard history.
//!
//! Fix: `App::drop_pending()` clears `state.pending` (the IPC-visible display
//! half) and `pending_payloads` (the held bytes). It is called from
//! `ManualUnpair`. History is intentionally preserved so a same-device
//! reconnect can resume it.

use fluxsync_core::{
    App, Config, Direction, Event, FirewallPolicy, Rule, StubWallClock,
};
use fluxsync_proto::Kind;

fn wall() -> StubWallClock {
    StubWallClock::new("14:32", 1_700_000_000_000)
}

fn link(app: &mut App) {
    app.handle(Event::ToggleOn, &wall());
    app.handle(
        Event::PeerSeen {
            peer_id: [7; 32],
            name: "Galaxy".into(),
        },
        &wall(),
    );
    app.handle(Event::HandshakeOk, &wall());
    // Healthy batteries so we are squarely Linked/Syncing.
    app.state.battery_level = 80;
    app.state.peer_battery = 70;
    app.handle(
        Event::BatteryChangedSelf {
            level: 80,
            charging: false,
        },
        &wall(),
    );
}

#[test]
fn manual_unpair_clears_parked_ask_items() {
    let mut app = App::new(Config::default());
    // Firewall ON, text = Ask → every text copy is parked (Defer).
    app.set_firewall(FirewallPolicy {
        enabled: true,
        text: Rule::Ask,
        url: Rule::Ask,
        code: Rule::Ask,
        image: Rule::Ask,
        sensitive: Rule::Ask,
    });

    link(&mut app);

    // Park 3 distinct outbound Ask items.
    for i in 1u8..=3 {
        app.handle(
            Event::LocalClipboardChange {
                hash: [i; 32],
                kind: Kind::Text,
                payload: format!("secret-{i}").into_bytes(),
                preview: format!("secret-{i}"),
                sensitive: false,
                lamport: i as u64,
            },
            &wall(),
        );
    }

    let parked: Vec<String> = app.state.pending.iter().map(|p| p.hash.clone()).collect();
    println!("PARKED pending.len() = {}", app.state.pending.len());
    for p in &app.state.pending {
        println!("  pending hash={} dir={:?} preview={}", p.hash, p.direction, p.preview);
    }
    assert_eq!(parked.len(), 3, "precondition: 3 items should be parked");

    // History len snapshot BEFORE the unlink — must survive ManualUnpair.
    let history_before = app.state.history.len();

    // ── The unlink ──
    app.handle(Event::ManualUnpair, &wall());

    println!("AFTER ManualUnpair: peer_name={:?} peer_id_zero={} on={}",
        app.state.peer_name,
        app.state.peer_id == [0u8; 32],
        app.state.on);
    println!("AFTER ManualUnpair: pending.len() = {}", app.state.pending.len());
    println!("AFTER ManualUnpair: history.len() = {} (was {})",
        app.state.history.len(), history_before);

    // Indirect probe of the *payload* half (pending_payloads is private):
    // re-resolving a parked hash with allow=true must NOT still emit the held
    // SendItem — the payload was cleared on unpair.
    let resolve_actions = app.handle(
        Event::ResolvePending {
            hash: parked[0].clone(),
            allow: true,
        },
        &wall(),
    );
    let payload_still_held = resolve_actions
        .iter()
        .any(|a| matches!(a, fluxsync_core::Action::SendItem { .. }
            | fluxsync_core::Action::WriteClipboard { .. }));
    println!(
        "AFTER ManualUnpair: resolving old hash emits held sync action = {payload_still_held}"
    );

    // ── FIXED behaviour (C3) ──
    // Manual unpair tears down the link, so the parked items that belonged to
    // that peer are gone — both the display half and the payload half.
    assert!(
        app.state.pending.is_empty(),
        "FIXED: ManualUnpair must clear state.pending, found {} item(s)",
        app.state.pending.len()
    );
    assert!(
        !payload_still_held,
        "FIXED: ManualUnpair must clear pending_payloads — no held SendItem/WriteClipboard \
         may be resolvable to a peer that no longer exists"
    );

    // ── Control: history is deliberately KEPT across ManualUnpair ──
    // (Distinguishes ManualUnpair from the security wipes — UntrustedPeerSeen /
    // GhostTimeout / peer-swap — which DO clear history.)
    assert_eq!(
        app.state.history.len(),
        history_before,
        "ManualUnpair must KEEP clipboard history (same-device reconnect resumes it)"
    );

    let _ = Direction::Outbound;
}
