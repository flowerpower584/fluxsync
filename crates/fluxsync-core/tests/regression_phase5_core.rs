//! REGRESSION (Phase 5 scan) — three confirmed core defects, now FIXED:
//!
//!  * FAVORITES vs in-memory cap: `App::push_history`/`restore_history` used a
//!    blind `truncate(50)` that ignored the `favorite` flag, while the on-disk
//!    vault prune is favorite-exempt. A pinned item pushed past index 50 thus
//!    vanished from `state.history` (the only list clients render) while
//!    surviving orphaned on disk. Fixed by `cap_history_keeping_favorites`.
//!
//!  * INBOUND FIREWALL ordering: `FrameReceivedClipboard` recorded the item to
//!    history (and the persistent vault) BEFORE the firewall gate ran, so a
//!    Block/Defer (Deny/Ask) inbound item was persisted and shown to clients
//!    despite the policy. Fixed by gating the history insert on a `Pass`
//!    decision; Defer items park in `pending`, Block items are dropped.
//!
//!  * is_sensitive long-hex gap: `\b[A-Fa-f0-9]{64}\b` matched a 64-hex digest
//!    but NOT a pure 96/128-hex run (a 64-byte raw key, sha256‖sha256) because
//!    the interior of a hex run has no word boundary. Fixed to `{64,}`.

use fluxsync_core::{
    is_sensitive, Action, App, Config, Direction, Event, FirewallPolicy, Rule, StubWallClock,
};
use fluxsync_proto::Kind;

fn wall() -> StubWallClock {
    StubWallClock::new("14:32", 1_700_000_000_000)
}

fn linked_app() -> App {
    let mut app = App::new(Config::default());
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
    app
}

fn local_change(n: u8, lamport: u64) -> Event {
    Event::LocalClipboardChange {
        hash: [n; 32],
        kind: Kind::Text,
        payload: format!("item-{n}").into_bytes(),
        preview: format!("item-{n}"),
        sensitive: false,
        lamport,
    }
}

fn inbound_text(n: u8, lamport: u64) -> Event {
    Event::FrameReceivedClipboard {
        hash: [n; 32],
        kind: Kind::Text,
        payload: format!("peer-{n}").into_bytes(),
        preview: format!("peer-{n}"),
        sensitive: false,
        lamport,
        resync: false,
    }
}

fn fw_inbound(text: Rule) -> FirewallPolicy {
    FirewallPolicy {
        enabled: true,
        text,
        ..FirewallPolicy::default()
    }
}

/// FIXED: a pinned item is NEVER evicted from the live history by the soft cap,
/// even after >50 newer items push it past index 50 — mirroring the on-disk
/// vault's favorite-exempt prune so the UI and disk agree.
#[test]
fn favorite_survives_in_memory_cap_overflow() {
    let mut app = linked_app();

    // Push the soon-to-be-favorite, then pin it by its stored (hex) hash.
    app.handle(local_change(1, 1), &wall());
    let fav_hash = app.snapshot().history[0].hash.clone();
    app.handle(
        Event::SetFavorite {
            hash: fav_hash.clone(),
            favorite: true,
        },
        &wall(),
    );

    // Flood with 60 distinct newer items (all non-favorite). Each inserts at
    // index 0, pushing the favorite well past the 50-item soft cap.
    for n in 2u8..=61 {
        app.handle(local_change(n, u64::from(n) + 1), &wall());
    }

    let hist = &app.snapshot().history;
    let fav = hist.iter().find(|h| h.hash == fav_hash);
    assert!(
        fav.is_some_and(|h| h.favorite),
        "FIXED: the pinned item must survive the in-memory cap, but it was evicted"
    );

    // Non-favorites are still bounded by the soft cap (favorites are the only
    // exemption), so the list is cap + the single favorite at most.
    let non_fav = hist.iter().filter(|h| !h.favorite).count();
    assert!(
        non_fav <= 50,
        "non-favorites must stay capped at 50, found {non_fav}"
    );
}

/// FIXED: an inbound item blocked by the firewall (Deny) is NOT written to the
/// clipboard AND NOT recorded in history/vault.
#[test]
fn inbound_firewall_deny_does_not_record_history() {
    let mut app = linked_app();
    app.set_firewall(fw_inbound(Rule::Deny));

    let acts = app.handle(inbound_text(9, 5), &wall());

    assert!(
        !acts.iter().any(|a| matches!(a, Action::WriteClipboard { .. })),
        "Deny must strip the WriteClipboard action"
    );
    assert!(
        app.snapshot().history.is_empty(),
        "FIXED: a Deny-blocked inbound item must NOT enter history, found {} item(s)",
        app.snapshot().history.len()
    );
}

/// FIXED: an inbound item deferred by the firewall (Ask) parks in `pending`
/// and is NOT recorded in history until the user approves it.
#[test]
fn inbound_firewall_ask_parks_without_recording_history() {
    let mut app = linked_app();
    app.set_firewall(fw_inbound(Rule::Ask));

    let acts = app.handle(inbound_text(9, 5), &wall());

    assert!(
        !acts.iter().any(|a| matches!(a, Action::WriteClipboard { .. })),
        "Ask must hold the WriteClipboard action"
    );
    assert_eq!(
        app.snapshot().pending.len(),
        1,
        "Ask must park the inbound item in pending"
    );
    assert_eq!(app.snapshot().pending[0].direction, Direction::Inbound);
    assert!(
        app.snapshot().history.is_empty(),
        "FIXED: a not-yet-approved deferred item must NOT be in history, found {} item(s)",
        app.snapshot().history.len()
    );
}

/// CONTROL: with the kind allowed, the inbound item IS written and recorded —
/// proving the gate only suppresses Block/Defer, not the happy path.
#[test]
fn inbound_firewall_allow_records_history() {
    let mut app = linked_app();
    app.set_firewall(fw_inbound(Rule::Allow));

    let acts = app.handle(inbound_text(9, 5), &wall());

    assert!(
        acts.iter().any(|a| matches!(a, Action::WriteClipboard { .. })),
        "Allow must keep the WriteClipboard action"
    );
    assert_eq!(
        app.snapshot().history.len(),
        1,
        "Allow must record the inbound item in history"
    );
}

/// FIXED: a pure run of 64+ hex chars is flagged sensitive. `{64}` missed
/// 96/128-hex runs (no interior word boundary); `{64,}` catches them.
#[test]
fn is_sensitive_flags_long_hex_runs() {
    let h64 = "a".repeat(64);
    let h96 = "a".repeat(96);
    let h128 = "a".repeat(128);
    let h63 = "a".repeat(63);

    assert!(is_sensitive(&h64), "64-hex digest must be sensitive");
    assert!(
        is_sensitive(&h96),
        "FIXED: 96-hex run must be flagged sensitive"
    );
    assert!(
        is_sensitive(&h128),
        "FIXED: 128-hex run (64-byte raw key) must be flagged sensitive"
    );
    assert!(
        !is_sensitive(&h63),
        "a 63-hex run is below the threshold and must NOT be flagged"
    );

    // Upper bound: a multi-KB pure-hex run is a hex DUMP, not a key. It has no
    // boundary-to-boundary window of length ≤512, so it must NOT be flagged —
    // otherwise large legitimate payloads (e.g. a big clipboard blob) would be
    // wrongly treated as secret and dropped from sync/history.
    let big_hex = "a".repeat(2048);
    assert!(
        !is_sensitive(&big_hex),
        "a multi-KB pure-hex blob must NOT be flagged (key heuristic, not a data filter)"
    );
}
