//! REGRESSION FIX3: the content-dedup ring must be rehydrated from
//! persisted history on restart.
//!
//! `App::restore_history` used to fill `state.history` but never seed
//! `self.dedup`, so a fresh `App` (daemon restart) started with an empty
//! ring even though the SAME content already lived in history. One echo
//! round-trip right after a restart (e.g. the peer resends because it never
//! got our Ack before we restarted) would ping-pong back into history as a
//! "new" item instead of being recognized as the duplicate it is.
//!
//! Fix: `restore_history` now seeds `self.dedup` from the restored items'
//! stored `HistoryItem.hash` (the only thing persisted — see
//! `history_store::VaultEntry`'s doc comment; the raw payload never reaches
//! disk), capped to the ring's capacity, newest-favoring.
//!
//! This test drives `App` directly (construct → populate → drop → construct
//! fresh → `restore_history`) rather than spawning a real daemon process,
//! since `restore_history` is exactly the seam the daemon calls on boot
//! (`crates/fluxsyncd/src/driver.rs`'s `history_store::load` +
//! `app.restore_history(...)`) — this is the core-level equivalent of an
//! actual restart.

use fluxsync_core::{canon_text, dedup::DedupRing, Action, App, Config, Event, StubWallClock};
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
    app
}

/// Same digest the live local-capture path uses (see `driver.rs`'s
/// `clipboard_dedup_hash`, which also CRLF-canonicalizes) — realistic rather
/// than an arbitrary sentinel, since `restore_history` seeds the ring
/// straight from this same stored value.
fn local_hash(text: &str) -> [u8; 32] {
    DedupRing::hash(canon_text(text).as_bytes()).into_bytes()
}

#[test]
fn restart_rehydrates_dedup_ring_so_echo_is_suppressed() {
    // ── "Before restart": capture one item locally. ──
    let mut app1 = linked_app();
    let text = "line1\r\nline2";
    let hash = local_hash(text);
    app1.handle(
        Event::LocalClipboardChange {
            hash,
            kind: Kind::Text,
            payload: text.as_bytes().to_vec(),
            preview: text.to_string(),
            sensitive: false,
            lamport: 1,
        },
        &wall(),
    );
    let persisted_items = app1.snapshot().history.clone();
    assert_eq!(persisted_items.len(), 1, "precondition: one item captured");
    drop(app1); // simulate the daemon process exiting

    // ── "After restart": a fresh App, rehydrated from what would have been
    // loaded off `history_store` (only `HistoryItem`s survive — see the
    // module doc above). ──
    let mut app2 = linked_app();
    app2.restore_history(persisted_items);
    assert_eq!(app2.snapshot().history.len(), 1, "history rehydrated");

    // The peer resends the SAME logical content (LF instead of the original
    // CRLF — canon-equivalent, exactly what `canon_text` normalizes) before
    // this device's very first live copy. FIXED: this must dedup exactly as
    // it would have pre-restart, not be treated as a fresh item.
    let acts = app2.handle(
        Event::FrameReceivedClipboard {
            peer_id: [7; 32],
            hash: [0xEE; 32], // wire-declared hash is untrusted/ignored (SE-14)
            kind: Kind::Text,
            payload: b"line1\nline2".to_vec(),
            preview: "line1\nline2".to_string(),
            sensitive: false,
            lamport: 2,
            resync: false,
        },
        &wall(),
    );
    assert!(
        acts.iter().any(|a| matches!(a, Action::DuplicateDropped)),
        "FIXED: a canon-equivalent echo right after restart must be deduped, \
         not re-applied as a new item"
    );
    assert_eq!(
        app2.snapshot().history.len(),
        1,
        "the deduped echo must not add a second history row"
    );

    // Control: genuinely NEW content is NOT affected by the rehydration —
    // it must still pass through normally.
    let acts_new = app2.handle(
        Event::FrameReceivedClipboard {
            peer_id: [7; 32],
            hash: [0xAA; 32],
            kind: Kind::Text,
            payload: b"a completely different copy".to_vec(),
            preview: "a completely different copy".to_string(),
            sensitive: false,
            lamport: 3,
            resync: false,
        },
        &wall(),
    );
    assert!(
        !acts_new
            .iter()
            .any(|a| matches!(a, Action::DuplicateDropped)),
        "genuinely new content must not be treated as a duplicate after rehydration"
    );
    assert_eq!(
        app2.snapshot().history.len(),
        2,
        "the genuinely new item must be recorded"
    );
}

/// Rehydration respects the ring's capacity: seeding must not panic or
/// behave incorrectly when history holds more (favorited) items than the
/// ring can hold — it should simply seed the newest `capacity` of them.
#[test]
fn restart_rehydration_respects_ring_capacity_with_many_favorites() {
    let mut app1 = linked_app();
    // More items than DEDUP_CAPACITY (50), all favorited so none are
    // trimmed by the in-memory soft cap either.
    for n in 0u32..60 {
        let text = format!("item-{n}");
        let hash = local_hash(&text);
        app1.handle(
            Event::LocalClipboardChange {
                hash,
                kind: Kind::Text,
                payload: text.clone().into_bytes(),
                preview: text,
                sensitive: false,
                lamport: u64::from(n) + 1,
            },
            &wall(),
        );
        let h = app1.snapshot().history[0].hash.clone();
        app1.handle(
            Event::SetFavorite {
                hash: h,
                favorite: true,
            },
            &wall(),
        );
    }
    let persisted_items = app1.snapshot().history.clone();
    assert_eq!(persisted_items.len(), 60);

    let mut app2 = linked_app();
    // Must not panic seeding a ring smaller than the persisted item count.
    app2.restore_history(persisted_items);
    assert_eq!(app2.snapshot().history.len(), 60);

    // The newest item ("item-59") must be deduped — it's within the
    // newest-`capacity` window that gets seeded.
    let acts = app2.handle(
        Event::FrameReceivedClipboard {
            peer_id: [7; 32],
            hash: [0xEE; 32],
            kind: Kind::Text,
            payload: b"item-59".to_vec(),
            preview: "item-59".to_string(),
            sensitive: false,
            lamport: 100,
            resync: false,
        },
        &wall(),
    );
    assert!(
        acts.iter().any(|a| matches!(a, Action::DuplicateDropped)),
        "the newest restored item must be seeded into the ring and dedup"
    );
}
