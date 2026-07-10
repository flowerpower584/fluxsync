//! REGRESSION FIX2: two DISTINCT invalid-UTF-8 payloads must not collide in
//! the content-dedup ring.
//!
//! `App::handle`'s `Event::FrameReceivedClipboard` arm used to key the ring
//! on `canon_text(&String::from_utf8_lossy(payload))` for every non-Image
//! kind. `from_utf8_lossy` replaces ANY invalid byte with U+FFFD, so two
//! payloads that only differ in their invalid leading byte —
//! `[0xFF, b'h', b'e', b'l', b'l', b'o']` vs
//! `[0xFE, b'h', b'e', b'l', b'l', b'o']` — both lossy-decoded to the
//! identical string `"\u{FFFD}hello"` and collided: the second was silently
//! treated as a duplicate (Ack'd, `Action::DuplicateDropped`, never
//! delivered/recorded).
//!
//! Fix: `std::str::from_utf8(payload)` — valid UTF-8 still canonicalizes
//! (CRLF-normalized) exactly as before; invalid UTF-8 hashes the RAW payload
//! bytes instead, so two distinct invalid payloads can never collide.

use fluxsync_core::{Action, App, Config, Event, StubWallClock};
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

fn inbound_bytes(payload: Vec<u8>, hash: [u8; 32], lamport: u64, preview: &str) -> Event {
    Event::FrameReceivedClipboard {
        peer_id: [7; 32],
        hash,
        kind: Kind::Text,
        payload,
        preview: preview.to_string(),
        sensitive: false,
        lamport,
        resync: false,
    }
}

/// The exact reported pair: `[0xFF, "hello"]` and `[0xFE, "hello"]`. Both
/// must be delivered — neither is a duplicate of the other.
#[test]
fn distinct_invalid_utf8_payloads_are_both_delivered() {
    let mut app = linked_app();

    let mut ff = vec![0xFFu8];
    ff.extend_from_slice(b"hello");
    let mut fe = vec![0xFEu8];
    fe.extend_from_slice(b"hello");
    assert_ne!(ff, fe, "sanity: the two payloads must actually differ");

    let first_payload_actions =
        app.handle(inbound_bytes(ff.clone(), [1; 32], 1, "invalid-ff"), &wall());
    assert!(
        !first_payload_actions
            .iter()
            .any(|a| matches!(a, Action::DuplicateDropped)),
        "the first (0xFF) payload must never be a duplicate"
    );
    assert!(
        first_payload_actions
            .iter()
            .any(|a| matches!(a, Action::WriteClipboard { .. })),
        "the first (0xFF) payload must be applied"
    );

    let second_payload_actions =
        app.handle(inbound_bytes(fe.clone(), [2; 32], 2, "invalid-fe"), &wall());
    assert!(
        !second_payload_actions
            .iter()
            .any(|a| matches!(a, Action::DuplicateDropped)),
        "FIXED: the second (0xFE) payload must NOT be treated as a duplicate \
         of the first, even though both lossy-decode to the same \
         U+FFFD-prefixed string"
    );
    assert!(
        second_payload_actions
            .iter()
            .any(|a| matches!(a, Action::WriteClipboard { .. })),
        "FIXED: the second (0xFE) payload must be applied, not silently dropped"
    );

    assert_eq!(
        app.snapshot().history.len(),
        2,
        "FIXED: both distinct invalid-UTF-8 payloads must land in history"
    );
}

/// Control: the SAME invalid-UTF-8 payload sent twice IS a genuine duplicate
/// and must still be suppressed — the fix must not turn off dedup for
/// invalid UTF-8 altogether, only stop it from colliding with a DIFFERENT
/// invalid payload.
#[test]
fn identical_invalid_utf8_payload_is_still_deduped() {
    let mut app = linked_app();
    let mut payload = vec![0xFFu8];
    payload.extend_from_slice(b"hello");

    app.handle(
        inbound_bytes(payload.clone(), [1; 32], 1, "invalid-ff"),
        &wall(),
    );
    let acts = app.handle(
        inbound_bytes(payload, [1; 32], 2, "invalid-ff-again"),
        &wall(),
    );

    assert!(
        acts.iter().any(|a| matches!(a, Action::DuplicateDropped)),
        "resending the IDENTICAL invalid-UTF-8 payload must still dedup"
    );
    assert_eq!(app.snapshot().history.len(), 1);
}

/// Control (unchanged behaviour): valid UTF-8 text still CRLF-canonicalizes,
/// so a `\r\n` copy and a later `\n` copy of the same logical text are still
/// deduped as before this fix — mirrors `regression_crlf_dedup.rs`, kept
/// here too so this file stands on its own as proof the invalid-UTF-8 branch
/// change didn't regress the valid branch.
#[test]
fn valid_utf8_crlf_dedup_is_unchanged() {
    let mut app = linked_app();
    app.handle(
        inbound_bytes(b"line1\r\nline2".to_vec(), [3; 32], 1, "line1\r\nline2"),
        &wall(),
    );
    let acts = app.handle(
        inbound_bytes(b"line1\nline2".to_vec(), [4; 32], 2, "line1\nline2"),
        &wall(),
    );

    assert!(
        acts.iter().any(|a| matches!(a, Action::DuplicateDropped)),
        "a CRLF copy and its LF-normalized twin must still dedup as one item"
    );
    assert_eq!(app.snapshot().history.len(), 1);
}
