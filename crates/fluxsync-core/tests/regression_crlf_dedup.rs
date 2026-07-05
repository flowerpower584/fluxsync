//! REGRESSION (candidate C1): CRLF dedup hole / cross-platform ping-pong — FIXED.
//!
//! Fix: `fluxsync_core::canon_text(s)` maps `\r\n` and lone `\r` to `\n` then
//! trims. It is used by the daemon's `clipboard_dedup_hash` / `CmdOp::Push`
//! hashing and by the core `App` on `FrameReceivedClipboard` (text kinds only;
//! images untouched). So the SAME logical text copied with CRLF vs LF now
//! hashes EQUAL, and an LF read-back of a CRLF item is dedup-suppressed — no
//! bounce, no duplicate history entry.
//!
//! These tests assert the FIXED (normalized) behavior; they pass green only
//! while the canonicalization is in place.

use fluxsync_core::{canon_text, Action, App, Config, DedupRing, Event, StubWallClock};
use fluxsync_proto::Kind;

fn wall() -> StubWallClock {
    StubWallClock::new("14:32", 1_700_000_000_000)
}

/// Exact replica of the PATCHED `fluxsyncd::driver::clipboard_dedup_hash`:
///   `DedupRing::hash(canon_text(text).as_bytes()).into_bytes()`
/// This is also what the patched `CmdOp::Push` does: canon_text, then hash.
fn clipboard_dedup_hash(text: &str) -> [u8; 32] {
    DedupRing::hash(canon_text(text).as_bytes()).into_bytes()
}

/// Drive an App to the Linked phase, mirroring the in-crate tests.
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

/// CONTRACT: `canon_text` collapses CRLF and lone CR to LF (then trims), so
/// every line-ending flavor of the same logical text canonicalizes identically.
#[test]
fn canon_text_normalizes_all_line_endings() {
    assert_eq!(canon_text("a\r\nb"), "a\nb");
    assert_eq!(canon_text("a\rb"), "a\nb");
    assert_eq!(canon_text("a\nb"), "a\nb");
    assert_eq!(canon_text("  a\r\nb  "), "a\nb"); // trim preserved
    assert_eq!(canon_text("a\r\nb"), canon_text("a\nb"));
}

/// ROOT CAUSE FIXED: same logical text, CRLF vs LF, hashes EQUAL so dedup works
/// cross-platform. canon_text normalizes internal line endings before hashing.
#[test]
fn crlf_and_lf_text_hash_equal() {
    let crlf = "line1\r\nline2\r\nline3";
    let lf = "line1\nline2\nline3";

    let h_crlf = clipboard_dedup_hash(crlf);
    let h_lf = clipboard_dedup_hash(lf);

    eprintln!("CRLF hash = {h_crlf:02x?}");
    eprintln!("  LF hash = {h_lf:02x?}");
    eprintln!("equal?     = {}", h_crlf == h_lf);

    assert_eq!(
        h_crlf, h_lf,
        "dedup hash must normalize CRLF->LF: same logical text must hash identically"
    );
}

/// BEHAVIORAL (FIXED): Peer A copies CRLF text; this device (B) receives it
/// (FrameReceivedClipboard) and writes it to the OS clipboard. The OS hands the
/// text back LF-normalized; B's watcher hashes the read-back exactly like the
/// patched `clipboard_dedup_hash` (canon_text) and fires LocalClipboardChange.
///
/// B must recognize it as the same item it just received and SUPPRESS the echo
/// (no SendItem) — and must NOT create a duplicate history entry.
#[test]
fn crlf_inbound_then_lf_readback_is_suppressed() {
    let mut app = linked_app();

    let crlf = "hello\r\nworld";
    let lf_normalized = "hello\nworld"; // what the OS clipboard returns on read-back

    // 1) Inbound from peer A. Core recomputes the dedup hash itself via
    //    canon_text(payload), so the wire `hash` field value is irrelevant;
    //    pass the real CRLF payload.
    let inbound = app.handle(
        Event::FrameReceivedClipboard {
            peer_id: [0u8; 32],
            hash: [0; 32],
            kind: Kind::Text,
            payload: crlf.as_bytes().to_vec(),
            preview: crlf.into(),
            lamport: 5,
            sensitive: false,

            resync: false,
        },
        &wall(),
    );
    assert!(
        inbound
            .iter()
            .any(|a| matches!(a, Action::WriteClipboard { .. })),
        "inbound CRLF item should be written to the clipboard"
    );
    let hist_after_inbound = app.state.history.len();

    // 2) Watcher reads the OS-normalized (LF) text back. Daemon computes the
    //    hash exactly like the patched CmdOp::Push / clipboard_dedup_hash.
    let readback = app.handle(
        Event::LocalClipboardChange {
            hash: clipboard_dedup_hash(lf_normalized),
            kind: Kind::Text,
            payload: lf_normalized.as_bytes().to_vec(),
            preview: lf_normalized.into(),
            sensitive: false,
            lamport: 6,
        },
        &wall(),
    );

    let bounced = readback
        .iter()
        .any(|a| matches!(a, Action::SendItem { .. }));
    eprintln!("LF read-back emitted SendItem (bounce)? {bounced}");
    eprintln!("history entries = {}", app.state.history.len());

    assert!(
        !bounced,
        "LF read-back of a CRLF item must be suppressed — no bounce to the peer (ping-pong)"
    );
    assert_eq!(
        app.state.history.len(),
        hist_after_inbound,
        "LF read-back of a CRLF item must NOT add a duplicate history entry"
    );
}

/// CONTROL: byte-identical read-back (no CRLF involved) IS suppressed. Proves
/// the harness models echo-suppression correctly, so the CRLF behavior above is
/// attributable to canonicalization, not to dedup being inert.
#[test]
fn control_identical_readback_is_suppressed() {
    let mut app = linked_app();
    let text = "plain text no newlines";

    app.handle(
        Event::FrameReceivedClipboard {
            peer_id: [0u8; 32],
            hash: [0; 32],
            kind: Kind::Text,
            payload: text.as_bytes().to_vec(),
            preview: text.into(),
            lamport: 5,
            sensitive: false,

            resync: false,
        },
        &wall(),
    );
    let readback = app.handle(
        Event::LocalClipboardChange {
            hash: clipboard_dedup_hash(text),
            kind: Kind::Text,
            payload: text.as_bytes().to_vec(),
            preview: text.into(),
            sensitive: false,
            lamport: 6,
        },
        &wall(),
    );
    assert!(
        !readback
            .iter()
            .any(|a| matches!(a, Action::SendItem { .. })),
        "identical read-back must be suppressed (sanity: harness models dedup)"
    );
}
