//! REGRESSION FIX1 (P0): a revoked/timed-out peer's Ask-parked pending items
//! must be dropped SELECTIVELY — a different peer's still-pending item must
//! survive. Before this fix, `Event::FrameReceivedClipboard` carried no
//! sender peer id, so `App`'s `pending`/`pending_payloads` had no way to key
//! an item to the peer that sent it; the only wipe available was
//! `drop_pending_all` (manual unpair, the security wipes), and NOTHING
//! dropped a single revoked peer's parked items — they lived forever (or
//! until an unrelated wipe-all event happened to clear the whole queue,
//! taking every OTHER peer's pending items down with it).
//!
//! Fix: `Event::FrameReceivedClipboard.peer_id` + `PendingItem`/
//! `PendingPayload.peer_id` + `App::drop_pending_for(peer_id)` (the
//! selective sibling of `drop_pending_all`), driven by a new
//! `Event::PeerRevoked { peer_id }`.

use fluxsync_core::{Action, App, Config, Direction, Event, FirewallPolicy, Rule, StubWallClock};
use fluxsync_proto::Kind;

const PEER_A: [u8; 32] = [0xAA; 32];
const PEER_B: [u8; 32] = [0xBB; 32];

fn wall() -> StubWallClock {
    StubWallClock::new("14:32", 1_700_000_000_000)
}

fn linked_app() -> App {
    let mut app = App::new(Config::default());
    app.set_firewall(FirewallPolicy {
        enabled: true,
        text: Rule::Ask,
        url: Rule::Ask,
        code: Rule::Ask,
        image: Rule::Ask,
        sensitive: Rule::Ask,
    });
    app.handle(Event::ToggleOn, &wall());
    app.handle(
        Event::PeerSeen {
            peer_id: PEER_A,
            name: "Peer A".into(),
        },
        &wall(),
    );
    app.handle(Event::HandshakeOk, &wall());
    app
}

fn inbound_from(peer_id: [u8; 32], n: u8) -> Event {
    Event::FrameReceivedClipboard {
        peer_id,
        hash: [n; 32],
        kind: Kind::Text,
        payload: format!("secret-from-peer-{n}").into_bytes(),
        preview: format!("secret-from-peer-{n}"),
        sensitive: false,
        lamport: u64::from(n),
        resync: false,
    }
}

fn holds_sync_action(actions: &[Action]) -> bool {
    actions
        .iter()
        .any(|a| matches!(a, Action::SendItem { .. } | Action::WriteClipboard { .. }))
}

/// Two peers each get an item parked under `Ask`. Revoking peer A must drop
/// ONLY A's parked item (both the display row and the held payload) — B's
/// must survive untouched, resolvable exactly as before.
#[test]
fn revoke_drops_only_that_peers_pending_items() {
    let mut app = linked_app();

    let a_actions = app.handle(inbound_from(PEER_A, 1), &wall());
    assert!(
        !holds_sync_action(&a_actions),
        "precondition: A's item must be parked (Ask), not applied"
    );
    let b_actions = app.handle(inbound_from(PEER_B, 2), &wall());
    assert!(
        !holds_sync_action(&b_actions),
        "precondition: B's item must be parked (Ask), not applied"
    );

    assert_eq!(app.state.pending.len(), 2, "both items must be parked");
    let a_hash = hex32(&[1u8; 32]);
    let b_hash = hex32(&[2u8; 32]);
    let a_item = app
        .state
        .pending
        .iter()
        .find(|p| p.hash == a_hash)
        .expect("A's item must be pending");
    assert_eq!(
        a_item.peer_id.as_deref(),
        Some(hex32(&PEER_A).as_str()),
        "the parked item must be tagged with the peer that sent it"
    );

    // ── Revoke peer A ──
    let revoke_actions = app.handle(Event::PeerRevoked { peer_id: PEER_A }, &wall());
    let dropped_hashes: Vec<[u8; 32]> = revoke_actions
        .iter()
        .find_map(|a| match a {
            Action::PendingDropped { hashes } => Some(hashes.clone()),
            _ => None,
        })
        .unwrap_or_default();
    assert_eq!(
        dropped_hashes,
        vec![[1u8; 32]],
        "PeerRevoked must report exactly A's dropped content hash"
    );

    // A's row is gone; B's survives.
    assert_eq!(
        app.state.pending.len(),
        1,
        "only A's parked item should be dropped"
    );
    assert_eq!(app.state.pending[0].hash, b_hash, "B's row must remain");

    // A's payload is gone too: resolving A's hash now emits no held action.
    let resolve_a = app.handle(
        Event::ResolvePending {
            hash: a_hash,
            allow: true,
        },
        &wall(),
    );
    assert!(
        !holds_sync_action(&resolve_a),
        "A's payload must be gone after revoke — nothing left to resolve"
    );

    // B's payload survives intact: resolving B's hash still applies it.
    let resolve_b = app.handle(
        Event::ResolvePending {
            hash: b_hash,
            allow: true,
        },
        &wall(),
    );
    assert!(
        resolve_b
            .iter()
            .any(|a| matches!(a, Action::WriteClipboard { .. })),
        "B's payload must still be resolvable after A's revoke"
    );
    assert_eq!(
        resolve_b[0],
        Action::WriteClipboard {
            kind: Kind::Text,
            payload: b"secret-from-peer-2".to_vec(),
            sensitive: false,
        }
    );
}

/// Revoking a peer with nothing parked is a harmless no-op — no
/// `Action::PendingDropped` at all (not even an empty one), and any OTHER
/// peer's parked items are left completely alone.
#[test]
fn revoke_with_nothing_parked_for_that_peer_is_noop() {
    let mut app = linked_app();
    app.handle(inbound_from(PEER_B, 9), &wall());
    assert_eq!(app.state.pending.len(), 1);

    let actions = app.handle(Event::PeerRevoked { peer_id: PEER_A }, &wall());
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::PendingDropped { .. })),
        "no PendingDropped signal when nothing was parked for the revoked peer"
    );
    assert_eq!(
        app.state.pending.len(),
        1,
        "an unrelated peer's revoke must not touch B's pending item"
    );
}

/// Control: `ManualUnpair` is the pre-existing wipe-ALL path and must still
/// drop every peer's parked items, not just one — distinguishing it from the
/// new selective `PeerRevoked` path.
#[test]
fn manual_unpair_still_wipes_every_peers_pending_items() {
    let mut app = linked_app();
    app.handle(inbound_from(PEER_A, 1), &wall());
    app.handle(inbound_from(PEER_B, 2), &wall());
    assert_eq!(app.state.pending.len(), 2, "precondition: both parked");

    app.handle(Event::ManualUnpair, &wall());

    assert!(
        app.state.pending.is_empty(),
        "ManualUnpair must still wipe every peer's parked items"
    );
}

/// Control: `Event::PeerLost` (a transient disconnect, e.g. a wifi blip)
/// must NOT drop any pending item — only an explicit revoke/timeout
/// (`PeerRevoked`) may.
#[test]
fn peer_lost_does_not_drop_pending() {
    let mut app = linked_app();
    app.handle(inbound_from(PEER_A, 1), &wall());
    assert_eq!(app.state.pending.len(), 1);

    let actions = app.handle(Event::PeerLost { peer_id: PEER_A }, &wall());
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::PendingDropped { .. })),
        "PeerLost must never emit PendingDropped"
    );
    assert_eq!(
        app.state.pending.len(),
        1,
        "a transient disconnect must not destroy the user's pending Ask decision"
    );

    let _ = Direction::Inbound;
}

/// Lowercase hex of a 32-byte id — mirrors the private `app::hex32` helper
/// so this test can compute the same `PendingItem.hash`/`peer_id` keys
/// without reaching into `App`'s internals.
fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap());
        s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap());
    }
    s
}
