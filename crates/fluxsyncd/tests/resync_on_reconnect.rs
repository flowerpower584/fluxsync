//! Integration test: resync-on-reconnect (resync-1).
//!
//! Two in-process daemons pair over loopback via the *real* IPC pairing
//! verbs (`PairShow` -> `PairAccept { addr }` -> `PairConfirm` x2, FS-052 —
//! same dance as `chaos_harness.rs`'s `pair_daemons`, ported to the
//! in-process `DaemonConfig`/`run()` harness instead of real subprocesses),
//! never `DaemonConfig::test_pair`: the resync mechanism only kicks in once
//! a real Noise handshake completes and both sides exchange `Msg::Hello`
//! (`Action::OpenSession` fires the Hello on both sides at the
//! Handshaking -> Linked transition, which is also where `resync-1` gets
//! negotiated — see `driver.rs`'s `Msg::Hello` arm).
//!
//! `B` is torn down and rebooted with the same identity + keystore dir (so
//! `peers.json` rehydrates the trust relationship — FS-039), then driven
//! back to `Linked` with an explicit, address-targeted `PairAccept` (the
//! documented manual-reconnect path: an already-trusted, non-pending peer
//! skips the FS-052 confirm gate). mDNS is disabled throughout; this repo's
//! chaos-harness learnings established that relying on mDNS on loopback is
//! flaky enough to make a deterministic test impossible.
//!
//! Scenarios:
//! 1. `missed_item_resyncs_after_relink` — an item pushed while `B` is down
//!    outlives `A`'s retransmit budget (~14s) and is dropped from inflight,
//!    then reappears in `B`'s history once `B` relinks, served out of `A`'s
//!    outbox (`items_resynced` on `A` advances).
//! 2. `sensitive_item_never_resyncs` — a sensitive-shaped item pushed
//!    alongside a normal one, both missed the same way, never enters the
//!    outbox (`outbox.rs`'s security invariant) and so is never re-offered,
//!    while the normal item recovers.

#![cfg(unix)]

use fluxsync_crypto::Identity;
use fluxsyncd::{
    cmd::{CmdData, CmdOp, CmdRequest, CmdResponse},
    run, DaemonConfig,
};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UdpSocket, UnixStream};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

/// `MAX_RETRANSMIT` (6) * `RETRANSMIT_INTERVAL` (2s) from `driver.rs` is a
/// 12-14s nominal budget (see `chaos_harness.rs`'s `RETRANSMIT_BUDGET`), but
/// under real scheduling the retransmit tick's own cadence is not a strict
/// clock — this file's development runs observed the six attempts landing
/// anywhere from 2s to 4s apart, pushing the actual drop past 20s more than
/// once. 28s gives real margin on top of the worst observed case. An item
/// pushed and never acked survives roughly this long before the sender
/// gives up and drops it from `inflight` (only a `tracing::warn` fires
/// there, no IPC-observable counter — see the module doc in
/// `chaos_harness.rs`). This is the one deliberate plain sleep in this
/// file; everywhere else uses `wait_until`.
const RETRANSMIT_EXHAUSTION_WAIT: Duration = Duration::from_secs(28);

/// Generous envelope for "relinked after an explicit reconnect", mirroring
/// `chaos_harness.rs`'s `RECONNECT_ENVELOPE`.
const RECONNECT_ENVELOPE: Duration = Duration::from_secs(30);

async fn pick_free_udp_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").await.expect("pick port");
    s.local_addr().expect("port").port()
}

async fn ipc_send_recv(path: &Path, req: CmdRequest) -> CmdResponse {
    let mut stream = UnixStream::connect(path).await.expect("connect ipc");
    stream
        .write_all(b"{\"subscribe\":\"cmd\"}\n")
        .await
        .expect("subscribe");
    stream.flush().await.expect("flush subscribe");
    let line = serde_json::to_string(&req).unwrap() + "\n";
    stream.write_all(line.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let (read, _w) = stream.into_split();
    let mut reader = BufReader::new(read);
    let mut buf = String::new();
    reader.read_line(&mut buf).await.unwrap();
    serde_json::from_str(buf.trim()).expect("parse resp")
}

async fn wait_until<F, Fut>(deadline: Duration, mut probe: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = std::time::Instant::now();
    loop {
        if probe().await {
            return true;
        }
        if start.elapsed() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn cfg_for(id: &Identity, port: u16, keystore: &Path, ipc: &Path, name: &str) -> DaemonConfig {
    let mut cfg = DaemonConfig::new(id.clone(), port, ipc.to_path_buf());
    cfg.udp_bind = "127.0.0.1".into();
    cfg.keystore_dir = Some(keystore.to_path_buf());
    cfg.disable_mdns = true;
    cfg.disable_clipboard = true;
    cfg.peer_name_self = name.into();
    cfg
}

async fn status(ipc: &Path) -> Box<fluxsync_core::State> {
    let resp = ipc_send_recv(ipc, CmdRequest { id: 1, op: CmdOp::Status }).await;
    match resp.data {
        Some(CmdData::State(s)) => s,
        other => panic!("expected State, got {other:?}"),
    }
}

/// Fallible sibling of `ipc_send_recv`: a freshly-spawned daemon can have
/// its ipc socket *file* created slightly before the listener actually
/// accepts connections, so probing this during startup must treat a
/// connection refusal as "not up yet", not a hard test failure.
async fn ipc_try_send_recv(path: &Path, req: CmdRequest) -> Option<CmdResponse> {
    let mut stream = UnixStream::connect(path).await.ok()?;
    stream.write_all(b"{\"subscribe\":\"cmd\"}\n").await.ok()?;
    stream.flush().await.ok()?;
    let line = serde_json::to_string(&req).unwrap() + "\n";
    stream.write_all(line.as_bytes()).await.ok()?;
    stream.flush().await.ok()?;
    let (read, _w) = stream.into_split();
    let mut reader = BufReader::new(read);
    let mut buf = String::new();
    reader.read_line(&mut buf).await.ok()?;
    serde_json::from_str(buf.trim()).ok()
}

async fn ipc_up(ipc: &Path, dur: Duration) -> bool {
    wait_until(dur, || async {
        if !ipc.exists() {
            return false;
        }
        ipc_try_send_recv(ipc, CmdRequest { id: 0, op: CmdOp::Status })
            .await
            .is_some_and(|r| r.ok)
    })
    .await
}

async fn set_threshold(ipc: &Path, value: u8) {
    let r = ipc_send_recv(ipc, CmdRequest { id: 0, op: CmdOp::SetThreshold { value } }).await;
    assert!(r.ok, "set-threshold failed: {r:?}");
}

async fn push(ipc: &Path, text: &str) {
    let r = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 2,
            op: CmdOp::Push { text: text.into() },
        },
    )
    .await;
    assert!(r.ok, "push {text:?} failed: {r:?}");
}

async fn clear_history(ipc: &Path, include_favorites: bool) {
    let r = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 9,
            op: CmdOp::ClearHistory { include_favorites },
        },
    )
    .await;
    assert!(r.ok, "clear-history failed: {r:?}");
}

async fn history_has(ipc: &Path, preview: &str) -> bool {
    status(ipc).await.history.iter().any(|h| h.preview == preview)
}

/// Full history row matching `preview`, so callers can inspect fields like
/// `resync` beyond the plain presence check `history_has` does.
async fn history_item(ipc: &Path, preview: &str) -> Option<fluxsync_core::HistoryItem> {
    status(ipc).await.history.iter().find(|h| h.preview == preview).cloned()
}

async fn phase_linked(ipc: &Path) -> bool {
    status(ipc).await.phase == "linked"
}

async fn items_resynced(ipc: &Path) -> u64 {
    status(ipc).await.metrics.as_ref().map_or(0, |m| m.items_resynced)
}

/// DEFECT 1 regression proof: a resync-delivered item's `WriteClipboard`
/// action was stripped (`Action::ResyncApplySuppressed`) instead of applied.
/// Clipboard I/O is disabled in this harness (`disable_clipboard = true`),
/// so this dedicated counter is the only IPC-observable signal — see
/// `ConnectionMetrics::resync_applies_suppressed`.
async fn resync_applies_suppressed(ipc: &Path) -> u64 {
    status(ipc)
        .await
        .metrics
        .as_ref()
        .map_or(0, |m| m.resync_applies_suppressed)
}

// ── Real IPC pairing (PairShow -> PairAccept -> PairConfirm x2) ──
// Mirrors chaos_harness.rs's helpers of the same names/shape, ported from
// the subprocess `Daemon` wrapper to plain ipc paths for the in-process
// harness used by two_daemons.rs / rekey.rs / vault_persist.rs.

async fn pair_show(ipc: &Path) -> (String, String) {
    let resp = ipc_send_recv(ipc, CmdRequest { id: 10, op: CmdOp::PairShow {} }).await;
    match resp.data {
        Some(CmdData::PairInfo { peer_id_hex, pubkey_b32, .. }) => (peer_id_hex, pubkey_b32),
        other => panic!("unexpected pair_show response: {other:?}"),
    }
}

async fn pair_accept(ipc: &Path, pubkey_b32: String, peer_name: &str, addr: SocketAddr) {
    let resp = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 11,
            op: CmdOp::PairAccept {
                pubkey_b32,
                name: peer_name.to_string(),
                addr: Some(addr.to_string()),
            },
        },
    )
    .await;
    assert!(resp.ok, "pair_accept failed: {resp:?}");
}

async fn pending_peer_id(ipc: &Path) -> Option<String> {
    let resp = ipc_send_recv(ipc, CmdRequest { id: 12, op: CmdOp::PairPending {} }).await;
    match resp.data {
        Some(CmdData::PendingPairs(v)) if !v.is_empty() => Some(v[0].peer_id.clone()),
        _ => None,
    }
}

/// FS-052: a fresh pair (either side) lands in `PairPending` and must be
/// explicitly confirmed or the 90s reaper revokes it.
async fn confirm_pending(ipc: &Path, dur: Duration) {
    let start = std::time::Instant::now();
    loop {
        if let Some(peer_id) = pending_peer_id(ipc).await {
            let resp = ipc_send_recv(
                ipc,
                CmdRequest {
                    id: 13,
                    op: CmdOp::PairConfirm { peer_id, accept: true },
                },
            )
            .await;
            assert!(resp.ok, "pair_confirm failed: {resp:?}");
            return;
        }
        assert!(start.elapsed() < dur, "no pending pair to confirm within {dur:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Full real pairing over loopback: `a` shows its pairing info, `b`
/// explicitly trusts + dials `a` (manual-address path, no mDNS reliance),
/// both land `Linked` via a real Noise handshake, then both confirm the
/// FS-052 pending entry. Returns `a`'s base32 static pubkey so the caller
/// can later drive an explicit reconnect-by-address after `b` restarts
/// (same "no unicast redial hint" gap documented in `docs/CHAOS.md`: every
/// production `StoredPeer` write persists `last_addr: None`, so a rebooted
/// daemon needs the pubkey handed back explicitly to redial without mDNS).
async fn pair_daemons(ipc_a: &Path, addr_a: SocketAddr, ipc_b: &Path) -> String {
    let (_a_id, a_pub) = pair_show(ipc_a).await;
    pair_accept(ipc_b, a_pub.clone(), "device-a", addr_a).await;

    let linked_a = wait_until(Duration::from_secs(10), || async { phase_linked(ipc_a).await }).await;
    let linked_b = wait_until(Duration::from_secs(10), || async { phase_linked(ipc_b).await }).await;
    assert!(linked_a, "a: did not reach linked phase while pairing");
    assert!(linked_b, "b: did not reach linked phase while pairing");

    confirm_pending(ipc_a, Duration::from_secs(10)).await;
    confirm_pending(ipc_b, Duration::from_secs(10)).await;
    a_pub
}

/// Spawn `A` and `B`, pair them for real, floor the battery threshold on
/// both (a real host below the default 20% would otherwise gate sync —
/// unrelated to what these tests exercise), and prove a sanity item syncs.
///
/// Returns everything a scenario needs to shut `B` down and restart it:
/// `(ipc_a, shutdown_a, h_a, id_b, keystore_b, ipc_b, port_b, addr_a, a_pub)`.
#[allow(clippy::type_complexity)]
async fn boot_and_link() -> (
    PathBuf,
    CancellationToken,
    tokio::task::JoinHandle<anyhow::Result<()>>,
    Identity,
    PathBuf,
    PathBuf,
    u16,
    SocketAddr,
    String,
) {
    let id_a = Identity::generate();
    let id_b = Identity::generate();

    let port_a = pick_free_udp_port().await;
    let port_b = pick_free_udp_port().await;
    assert_ne!(port_a, port_b);

    let dir = tempfile::tempdir().expect("tempdir");
    let dir = Box::leak(Box::new(dir)); // kept alive for the whole test
    let keystore_a = dir.path().join("ks-a");
    let keystore_b = dir.path().join("ks-b");
    std::fs::create_dir(&keystore_a).unwrap();
    std::fs::create_dir(&keystore_b).unwrap();
    let ipc_a = keystore_a.join("a.sock");
    let ipc_b = keystore_b.join("b.sock");

    let addr_a: SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();

    let shutdown_a = CancellationToken::new();
    let shutdown_b = CancellationToken::new();
    let h_a = tokio::spawn(run(
        cfg_for(&id_a, port_a, &keystore_a, &ipc_a, "device-a"),
        shutdown_a.clone(),
    ));
    let h_b = tokio::spawn(run(
        cfg_for(&id_b, port_b, &keystore_b, &ipc_b, "device-b"),
        shutdown_b.clone(),
    ));

    assert!(ipc_up(&ipc_a, Duration::from_secs(5)).await, "a: ipc not up");
    assert!(ipc_up(&ipc_b, Duration::from_secs(5)).await, "b: ipc not up");

    set_threshold(&ipc_a, 5).await;
    set_threshold(&ipc_b, 5).await;

    let a_pub = pair_daemons(&ipc_a, addr_a, &ipc_b).await;

    let sanity = "resync-sanity-item";
    push(&ipc_a, sanity).await;
    assert!(
        wait_until(Duration::from_secs(5), || async { history_has(&ipc_b, sanity).await }).await,
        "sanity item never reached b before the resync scenario started"
    );

    // Shut b down cleanly; a stays up and un-toggled from here on.
    shutdown_b.cancel();
    let _ = timeout(Duration::from_secs(5), h_b).await.expect("b: clean shutdown hung");

    (ipc_a, shutdown_a, h_a, id_b, keystore_b, ipc_b, port_b, addr_a, a_pub)
}

/// Restart `b` with the same identity + keystore dir (so `peers.json`
/// rehydrates A's trust) and drive relink with an explicit `PairAccept`
/// (the manual-reconnect path: already-trusted + not pending skips the
/// FS-052 confirm gate — see `pair_daemons`'s doc and `driver.rs`'s
/// `already_confirmed` check).
async fn restart_b_and_relink(
    id_b: &Identity,
    keystore_b: &Path,
    ipc_b: &Path,
    addr_a: SocketAddr,
    a_pub: String,
    ipc_a: &Path,
) -> (CancellationToken, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let port_b2 = pick_free_udp_port().await;
    let shutdown_b2 = CancellationToken::new();
    let h_b2 = tokio::spawn(run(
        cfg_for(id_b, port_b2, keystore_b, ipc_b, "device-b-v2"),
        shutdown_b2.clone(),
    ));
    assert!(ipc_up(ipc_b, Duration::from_secs(5)).await, "b2: ipc not up after restart");

    pair_accept(ipc_b, a_pub, "device-a", addr_a).await;

    let relinked_a = wait_until(RECONNECT_ENVELOPE, || async { phase_linked(ipc_a).await }).await;
    let relinked_b = wait_until(RECONNECT_ENVELOPE, || async { phase_linked(ipc_b).await }).await;
    assert!(relinked_a, "a: did not recover to linked within {RECONNECT_ENVELOPE:?} of b's restart");
    assert!(relinked_b, "b2: did not reach linked within {RECONNECT_ENVELOPE:?} of restart");

    (shutdown_b2, h_b2)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missed_item_resyncs_after_relink() {
    let _ = tracing_subscriber::fmt::try_init();

    let (ipc_a, shutdown_a, h_a, id_b, keystore_b, ipc_b, _port_b, addr_a, a_pub) =
        boot_and_link().await;

    // ── b is down: push an item it will never see live ──
    let missed = "resync-missed-item";
    push(&ipc_a, missed).await;

    // Also push a second missed item that the user clears from `a` (a
    // non-favorite) before `b` ever relinks. "Clear clipboard history" is
    // local-only + must purge a's resync outbox: if it didn't, this item
    // would still resync onto `b` even though the user deleted it on `a`.
    // `missed` is pinned as a favorite first so the blanket
    // `ClearHistory{include_favorites: false}` below — which drops every
    // non-favorite, not just `cleared` — doesn't also wipe it out from under
    // the existing resync-recovery assertions further down; favorite status
    // has no bearing on resync/outbox behavior, only on vault TTL/cap.
    let cleared = "resync-cleared-item";
    push(&ipc_a, cleared).await;
    assert!(
        history_has(&ipc_a, cleared).await,
        "cleared-to-be item never reached a's own history"
    );
    let missed_hash = history_item(&ipc_a, missed)
        .await
        .expect("missed item must be in a's history before pinning")
        .hash;
    let fav_resp = ipc_send_recv(
        &ipc_a,
        CmdRequest {
            id: 8,
            op: CmdOp::SetFavorite { hash: missed_hash, favorite: true },
        },
    )
    .await;
    assert!(fav_resp.ok, "set-favorite on missed item failed: {fav_resp:?}");

    clear_history(&ipc_a, false).await;
    assert!(
        !history_has(&ipc_a, cleared).await,
        "ClearHistory did not remove the item from a's in-memory history"
    );
    assert!(
        history_has(&ipc_a, missed).await,
        "ClearHistory{{include_favorites: false}} must keep a favorited item"
    );

    // Deliberate plain sleep: no IPC-observable signal fires when an item
    // is dropped from `inflight` after MAX_RETRANSMIT (only a
    // `tracing::warn`, see the module doc), and this is the one thing this
    // test wants to be genuinely time-based rather than polled — waiting
    // past the retransmit budget proves the item can ONLY reappear via the
    // resync-1 outbox path, not a lucky in-flight retransmit landing after
    // b comes back.
    tokio::time::sleep(RETRANSMIT_EXHAUSTION_WAIT).await;

    let items_resynced_before = items_resynced(&ipc_a).await;

    let (shutdown_b2, h_b2) =
        restart_b_and_relink(&id_b, &keystore_b, &ipc_b, addr_a, a_pub, &ipc_a).await;

    assert!(
        wait_until(Duration::from_secs(15), || async { history_has(&ipc_b, missed).await }).await,
        "missed item never resynced onto b within 15s of relink"
    );

    // Client-side marker (this fix): a pull-resynced item must land in
    // history with `resync == true` so Android's poll loop can mark it seen
    // without applying it to the OS clipboard, while a normal, live-pushed
    // item (the `boot_and_link` sanity item, delivered to b before it went
    // down) stays `resync == false`.
    let missed_item = history_item(&ipc_b, missed)
        .await
        .expect("missed item must be present in b's history after resync");
    assert!(missed_item.resync, "pull-resynced item must have resync == true");

    let sanity_item = history_item(&ipc_b, "resync-sanity-item")
        .await
        .expect("sanity item (live-pushed before b went down) must survive in b's history");
    assert!(!sanity_item.resync, "a live-pushed item must have resync == false");

    assert!(
        wait_until(Duration::from_secs(5), || async {
            items_resynced(&ipc_a).await > items_resynced_before
        })
        .await,
        "a's items_resynced counter never advanced — item may have arrived by a path other than \
         resync-1's outbox"
    );

    // The item cleared from a's history (and outbox) before b relinked must
    // never surface on b — same ordering-based bound used elsewhere in this
    // suite: resync-1 offers the whole outbox in one Hello round trip, so a
    // few extra seconds past the confirmed resync above rules out a late
    // arrival, not just "hasn't arrived yet".
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !history_has(&ipc_b, cleared).await,
        "a cleared (non-favorite) item leaked onto b via the resync outbox — ClearHistory must \
         purge the outbox"
    );
    assert_eq!(
        items_resynced(&ipc_a).await,
        items_resynced_before + 1,
        "a's items_resynced advanced by more than the still-pending missed item alone — the \
         cleared item may have been served from the outbox too"
    );

    shutdown_a.cancel();
    shutdown_b2.cancel();
    let _ = timeout(Duration::from_secs(5), h_a).await.expect("a: clean shutdown hung");
    let _ = timeout(Duration::from_secs(5), h_b2).await.expect("b2: clean shutdown hung");
}

/// H2 regression: `CmdOp::ClearHistory` is LOCAL-ONLY by design — it never
/// tells the peer to forget anything. `boot_and_link`'s sanity item was
/// delivered to `b` live (so `b`'s own resync outbox holds it) BEFORE `a`
/// clears it here; unlike `missed_item_resyncs_after_relink`'s "cleared"
/// item (which `b` never saw at all), this is the actual resurrection path:
/// `b` still has it, so on relink `b`'s `ResyncOffer` re-offers the exact
/// hash `a` just deleted. Without the cleared-hash tombstone, `a`'s own
/// `missing_resync_hashes` would call it missing (gone from both history
/// and outbox) and pull it straight back. A second, genuinely-missed item
/// pushed while `b` is down proves the tombstone is selective — it only
/// blocks the one hash `a` deliberately cleared, not resync in general.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cleared_item_does_not_resurrect_via_peer_outbox() {
    let _ = tracing_subscriber::fmt::try_init();

    let (ipc_a, shutdown_a, h_a, id_b, keystore_b, ipc_b, _port_b, addr_a, a_pub) =
        boot_and_link().await;

    // `resync-sanity-item` was pushed and confirmed delivered to b (still
    // live) inside `boot_and_link`, so b's own outbox already holds it.
    let cleared = "resync-sanity-item";
    assert!(
        history_has(&ipc_a, cleared).await,
        "sanity item must still be in a's history before it's cleared"
    );

    clear_history(&ipc_a, false).await;
    assert!(
        !history_has(&ipc_a, cleared).await,
        "ClearHistory did not remove the sanity item from a's history"
    );

    // A genuinely-missed, never-cleared item: b was already down when this
    // was pushed, so it can only reach b via resync-1 — proves the
    // tombstone above doesn't block unrelated pulls.
    let missed = "resync-h2-genuinely-missed-item";
    push(&ipc_a, missed).await;

    // Same deliberate plain sleep as the other scenarios in this file —
    // past the retransmit budget before b comes back.
    tokio::time::sleep(RETRANSMIT_EXHAUSTION_WAIT).await;

    let (shutdown_b2, h_b2) =
        restart_b_and_relink(&id_b, &keystore_b, &ipc_b, addr_a, a_pub, &ipc_a).await;

    assert!(
        wait_until(Duration::from_secs(15), || async { history_has(&ipc_b, missed).await }).await,
        "genuinely-missed item never resynced onto b within 15s of relink"
    );

    // Ordering-based bound, not a blind sleep: resync-1 offers the whole
    // outbox in one Hello-triggered round trip, so if the cleared item were
    // ever going to resurrect it would have landed in the same window as
    // the genuinely-missed item's confirmed arrival above.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !history_has(&ipc_a, cleared).await,
        "H2: a's own ClearHistory was resurrected by b's ResyncOffer for the same hash"
    );

    shutdown_a.cancel();
    shutdown_b2.cancel();
    let _ = timeout(Duration::from_secs(5), h_a).await.expect("a: clean shutdown hung");
    let _ = timeout(Duration::from_secs(5), h_b2).await.expect("b2: clean shutdown hung");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sensitive_item_never_resyncs() {
    let _ = tracing_subscriber::fmt::try_init();

    let (ipc_a, shutdown_a, h_a, id_b, keystore_b, ipc_b, _port_b, addr_a, a_pub) =
        boot_and_link().await;

    // Canonical 64-char lowercase hex fixture from
    // `fluxsync_core::classify`'s own `detects_hex64` test — deliberately
    // not inventing a new "looks sensitive" string.
    let secret = "deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef";
    let control = "resync-control-item";

    // ── b is down: push a sensitive-shaped item AND a normal one ──
    push(&ipc_a, control).await;
    push(&ipc_a, secret).await;

    // Same deliberate plain sleep as missed_item_resyncs_after_relink —
    // past the retransmit budget for both items before b comes back.
    tokio::time::sleep(RETRANSMIT_EXHAUSTION_WAIT).await;

    let items_resynced_before = items_resynced(&ipc_a).await;

    let (shutdown_b2, h_b2) =
        restart_b_and_relink(&id_b, &keystore_b, &ipc_b, addr_a, a_pub, &ipc_a).await;

    // The control item proves resync actually ran.
    assert!(
        wait_until(Duration::from_secs(15), || async { history_has(&ipc_b, control).await }).await,
        "control item never resynced onto b within 15s of relink"
    );
    assert!(
        !history_has(&ipc_b, secret).await,
        "sensitive item leaked into b's history via resync"
    );

    // Ordering-based bound, not a blind sleep: resync-1 offers the whole
    // outbox in one Hello-triggered round trip, so if the sensitive item
    // were ever going to arrive it would have landed in the same window as
    // the control item above. A few extra seconds of margin confirms it
    // really isn't coming, not just "hasn't arrived yet".
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !history_has(&ipc_b, secret).await,
        "sensitive item appeared in b's history after a delay — resync must have served it late"
    );

    // Only the control item should have been served out of a's outbox —
    // the sensitive item was never inserted into it in the first place
    // (outbox.rs's security invariant), so it can't have been counted here
    // either.
    assert_eq!(
        items_resynced(&ipc_a).await,
        items_resynced_before + 1,
        "a's items_resynced advanced by more than the control item alone — \
         the sensitive item may have been served from the outbox"
    );

    shutdown_a.cancel();
    shutdown_b2.cancel();
    let _ = timeout(Duration::from_secs(5), h_a).await.expect("a: clean shutdown hung");
    let _ = timeout(Duration::from_secs(5), h_b2).await.expect("b2: clean shutdown hung");
}

/// DEFECT 1 + DEFECT 2 regression: the live "every macOS relaunch" bug.
///
/// Extends the two-cycle structure above with a SECOND relink of `b` rather
/// than duplicating a new harness:
///  * Cycle 1 proves a missed item — deliberately CRLF-bearing text, DEFECT
///    2(a)'s prime suspect (a hash mismatch from text normalization between
///    the wire hash and a locally-recomputed history hash) — still resyncs,
///    and that its `WriteClipboard` apply was suppressed
///    (`resync_applies_suppressed`, DEFECT 1) rather than silently replacing
///    whatever was already on `b`'s OS-clipboard-equivalent (clipboard I/O
///    is disabled in this harness, so the dedicated counter is the
///    IPC-observable stand-in the module doc's "add a test-visible counter"
///    escape hatch calls for).
///  * Cycle 2 kills `b` a SECOND time and restarts it fresh again. If the
///    held-check that should stop a repeat pull were broken (DEFECT 2 — the
///    vault-persist race that dropped the resynced item before the next
///    boot's vault load could see it, or a hash mismatch that made the
///    held-check never match), `a` would serve the same item again on this
///    second relink and `items_resynced` would advance a second time. It
///    must not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resync_apply_suppressed_and_loop_stops_after_second_relink() {
    let _ = tracing_subscriber::fmt::try_init();

    let (ipc_a, shutdown_a, h_a, id_b, keystore_b, ipc_b, _port_b, addr_a, a_pub) =
        boot_and_link().await;

    // CRLF-bearing text: if the offered hash (computed by `a` over its own
    // outbox entry) ever diverged from the hash `b` recomputes for the SAME
    // logical content, the held-check would miss forever and this whole
    // test would hang on the cycle-2 assertion below instead of passing.
    // No TRAILING \r\n here (only an internal one, between the two lines):
    // `CmdOp::Push` trims the pushed text's outer whitespace before hashing
    // AND before stamping `HistoryItem.preview`, so a trailing CRLF in this
    // literal would never round-trip back out of `history_has`'s exact
    // string match — that's a test-harness pitfall, not a resync-1 bug.
    let missed = "resync-crlf-item\r\nsecond line";
    push(&ipc_a, missed).await;

    // Same deliberate plain sleep as the scenarios above — past the
    // retransmit budget before b comes back, so the item can only reappear
    // via the resync-1 outbox path.
    tokio::time::sleep(RETRANSMIT_EXHAUSTION_WAIT).await;

    let items_resynced_before_cycle1 = items_resynced(&ipc_a).await;

    // ── Cycle 1: b comes back, resync-1 delivers the missed item ──
    // NOTE: b2 is a brand-new process (fresh `MetricsTracker::new()`), so
    // `resync_applies_suppressed` starts at 0 — no "before" baseline needs
    // querying over b's IPC while b is still down (its socket isn't even
    // listening yet).
    let (shutdown_b2, h_b2) =
        restart_b_and_relink(&id_b, &keystore_b, &ipc_b, addr_a, a_pub.clone(), &ipc_a).await;

    assert!(
        wait_until(Duration::from_secs(15), || async { history_has(&ipc_b, missed).await }).await,
        "CRLF item never resynced onto b within 15s of relink cycle 1 — if this hangs, suspect \
         a hash mismatch between a's offered hash and b's history hash (DEFECT 2a)"
    );
    assert!(
        wait_until(Duration::from_secs(5), || async {
            items_resynced(&ipc_a).await > items_resynced_before_cycle1
        })
        .await,
        "a's items_resynced counter never advanced for cycle 1"
    );

    // DEFECT 1: the resync delivery must NOT have applied to b's OS
    // clipboard — proven via the dedicated suppression counter.
    assert!(
        wait_until(Duration::from_secs(5), || async {
            resync_applies_suppressed(&ipc_b).await > 0
        })
        .await,
        "b never recorded a suppressed resync apply for the CRLF item — DEFECT 1 not fixed"
    );
    let items_resynced_after_cycle1 = items_resynced(&ipc_a).await;

    // ── Cycle 2: kill b again, restart it fresh a second time, relink ──
    // b's vault must have persisted the resynced item before this shutdown
    // (DEFECT 2's fix: the vault persister is now a tracked, joined task
    // that flushes on `shutdown` rather than a detached spawn a fast
    // shutdown could race past), so the rehydrated history already holds
    // the hash and resync-1's held-check must skip it entirely this time.
    shutdown_b2.cancel();
    let _ = timeout(Duration::from_secs(5), h_b2).await.expect("b2: clean shutdown hung");

    let (shutdown_b3, h_b3) =
        restart_b_and_relink(&id_b, &keystore_b, &ipc_b, addr_a, a_pub, &ipc_a).await;

    assert!(
        history_has(&ipc_b, missed).await,
        "b lost the resynced item across its own restart (vault flush regressed)"
    );
    // Real window for an errant second pull to land before asserting it
    // didn't — mirrors the ordering-based bound in
    // `sensitive_item_never_resyncs` rather than a blind race.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(
        items_resynced(&ipc_a).await,
        items_resynced_after_cycle1,
        "a re-served the CRLF item on a SECOND relink cycle — resync-1's held-check did not \
         stop the loop (DEFECT 2); items_resynced must not grow between cycle 1 and cycle 2"
    );

    shutdown_a.cancel();
    shutdown_b3.cancel();
    let _ = timeout(Duration::from_secs(5), h_a).await.expect("a: clean shutdown hung");
    let _ = timeout(Duration::from_secs(5), h_b3).await.expect("b3: clean shutdown hung");
}

/// DEFECT 3 regression: resync-1's promise is narrow — recover items whose
/// DELIVERY was actually attempted but went unacked when the link dropped —
/// not "resurface anything ever copied while fully offline". `a` is booted
/// alone (no peer paired at all yet, so `transport.linked_peer_ids()` is
/// empty) and an item is copied in that window, before `b` even exists.
/// Once `a` and `b` pair for the very first time, the item must never
/// appear in `b`'s history: it was never inserted into `a`'s outbox in the
/// first place (see the `targets.is_empty()` gate in the `Action::SendItem`
/// dispatch, ordered BEFORE the outbox write).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn item_copied_while_fully_unlinked_never_resyncs() {
    let _ = tracing_subscriber::fmt::try_init();

    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let port_a = pick_free_udp_port().await;
    let port_b = pick_free_udp_port().await;
    assert_ne!(port_a, port_b);

    let dir = tempfile::tempdir().expect("tempdir");
    let dir = Box::leak(Box::new(dir));
    let keystore_a = dir.path().join("ks-a");
    let keystore_b = dir.path().join("ks-b");
    std::fs::create_dir(&keystore_a).unwrap();
    std::fs::create_dir(&keystore_b).unwrap();
    let ipc_a = keystore_a.join("a.sock");
    let ipc_b = keystore_b.join("b.sock");
    let addr_a: SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();

    let shutdown_a = CancellationToken::new();
    let h_a = tokio::spawn(run(
        cfg_for(&id_a, port_a, &keystore_a, &ipc_a, "device-a"),
        shutdown_a.clone(),
    ));
    assert!(ipc_up(&ipc_a, Duration::from_secs(5)).await, "a: ipc not up");
    set_threshold(&ipc_a, 5).await;

    // a has no peer at all yet (never paired) — copy here, with zero linked
    // peers. This is the privacy-leak scenario: an old private copy made
    // with no peer connected must never flush to whichever peer links next.
    let offline_item = "resync-offline-privacy-leak";
    push(&ipc_a, offline_item).await;

    // Now bring b up and pair with a for the very first time.
    let shutdown_b = CancellationToken::new();
    let h_b = tokio::spawn(run(
        cfg_for(&id_b, port_b, &keystore_b, &ipc_b, "device-b"),
        shutdown_b.clone(),
    ));
    assert!(ipc_up(&ipc_b, Duration::from_secs(5)).await, "b: ipc not up");
    set_threshold(&ipc_b, 5).await;

    pair_daemons(&ipc_a, addr_a, &ipc_b).await;

    // Real window — the same one a legitimate missed item gets in the other
    // scenarios above — for an errant resync to land before asserting it
    // didn't.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(
        !history_has(&ipc_b, offline_item).await,
        "an item copied while fully unlinked leaked to b via resync-1 (DEFECT 3)"
    );

    shutdown_a.cancel();
    shutdown_b.cancel();
    let _ = timeout(Duration::from_secs(5), h_a).await.expect("a: clean shutdown hung");
    let _ = timeout(Duration::from_secs(5), h_b).await.expect("b: clean shutdown hung");
}
