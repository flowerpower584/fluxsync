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

async fn history_has(ipc: &Path, preview: &str) -> bool {
    status(ipc).await.history.iter().any(|h| h.preview == preview)
}

async fn phase_linked(ipc: &Path) -> bool {
    status(ipc).await.phase == "linked"
}

async fn items_resynced(ipc: &Path) -> u64 {
    status(ipc).await.metrics.as_ref().map_or(0, |m| m.items_resynced)
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

    assert!(
        wait_until(Duration::from_secs(5), || async {
            items_resynced(&ipc_a).await > items_resynced_before
        })
        .await,
        "a's items_resynced counter never advanced — item may have arrived by a path other than \
         resync-1's outbox"
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
