//! Integration test: automatic relink via persisted `last_addr` — no mDNS,
//! no explicit `PairAccept` driving the reconnect.
//!
//! This is the deterministic counterpart to the scenario
//! `chaos_harness.rs` previously documented as relying on mDNS (flaky on
//! loopback) or an explicit manual `PairAccept` (see
//! `resync_on_reconnect.rs`'s `restart_b_and_relink`, which is a
//! *different*, still-valid scenario: it proves relink works when the user
//! or CLI explicitly re-dials a known address). Here, nothing drives the
//! reconnect except the daemon itself: `A` and `B` pair for real, sync one
//! item to prove the link is live, then `B` is torn down and rebooted with
//! the SAME identity + keystore dir (so `peers.json` — including the
//! `last_addr` written during the initial handshake — rehydrates). With
//! mDNS disabled on BOTH daemons, `B` must relink to `A` purely from its
//! own persisted `last_addr` (fed into `Transport` at boot, then redialed
//! by the always-on proactive-probe reconnect task), with zero explicit
//! IPC command driving the reconnect.
//!
//! `B` rebinds to the SAME UDP port across the simulated restart
//! (deliberately, unlike `resync_on_reconnect.rs`'s `restart_b_and_relink`,
//! which picks a fresh ephemeral port because its relink is always
//! address-supplied by the explicit `PairAccept`). This matters here
//! because which side actually initiates the blind redial is governed by a
//! deterministic tie-break on the two (randomly generated) identity public
//! keys — reusing the port means BOTH directions of redial are valid no
//! matter which identity wins that tie-break, so the test is deterministic
//! regardless of `Identity::generate()`'s randomness. It also matches
//! production reality: the real `fluxsyncd` binary defaults to a fixed UDP
//! port (41889) across restarts, so this is the realistic case, not a
//! test-only convenience.

#![cfg(unix)]

use fluxsync_crypto::Identity;
use fluxsyncd::{
    cmd::{CmdData, CmdOp, CmdRequest, CmdResponse},
    run, DaemonConfig,
};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UdpSocket, UnixStream};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

/// Generous envelope for "relinked after a restart", mirroring
/// `resync_on_reconnect.rs`'s `RECONNECT_ENVELOPE`. The proactive-probe
/// redial ticks every 200ms once ready, but the tie-break loser's side
/// only redials after its stale session times out via the heartbeat
/// watchdog (~9s) — 30s comfortably covers either path.
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

// ── Real IPC pairing (PairShow -> PairAccept -> PairConfirm x2) ──
// Mirrors resync_on_reconnect.rs / chaos_harness.rs's helpers of the same
// names/shape. Used ONLY for the initial pairing here — the whole point of
// this test is that the SUBSEQUENT relink after B's restart happens with
// NONE of this driving it.

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
/// explicitly trusts + dials `a` (manual-address path — used only to
/// bootstrap the initial pairing in this test, never for the relink under
/// test), both land `Linked` via a real Noise handshake, then both confirm
/// the FS-052 pending entry. Returns `a`'s base32 static pubkey (unused by
/// the relink itself, kept for parity with the other harness files /
/// possible future scenarios in this file).
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b_relinks_via_persisted_last_addr_with_no_mdns_and_no_pair_accept() {
    let _ = tracing_subscriber::fmt::try_init();

    let id_a = Identity::generate();
    let id_b = Identity::generate();

    let port_a = pick_free_udp_port().await;
    let port_b = pick_free_udp_port().await;
    assert_ne!(port_a, port_b);

    let dir = tempfile::tempdir().expect("tempdir");
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

    // Host-battery gate: sync does not proceed until both sides lower the
    // threshold below whatever the real host's battery reports.
    set_threshold(&ipc_a, 5).await;
    set_threshold(&ipc_b, 5).await;

    pair_daemons(&ipc_a, addr_a, &ipc_b).await;

    // Prove the link works before touching it: sync one item both ways.
    let sanity = "last-addr-sanity-item";
    push(&ipc_a, sanity).await;
    assert!(
        wait_until(Duration::from_secs(5), || async { history_has(&ipc_b, sanity).await }).await,
        "sanity item never reached b before the relink scenario started"
    );

    // Shut b down cleanly.
    shutdown_b.cancel();
    let _ = timeout(Duration::from_secs(5), h_b).await.expect("b: clean shutdown hung");

    // Restart b with the SAME identity, the SAME on-disk keystore dir (so
    // `peers.json` — including the `last_addr` persisted during the
    // handshake above — rehydrates), and the SAME UDP port (see module doc
    // for why this matters for determinism). Crucially: NO `pair_accept`,
    // no other IPC command that could drive the reconnect. mDNS stays
    // disabled on both `a` and `b2` throughout (via `cfg_for`).
    // Replicates the "State-Aware Boot" logic the real `fluxsyncd` binary
    // applies in `main.rs` (a non-empty `peers.json` sets `start_on =
    // true` so the daemon auto-toggles sync on at boot instead of sitting
    // idle until a user/IPC action). The in-process harness constructs
    // `DaemonConfig` directly (bypassing `main.rs`), so it must set this
    // explicitly to mirror that real-binary behavior — without it, b2
    // would boot into "idle" and never start discovering/redialing at
    // all, regardless of the persisted `last_addr`.
    let mut cfg_b2 = cfg_for(&id_b, port_b, &keystore_b, &ipc_b, "device-b-restarted");
    cfg_b2.start_on = true;
    let shutdown_b2 = CancellationToken::new();
    let h_b2 = tokio::spawn(run(cfg_b2, shutdown_b2.clone()));
    assert!(ipc_up(&ipc_b, Duration::from_secs(5)).await, "b2: ipc not up after restart");

    // The reload path uses `keystore_dir::load_peers`/`load_trusted_peers`
    // for the trust set, but a fresh boot's in-memory battery threshold
    // resets, and the battery gate must not be what blocks the relink
    // under test — floor it exactly as at first boot.
    set_threshold(&ipc_b, 5).await;

    let relinked_a = wait_until(RECONNECT_ENVELOPE, || async { phase_linked(&ipc_a).await }).await;
    let relinked_b = wait_until(RECONNECT_ENVELOPE, || async { phase_linked(&ipc_b).await }).await;
    assert!(
        relinked_a,
        "a: did not automatically relink within {RECONNECT_ENVELOPE:?} of b's restart \
         (no PairAccept was ever sent — this must come from persisted last_addr redial)"
    );
    assert!(
        relinked_b,
        "b2: did not automatically relink within {RECONNECT_ENVELOPE:?} of restart \
         (no PairAccept was ever sent — this must come from persisted last_addr redial)"
    );

    // Prove the relink is a genuinely live, working session — not just a
    // stale connection object reporting "linked" — by syncing a fresh item
    // that did not exist before the restart.
    //
    // `relinked_a` above can pass on its very first poll even before the
    // real redial happens: `a` never restarted, so right after `b2` boots
    // `a`'s FSM still (briefly, correctly) reports "linked" against the
    // OLD pre-restart session until its own ~9s heartbeat timeout notices
    // the peer is gone and cycles through Discovering/Handshaking back to
    // Linked with `b2`'s NEW session (or, on the other side of the
    // dial-direction tie-break, `a` redials `b2` and the old session is
    // replaced transparently with no visible phase flap at all — see
    // `run_responder`'s `replacing_live_session` handling in
    // `handshake.rs`). Either way, a single "both report linked" snapshot
    // does not prove the CURRENT session is the new one. So: retry the
    // push with a fresh, uniquely-suffixed payload each attempt (the
    // content dedup ring would otherwise silently swallow a retried
    // identical payload as an already-seen echo) until one actually
    // reaches `b2`, bounded by the same envelope as the relink itself.
    let mut relink_is_live = false;
    let deadline = std::time::Instant::now() + RECONNECT_ENVELOPE;
    let mut attempt = 0u32;
    while std::time::Instant::now() < deadline {
        attempt += 1;
        let payload = format!("last-addr-post-relink-item-{attempt}");
        push(&ipc_a, &payload).await;
        let arrived =
            wait_until(Duration::from_secs(3), || async { history_has(&ipc_b, &payload).await })
                .await;
        if arrived {
            relink_is_live = true;
            break;
        }
    }
    assert!(
        relink_is_live,
        "no post-relink item ever reached b2 within {RECONNECT_ENVELOPE:?} of retries — \
         the relink never became genuinely live"
    );

    shutdown_a.cancel();
    shutdown_b2.cancel();
    let _ = timeout(Duration::from_secs(5), h_a).await.expect("a: clean shutdown hung");
    let _ = timeout(Duration::from_secs(5), h_b2).await.expect("b2: clean shutdown hung");
}
