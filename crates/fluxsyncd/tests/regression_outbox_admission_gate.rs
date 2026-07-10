//! REGRESSION: the resync outbox must only ever hold items already admitted
//! to history — never an item the clipboard firewall Blocked or an `Ask`
//! item the user denied. Before this fix, `complete_reassembled_item` /
//! `dispatch_inbound_frame` inserted into the outbox at receive time,
//! BEFORE `Event::FrameReceivedClipboard` ever reached the firewall gate, so
//! a Blocked or denied item still sat in the outbox and could be served to
//! a different peer via `Msg::ResyncOffer`/`Msg::ResyncPull`.
//!
//! Structure mirrors `resync_on_reconnect.rs`'s `sensitive_item_never_resyncs`
//! almost exactly (a CONTROL item proves resync-1 is genuinely active, then
//! the target item must never appear) — same two-daemon-over-loopback
//! harness (real pairing dance, real restart+relink), same ordering-based
//! bound instead of a blind "it never showed up" sleep. The one addition:
//! since the sender (`B`) also keeps its own copy of whatever it pushes,
//! `B` must `ClearHistory` its own copy (which also purges `B`'s own
//! outbox) before restarting, or `missing_resync_hashes` would never even
//! consider the item "missing" and B would never re-pull it — the test
//! would trivially pass without exercising anything.
//!
//! (d) is a pure `Outbox` unit-style test (no daemon needed): a single
//! ~9 MiB item must survive `insert` immediately — `outbox.rs`'s
//! `MAX_TOTAL_BYTES` used to be smaller than `fluxsync_proto::MAX_PAYLOAD`,
//! so a legal near-cap item self-evicted the instant it was inserted.

#![cfg(unix)]

use fluxsync_core::{FirewallPolicy, Rule};
use fluxsync_crypto::Identity;
use fluxsyncd::{
    cmd::{CmdData, CmdOp, CmdRequest, CmdResponse},
    history_store, run, DaemonConfig,
};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UdpSocket, UnixStream};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

/// Same envelope `resync_on_reconnect.rs` uses for "relinked after an
/// explicit reconnect".
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
    let resp = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 1,
            op: CmdOp::Status,
        },
    )
    .await;
    match resp.data {
        Some(CmdData::State(s)) => s,
        other => panic!("expected State, got {other:?}"),
    }
}

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
        ipc_try_send_recv(
            ipc,
            CmdRequest {
                id: 0,
                op: CmdOp::Status,
            },
        )
        .await
        .is_some_and(|r| r.ok)
    })
    .await
}

/// KNOWN TRAP: a real host battery <=20% and discharging silently pauses
/// sync (the battery-policy `Paused` gate). Floor both daemons' thresholds
/// right after boot.
async fn set_threshold(ipc: &Path, value: u8) {
    let r = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 0,
            op: CmdOp::SetThreshold { value },
        },
    )
    .await;
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

async fn set_firewall(ipc: &Path, policy: FirewallPolicy) {
    let r = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 3,
            op: CmdOp::SetFirewall { policy },
        },
    )
    .await;
    assert!(r.ok, "set-firewall failed: {r:?}");
}

async fn resolve_pending(ipc: &Path, hash: String, allow: bool) {
    let r = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 4,
            op: CmdOp::ResolvePending { hash, allow },
        },
    )
    .await;
    assert!(r.ok, "resolve-pending failed: {r:?}");
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
    status(ipc)
        .await
        .history
        .iter()
        .any(|h| h.preview == preview)
}

/// Read the on-disk vault directly with the REAL load path + REAL at-rest
/// key. Used to confirm the vault persister (async relative to an IPC
/// `ClearHistory` call) has actually flushed to disk before a test kills and
/// restarts the same daemon — otherwise the restart would rehydrate the
/// STALE, pre-clear file and the test would prove nothing.
fn disk_has(keystore: &Path, id: &Identity, preview: &str) -> bool {
    let key = id.derive_at_rest_key(history_store::AT_REST_CONTEXT);
    let now_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    history_store::load(keystore, &key, now_ms, history_store::DEFAULT_TTL_SECS)
        .is_ok_and(|v| v.iter().any(|e| e.item.preview == preview))
}

async fn phase_linked(ipc: &Path) -> bool {
    status(ipc).await.phase == "linked"
}

/// `a`'s heartbeat watchdog only notices an ungraceful peer disconnect (no
/// `Bye`, e.g. a killed process — exactly what `shutdown_first_b` does) after
/// 3 missed pings (~9s, see `heartbeat_loop`'s doc comment). Until then `a`'s
/// single FSM is still sitting in `Linked` for the now-dead session, so a
/// restarted `b2` dialing back in does NOT retrigger `Action::OpenSession`
/// (already Linked — nothing to transition) and never gets `a`'s `Msg::Hello`
/// at all. Wait for `a` to fall out of `linked` before restarting `b`, or the
/// whole resync-1 Hello/offer exchange silently never happens.
async fn wait_a_notices_disconnect(ipc_a: &Path) {
    assert!(
        wait_until(Duration::from_secs(15), || async {
            status(ipc_a).await.phase != "linked"
        })
        .await,
        "a never detected b's disconnect (heartbeat timeout, ~9s) before the restart"
    );
}

/// First parked `pending` row's hex hash, if any (the firewall `Ask` gate
/// only ever parks one at a time in these tests).
async fn first_pending_hash(ipc: &Path) -> Option<String> {
    status(ipc).await.pending.first().map(|p| p.hash.clone())
}

// ── Real IPC pairing (PairShow -> PairAccept -> PairConfirm x2) ──
// Copied verbatim from resync_on_reconnect.rs (itself ported from
// chaos_harness.rs's subprocess-based helpers of the same names/shape).

async fn pair_show(ipc: &Path) -> (String, String) {
    let resp = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 10,
            op: CmdOp::PairShow {},
        },
    )
    .await;
    match resp.data {
        Some(CmdData::PairInfo {
            peer_id_hex,
            pubkey_b32,
            ..
        }) => (peer_id_hex, pubkey_b32),
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
    let resp = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 12,
            op: CmdOp::PairPending {},
        },
    )
    .await;
    match resp.data {
        Some(CmdData::PendingPairs(v)) if !v.is_empty() => Some(v[0].peer_id.clone()),
        _ => None,
    }
}

async fn confirm_pending(ipc: &Path, dur: Duration) {
    let start = std::time::Instant::now();
    loop {
        if let Some(peer_id) = pending_peer_id(ipc).await {
            let resp = ipc_send_recv(
                ipc,
                CmdRequest {
                    id: 13,
                    op: CmdOp::PairConfirm {
                        peer_id,
                        accept: true,
                    },
                },
            )
            .await;
            assert!(resp.ok, "pair_confirm failed: {resp:?}");
            return;
        }
        assert!(
            start.elapsed() < dur,
            "no pending pair to confirm within {dur:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn pair_daemons(ipc_a: &Path, addr_a: SocketAddr, ipc_b: &Path) -> String {
    let (_a_id, a_pub) = pair_show(ipc_a).await;
    pair_accept(ipc_b, a_pub.clone(), "device-a", addr_a).await;

    let linked_a = wait_until(Duration::from_secs(10), || async {
        phase_linked(ipc_a).await
    })
    .await;
    let linked_b = wait_until(Duration::from_secs(10), || async {
        phase_linked(ipc_b).await
    })
    .await;
    assert!(linked_a, "a: did not reach linked phase while pairing");
    assert!(linked_b, "b: did not reach linked phase while pairing");

    confirm_pending(ipc_a, Duration::from_secs(10)).await;
    confirm_pending(ipc_b, Duration::from_secs(10)).await;
    a_pub
}

#[allow(clippy::type_complexity)]
async fn boot_and_pair() -> (
    PathBuf,
    CancellationToken,
    tokio::task::JoinHandle<anyhow::Result<()>>,
    Identity,
    PathBuf,
    PathBuf,
    SocketAddr,
    String,
    CancellationToken,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
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
    let shutdown_b = CancellationToken::new();
    let h_a = tokio::spawn(run(
        cfg_for(&id_a, port_a, &keystore_a, &ipc_a, "device-a"),
        shutdown_a.clone(),
    ));
    let h_b = tokio::spawn(run(
        cfg_for(&id_b, port_b, &keystore_b, &ipc_b, "device-b"),
        shutdown_b.clone(),
    ));

    assert!(
        ipc_up(&ipc_a, Duration::from_secs(5)).await,
        "a: ipc not up"
    );
    assert!(
        ipc_up(&ipc_b, Duration::from_secs(5)).await,
        "b: ipc not up"
    );

    set_threshold(&ipc_a, 5).await;
    set_threshold(&ipc_b, 5).await;

    let a_pub = pair_daemons(&ipc_a, addr_a, &ipc_b).await;

    (
        ipc_a, shutdown_a, h_a, id_b, keystore_b, ipc_b, addr_a, a_pub, shutdown_b, h_b,
    )
}

/// Cleanly stop `b`'s FIRST incarnation (from `boot_and_pair`) before a test
/// restarts it as `b2` on the same `ipc_b`/keystore path — otherwise the
/// still-listening original socket would collide with the fresh one.
async fn shutdown_first_b(
    shutdown_b: CancellationToken,
    h_b: tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    shutdown_b.cancel();
    let _ = timeout(Duration::from_secs(5), h_b)
        .await
        .expect("b (first incarnation): clean shutdown hung");
}

async fn restart_b_and_relink(
    id_b: &Identity,
    keystore_b: &Path,
    ipc_b: &Path,
    addr_a: SocketAddr,
    a_pub: String,
    ipc_a: &Path,
) -> (
    CancellationToken,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let port_b2 = pick_free_udp_port().await;
    let shutdown_b2 = CancellationToken::new();
    let h_b2 = tokio::spawn(run(
        cfg_for(id_b, port_b2, keystore_b, ipc_b, "device-b-v2"),
        shutdown_b2.clone(),
    ));
    assert!(
        ipc_up(ipc_b, Duration::from_secs(5)).await,
        "b2: ipc not up after restart"
    );

    pair_accept(ipc_b, a_pub, "device-a", addr_a).await;

    let relinked_a = wait_until(RECONNECT_ENVELOPE, || async { phase_linked(ipc_a).await }).await;
    let relinked_b = wait_until(RECONNECT_ENVELOPE, || async { phase_linked(ipc_b).await }).await;
    assert!(
        relinked_a,
        "a: did not recover to linked within {RECONNECT_ENVELOPE:?} of b's restart"
    );
    assert!(
        relinked_b,
        "b2: did not reach linked within {RECONNECT_ENVELOPE:?} of restart"
    );

    (shutdown_b2, h_b2)
}

/// (a) A firewall-Blocked inbound item must never enter `a`'s outbox, so it
/// can never be offered to `b` via `Msg::ResyncOffer` after `b` forgets its
/// own copy and relinks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn firewall_blocked_inbound_item_never_resyncs() {
    let _ = tracing_subscriber::fmt::try_init();

    let (ipc_a, shutdown_a, h_a, id_b, keystore_b, ipc_b, addr_a, a_pub, shutdown_b, h_b) =
        boot_and_pair().await;

    // a: Deny every inbound text item outright.
    set_firewall(
        &ipc_a,
        FirewallPolicy {
            enabled: true,
            text: Rule::Deny,
            ..FirewallPolicy::default()
        },
    )
    .await;

    let control = "outbox-gate-control-item";
    let blocked = "outbox-gate-blocked-item";

    // b pushes both; only `control` is a normal item a's firewall admits
    // (Kind::Url stays Allow — only `text` was denied above).
    push(&ipc_b, blocked).await;
    let control_resp = ipc_send_recv(
        &ipc_b,
        CmdRequest {
            id: 20,
            op: CmdOp::Push {
                text: format!("https://example.com/{control}"),
            },
        },
    )
    .await;
    assert!(control_resp.ok, "control push failed: {control_resp:?}");

    // a must never have admitted the blocked item into its own history.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !history_has(&ipc_a, blocked).await,
        "a's firewall must have blocked the item — it must never reach a's history"
    );
    assert!(
        history_has(&ipc_a, &format!("https://example.com/{control}")).await,
        "precondition: control item must have reached a's history (else resync-1 has nothing to prove)"
    );

    // b forgets its own copies (also purges b's own outbox for both hashes)
    // so relinking will genuinely re-request whatever it's missing.
    clear_history(&ipc_b, true).await;
    assert!(!history_has(&ipc_b, blocked).await);
    assert!(!history_has(&ipc_b, &format!("https://example.com/{control}")).await);

    // The vault persister flushes ClearHistory to disk ASYNCHRONOUSLY — wait
    // for it before killing b, or the restart below would rehydrate the
    // STALE pre-clear vault and the control item would never look "missing"
    // to relinked b, proving nothing.
    let control_full = format!("https://example.com/{control}");
    assert!(
        wait_until(Duration::from_secs(5), || async {
            !disk_has(&keystore_b, &id_b, blocked) && !disk_has(&keystore_b, &id_b, &control_full)
        })
        .await,
        "b's on-disk vault never reflected ClearHistory before the restart"
    );

    // a stays up the whole time — only b goes down and relinks.
    shutdown_first_b(shutdown_b, h_b).await;
    wait_a_notices_disconnect(&ipc_a).await;
    let (shutdown_b2, h_b2) =
        restart_b_and_relink(&id_b, &keystore_b, &ipc_b, addr_a, a_pub, &ipc_a).await;

    // Control item proves resync-1 genuinely ran.
    assert!(
        wait_until(Duration::from_secs(15), || async {
            history_has(&ipc_b, &format!("https://example.com/{control}")).await
        })
        .await,
        "control item never resynced onto b within 15s of relink — resync-1 may not be active"
    );

    // Ordering-based bound, not a blind sleep: resync-1 offers the whole
    // outbox in one Hello round trip, so a few extra seconds past the
    // confirmed control resync rules out a late arrival, not just "hasn't
    // arrived yet".
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !history_has(&ipc_b, blocked).await,
        "a firewall-Blocked inbound item leaked to b via a's resync outbox"
    );

    shutdown_a.cancel();
    shutdown_b2.cancel();
    let _ = timeout(Duration::from_secs(5), h_a)
        .await
        .expect("a: clean shutdown hung");
    let _ = timeout(Duration::from_secs(5), h_b2)
        .await
        .expect("b2: clean shutdown hung");
}

/// (b) An `Ask`-parked inbound item, explicitly denied via
/// `ResolvePending{allow:false}`, must never be servable via
/// `Msg::ResyncPull` either — same proof shape as (a).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ask_denied_inbound_item_never_resyncs() {
    let _ = tracing_subscriber::fmt::try_init();

    let (ipc_a, shutdown_a, h_a, id_b, keystore_b, ipc_b, addr_a, a_pub, shutdown_b, h_b) =
        boot_and_pair().await;

    // a: Ask (defer) every inbound text item.
    set_firewall(
        &ipc_a,
        FirewallPolicy {
            enabled: true,
            text: Rule::Ask,
            ..FirewallPolicy::default()
        },
    )
    .await;

    let control = "outbox-gate-control-item-b";
    let denied = "outbox-gate-denied-item";

    push(&ipc_b, denied).await;
    let control_resp = ipc_send_recv(
        &ipc_b,
        CmdRequest {
            id: 21,
            op: CmdOp::Push {
                text: format!("https://example.com/{control}"),
            },
        },
    )
    .await;
    assert!(control_resp.ok, "control push failed: {control_resp:?}");

    // The denied item must land in a's `pending` queue (Ask parks it) —
    // find it and explicitly deny it.
    let got_pending = wait_until(Duration::from_secs(5), || async {
        first_pending_hash(&ipc_a).await.is_some()
    })
    .await;
    assert!(
        got_pending,
        "a's firewall Ask rule never parked the pushed item"
    );
    let pending_hash = first_pending_hash(&ipc_a).await.expect("pending hash");
    resolve_pending(&ipc_a, pending_hash, false).await;

    // a must never have admitted the denied item into its own history.
    assert!(
        !history_has(&ipc_a, denied).await,
        "a denied item must never reach a's history"
    );

    clear_history(&ipc_b, true).await;
    assert!(!history_has(&ipc_b, denied).await);

    let control_full = format!("https://example.com/{control}");
    assert!(
        wait_until(Duration::from_secs(5), || async {
            !disk_has(&keystore_b, &id_b, denied) && !disk_has(&keystore_b, &id_b, &control_full)
        })
        .await,
        "b's on-disk vault never reflected ClearHistory before the restart"
    );

    shutdown_first_b(shutdown_b, h_b).await;
    wait_a_notices_disconnect(&ipc_a).await;
    let (shutdown_b2, h_b2) =
        restart_b_and_relink(&id_b, &keystore_b, &ipc_b, addr_a, a_pub, &ipc_a).await;

    assert!(
        wait_until(Duration::from_secs(15), || async {
            history_has(&ipc_b, &format!("https://example.com/{control}")).await
        })
        .await,
        "control item never resynced onto b within 15s of relink — resync-1 may not be active"
    );

    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !history_has(&ipc_b, denied).await,
        "an Ask-denied inbound item leaked to b via a's resync outbox"
    );

    shutdown_a.cancel();
    shutdown_b2.cancel();
    let _ = timeout(Duration::from_secs(5), h_a)
        .await
        .expect("a: clean shutdown hung");
    let _ = timeout(Duration::from_secs(5), h_b2)
        .await
        .expect("b2: clean shutdown hung");
}

/// (d) FIX 4: `MAX_TOTAL_BYTES` used to be 8 MiB, smaller than
/// `fluxsync_proto::MAX_PAYLOAD` (16 MiB), so a single legal ~9 MiB item
/// self-evicted the instant `evict_over_caps` ran right after its own
/// insert. No daemon needed — this exercises `Outbox` directly.
#[test]
fn max_size_admitted_item_survives_cap_fix() {
    use fluxsyncd::outbox::{Entry, Outbox};

    let big = vec![0u8; 9 * 1024 * 1024]; // ~9 MiB: within MAX_PAYLOAD, over the old 8 MiB cap
    let hash = [0x55u8; 32];
    let mut ob = Outbox::new();
    ob.insert(
        hash,
        Entry {
            payload: big.clone(),
            kind: fluxsync_proto::Kind::Text,
            origin: [1u8; 32],
            seq: 1,
            created: std::time::Instant::now(),
        },
    );

    let got = ob
        .get(hash)
        .expect("a ~9 MiB item must survive its own insert");
    assert_eq!(got.payload.len(), big.len());
}
