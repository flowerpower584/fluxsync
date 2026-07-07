//! FluxMesh 2C-b integration test: three `fluxsyncd` instances in a line
//! topology A — B — C exchange one clipboard item via B's relay.
//!
//! B is linked to both A and C; A and C are linked only to B. A clipboard
//! item pushed on A must reach B (direct) and C (relayed by B) exactly once,
//! and must never loop back to A. Sessions are injected with `pair_for_test`
//! via `DaemonConfig::{test_pair, test_pairs}`, skipping the QR/handshake flow
//! (that path has its own tests).
//!
//! Gated on `cfg(unix)` like `two_daemons.rs` (the IPC client uses
//! `tokio::net::UnixStream`).

#![cfg(unix)]
#![allow(clippy::similar_names)] // sess_a_b/sess_b_a/sess_b_c/sess_c_b name link-specific session pairs

use fluxsync_core::{FirewallPolicy, Rule};
use fluxsync_crypto::{test_util::pair_for_test, Identity};
use fluxsyncd::{
    cmd::{CmdData, CmdOp, CmdRequest},
    run, DaemonConfig, TestPair, TestPendingPair,
};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UdpSocket, UnixStream};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

static PANIC_TRIGGERED: AtomicBool = AtomicBool::new(false);

fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        PANIC_TRIGGERED.store(true, Ordering::SeqCst);
        prev(info);
    }));
}

async fn pick_free_udp_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").await.expect("pick port");
    s.local_addr().expect("port").port()
}

async fn ipc_send_recv(path: &PathBuf, req: CmdRequest) -> fluxsyncd::cmd::CmdResponse {
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

/// Count history rows whose preview matches `text` for the daemon at `ipc`.
async fn history_count(ipc: &PathBuf, text: &str) -> usize {
    let resp = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 99,
            op: CmdOp::Status,
        },
    )
    .await;
    match resp.data {
        Some(CmdData::State(s)) => s.history.iter().filter(|h| h.preview == text).count(),
        _ => 0,
    }
}

async fn peer_name(ipc: &PathBuf) -> Option<String> {
    if !ipc.exists() {
        return None;
    }
    let resp = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 1,
            op: CmdOp::Status,
        },
    )
    .await;
    match resp.data {
        Some(CmdData::State(s)) => Some(s.peer_name),
        _ => None,
    }
}

/// FluxMesh Phase 3: `(peers.len(), primary_count)` from the daemon's State.
async fn mesh_peers(ipc: &PathBuf) -> (usize, usize) {
    let resp = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 5,
            op: CmdOp::Status,
        },
    )
    .await;
    match resp.data {
        Some(CmdData::State(s)) => (
            s.peers.len(),
            s.peers.iter().filter(|p| p.primary).count(),
        ),
        _ => (0, 0),
    }
}

fn base_cfg(identity: Identity, port: u16, ipc: PathBuf, name: &str) -> DaemonConfig {
    let mut cfg = DaemonConfig::new(identity, port, ipc);
    cfg.udp_bind = "127.0.0.1".into();
    cfg.disable_clipboard = true;
    cfg.disable_mdns = true;
    cfg.peer_name_self = name.into();
    cfg
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn three_node_line_relays_one_item_exactly_once() {
    let _ = tracing_subscriber::fmt::try_init();
    install_panic_hook();

    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let id_c = Identity::generate();
    let (pid_a, pid_b, pid_c) = (id_a.peer_id(), id_b.peer_id(), id_c.peer_id());

    // Two independent session pairs: A<->B and B<->C.
    let (sess_a_b, sess_b_a) = pair_for_test(&id_a, &id_b).expect("pair a-b");
    let (sess_b_c, sess_c_b) = pair_for_test(&id_b, &id_c).expect("pair b-c");

    let (port_a, port_b, port_c) = (
        pick_free_udp_port().await,
        pick_free_udp_port().await,
        pick_free_udp_port().await,
    );
    let addr_a: SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();
    let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();
    let addr_c: SocketAddr = format!("127.0.0.1:{port_c}").parse().unwrap();

    let dir = tempfile::tempdir().expect("tempdir");
    let ipc_a = dir.path().join("a.sock");
    let ipc_b = dir.path().join("b.sock");
    let ipc_c = dir.path().join("c.sock");

    // A — linked only to B (B is its primary).
    let mut cfg_a = base_cfg(id_a, port_a, ipc_a.clone(), "node-a");
    cfg_a.test_pair = Some(TestPair {
        session: sess_a_b,
        peer_addr: addr_b,
        peer_name: "node-b".into(),
        peer_id: pid_b,
    });

    // C — linked only to B (B is its primary).
    let mut cfg_c = base_cfg(id_c, port_c, ipc_c.clone(), "node-c");
    cfg_c.test_pair = Some(TestPair {
        session: sess_c_b,
        peer_addr: addr_b,
        peer_name: "node-b".into(),
        peer_id: pid_b,
    });

    // B — the relay: primary A, secondary C.
    let mut cfg_b = base_cfg(id_b, port_b, ipc_b.clone(), "node-b");
    cfg_b.test_pair = Some(TestPair {
        session: sess_b_a,
        peer_addr: addr_a,
        peer_name: "node-a".into(),
        peer_id: pid_a,
    });
    cfg_b.test_pairs = vec![TestPair {
        session: sess_b_c,
        peer_addr: addr_c,
        peer_name: "node-c".into(),
        peer_id: pid_c,
    }];

    let sd_a = CancellationToken::new();
    let sd_b = CancellationToken::new();
    let sd_c = CancellationToken::new();
    let (ca, cb, cc) = (sd_a.clone(), sd_b.clone(), sd_c.clone());
    let h_a = tokio::spawn(async move { run(cfg_a, ca).await });
    let h_b = tokio::spawn(async move { run(cfg_b, cb).await });
    let h_c = tokio::spawn(async move { run(cfg_c, cc).await });

    // ── 1. each daemon projects its primary peer within 2s ──
    let up = wait_until(Duration::from_secs(2), || async {
        peer_name(&ipc_a).await.as_deref() == Some("node-b")
            && peer_name(&ipc_b).await.as_deref() == Some("node-a")
            && peer_name(&ipc_c).await.as_deref() == Some("node-b")
    })
    .await;
    assert!(up, "all three daemons did not reach Linked within 2s");

    // ── 2. push from A → must reach B (direct) and C (relayed by B) ──
    let text = "hello mesh world";
    let push = ipc_send_recv(
        &ipc_a,
        CmdRequest {
            id: 42,
            op: CmdOp::Push { text: text.into() },
        },
    )
    .await;
    assert!(push.ok, "push failed: {push:?}");

    let arrived = wait_until(Duration::from_secs(3), || async {
        history_count(&ipc_b, text).await >= 1 && history_count(&ipc_c, text).await >= 1
    })
    .await;
    assert!(
        arrived,
        "item did not reach both B and C within 3s (B={}, C={})",
        history_count(&ipc_b, text).await,
        history_count(&ipc_c, text).await
    );

    // ── 3. exactly once everywhere, and no loop back to A ──
    // Give any stray relay/echo a moment to (incorrectly) land.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(history_count(&ipc_b, text).await, 1, "B applied item twice");
    assert_eq!(history_count(&ipc_c, text).await, 1, "C applied item twice");
    assert_eq!(
        history_count(&ipc_a, text).await,
        1,
        "A has more than its single local copy (item looped back)"
    );

    // ── 3b. a CHUNKED item (payload > MAX_CHUNK_DATA = 1 KiB) must ALSO relay
    //        A → B (direct) → C (B re-chunks and forwards). Robustness slice 3.
    // ~3.7 KiB → multi-frame. Pre-trimmed to match what the daemon stores
    // (the Push handler trims, which would otherwise drop the trailing space).
    let big = "the quick brown fox jumps over "
        .repeat(120)
        .trim()
        .to_string();
    let push2 = ipc_send_recv(
        &ipc_a,
        CmdRequest {
            id: 43,
            op: CmdOp::Push { text: big.clone() },
        },
    )
    .await;
    assert!(push2.ok, "chunked push failed: {push2:?}");

    let arrived2 = wait_until(Duration::from_secs(3), || async {
        history_count(&ipc_b, &big).await >= 1 && history_count(&ipc_c, &big).await >= 1
    })
    .await;
    assert!(
        arrived2,
        "chunked item did not reach both B and C within 3s (B={}, C={})",
        history_count(&ipc_b, &big).await,
        history_count(&ipc_c, &big).await
    );

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(history_count(&ipc_b, &big).await, 1, "B applied chunked item twice");
    assert_eq!(history_count(&ipc_c, &big).await, 1, "C applied chunked item twice");
    assert_eq!(
        history_count(&ipc_a, &big).await,
        1,
        "chunked item looped back to A"
    );

    // ── 4. clean shutdown, no panic ──
    sd_a.cancel();
    sd_b.cancel();
    sd_c.cancel();
    for (h, who) in [(h_a, "A"), (h_b, "B"), (h_c, "C")] {
        timeout(Duration::from_millis(500), h)
            .await
            .unwrap_or_else(|_| panic!("daemon {who} did not shut down in 500ms"))
            .unwrap_or_else(|_| panic!("daemon {who} task panicked"))
            .unwrap_or_else(|_| panic!("daemon {who} run() returned Err"));
    }
    assert!(
        !PANIC_TRIGGERED.load(Ordering::SeqCst),
        "a panic was captured by the test panic hook"
    );
}

/// FluxMesh robustness slice 2: B's PRIMARY (A) leaves while a secondary (C) is
/// still live. B must fail over to C — keep the link "connected" with C as the
/// new primary — instead of dropping to Discovering. The discriminator is B's
/// singular `peer_name`: it flips A → C (the old code left it stale on A or
/// cleared it on GhostTimeout, never C).
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn primary_failover_promotes_secondary_when_primary_leaves() {
    let _ = tracing_subscriber::fmt::try_init();
    install_panic_hook();

    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let id_c = Identity::generate();
    let (pid_a, _pid_b, pid_c) = (id_a.peer_id(), id_b.peer_id(), id_c.peer_id());
    let (sess_a_b, sess_b_a) = pair_for_test(&id_a, &id_b).expect("pair a-b");
    let (sess_b_c, sess_c_b) = pair_for_test(&id_b, &id_c).expect("pair b-c");

    let (port_a, port_b, port_c) = (
        pick_free_udp_port().await,
        pick_free_udp_port().await,
        pick_free_udp_port().await,
    );
    let addr_a: SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();
    let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();
    let addr_c: SocketAddr = format!("127.0.0.1:{port_c}").parse().unwrap();

    let dir = tempfile::tempdir().expect("tempdir");
    let ipc_a = dir.path().join("a.sock");
    let ipc_b = dir.path().join("b.sock");
    let ipc_c = dir.path().join("c.sock");

    let mut cfg_a = base_cfg(id_a, port_a, ipc_a.clone(), "node-a");
    cfg_a.test_pair = Some(TestPair {
        session: sess_a_b,
        peer_addr: addr_b,
        peer_name: "node-b".into(),
        peer_id: id_b.peer_id(),
    });
    let mut cfg_c = base_cfg(id_c, port_c, ipc_c.clone(), "node-c");
    cfg_c.test_pair = Some(TestPair {
        session: sess_c_b,
        peer_addr: addr_b,
        peer_name: "node-b".into(),
        peer_id: id_b.peer_id(),
    });
    // B — primary A, secondary C.
    let mut cfg_b = base_cfg(id_b, port_b, ipc_b.clone(), "node-b");
    cfg_b.test_pair = Some(TestPair {
        session: sess_b_a,
        peer_addr: addr_a,
        peer_name: "node-a".into(),
        peer_id: pid_a,
    });
    cfg_b.test_pairs = vec![TestPair {
        session: sess_b_c,
        peer_addr: addr_c,
        peer_name: "node-c".into(),
        peer_id: pid_c,
    }];

    let sd_a = CancellationToken::new();
    let sd_b = CancellationToken::new();
    let sd_c = CancellationToken::new();
    let (ca, cb, cc) = (sd_a.clone(), sd_b.clone(), sd_c.clone());
    let h_a = tokio::spawn(async move { run(cfg_a, ca).await });
    let h_b = tokio::spawn(async move { run(cfg_b, cb).await });
    let h_c = tokio::spawn(async move { run(cfg_c, cc).await });

    // B starts with A as primary and lists both peers.
    let up = wait_until(Duration::from_secs(2), || async {
        peer_name(&ipc_b).await.as_deref() == Some("node-a") && mesh_peers(&ipc_b).await.0 == 2
    })
    .await;
    assert!(up, "B did not reach its A-primary / 2-peer steady state");

    // A unpairs → sends Bye to B (its only peer). B's primary just left.
    let unpair = ipc_send_recv(
        &ipc_a,
        CmdRequest {
            id: 77,
            op: CmdOp::Unpair {},
        },
    )
    .await;
    assert!(unpair.ok, "unpair on A failed: {unpair:?}");

    // B fails over to the live secondary C: primary projection flips to node-c,
    // and the mesh list collapses to just C (still the primary).
    let failed_over = wait_until(Duration::from_secs(3), || async {
        peer_name(&ipc_b).await.as_deref() == Some("node-c")
    })
    .await;
    assert!(
        failed_over,
        "B did not fail over to secondary C (peer_name = {:?})",
        peer_name(&ipc_b).await
    );
    assert_eq!(
        mesh_peers(&ipc_b).await,
        (1, 1),
        "after failover B should list only C as the single primary"
    );

    sd_a.cancel();
    sd_b.cancel();
    sd_c.cancel();
    for (h, who) in [(h_a, "A"), (h_b, "B"), (h_c, "C")] {
        timeout(Duration::from_millis(500), h)
            .await
            .unwrap_or_else(|_| panic!("daemon {who} did not shut down in 500ms"))
            .unwrap_or_else(|_| panic!("daemon {who} task panicked"))
            .unwrap_or_else(|_| panic!("daemon {who} run() returned Err"));
    }
    assert!(
        !PANIC_TRIGGERED.load(Ordering::SeqCst),
        "a panic was captured by the test panic hook"
    );
}

/// FluxMesh robustness slice 4: B revokes its SECONDARY peer C (per-peer
/// unpair). C's session must tear down on both sides while B's PRIMARY link to
/// A is left completely untouched — the old Revoke only dropped a session when
/// the target was the primary, so a revoked secondary kept syncing.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn revoke_secondary_drops_only_that_peer() {
    let _ = tracing_subscriber::fmt::try_init();
    install_panic_hook();

    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let id_c = Identity::generate();
    let (pid_a, _pid_b, pid_c) = (id_a.peer_id(), id_b.peer_id(), id_c.peer_id());
    let (sess_a_b, sess_b_a) = pair_for_test(&id_a, &id_b).expect("pair a-b");
    let (sess_b_c, sess_c_b) = pair_for_test(&id_b, &id_c).expect("pair b-c");

    let (port_a, port_b, port_c) = (
        pick_free_udp_port().await,
        pick_free_udp_port().await,
        pick_free_udp_port().await,
    );
    let addr_a: SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();
    let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();
    let addr_c: SocketAddr = format!("127.0.0.1:{port_c}").parse().unwrap();

    let dir = tempfile::tempdir().expect("tempdir");
    let ipc_a = dir.path().join("a.sock");
    let ipc_b = dir.path().join("b.sock");
    let ipc_c = dir.path().join("c.sock");

    let mut cfg_a = base_cfg(id_a, port_a, ipc_a.clone(), "node-a");
    cfg_a.test_pair = Some(TestPair {
        session: sess_a_b,
        peer_addr: addr_b,
        peer_name: "node-b".into(),
        peer_id: id_b.peer_id(),
    });
    let mut cfg_c = base_cfg(id_c, port_c, ipc_c.clone(), "node-c");
    cfg_c.test_pair = Some(TestPair {
        session: sess_c_b,
        peer_addr: addr_b,
        peer_name: "node-b".into(),
        peer_id: id_b.peer_id(),
    });
    let mut cfg_b = base_cfg(id_b, port_b, ipc_b.clone(), "node-b");
    cfg_b.test_pair = Some(TestPair {
        session: sess_b_a,
        peer_addr: addr_a,
        peer_name: "node-a".into(),
        peer_id: pid_a,
    });
    cfg_b.test_pairs = vec![TestPair {
        session: sess_b_c,
        peer_addr: addr_c,
        peer_name: "node-c".into(),
        peer_id: pid_c,
    }];

    let sd_a = CancellationToken::new();
    let sd_b = CancellationToken::new();
    let sd_c = CancellationToken::new();
    let (ca, cb, cc) = (sd_a.clone(), sd_b.clone(), sd_c.clone());
    let h_a = tokio::spawn(async move { run(cfg_a, ca).await });
    let h_b = tokio::spawn(async move { run(cfg_b, cb).await });
    let h_c = tokio::spawn(async move { run(cfg_c, cc).await });

    let up = wait_until(Duration::from_secs(2), || async {
        peer_name(&ipc_b).await.as_deref() == Some("node-a")
            && mesh_peers(&ipc_b).await.0 == 2
            && mesh_peers(&ipc_c).await.0 == 1
    })
    .await;
    assert!(up, "B did not reach A-primary / 2-peer steady state");

    // B revokes ONLY its secondary C.
    let pid_c_hex: String = pid_c.iter().fold(String::new(), |mut out, b| {
        write!(out, "{b:02x}").unwrap();
        out
    });
    let revoke = ipc_send_recv(
        &ipc_b,
        CmdRequest {
            id: 88,
            op: CmdOp::Revoke { peer_id: pid_c_hex },
        },
    )
    .await;
    assert!(revoke.ok, "revoke of secondary failed: {revoke:?}");

    // B drops C from the mesh but keeps A as the (still primary) link.
    let dropped = wait_until(Duration::from_secs(3), || async {
        mesh_peers(&ipc_b).await == (1, 1) && peer_name(&ipc_b).await.as_deref() == Some("node-a")
    })
    .await;
    assert!(
        dropped,
        "B did not drop only C (peers={:?}, primary={:?})",
        mesh_peers(&ipc_b).await,
        peer_name(&ipc_b).await
    );

    // C received the Revoke and tore its side down (no live peers left).
    let c_down = wait_until(Duration::from_secs(3), || async {
        mesh_peers(&ipc_c).await == (0, 0)
    })
    .await;
    assert!(c_down, "C did not tear down its session after being revoked");

    sd_a.cancel();
    sd_b.cancel();
    sd_c.cancel();
    for (h, who) in [(h_a, "A"), (h_b, "B"), (h_c, "C")] {
        timeout(Duration::from_millis(500), h)
            .await
            .unwrap_or_else(|_| panic!("daemon {who} did not shut down in 500ms"))
            .unwrap_or_else(|_| panic!("daemon {who} task panicked"))
            .unwrap_or_else(|_| panic!("daemon {who} run() returned Err"));
    }
    assert!(
        !PANIC_TRIGGERED.load(Ordering::SeqCst),
        "a panic was captured by the test panic hook"
    );
}

/// FluxMesh bug #5 (P0 security): rejecting a SECONDARY's SAS pairing
/// (`CmdOp::PairConfirm { accept: false }`) used to fire
/// `Event::ManualUnpair`, whose `CloseSession`/`DropPeer` actions are
/// unit/primary-only — they send `Bye` and drop the session on the PRIMARY
/// slot regardless of which peer was actually being rejected. So rejecting
/// C's (secondary) pairing on B tore down B's healthy PRIMARY link to A,
/// while C — which never got a session drop at all — stayed fully linked.
/// The fix makes the reject peer-scoped, mirroring `CmdOp::Revoke`: B must
/// drop only C, and A's link must survive completely untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn pair_confirm_reject_secondary_drops_only_that_peer() {
    let _ = tracing_subscriber::fmt::try_init();
    install_panic_hook();

    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let id_c = Identity::generate();
    let (pid_a, _pid_b, pid_c) = (id_a.peer_id(), id_b.peer_id(), id_c.peer_id());
    let c_static_pub = id_c.public_key();
    let (sess_a_b, sess_b_a) = pair_for_test(&id_a, &id_b).expect("pair a-b");
    let (sess_b_c, sess_c_b) = pair_for_test(&id_b, &id_c).expect("pair b-c");

    let (port_a, port_b, port_c) = (
        pick_free_udp_port().await,
        pick_free_udp_port().await,
        pick_free_udp_port().await,
    );
    let addr_a: SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();
    let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();
    let addr_c: SocketAddr = format!("127.0.0.1:{port_c}").parse().unwrap();

    let dir = tempfile::tempdir().expect("tempdir");
    let ipc_a = dir.path().join("a.sock");
    let ipc_b = dir.path().join("b.sock");
    let ipc_c = dir.path().join("c.sock");

    let mut cfg_a = base_cfg(id_a, port_a, ipc_a.clone(), "node-a");
    cfg_a.test_pair = Some(TestPair {
        session: sess_a_b,
        peer_addr: addr_b,
        peer_name: "node-b".into(),
        peer_id: id_b.peer_id(),
    });
    let mut cfg_c = base_cfg(id_c, port_c, ipc_c.clone(), "node-c");
    cfg_c.test_pair = Some(TestPair {
        session: sess_c_b,
        peer_addr: addr_b,
        peer_name: "node-b".into(),
        peer_id: id_b.peer_id(),
    });
    let mut cfg_b = base_cfg(id_b, port_b, ipc_b.clone(), "node-b");
    cfg_b.test_pair = Some(TestPair {
        session: sess_b_a,
        peer_addr: addr_a,
        peer_name: "node-a".into(),
        peer_id: pid_a,
    });
    cfg_b.test_pairs = vec![TestPair {
        session: sess_b_c,
        peer_addr: addr_c,
        peer_name: "node-c".into(),
        peer_id: pid_c,
    }];
    // C is a freshly TOFU-joined secondary still awaiting the human's SAS
    // verdict on B — exactly the state `CmdOp::PairConfirm` resolves.
    cfg_b.test_pending_pair = Some(TestPendingPair {
        peer_id: pid_c,
        static_pub: c_static_pub,
        name: "node-c".into(),
        sas_words: [
            "alpha".into(),
            "bravo".into(),
            "charlie".into(),
            "delta".into(),
            "echo".into(),
            "foxtrot".into(),
        ],
        from: addr_c,
        expires_in: Duration::from_secs(60),
    });

    let sd_a = CancellationToken::new();
    let sd_b = CancellationToken::new();
    let sd_c = CancellationToken::new();
    let (ca, cb, cc) = (sd_a.clone(), sd_b.clone(), sd_c.clone());
    let h_a = tokio::spawn(async move { run(cfg_a, ca).await });
    let h_b = tokio::spawn(async move { run(cfg_b, cb).await });
    let h_c = tokio::spawn(async move { run(cfg_c, cc).await });

    let up = wait_until(Duration::from_secs(2), || async {
        peer_name(&ipc_b).await.as_deref() == Some("node-a")
            && mesh_peers(&ipc_b).await.0 == 2
            && mesh_peers(&ipc_c).await.0 == 1
    })
    .await;
    assert!(up, "B did not reach A-primary / 2-peer steady state");

    // B rejects C's (secondary) pending SAS pairing.
    let pid_c_hex: String = pid_c.iter().fold(String::new(), |mut out, b| {
        write!(out, "{b:02x}").unwrap();
        out
    });
    let reject = ipc_send_recv(
        &ipc_b,
        CmdRequest {
            id: 89,
            op: CmdOp::PairConfirm {
                peer_id: pid_c_hex,
                accept: false,
            },
        },
    )
    .await;
    assert!(
        reject.ok,
        "reject of secondary's pending pair failed: {reject:?}"
    );

    // B drops ONLY C — A's primary link must survive completely untouched.
    // Before the fix, `Event::ManualUnpair`'s primary-only `CloseSession`
    // dropped A's session instead (and left C fully linked).
    let dropped = wait_until(Duration::from_secs(3), || async {
        mesh_peers(&ipc_b).await == (1, 1) && peer_name(&ipc_b).await.as_deref() == Some("node-a")
    })
    .await;
    assert!(
        dropped,
        "B did not keep A as its sole live primary after rejecting secondary C \
         (peers={:?}, primary_name={:?})",
        mesh_peers(&ipc_b).await,
        peer_name(&ipc_b).await
    );

    // C received the (accept:false) PairConfirm and tore its own side down.
    let c_down = wait_until(Duration::from_secs(3), || async {
        mesh_peers(&ipc_c).await == (0, 0)
    })
    .await;
    assert!(c_down, "C did not tear down its session after being rejected");

    // Positive proof A's session is genuinely alive, not just labeled so: a
    // fresh push from A must still reach B.
    let text = "still-linked-after-secondary-reject";
    let push = ipc_send_recv(
        &ipc_a,
        CmdRequest {
            id: 90,
            op: CmdOp::Push { text: text.into() },
        },
    )
    .await;
    assert!(push.ok, "push from A failed: {push:?}");
    let arrived = wait_until(Duration::from_secs(2), || async {
        history_count(&ipc_b, text).await >= 1
    })
    .await;
    assert!(
        arrived,
        "A's push never reached B — the primary session was corrupted by the secondary's reject"
    );

    sd_a.cancel();
    sd_b.cancel();
    sd_c.cancel();
    for (h, who) in [(h_a, "A"), (h_b, "B"), (h_c, "C")] {
        timeout(Duration::from_millis(500), h)
            .await
            .unwrap_or_else(|_| panic!("daemon {who} did not shut down in 500ms"))
            .unwrap_or_else(|_| panic!("daemon {who} task panicked"))
            .unwrap_or_else(|_| panic!("daemon {who} run() returned Err"));
    }
    assert!(
        !PANIC_TRIGGERED.load(Ordering::SeqCst),
        "a panic was captured by the test panic hook"
    );
}

/// Star push: B (centre) pushes; both leaves A and C receive it directly.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn three_node_center_push_reaches_both_leaves() {
    let _ = tracing_subscriber::fmt::try_init();
    install_panic_hook();

    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let id_c = Identity::generate();
    let (pid_a, _pid_b, pid_c) = (id_a.peer_id(), id_b.peer_id(), id_c.peer_id());
    let (sess_a_b, sess_b_a) = pair_for_test(&id_a, &id_b).expect("pair a-b");
    let (sess_b_c, sess_c_b) = pair_for_test(&id_b, &id_c).expect("pair b-c");

    let (port_a, port_b, port_c) = (
        pick_free_udp_port().await,
        pick_free_udp_port().await,
        pick_free_udp_port().await,
    );
    let addr_a: SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();
    let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();
    let addr_c: SocketAddr = format!("127.0.0.1:{port_c}").parse().unwrap();

    let dir = tempfile::tempdir().expect("tempdir");
    let ipc_a = dir.path().join("a.sock");
    let ipc_b = dir.path().join("b.sock");
    let ipc_c = dir.path().join("c.sock");

    let mut cfg_a = base_cfg(id_a, port_a, ipc_a.clone(), "node-a");
    cfg_a.test_pair = Some(TestPair {
        session: sess_a_b,
        peer_addr: addr_b,
        peer_name: "node-b".into(),
        peer_id: id_b.peer_id(),
    });
    let mut cfg_c = base_cfg(id_c, port_c, ipc_c.clone(), "node-c");
    cfg_c.test_pair = Some(TestPair {
        session: sess_c_b,
        peer_addr: addr_b,
        peer_name: "node-b".into(),
        peer_id: id_b.peer_id(),
    });
    let mut cfg_b = base_cfg(id_b, port_b, ipc_b.clone(), "node-b");
    cfg_b.test_pair = Some(TestPair {
        session: sess_b_a,
        peer_addr: addr_a,
        peer_name: "node-a".into(),
        peer_id: pid_a,
    });
    cfg_b.test_pairs = vec![TestPair {
        session: sess_b_c,
        peer_addr: addr_c,
        peer_name: "node-c".into(),
        peer_id: pid_c,
    }];

    let sd_a = CancellationToken::new();
    let sd_b = CancellationToken::new();
    let sd_c = CancellationToken::new();
    let (ca, cb, cc) = (sd_a.clone(), sd_b.clone(), sd_c.clone());
    let h_a = tokio::spawn(async move { run(cfg_a, ca).await });
    let h_b = tokio::spawn(async move { run(cfg_b, cb).await });
    let h_c = tokio::spawn(async move { run(cfg_c, cc).await });

    let up = wait_until(Duration::from_secs(2), || async {
        peer_name(&ipc_a).await.as_deref() == Some("node-b")
            && peer_name(&ipc_b).await.as_deref() == Some("node-a")
            && peer_name(&ipc_c).await.as_deref() == Some("node-b")
    })
    .await;
    assert!(up, "all three daemons did not reach Linked within 2s");

    // ── FluxMesh Phase 3: B (centre) lists BOTH leaves; each leaf lists B ──
    let listed = wait_until(Duration::from_secs(2), || async {
        mesh_peers(&ipc_b).await.0 == 2
    })
    .await;
    assert!(listed, "B did not surface both mesh peers in State.peers");
    let (b_count, b_primary) = mesh_peers(&ipc_b).await;
    assert_eq!(b_count, 2, "B should list both leaves");
    assert_eq!(b_primary, 1, "exactly one of B's peers is the primary");
    assert_eq!(mesh_peers(&ipc_a).await, (1, 1), "A lists only B (primary)");
    assert_eq!(mesh_peers(&ipc_c).await, (1, 1), "C lists only B (primary)");

    let text = "from the centre";
    let push = ipc_send_recv(
        &ipc_b,
        CmdRequest {
            id: 7,
            op: CmdOp::Push { text: text.into() },
        },
    )
    .await;
    assert!(push.ok, "push failed: {push:?}");

    let arrived = wait_until(Duration::from_secs(3), || async {
        history_count(&ipc_a, text).await >= 1 && history_count(&ipc_c, text).await >= 1
    })
    .await;
    assert!(arrived, "centre push did not reach both leaves within 3s");

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(history_count(&ipc_a, text).await, 1, "A applied item twice");
    assert_eq!(history_count(&ipc_c, text).await, 1, "C applied item twice");

    sd_a.cancel();
    sd_b.cancel();
    sd_c.cancel();
    for (h, who) in [(h_a, "A"), (h_b, "B"), (h_c, "C")] {
        timeout(Duration::from_millis(500), h)
            .await
            .unwrap_or_else(|_| panic!("daemon {who} did not shut down in 500ms"))
            .unwrap_or_else(|_| panic!("daemon {who} task panicked"))
            .unwrap_or_else(|_| panic!("daemon {who} run() returned Err"));
    }
    assert!(
        !PANIC_TRIGGERED.load(Ordering::SeqCst),
        "a panic was captured by the test panic hook"
    );
}

/// Read `State.firewall.enabled` from the daemon at `ipc`.
async fn firewall_enabled(ipc: &PathBuf) -> bool {
    let resp = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 7,
            op: CmdOp::Status,
        },
    )
    .await;
    match resp.data {
        Some(CmdData::State(s)) => s.firewall.enabled,
        _ => false,
    }
}

/// FluxFirewall slice 3: a `SetFirewall` IPC command with `text = Never` on the
/// sender must stop locally-copied text from reaching the peer, the policy must
/// surface in `State`, and flipping the rule back to `Always` must restore the
/// flow — all driven headlessly over IPC, no devices.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn firewall_deny_outbound_blocks_peer_and_is_reversible() {
    let _ = tracing_subscriber::fmt::try_init();
    install_panic_hook();

    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let (pid_a, pid_b) = (id_a.peer_id(), id_b.peer_id());
    let (sess_a_b, sess_b_a) = pair_for_test(&id_a, &id_b).expect("pair a-b");

    let (port_a, port_b) = (pick_free_udp_port().await, pick_free_udp_port().await);
    let addr_a: SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();
    let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();

    let dir = tempfile::tempdir().expect("tempdir");
    let ipc_a = dir.path().join("a.sock");
    let ipc_b = dir.path().join("b.sock");

    let mut cfg_a = base_cfg(id_a, port_a, ipc_a.clone(), "node-a");
    cfg_a.test_pair = Some(TestPair {
        session: sess_a_b,
        peer_addr: addr_b,
        peer_name: "node-b".into(),
        peer_id: pid_b,
    });
    let mut cfg_b = base_cfg(id_b, port_b, ipc_b.clone(), "node-b");
    cfg_b.test_pair = Some(TestPair {
        session: sess_b_a,
        peer_addr: addr_a,
        peer_name: "node-a".into(),
        peer_id: pid_a,
    });

    let sd_a = CancellationToken::new();
    let sd_b = CancellationToken::new();
    let (ca, cb) = (sd_a.clone(), sd_b.clone());
    let h_a = tokio::spawn(async move { run(cfg_a, ca).await });
    let h_b = tokio::spawn(async move { run(cfg_b, cb).await });

    let up = wait_until(Duration::from_secs(2), || async {
        peer_name(&ipc_a).await.as_deref() == Some("node-b")
            && peer_name(&ipc_b).await.as_deref() == Some("node-a")
    })
    .await;
    assert!(up, "A/B did not link within 2s");

    // ── 1. firewall OFF (default): a normal push reaches B ──
    let allowed = "fw-allowed-control";
    let p = ipc_send_recv(
        &ipc_a,
        CmdRequest {
            id: 1,
            op: CmdOp::Push {
                text: allowed.into(),
            },
        },
    )
    .await;
    assert!(p.ok, "control push failed: {p:?}");
    assert!(
        wait_until(Duration::from_secs(2), || async {
            history_count(&ipc_b, allowed).await >= 1
        })
        .await,
        "control push never reached B"
    );

    // ── 2. enable firewall on A with text = Never; it must show up in State ──
    let policy = FirewallPolicy {
        enabled: true,
        text: Rule::Deny,
        url: Rule::Allow,
        code: Rule::Allow,
        image: Rule::Allow,
        sensitive: Rule::Ask,
    };
    let set = ipc_send_recv(
        &ipc_a,
        CmdRequest {
            id: 2,
            op: CmdOp::SetFirewall { policy },
        },
    )
    .await;
    assert!(set.ok, "set-firewall failed: {set:?}");
    assert!(
        firewall_enabled(&ipc_a).await,
        "A did not project the enabled firewall into State"
    );

    // ── 3. a Never-text push must NOT reach B ──
    let blocked = "fw-blocked-text";
    let p2 = ipc_send_recv(
        &ipc_a,
        CmdRequest {
            id: 3,
            op: CmdOp::Push {
                text: blocked.into(),
            },
        },
    )
    .await;
    assert!(p2.ok, "blocked push rejected locally: {p2:?}");
    // Give it a generous window on loopback; it must stay absent on B.
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(
        history_count(&ipc_b, blocked).await,
        0,
        "Never-text leaked to the peer"
    );

    // ── 4. reversible: flip text back to Always and it flows again ──
    let policy2 = FirewallPolicy {
        enabled: true,
        text: Rule::Allow,
        ..FirewallPolicy::default()
    };
    let set2 = ipc_send_recv(
        &ipc_a,
        CmdRequest {
            id: 4,
            op: CmdOp::SetFirewall { policy: policy2 },
        },
    )
    .await;
    assert!(set2.ok, "second set-firewall failed: {set2:?}");
    let allowed2 = "fw-allowed-again";
    let p3 = ipc_send_recv(
        &ipc_a,
        CmdRequest {
            id: 5,
            op: CmdOp::Push {
                text: allowed2.into(),
            },
        },
    )
    .await;
    assert!(p3.ok, "re-allowed push failed: {p3:?}");
    assert!(
        wait_until(Duration::from_secs(2), || async {
            history_count(&ipc_b, allowed2).await >= 1
        })
        .await,
        "push after re-allow never reached B"
    );

    sd_a.cancel();
    sd_b.cancel();
    let _ = timeout(Duration::from_secs(2), h_a).await;
    let _ = timeout(Duration::from_secs(2), h_b).await;
    assert!(
        !PANIC_TRIGGERED.load(Ordering::SeqCst),
        "a daemon panicked during the firewall test"
    );
}

/// The hex hashes currently parked in `State.pending` at `ipc`.
async fn pending_hashes(ipc: &PathBuf) -> Vec<String> {
    let resp = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 8,
            op: CmdOp::Status,
        },
    )
    .await;
    match resp.data {
        Some(CmdData::State(s)) => s.pending.iter().map(|p| p.hash.clone()).collect(),
        _ => Vec::new(),
    }
}

/// FluxFirewall slice 4: an `Ask` rule must PARK a locally-copied item (the
/// peer does not get it, it shows up in `State.pending`), and a `resolve` with
/// `allow=true` must finally deliver it. A second item resolved with
/// `allow=false` must be dropped. All headless over IPC.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn firewall_ask_parks_then_resolve_delivers_or_drops() {
    let _ = tracing_subscriber::fmt::try_init();
    install_panic_hook();

    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let (pid_a, pid_b) = (id_a.peer_id(), id_b.peer_id());
    let (sess_a_b, sess_b_a) = pair_for_test(&id_a, &id_b).expect("pair a-b");

    let (port_a, port_b) = (pick_free_udp_port().await, pick_free_udp_port().await);
    let addr_a: SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();
    let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();

    let dir = tempfile::tempdir().expect("tempdir");
    let ipc_a = dir.path().join("a.sock");
    let ipc_b = dir.path().join("b.sock");

    let mut cfg_a = base_cfg(id_a, port_a, ipc_a.clone(), "node-a");
    cfg_a.test_pair = Some(TestPair {
        session: sess_a_b,
        peer_addr: addr_b,
        peer_name: "node-b".into(),
        peer_id: pid_b,
    });
    let mut cfg_b = base_cfg(id_b, port_b, ipc_b.clone(), "node-b");
    cfg_b.test_pair = Some(TestPair {
        session: sess_b_a,
        peer_addr: addr_a,
        peer_name: "node-a".into(),
        peer_id: pid_a,
    });

    let sd_a = CancellationToken::new();
    let sd_b = CancellationToken::new();
    let (ca, cb) = (sd_a.clone(), sd_b.clone());
    let h_a = tokio::spawn(async move { run(cfg_a, ca).await });
    let h_b = tokio::spawn(async move { run(cfg_b, cb).await });

    let up = wait_until(Duration::from_secs(2), || async {
        peer_name(&ipc_a).await.as_deref() == Some("node-b")
            && peer_name(&ipc_b).await.as_deref() == Some("node-a")
    })
    .await;
    assert!(up, "A/B did not link within 2s");

    // text = Ask on the sender.
    let policy = FirewallPolicy {
        enabled: true,
        text: Rule::Ask,
        ..FirewallPolicy::default()
    };
    let set = ipc_send_recv(
        &ipc_a,
        CmdRequest {
            id: 1,
            op: CmdOp::SetFirewall { policy },
        },
    )
    .await;
    assert!(set.ok, "set-firewall failed: {set:?}");

    // ── 1. push "ask-deliver" → parked on A, NOT delivered to B ──
    let deliver = "ask-deliver";
    let p1 = ipc_send_recv(
        &ipc_a,
        CmdRequest {
            id: 2,
            op: CmdOp::Push {
                text: deliver.into(),
            },
        },
    )
    .await;
    assert!(p1.ok);
    let parked = wait_until(Duration::from_secs(2), || async {
        pending_hashes(&ipc_a).await.len() == 1
    })
    .await;
    assert!(parked, "item was not parked in State.pending");
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        history_count(&ipc_b, deliver).await,
        0,
        "parked item reached the peer before approval"
    );

    // approve → it is delivered and leaves the pending queue.
    let hash = pending_hashes(&ipc_a).await.remove(0);
    let resolve = ipc_send_recv(
        &ipc_a,
        CmdRequest {
            id: 3,
            op: CmdOp::ResolvePending {
                hash: hash.clone(),
                allow: true,
            },
        },
    )
    .await;
    assert!(resolve.ok, "resolve(allow) failed: {resolve:?}");
    assert!(
        wait_until(Duration::from_secs(2), || async {
            history_count(&ipc_b, deliver).await >= 1
        })
        .await,
        "approved item never reached B"
    );
    assert!(
        pending_hashes(&ipc_a).await.is_empty(),
        "pending not cleared after approve"
    );

    // ── 2. push "ask-drop" → park, then DENY → never delivered ──
    let drop_text = "ask-drop";
    let p2 = ipc_send_recv(
        &ipc_a,
        CmdRequest {
            id: 4,
            op: CmdOp::Push {
                text: drop_text.into(),
            },
        },
    )
    .await;
    assert!(p2.ok);
    let parked2 = wait_until(Duration::from_secs(2), || async {
        pending_hashes(&ipc_a).await.len() == 1
    })
    .await;
    assert!(parked2, "second item was not parked");
    let hash2 = pending_hashes(&ipc_a).await.remove(0);
    let deny = ipc_send_recv(
        &ipc_a,
        CmdRequest {
            id: 5,
            op: CmdOp::ResolvePending {
                hash: hash2,
                allow: false,
            },
        },
    )
    .await;
    assert!(deny.ok, "resolve(deny) failed: {deny:?}");
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        history_count(&ipc_b, drop_text).await,
        0,
        "denied item leaked to the peer"
    );
    assert!(
        pending_hashes(&ipc_a).await.is_empty(),
        "pending not cleared after deny"
    );

    sd_a.cancel();
    sd_b.cancel();
    let _ = timeout(Duration::from_secs(2), h_a).await;
    let _ = timeout(Duration::from_secs(2), h_b).await;
    assert!(
        !PANIC_TRIGGERED.load(Ordering::SeqCst),
        "a daemon panicked during the ask/resolve test"
    );
}
