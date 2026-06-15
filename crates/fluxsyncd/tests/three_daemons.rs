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

use fluxsync_crypto::{test_util::pair_for_test, Identity};
use fluxsyncd::{
    cmd::{CmdData, CmdOp, CmdRequest},
    run, DaemonConfig, TestPair,
};
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
