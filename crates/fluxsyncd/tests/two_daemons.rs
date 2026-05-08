//! Integration test: two `fluxsyncd` instances exchange one clipboard
//! item over loopback UDP, then shut down cleanly.
//!
//! Skips the QR/handshake flow by injecting `pair_for_test` sessions
//! via `DaemonConfig::test_pair`. A regression in this test means the
//! sync path broke; the pairing path has its own dedicated test.
//!
//! Gated on `cfg(unix)` because the IPC client used in this test relies
//! on `tokio::net::UnixStream`. The Windows IPC path is exercised by
//! `fluxctl::one_shot` (Named Pipes) directly; we'll add a Windows
//! variant of this test alongside the v0.1.1 Named Pipe daemon work.

#![cfg(unix)]

use fluxsync_crypto::{test_util::pair_for_test, Identity};
use fluxsyncd::{
    cmd::{Channel, CmdData, CmdRequest, CmdResponse, Subscribe},
    run, DaemonConfig, TestPair,
};
use serde_json::json;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UdpSocket, UnixStream};
use tokio::sync::Notify;
use tokio::time::timeout;

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

async fn write_subscribe_cmd(stream: &mut UnixStream) -> std::io::Result<()> {
    stream.write_all(b"{\"subscribe\":\"cmd\"}\n").await?;
    stream.flush().await
}

async fn ipc_send_recv(path: &PathBuf, req: CmdRequest) -> CmdResponse {
    let mut stream = UnixStream::connect(path).await.expect("connect ipc");
    write_subscribe_cmd(&mut stream).await.expect("subscribe");
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_daemons_exchange_one_item_and_shutdown_cleanly() {
    let _ = tracing_subscriber::fmt::try_init();
    install_panic_hook();
    let _ = Subscribe {
        subscribe: Channel::Cmd,
    };

    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let peer_id_a = id_a.peer_id();
    let peer_id_b = id_b.peer_id();
    let (sess_a, sess_b) = pair_for_test(&id_a, &id_b).expect("pair");

    let port_a = pick_free_udp_port().await;
    let port_b = pick_free_udp_port().await;
    assert_ne!(port_a, port_b);

    let dir = tempfile::tempdir().expect("tempdir");
    let ipc_a = dir.path().join("a.sock");
    let ipc_b = dir.path().join("b.sock");

    let addr_a: SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();
    let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();

    let mut cfg_a = DaemonConfig::new(id_a, port_a, ipc_a.clone());
    cfg_a.udp_bind = "127.0.0.1".into();
    cfg_a.disable_clipboard = true;
    cfg_a.disable_mdns = true;
    cfg_a.peer_name_self = "device-a".into();
    cfg_a.test_pair = Some(TestPair {
        session: sess_a,
        peer_addr: addr_b,
        peer_name: "device-b".into(),
        peer_id: peer_id_b,
    });

    let mut cfg_b = DaemonConfig::new(id_b, port_b, ipc_b.clone());
    cfg_b.udp_bind = "127.0.0.1".into();
    cfg_b.disable_clipboard = true;
    cfg_b.disable_mdns = true;
    cfg_b.peer_name_self = "device-b".into();
    cfg_b.test_pair = Some(TestPair {
        session: sess_b,
        peer_addr: addr_a,
        peer_name: "device-a".into(),
        peer_id: peer_id_a,
    });

    let shutdown_a = Arc::new(Notify::new());
    let shutdown_b = Arc::new(Notify::new());
    let s_a = shutdown_a.clone();
    let s_b = shutdown_b.clone();

    let h_a = tokio::spawn(async move { run(cfg_a, s_a).await });
    let h_b = tokio::spawn(async move { run(cfg_b, s_b).await });

    // ── 1. both daemons reach a non-Inactive status within 2s ──
    let linked_a = wait_until(Duration::from_secs(2), || async {
        if !ipc_a.exists() {
            return false;
        }
        let resp = ipc_send_recv(
            &ipc_a,
            CmdRequest {
                id: 1,
                op: fluxsyncd::cmd::CmdOp::Status,
            },
        )
        .await;
        if let Some(CmdData::State(s)) = resp.data {
            if s.peer_name == "device-b" {
                return true;
            }
        }
        false
    })
    .await;
    assert!(linked_a, "daemon A did not reach Linked state in 2s");

    let linked_b = wait_until(Duration::from_secs(2), || async {
        if !ipc_b.exists() {
            return false;
        }
        let resp = ipc_send_recv(
            &ipc_b,
            CmdRequest {
                id: 1,
                op: fluxsyncd::cmd::CmdOp::Status,
            },
        )
        .await;
        if let Some(CmdData::State(s)) = resp.data {
            return s.peer_name == "device-a";
        }
        false
    })
    .await;
    assert!(linked_b, "daemon B did not reach Linked state in 2s");

    // ── 2. push from A → arrives on B within 2s ──
    let push_resp = ipc_send_recv(
        &ipc_a,
        CmdRequest {
            id: 42,
            op: fluxsyncd::cmd::CmdOp::Push {
                text: "hello world".into(),
            },
        },
    )
    .await;
    assert!(push_resp.ok, "push failed: {push_resp:?}");

    let received = wait_until(Duration::from_secs(2), || async {
        let resp = ipc_send_recv(
            &ipc_b,
            CmdRequest {
                id: 2,
                op: fluxsyncd::cmd::CmdOp::Status,
            },
        )
        .await;
        if let Some(CmdData::State(s)) = resp.data {
            return s.history.iter().any(|h| h.preview == "hello world");
        }
        false
    })
    .await;
    assert!(
        received,
        "push from A did not appear in B's history within 2s"
    );

    // ── 3. shutdown via Notify, both tasks join within 500ms ──
    let t_shutdown = std::time::Instant::now();
    shutdown_a.notify_waiters();
    shutdown_b.notify_waiters();
    timeout(Duration::from_millis(500), h_a)
        .await
        .expect("daemon A did not shut down in 500ms")
        .expect("daemon A task panic")
        .expect("daemon A run() returned Err");
    timeout(Duration::from_millis(500), h_b)
        .await
        .expect("daemon B did not shut down in 500ms")
        .expect("daemon B task panic")
        .expect("daemon B run() returned Err");
    assert!(
        t_shutdown.elapsed() < Duration::from_millis(500),
        "shutdown took longer than 500ms total"
    );

    // ── 4. no panic was triggered ──
    assert!(
        !PANIC_TRIGGERED.load(Ordering::SeqCst),
        "a panic was captured by the test panic hook"
    );

    // satisfy unused warnings on json! when the file is built without the
    // commented-out helper paths
    let _ = json!(null);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_starts_unpaired_and_responds_to_status() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("trace")
        .try_init();
    install_panic_hook();
    let id = Identity::generate();
    let port = pick_free_udp_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let ipc = dir.path().join("solo.sock");

    let mut cfg = DaemonConfig::new(id, port, ipc.clone());
    cfg.udp_bind = "127.0.0.1".into();
    cfg.disable_clipboard = true;
    cfg.disable_mdns = true;
    // No test_pair — simulates a fresh first-run with no peer.

    let shutdown = Arc::new(Notify::new());
    let s = shutdown.clone();
    let h = tokio::spawn(async move { run(cfg, s).await });

    let started = wait_until(Duration::from_secs(2), || async {
        if !ipc.exists() {
            return false;
        }
        let resp = ipc_send_recv(
            &ipc,
            CmdRequest {
                id: 1,
                op: fluxsyncd::cmd::CmdOp::Status,
            },
        )
        .await;
        resp.ok
    })
    .await;
    assert!(
        started,
        "unpaired daemon did not respond to status within 2s"
    );

    shutdown.notify_waiters();
    timeout(Duration::from_millis(500), h)
        .await
        .expect("solo daemon did not shut down in 500ms")
        .expect("solo daemon task panicked")
        .expect("solo daemon run() returned Err");

    assert!(
        !PANIC_TRIGGERED.load(Ordering::SeqCst),
        "a panic was captured during the unpaired-boot test"
    );
}
