//! DIR-P1-09 integration test: reliability counters advance at the real
//! chokepoints in a live two-daemon loopback exchange.
//!
//! Mirrors `two_daemons.rs`'s in-process, loopback, `test_pair`-seeded
//! setup (no real Noise handshake needed — this test doesn't force a
//! rekey, just plain clipboard traffic).

#![cfg(unix)]

use fluxsync_crypto::{test_util::pair_for_test, Identity};
use fluxsyncd::{
    cmd::{CmdData, CmdOp, CmdRequest, CmdResponse},
    run, DaemonConfig, TestPair,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UdpSocket, UnixStream};
use tokio_util::sync::CancellationToken;

async fn pick_free_udp_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").await.expect("pick port");
    s.local_addr().expect("port").port()
}

async fn ipc_send_recv(path: &PathBuf, req: CmdRequest) -> CmdResponse {
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

async fn status(ipc: &PathBuf) -> Box<fluxsync_core::State> {
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

async fn push(ipc: &PathBuf, text: &str) {
    let resp = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 2,
            op: CmdOp::Push { text: text.into() },
        },
    )
    .await;
    assert!(resp.ok, "push {text:?} failed: {resp:?}");
}

async fn history_len(ipc: &PathBuf) -> usize {
    status(ipc).await.history.len()
}

async fn items_sent(ipc: &PathBuf) -> u64 {
    status(ipc).await.metrics.as_ref().map_or(0, |m| m.items_sent)
}

async fn items_received(ipc: &PathBuf) -> u64 {
    status(ipc)
        .await
        .metrics
        .as_ref()
        .map_or(0, |m| m.items_received)
}

async fn dedup_drops(ipc: &PathBuf) -> u64 {
    status(ipc).await.metrics.as_ref().map_or(0, |m| m.dedup_drops)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn counters_advance_on_send_receive_and_duplicate() {
    let _ = tracing_subscriber::fmt::try_init();

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

    let shutdown_a = CancellationToken::new();
    let shutdown_b = CancellationToken::new();
    let s_a = shutdown_a.clone();
    let s_b = shutdown_b.clone();

    let _h_a = tokio::spawn(async move { run(cfg_a, s_a).await });
    let _h_b = tokio::spawn(async move { run(cfg_b, s_b).await });

    assert!(wait_until(Duration::from_secs(2), || async { ipc_a.exists() }).await);
    assert!(wait_until(Duration::from_secs(2), || async { ipc_b.exists() }).await);
    // This is an in-process test daemon on a real machine: the battery
    // watcher reads the REAL host battery (see `battery.rs`), and a
    // laptop below the 20% default threshold would force the FSM's
    // policy layer (`App::phase_for_policy_ext`) into `Paused`, which
    // blocks `Action::SendItem` — unrelated to what this test is
    // actually exercising. Floor the threshold so real ambient battery
    // never gates this test.
    ipc_send_recv(
        &ipc_a,
        CmdRequest {
            id: 0,
            op: CmdOp::SetThreshold { value: 5 },
        },
    )
    .await;
    ipc_send_recv(
        &ipc_b,
        CmdRequest {
            id: 0,
            op: CmdOp::SetThreshold { value: 5 },
        },
    )
    .await;

    assert!(
        wait_until(Duration::from_secs(2), || async {
            status(&ipc_a).await.peer_name == "device-b"
        })
        .await,
        "daemon A did not link in 2s"
    );
    assert!(
        wait_until(Duration::from_secs(2), || async {
            status(&ipc_b).await.peer_name == "device-a"
        })
        .await,
        "daemon B did not link in 2s"
    );

    // Both `test_pair`-seeded daemons boot with an already-clean slate.
    assert_eq!(items_sent(&ipc_a).await, 0);
    assert_eq!(items_received(&ipc_b).await, 0);
    assert_eq!(dedup_drops(&ipc_a).await, 0);

    // ── send N distinct items A -> B ──
    let n: u64 = 3;
    let n_usize = usize::try_from(n).expect("n fits usize");
    let texts = ["counter-item-1", "counter-item-2", "counter-item-3"];
    for t in texts {
        push(&ipc_a, t).await;
    }

    assert!(
        wait_until(Duration::from_secs(3), || async {
            history_len(&ipc_b).await >= n_usize
        })
        .await,
        "B did not receive all {n} items in time"
    );

    assert!(
        wait_until(Duration::from_secs(2), || async { items_sent(&ipc_a).await == n }).await,
        "items_sent on A never reached {n} (was {})",
        items_sent(&ipc_a).await
    );
    assert!(
        wait_until(Duration::from_secs(2), || async { items_received(&ipc_b).await == n }).await,
        "items_received on B never reached {n} (was {})",
        items_received(&ipc_b).await
    );

    // ── resend a duplicate of the first item from A: the LOCAL dedup ring
    // suppresses the second identical push before it ever reaches the
    // transport (same content hash, `clipboard_dedup_hash`) ──
    push(&ipc_a, texts[0]).await;

    assert!(
        wait_until(Duration::from_secs(2), || async { dedup_drops(&ipc_a).await >= 1 }).await,
        "duplicates_dropped (dedup_drops) never advanced on A after resending a duplicate"
    );

    // The duplicate must not have been counted as a fresh send.
    assert_eq!(
        items_sent(&ipc_a).await,
        n,
        "a deduped resend must not bump items_sent"
    );

    shutdown_a.cancel();
    shutdown_b.cancel();
}
