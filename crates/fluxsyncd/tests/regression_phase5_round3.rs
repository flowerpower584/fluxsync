//! Phase 5 round 3 regression: FS-052 egress hole fix (Fix A, part 1).
//!
//! `Action::SendItem`'s fan-out used to send to every
//! `transport.linked_peer_ids()` peer regardless of pending status —
//! `gate_outbound` only suppresses the whole action when the PRIMARY peer is
//! pending. A pending SECONDARY mesh peer with a live session still got the
//! plaintext clipboard. This drives three real in-process daemons, mirroring
//! `three_daemons.rs`'s line topology, but marks the secondary peer PENDING
//! via `DaemonConfig::test_pending_pair` (skipping the QR/handshake flow like
//! `test_pair`/`test_pairs` do) and proves the pending peer's history stays
//! empty while the confirmed primary still gets the item.
//!
//! Fixes B, C, and D (inflight-merge on `ResyncPull`, the live-firewall
//! re-check on resync serve, and the SE-14 wire-hash verification) are
//! covered by driver-level unit tests in `driver.rs` instead — all three
//! turn on internal state (`Inflight::pending_peers`, the firewall's
//! `decide()` call, `dispatch_inbound_frame`'s outbox-insert timing) with no
//! IPC-observable signal of their own, and are far more precisely and
//! deterministically exercised via a direct function call than by racing
//! real network delivery.

#![cfg(unix)]
#![allow(clippy::similar_names)] // sess_a_b/sess_b_a/sess_b_c/sess_c_b name link-specific session pairs

use fluxsync_core::HistoryItem;
use fluxsync_crypto::{test_util::pair_for_test, Identity};
use fluxsyncd::{
    cmd::{CmdData, CmdOp, CmdRequest},
    config::{TestPair, TestPendingPair},
    run, DaemonConfig,
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

async fn history(ipc: &PathBuf) -> Vec<HistoryItem> {
    let resp = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 1,
            op: CmdOp::Status,
        },
    )
    .await;
    match resp.data {
        Some(CmdData::State(s)) => s.history,
        _ => Vec::new(),
    }
}

async fn history_count(ipc: &PathBuf, text: &str) -> usize {
    history(ipc)
        .await
        .iter()
        .filter(|h| h.preview == text)
        .count()
}

async fn peer_name(ipc: &PathBuf) -> Option<String> {
    if !ipc.exists() {
        return None;
    }
    let resp = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 2,
            op: CmdOp::Status,
        },
    )
    .await;
    match resp.data {
        Some(CmdData::State(s)) => Some(s.peer_name),
        _ => None,
    }
}

async fn set_threshold(ipc: &PathBuf, value: u8) {
    let r = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 3,
            op: CmdOp::SetThreshold { value },
        },
    )
    .await;
    assert!(r.ok, "set-threshold failed: {r:?}");
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
async fn pending_secondary_peer_excluded_from_send_item_fan_out() {
    let _ = tracing_subscriber::fmt::try_init();

    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let id_c = Identity::generate();
    let (pid_a, pid_b, pid_c) = (id_a.peer_id(), id_b.peer_id(), id_c.peer_id());

    // Two independent session pairs: A<->B (confirmed) and B<->C (pending).
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

    // A — linked only to B, and CONFIRMED (no pending entry).
    let mut cfg_a = base_cfg(id_a, port_a, ipc_a.clone(), "node-a");
    cfg_a.test_pair = Some(TestPair {
        session: sess_a_b,
        peer_addr: addr_b,
        peer_name: "node-b".into(),
        peer_id: pid_b,
    });

    // C — linked only to B, but B will mark C's peer_id PENDING below.
    let mut cfg_c = base_cfg(id_c, port_c, ipc_c.clone(), "node-c");
    cfg_c.test_pair = Some(TestPair {
        session: sess_c_b,
        peer_addr: addr_b,
        peer_name: "node-b".into(),
        peer_id: pid_b,
    });

    // B — the pusher: primary A (confirmed), secondary C (PENDING — has a
    // live session via `test_pairs`, but also lands in B's `PendingSet` via
    // `test_pending_pair`, exactly like a peer that finished the Noise TOFU
    // handshake but whose human has not yet verbally confirmed the SAS words).
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
    cfg_b.test_pending_pair = Some(TestPendingPair {
        peer_id: pid_c,
        static_pub: [0u8; 32],
        name: "node-c".into(),
        sas_words: std::array::from_fn(|i| format!("word{i}")),
        from: addr_c,
        expires_in: Duration::from_secs(90),
    });

    let sd_a = CancellationToken::new();
    let sd_b = CancellationToken::new();
    let sd_c = CancellationToken::new();
    let (ca, cb, cc) = (sd_a.clone(), sd_b.clone(), sd_c.clone());
    let _h_a = tokio::spawn(async move { run(cfg_a, ca).await });
    let _h_b = tokio::spawn(async move { run(cfg_b, cb).await });
    let _h_c = tokio::spawn(async move { run(cfg_c, cc).await });

    // Each daemon reaches Linked and projects its primary peer.
    let up = wait_until(Duration::from_secs(2), || async {
        peer_name(&ipc_a).await.as_deref() == Some("node-b")
            && peer_name(&ipc_b).await.as_deref() == Some("node-a")
            && peer_name(&ipc_c).await.as_deref() == Some("node-b")
    })
    .await;
    assert!(up, "all three daemons did not reach Linked within 2s");

    // Host-battery pause trap: floor the threshold before pushing.
    set_threshold(&ipc_a, 5).await;
    set_threshold(&ipc_b, 5).await;
    set_threshold(&ipc_c, 5).await;

    // Push FROM B: fans out to both A (confirmed primary) and C (pending
    // secondary) at the transport level, but the FS-052 gate must exclude C.
    let text = "fs052-secondary-pending-must-not-leak";
    let push = ipc_send_recv(
        &ipc_b,
        CmdRequest {
            id: 42,
            op: CmdOp::Push { text: text.into() },
        },
    )
    .await;
    assert!(push.ok, "push on b failed: {push:?}");

    let a_got_it = wait_until(Duration::from_secs(3), || async {
        history_count(&ipc_a, text).await >= 1
    })
    .await;
    assert!(
        a_got_it,
        "the CONFIRMED primary peer (a) must still receive the pushed item"
    );

    // Give C every chance to (incorrectly) receive it before asserting its
    // absence — a generous window well past normal delivery latency.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        history_count(&ipc_c, text).await,
        0,
        "FS-052: the PENDING secondary peer (c) must NOT receive the SendItem fan-out"
    );
}
