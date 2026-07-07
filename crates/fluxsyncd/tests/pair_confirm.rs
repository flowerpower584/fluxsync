//! Integration test: FS-052 `PairConfirm` accept and reject paths at the
//! daemon level. Verifies that
//!
//! - `accept = true` drops the pending entry but keeps the peer trusted, and
//! - `accept = false` drops the pending entry **and** revokes trust.
//!
//! Pairing is injected via `DaemonConfig::test_pending_pair` + `test_pair`,
//! so the test never runs the real Noise handshake — it exercises only the
//! IPC + driver dispatch around the pending set and the trusted set.
//!
//! Closes M3 in `FluxSync_DIFFERENTIAL_REVIEW_2026-05-23.md`.

#![cfg(unix)]

use fluxsync_crypto::{test_util::pair_for_test, Identity};
use fluxsyncd::{
    cmd::{CmdData, CmdOp, CmdRequest, CmdResponse},
    run, DaemonConfig, TestPair, TestPendingPair,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UdpSocket, UnixStream};
use tokio::time::timeout;
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

/// Spin up one daemon with a peer already trusted (via `test_pair`) and a
/// matching entry in the pending-pair set (via `test_pending_pair`). The
/// caller drives `PairConfirm` against it.
///
/// Returns `(ipc_path, shutdown, join_handle, peer_id_hex)`.
async fn spawn_daemon_with_pending() -> (
    PathBuf,
    CancellationToken,
    tokio::task::JoinHandle<anyhow::Result<()>>,
    String,
) {
    let id_local = Identity::generate();
    let id_peer = Identity::generate();
    let peer_id = id_peer.peer_id();
    let peer_static_pub = id_peer.public_key();
    let (sess_local, _sess_peer) = pair_for_test(&id_local, &id_peer).expect("pair");

    let port = pick_free_udp_port().await;
    let peer_port = pick_free_udp_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    // Hold the tempdir alive for the daemon's lifetime.
    let dir = Box::leak(Box::new(dir));
    let ipc = dir.path().join("d.sock");

    let peer_addr: SocketAddr = format!("127.0.0.1:{peer_port}").parse().unwrap();

    let mut cfg = DaemonConfig::new(id_local, port, ipc.clone());
    cfg.udp_bind = "127.0.0.1".into();
    cfg.disable_clipboard = true;
    cfg.disable_mdns = true;
    cfg.peer_name_self = "device-local".into();
    cfg.test_pair = Some(TestPair {
        session: sess_local,
        peer_addr,
        peer_name: "device-peer".into(),
        peer_id,
    });
    cfg.test_pending_pair = Some(TestPendingPair {
        peer_id,
        static_pub: peer_static_pub,
        name: "device-peer".into(),
        sas_words: [
            "alpha".into(),
            "bravo".into(),
            "charlie".into(),
            "delta".into(),
            "echo".into(),
            "foxtrot".into(),
        ],
        from: peer_addr,
        expires_in: Duration::from_secs(60),
    });

    let shutdown = CancellationToken::new();
    let s = shutdown.clone();
    let h = tokio::spawn(async move { run(cfg, s).await });

    // Wait for the IPC socket to come up.
    let up = wait_until(Duration::from_secs(2), || async {
        if !ipc.exists() {
            return false;
        }
        let resp = ipc_send_recv(
            &ipc,
            CmdRequest {
                id: 1,
                op: CmdOp::Status,
            },
        )
        .await;
        resp.ok
    })
    .await;
    assert!(up, "daemon did not come up in 2s");

    (ipc, shutdown, h, hex::encode(peer_id))
}

/// `CmdData` is `#[serde(untagged)]`, so an empty `Vec<PendingPairEntry>`
/// is indistinguishable from an empty `Vec<PeerEntry>` after a round-trip
/// through JSON — both serialize to `[]`. We tolerate either shape and
/// treat an empty `Peers` payload as an empty pending list.
async fn pending_peer_ids(ipc: &PathBuf) -> Vec<String> {
    let resp = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 10,
            op: CmdOp::PairPending {},
        },
    )
    .await;
    match resp.data {
        Some(CmdData::PendingPairs(entries)) => entries.into_iter().map(|e| e.peer_id).collect(),
        Some(CmdData::Peers(entries)) if entries.is_empty() => Vec::new(),
        None => Vec::new(),
        other => panic!("expected PendingPairs, got {other:?}"),
    }
}

/// The hex peer ids currently in the persisted trust store, straight from
/// `CmdOp::TrustList` — the authoritative observable for a revoke.
async fn trusted_peer_ids(ipc: &PathBuf) -> Vec<String> {
    let resp = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 12,
            op: CmdOp::TrustList {},
        },
    )
    .await;
    match resp.data {
        Some(CmdData::TrustList(entries)) => {
            entries.into_iter().map(|e| e.peer_id_hex).collect()
        }
        // `CmdData` is `#[serde(untagged)]`: an empty `TrustList` round-trips
        // as `[]`, indistinguishable from any other empty list variant.
        Some(CmdData::Peers(entries)) if entries.is_empty() => Vec::new(),
        Some(CmdData::PendingPairs(entries)) if entries.is_empty() => Vec::new(),
        None => Vec::new(),
        other => panic!("expected TrustList, got {other:?}"),
    }
}

/// `Peers` reports the *currently-linked* peer (driver fills `peer_id` with
/// the placeholder `"paired"`, not the real hex), so we compare on `name`.
async fn linked_peer_names(ipc: &PathBuf) -> Vec<String> {
    let resp = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 11,
            op: CmdOp::Peers,
        },
    )
    .await;
    match resp.data {
        Some(CmdData::Peers(entries)) => entries.into_iter().map(|e| e.name).collect(),
        other => panic!("expected Peers, got {other:?}"),
    }
}

async fn shutdown_daemon(
    shutdown: CancellationToken,
    h: tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    shutdown.cancel();
    let _ = timeout(Duration::from_millis(500), h).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pair_confirm_accept_drops_pending_keeps_trusted() {
    let _ = tracing_subscriber::fmt::try_init();
    let (ipc, shutdown, h, peer_id_hex) = spawn_daemon_with_pending().await;

    // Wait for the test_pair injection events to settle so the App
    // snapshot reflects `peer_name = "device-peer"`.
    let linked_pre = wait_until(Duration::from_secs(1), || async {
        linked_peer_names(&ipc)
            .await
            .contains(&"device-peer".to_string())
    })
    .await;
    assert!(linked_pre, "expected linked peer before PairConfirm");

    assert!(
        pending_peer_ids(&ipc).await.contains(&peer_id_hex),
        "expected pending entry before PairConfirm"
    );

    let resp = ipc_send_recv(
        &ipc,
        CmdRequest {
            id: 20,
            op: CmdOp::PairConfirm {
                peer_id: peer_id_hex.clone(),
                accept: true,
            },
        },
    )
    .await;
    assert!(resp.ok, "PairConfirm accept failed: {resp:?}");

    assert!(
        !pending_peer_ids(&ipc).await.contains(&peer_id_hex),
        "pending entry must be removed after accept"
    );
    // Trust survived: ManualUnpair was NOT fired, so the linked peer is
    // still reported.
    assert!(
        linked_peer_names(&ipc)
            .await
            .contains(&"device-peer".to_string()),
        "linked peer must survive accept"
    );

    shutdown_daemon(shutdown, h).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pair_confirm_reject_drops_pending_and_revokes_trust() {
    let _ = tracing_subscriber::fmt::try_init();
    let (ipc, shutdown, h, peer_id_hex) = spawn_daemon_with_pending().await;

    let linked_pre = wait_until(Duration::from_secs(1), || async {
        linked_peer_names(&ipc)
            .await
            .contains(&"device-peer".to_string())
    })
    .await;
    assert!(linked_pre, "expected linked peer before PairConfirm");

    assert!(
        pending_peer_ids(&ipc).await.contains(&peer_id_hex),
        "expected pending entry before PairConfirm"
    );

    let resp = ipc_send_recv(
        &ipc,
        CmdRequest {
            id: 30,
            op: CmdOp::PairConfirm {
                peer_id: peer_id_hex.clone(),
                accept: false,
            },
        },
    )
    .await;
    assert!(resp.ok, "PairConfirm reject failed: {resp:?}");

    // Reject is a peer-scoped revoke (same teardown as `CmdOp::Revoke`, not
    // the old global `ManualUnpair`): the pending entry AND the trust-store
    // entry must both be gone. `state.peer_name` may keep the stale name
    // until GhostTimeout — exactly like revoking the primary — so trust
    // revocation is asserted directly via `TrustList` rather than through
    // the `Peers` projection.
    let purged = wait_until(Duration::from_secs(1), || async {
        let pending = pending_peer_ids(&ipc).await;
        let trusted = trusted_peer_ids(&ipc).await;
        !pending.contains(&peer_id_hex) && !trusted.contains(&peer_id_hex)
    })
    .await;
    assert!(purged, "pending + trust must both be cleared after reject");

    shutdown_daemon(shutdown, h).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pair_confirm_unknown_peer_id_errors() {
    let _ = tracing_subscriber::fmt::try_init();
    let (ipc, shutdown, h, _peer_id_hex) = spawn_daemon_with_pending().await;

    // 32-byte hex that doesn't match the pending entry.
    let unknown = hex::encode([0xAAu8; 32]);
    let resp = ipc_send_recv(
        &ipc,
        CmdRequest {
            id: 40,
            op: CmdOp::PairConfirm {
                peer_id: unknown,
                accept: true,
            },
        },
    )
    .await;
    assert!(!resp.ok, "PairConfirm with unknown peer_id must fail");
    assert_eq!(
        resp.err.as_deref(),
        Some("no pending pair with that peer_id"),
        "error message changed; update test or code"
    );

    shutdown_daemon(shutdown, h).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pair_confirm_bad_hex_errors() {
    let _ = tracing_subscriber::fmt::try_init();
    let (ipc, shutdown, h, _peer_id_hex) = spawn_daemon_with_pending().await;

    let resp = ipc_send_recv(
        &ipc,
        CmdRequest {
            id: 50,
            op: CmdOp::PairConfirm {
                peer_id: "not-hex".into(),
                accept: true,
            },
        },
    )
    .await;
    assert!(!resp.ok, "PairConfirm with non-hex must fail");
    assert_eq!(resp.err.as_deref(), Some("bad hex peer_id"));

    shutdown_daemon(shutdown, h).await;
}
