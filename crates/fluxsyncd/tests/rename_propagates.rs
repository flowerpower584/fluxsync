//! DIR-P3-01 integration test: device rename propagation to an
//! already-linked peer.
//!
//! Proves the documented contract: a `CmdOp::SetDeviceName` updates the
//! renaming daemon's own state immediately, but the peer only learns the
//! new name via `Msg::Hello` on the *next session establishment* — a
//! fresh `Handshaking -> Linked` transition (`Action::OpenSession` only
//! fires from that FSM arm). Notably this is NOT the DIR-P2-03 automatic
//! rekey: a rekey is deliberately invisible at the FSM level (phase never
//! leaves `"linked"`, see `rekey.rs`), so `transition(Phase::Linked,
//! Event::HandshakeOk)` hits the catch-all with no actions and no fresh
//! `Msg::Hello` is sent — confirmed empirically while writing this test.
//! The next *genuine* session establishment (here: a daemon restart,
//! mirroring `vault_persist.rs`'s restart pattern) is what actually
//! carries the rename, and that is the honest, documented minimum this
//! feature promises — no new wire message, no forced disruptive
//! reconnect just to push a cosmetic field.

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

/// Floor the battery threshold so a real, low, discharging host battery
/// (this is an in-process daemon reading the REAL machine battery, see
/// `battery.rs`) can never force the FSM's policy layer into `Paused` and
/// gate this test on something it isn't exercising.
async fn floor_battery_threshold(ipc: &PathBuf) {
    ipc_send_recv(
        ipc,
        CmdRequest {
            id: 0,
            op: CmdOp::SetThreshold { value: 5 },
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::similar_names)] // sess_a1/sess_b1/sess_a2/sess_b2 etc. name two daemons across two runs
async fn rename_reaches_peer_only_on_next_session_establishment() {
    let _ = tracing_subscriber::fmt::try_init();

    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let peer_id_a = id_a.peer_id();
    let peer_id_b = id_b.peer_id();

    let dir = tempfile::tempdir().expect("tempdir");
    let keystore_a = dir.path().join("ks-a");
    std::fs::create_dir(&keystore_a).unwrap();
    let ipc_a = dir.path().join("a.sock");
    let ipc_b = dir.path().join("b.sock");

    // ── v1: A and B pair and link ──
    let (sess_a1, sess_b1) = pair_for_test(&id_a, &id_b).expect("pair v1");
    let port_a1 = pick_free_udp_port().await;
    let port_b1 = pick_free_udp_port().await;
    let addr_a1: SocketAddr = format!("127.0.0.1:{port_a1}").parse().unwrap();
    let addr_b1: SocketAddr = format!("127.0.0.1:{port_b1}").parse().unwrap();

    let mut cfg_a1 = DaemonConfig::new(id_a.clone(), port_a1, ipc_a.clone());
    cfg_a1.udp_bind = "127.0.0.1".into();
    cfg_a1.disable_clipboard = true;
    cfg_a1.disable_mdns = true;
    cfg_a1.peer_name_self = "device-a".into();
    cfg_a1.keystore_dir = Some(keystore_a.clone());
    cfg_a1.test_pair = Some(TestPair {
        session: sess_a1,
        peer_addr: addr_b1,
        peer_name: "device-b".into(),
        peer_id: peer_id_b,
    });

    let mut cfg_b1 = DaemonConfig::new(id_b.clone(), port_b1, ipc_b.clone());
    cfg_b1.udp_bind = "127.0.0.1".into();
    cfg_b1.disable_clipboard = true;
    cfg_b1.disable_mdns = true;
    cfg_b1.peer_name_self = "device-b".into();
    cfg_b1.test_pair = Some(TestPair {
        session: sess_b1,
        peer_addr: addr_a1,
        peer_name: "device-a".into(),
        peer_id: peer_id_a,
    });

    let sd_a1 = CancellationToken::new();
    let sd_b1 = CancellationToken::new();
    let h_a1 = tokio::spawn(run(cfg_a1, sd_a1.clone()));
    let h_b1 = tokio::spawn(run(cfg_b1, sd_b1.clone()));

    assert!(wait_until(Duration::from_secs(2), || async { ipc_a.exists() }).await);
    assert!(wait_until(Duration::from_secs(2), || async { ipc_b.exists() }).await);
    floor_battery_threshold(&ipc_a).await;
    floor_battery_threshold(&ipc_b).await;

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

    // ── A renames itself ──
    let r = ipc_send_recv(
        &ipc_a,
        CmdRequest {
            id: 2,
            op: CmdOp::SetDeviceName {
                name: "Dethie's MacBook".into(),
            },
        },
    )
    .await;
    assert!(r.ok, "set-device-name failed: {r:?}");

    // A's own state reflects the rename immediately — this is local, no
    // wire round-trip needed.
    assert_eq!(status(&ipc_a).await.device_name, "Dethie's MacBook");

    // B must NOT see the new name yet: no session establishment has
    // happened since the rename.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        status(&ipc_b).await.peer_name,
        "device-a",
        "B must not see A's new name before the next session establishment"
    );

    // ── shut both down, then bring up a fresh v2 pairing: this is the
    // next session establishment. A reuses `keystore_a`, so its boot
    // reloads the persisted rename (`device_name.json`) BEFORE the
    // synthetic `test_pair` boot handshake fires `Action::OpenSession`
    // and sends the real `Msg::Hello` B will decrypt. ──
    sd_a1.cancel();
    sd_b1.cancel();
    let _ = timeout(Duration::from_secs(5), h_a1)
        .await
        .expect("v1 A shutdown hung");
    let _ = timeout(Duration::from_secs(5), h_b1)
        .await
        .expect("v1 B shutdown hung");

    let (sess_a2, sess_b2) = pair_for_test(&id_a, &id_b).expect("pair v2");
    let port_a2 = pick_free_udp_port().await;
    let port_b2 = pick_free_udp_port().await;
    let addr_a2: SocketAddr = format!("127.0.0.1:{port_a2}").parse().unwrap();
    let addr_b2: SocketAddr = format!("127.0.0.1:{port_b2}").parse().unwrap();

    let mut cfg_a2 = DaemonConfig::new(id_a, port_a2, ipc_a.clone());
    cfg_a2.udp_bind = "127.0.0.1".into();
    cfg_a2.disable_clipboard = true;
    cfg_a2.disable_mdns = true;
    // Deliberately a DIFFERENT boot-time default than v1 — proves the
    // persisted rename (not this field) is what wins on reload, same
    // contract `device_name_survives_restart` (vault_persist.rs) checks.
    cfg_a2.peer_name_self = "device-a-v2-should-be-overridden".into();
    cfg_a2.keystore_dir = Some(keystore_a);
    cfg_a2.test_pair = Some(TestPair {
        session: sess_a2,
        peer_addr: addr_b2,
        peer_name: "device-b".into(),
        peer_id: peer_id_b,
    });

    let mut cfg_b2 = DaemonConfig::new(id_b, port_b2, ipc_b.clone());
    cfg_b2.udp_bind = "127.0.0.1".into();
    cfg_b2.disable_clipboard = true;
    cfg_b2.disable_mdns = true;
    cfg_b2.peer_name_self = "device-b".into();
    cfg_b2.test_pair = Some(TestPair {
        session: sess_b2,
        peer_addr: addr_a2,
        peer_name: "device-a".into(), // stale; B relearns the real name via Hello below
        peer_id: peer_id_a,
    });

    let sd_a2 = CancellationToken::new();
    let sd_b2 = CancellationToken::new();
    let _h_a2 = tokio::spawn(run(cfg_a2, sd_a2.clone()));
    let _h_b2 = tokio::spawn(run(cfg_b2, sd_b2.clone()));

    assert!(wait_until(Duration::from_secs(2), || async { ipc_a.exists() }).await);
    assert!(wait_until(Duration::from_secs(2), || async { ipc_b.exists() }).await);
    floor_battery_threshold(&ipc_a).await;
    floor_battery_threshold(&ipc_b).await;

    // A's boot-time state must already show the reloaded rename.
    assert_eq!(status(&ipc_a).await.device_name, "Dethie's MacBook");

    assert!(
        wait_until(Duration::from_secs(3), || async {
            status(&ipc_b).await.peer_name == "Dethie's MacBook"
        })
        .await,
        "B never saw A's renamed Hello on the next session establishment"
    );

    sd_a2.cancel();
    sd_b2.cancel();
}
