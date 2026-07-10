//! Item 6 (DIR-P3-04): `CmdOp::SetLaunchAtLogin` was a daemon-side no-op
//! (the tray's autostart plugin does the real work) and has been removed
//! entirely from `CmdOp` + the daemon's dispatch match. An OLDER client
//! binary that still sends the removed op's wire shape must get a clean
//! JSON error response on that one request — not a crash, and not a
//! dropped connection — since the local IPC line parser already treats an
//! unrecognized `op` tag as an ordinary "bad json" `CmdResponse::err`
//! (`handle_ipc_client`, driver.rs) before it ever reaches the daemon's
//! `CmdOp` dispatch. This proves that contract still holds post-removal,
//! and that the SAME connection keeps serving later, still-valid requests.

#![cfg(unix)]

use fluxsync_crypto::Identity;
use fluxsyncd::{run, DaemonConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UdpSocket, UnixStream};
use tokio_util::sync::CancellationToken;

async fn pick_free_udp_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").await.expect("pick port");
    s.local_addr().expect("port").port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removed_set_launch_at_login_op_gets_graceful_error_not_a_disconnect() {
    let _ = tracing_subscriber::fmt::try_init();

    let id = Identity::generate();
    let port = pick_free_udp_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let ipc = dir.path().join("a.sock");

    let mut cfg = DaemonConfig::new(id, port, ipc.clone());
    cfg.udp_bind = "127.0.0.1".into();
    cfg.disable_clipboard = true;
    cfg.disable_mdns = true;
    cfg.peer_name_self = "device-a".into();

    let shutdown = CancellationToken::new();
    let sd = shutdown.clone();
    let daemon = tokio::spawn(async move { run(cfg, sd).await });

    let mut stream = None;
    for _ in 0..200 {
        if let Ok(s) = UnixStream::connect(&ipc).await {
            stream = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let stream = stream.expect("ipc never came up");
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    write_half
        .write_all(b"{\"subscribe\":\"cmd\"}\n")
        .await
        .expect("subscribe");
    write_half.flush().await.expect("flush subscribe");

    // An older client's wire shape for the now-removed op.
    write_half
        .write_all(b"{\"id\":1,\"op\":\"set_launch_at_login\",\"value\":true}\n")
        .await
        .expect("write removed-op request");
    write_half.flush().await.expect("flush removed-op request");

    let mut resp1 = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut resp1))
        .await
        .expect("daemon never answered the removed op")
        .expect("read error on removed-op response");
    assert!(
        resp1.contains("\"ok\":false"),
        "FIXED: a removed op must get an error envelope, not silently succeed: {resp1:?}"
    );
    assert!(
        !resp1.contains("panic"),
        "removed-op response must not carry a panic trace: {resp1:?}"
    );

    // The connection must stay open and keep serving valid requests.
    write_half
        .write_all(b"{\"id\":2,\"op\":\"status\"}\n")
        .await
        .expect("write status request");
    write_half.flush().await.expect("flush status request");

    let mut resp2 = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut resp2))
        .await
        .expect("daemon dropped the connection after the removed op — must stay open")
        .expect("read error on follow-up status response");
    assert!(
        resp2.contains("\"ok\":true"),
        "a valid request right after the removed op must still succeed: {resp2:?}"
    );

    shutdown.cancel();
    drop(write_half);
    drop(reader);
    let _ = tokio::time::timeout(Duration::from_secs(5), daemon).await;
}
