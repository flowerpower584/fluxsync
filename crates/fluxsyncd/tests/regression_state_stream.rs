//! REGRESSION: the IPC `state` channel publishes each snapshot once.
//!
//! `handle_ipc_client` used to write the opening snapshot from a plain
//! `watch::Receiver::borrow()`, which does not mark the value as seen, so
//! the very next `changed()` resolved immediately and every new subscriber
//! received that same first snapshot twice. Separately, `Action::EmitState`
//! published (and woke every subscriber, which re-serialized the whole
//! State including full-text history) even when the snapshot was identical.
//!
//! This drives the real daemon in-process and asserts:
//!   * after the daemon has published at least once (as it always has in
//!     real use), a new subscriber gets exactly ONE opening snapshot;
//!   * a real change (sync toggled over the cmd channel) still arrives as a
//!     fresh snapshot carrying the new value.

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

async fn connect(ipc: &std::path::Path) -> UnixStream {
    for _ in 0..200 {
        if let Ok(s) = UnixStream::connect(ipc).await {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("ipc never came up");
}

/// Next NDJSON line within `wait`, or `None` if nothing arrived.
async fn next_line<R: tokio::io::AsyncBufRead + Unpin>(
    r: &mut R,
    wait: Duration,
) -> Option<String> {
    let mut line = String::new();
    match tokio::time::timeout(wait, r.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => Some(line),
        Ok(Ok(_)) => panic!("state stream closed unexpectedly"),
        Ok(Err(e)) => panic!("state stream read error: {e}"),
        Err(_) => None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn state_stream_sends_each_snapshot_once() {
    let _ = tracing_subscriber::fmt::try_init();

    let id = Identity::generate();
    let port = pick_free_udp_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let ipc = dir.path().join("s.sock");

    let mut cfg = DaemonConfig::new(id, port, ipc.clone());
    cfg.udp_bind = "127.0.0.1".into();
    cfg.disable_clipboard = true;
    cfg.disable_mdns = true;
    cfg.peer_name_self = "device-s".into();

    let shutdown = CancellationToken::new();
    let sd = shutdown.clone();
    let daemon = tokio::spawn(async move { run(cfg, sd).await });

    // Let boot-time publishes (auto-start toggle, battery probe) settle so
    // the assertions below only see what this test causes.
    drop(connect(&ipc).await);
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // ---- A cmd connection: read `on`, then flip it once BEFORE anyone
    // subscribes. A real daemon has always published by the time a client
    // attaches (sync start, battery, peers); that publish is what left every
    // later subscriber's watch receiver one version behind.
    let (cmd_read, mut cmd_write) = connect(&ipc).await.into_split();
    let mut cmd = BufReader::new(cmd_read);
    cmd_write
        .write_all(b"{\"subscribe\":\"cmd\"}\n{\"id\":1,\"op\":\"status\"}\n")
        .await
        .expect("status");
    cmd_write.flush().await.expect("flush");
    let status = next_line(&mut cmd, Duration::from_secs(5))
        .await
        .expect("no status response");
    let status: serde_json::Value = serde_json::from_str(status.trim()).expect("JSON");
    let boot_on = status["data"]["on"].as_bool().expect("`on` is a bool");

    let toggle = |id: u32, on: bool| format!("{{\"id\":{id},\"op\":\"toggle\",\"on\":{on}}}\n");
    cmd_write
        .write_all(toggle(2, !boot_on).as_bytes())
        .await
        .expect("toggle");
    cmd_write.flush().await.expect("flush");
    let resp = next_line(&mut cmd, Duration::from_secs(5))
        .await
        .expect("no toggle response");
    assert!(resp.contains("\"ok\":true"), "toggle rejected: {resp}");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // ---- Subscribe to the state channel.
    let (state_read, mut state_write) = connect(&ipc).await.into_split();
    let mut state = BufReader::new(state_read);
    state_write
        .write_all(b"{\"subscribe\":\"state\"}\n")
        .await
        .expect("subscribe state");
    state_write.flush().await.expect("flush");

    let first = next_line(&mut state, Duration::from_secs(5))
        .await
        .expect("no opening snapshot");
    let first: serde_json::Value = serde_json::from_str(first.trim()).expect("snapshot is JSON");
    assert_eq!(
        first["on"].as_bool(),
        Some(!boot_on),
        "opening snapshot is not the current state: {first}"
    );

    // ---- Nothing changed since: nothing more must arrive.
    let dup = next_line(&mut state, Duration::from_millis(1200)).await;
    assert!(
        dup.is_none(),
        "a fresh subscriber received its opening snapshot twice: {dup:?}"
    );

    // ---- A real change still streams, once, with the new value.
    cmd_write
        .write_all(toggle(3, boot_on).as_bytes())
        .await
        .expect("toggle back");
    cmd_write.flush().await.expect("flush");
    let resp = next_line(&mut cmd, Duration::from_secs(5))
        .await
        .expect("no toggle response");
    assert!(resp.contains("\"ok\":true"), "toggle rejected: {resp}");

    let changed = next_line(&mut state, Duration::from_secs(5))
        .await
        .expect("toggle never reached the state stream");
    let changed: serde_json::Value = serde_json::from_str(changed.trim()).expect("JSON");
    assert_eq!(
        changed["on"].as_bool(),
        Some(boot_on),
        "stream carried a stale `on`"
    );

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(10), daemon).await;
}
