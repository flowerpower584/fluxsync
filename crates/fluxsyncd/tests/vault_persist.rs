//! Integration test: FluxVault persists clipboard history across a daemon
//! restart. A daemon copies an item, is killed, and a fresh daemon with the
//! same identity + keystore dir rehydrates the item from the encrypted
//! on-disk vault (`history.enc`).
//!
//! Gated on `cfg(unix)` because the IPC client uses `tokio::net::UnixStream`,
//! like `two_daemons`.

#![cfg(unix)]

use fluxsync_crypto::Identity;
use fluxsyncd::{
    cmd::{CmdData, CmdOp, CmdRequest, CmdResponse},
    run, DaemonConfig,
};
use std::path::Path;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UdpSocket, UnixStream};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

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
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn cfg_for(id: &Identity, port: u16, keystore: &Path, ipc: &Path, name: &str) -> DaemonConfig {
    let mut cfg = DaemonConfig::new(id.clone(), port, ipc.to_path_buf());
    cfg.udp_bind = "127.0.0.1".into();
    cfg.keystore_dir = Some(keystore.to_path_buf());
    cfg.disable_mdns = true;
    // In-process test daemons must not drive the real OS clipboard.
    cfg.disable_clipboard = true;
    cfg.peer_name_self = name.into();
    cfg
}

async fn history_has(ipc: &Path, preview: &str, id: u64) -> bool {
    let r = ipc_send_recv(ipc, CmdRequest { id, op: CmdOp::Status }).await;
    matches!(r.data, Some(CmdData::State(s)) if s.history.iter().any(|h| h.preview == preview))
}

#[tokio::test]
async fn history_survives_restart() {
    let id = Identity::generate();
    let port = pick_free_udp_port().await;
    let dir = tempdir().unwrap();
    let keystore = dir.path().join("ks");
    std::fs::create_dir(&keystore).unwrap();
    let ipc = keystore.join("d.sock");

    // ── v1: copy an item, let the vault persist it ──
    let sd1 = CancellationToken::new();
    let h1 = tokio::spawn(run(cfg_for(&id, port, &keystore, &ipc, "vault-d"), sd1.clone()));
    assert!(
        wait_until(Duration::from_secs(5), || async { ipc.exists() }).await,
        "v1 ipc never appeared"
    );

    ipc_send_recv(&ipc, CmdRequest { id: 0, op: CmdOp::Toggle { on: true } }).await;
    let r = ipc_send_recv(
        &ipc,
        CmdRequest {
            id: 1,
            op: CmdOp::Push {
                text: "hello-vault".into(),
            },
        },
    )
    .await;
    assert!(r.ok, "push failed: {r:?}");

    assert!(
        wait_until(Duration::from_secs(5), || async { history_has(&ipc, "hello-vault", 2).await }).await,
        "item never reached in-memory history"
    );
    let hist_file = keystore.join("history.enc");
    assert!(
        wait_until(Duration::from_secs(5), || {
            let f = hist_file.clone();
            async move { f.exists() }
        })
        .await,
        "vault file never written"
    );

    sd1.cancel();
    let _ = timeout(Duration::from_secs(5), h1).await.expect("v1 shutdown hung");

    // ── v2: same identity + keystore → history is rehydrated ──
    let port2 = pick_free_udp_port().await;
    let sd2 = CancellationToken::new();
    let h2 = tokio::spawn(run(cfg_for(&id, port2, &keystore, &ipc, "vault-d-v2"), sd2.clone()));
    assert!(
        wait_until(Duration::from_secs(5), || async { ipc.exists() }).await,
        "v2 ipc never appeared"
    );

    assert!(
        wait_until(Duration::from_secs(5), || async { history_has(&ipc, "hello-vault", 3).await }).await,
        "history was not restored from the vault after restart"
    );

    sd2.cancel();
    let _ = timeout(Duration::from_secs(5), h2).await.expect("v2 shutdown hung");
}
