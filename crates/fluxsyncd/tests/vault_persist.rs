//! Integration test: FluxVault persists clipboard history across a daemon
//! restart. A daemon copies an item, is killed, and a fresh daemon with the
//! same identity + keystore dir rehydrates the item from the encrypted
//! on-disk vault (`history.enc`).
//!
//! Gated on `cfg(unix)` because the IPC client uses `tokio::net::UnixStream`,
//! like `two_daemons`.

#![cfg(unix)]

use fluxsync_core::{FirewallPolicy, Rule};
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

/// `(hash, favorite)` of the history item with this preview, if present.
async fn item_of(ipc: &Path, preview: &str, id: u64) -> Option<(String, bool)> {
    let r = ipc_send_recv(ipc, CmdRequest { id, op: CmdOp::Status }).await;
    if let Some(CmdData::State(s)) = r.data {
        s.history
            .iter()
            .find(|h| h.preview == preview)
            .map(|h| (h.hash.clone(), h.favorite))
    } else {
        None
    }
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

/// Read `(enabled, text_rule)` of the firewall from the daemon's State.
async fn firewall_of(ipc: &Path, id: u64) -> Option<(bool, Rule)> {
    let r = ipc_send_recv(ipc, CmdRequest { id, op: CmdOp::Status }).await;
    match r.data {
        Some(CmdData::State(s)) => Some((s.firewall.enabled, s.firewall.text)),
        _ => None,
    }
}

/// FluxFirewall slice 5: a `SetFirewall` must be written to `firewall.json` and
/// rehydrated on the next boot, so the policy is not silently lost on restart.
#[tokio::test]
async fn firewall_policy_survives_restart() {
    let id = Identity::generate();
    let port = pick_free_udp_port().await;
    let dir = tempdir().unwrap();
    let keystore = dir.path().join("ks");
    std::fs::create_dir(&keystore).unwrap();
    let ipc = keystore.join("d.sock");

    // ── v1: enable the firewall with text = Never ──
    let sd1 = CancellationToken::new();
    let h1 = tokio::spawn(run(cfg_for(&id, port, &keystore, &ipc, "fw-d"), sd1.clone()));
    assert!(wait_until(Duration::from_secs(5), || async { ipc.exists() }).await);

    let policy = FirewallPolicy {
        enabled: true,
        text: Rule::Deny,
        ..FirewallPolicy::default()
    };
    let r = ipc_send_recv(
        &ipc,
        CmdRequest {
            id: 1,
            op: CmdOp::SetFirewall { policy },
        },
    )
    .await;
    assert!(r.ok, "set-firewall failed: {r:?}");

    let fw_file = keystore.join("firewall.json");
    assert!(
        wait_until(Duration::from_secs(5), || {
            let f = fw_file.clone();
            async move { f.exists() }
        })
        .await,
        "firewall.json was never written"
    );
    assert_eq!(
        firewall_of(&ipc, 2).await,
        Some((true, Rule::Deny)),
        "policy not reflected in v1 State"
    );

    sd1.cancel();
    let _ = timeout(Duration::from_secs(5), h1).await.expect("v1 shutdown hung");

    // ── v2: same keystore → policy is rehydrated from disk ──
    let port2 = pick_free_udp_port().await;
    let sd2 = CancellationToken::new();
    let h2 = tokio::spawn(run(cfg_for(&id, port2, &keystore, &ipc, "fw-d-v2"), sd2.clone()));
    assert!(wait_until(Duration::from_secs(5), || async { ipc.exists() }).await);

    assert!(
        wait_until(Duration::from_secs(5), || {
            let ipc = ipc.clone();
            async move { firewall_of(&ipc, 3).await == Some((true, Rule::Deny)) }
        })
        .await,
        "firewall policy was not restored after restart"
    );

    sd2.cancel();
    let _ = timeout(Duration::from_secs(5), h2).await.expect("v2 shutdown hung");
}

#[tokio::test]
async fn favorite_flag_survives_restart() {
    let id = Identity::generate();
    let port = pick_free_udp_port().await;
    let dir = tempdir().unwrap();
    let keystore = dir.path().join("ks");
    std::fs::create_dir(&keystore).unwrap();
    let ipc = keystore.join("d.sock");

    let sd1 = CancellationToken::new();
    let h1 = tokio::spawn(run(cfg_for(&id, port, &keystore, &ipc, "fav-d"), sd1.clone()));
    assert!(wait_until(Duration::from_secs(5), || async { ipc.exists() }).await);

    ipc_send_recv(&ipc, CmdRequest { id: 0, op: CmdOp::Toggle { on: true } }).await;
    ipc_send_recv(
        &ipc,
        CmdRequest {
            id: 1,
            op: CmdOp::Push {
                text: "pin-me".into(),
            },
        },
    )
    .await;

    // Wait for the item to land, then read its hash and pin it.
    assert!(
        wait_until(Duration::from_secs(5), || async { history_has(&ipc, "pin-me", 2).await }).await,
        "item never reached history"
    );
    let (hash, _) = item_of(&ipc, "pin-me", 3).await.expect("item present");

    let r = ipc_send_recv(
        &ipc,
        CmdRequest {
            id: 3,
            op: CmdOp::SetFavorite {
                hash,
                favorite: true,
            },
        },
    )
    .await;
    assert!(r.ok, "set-favorite failed: {r:?}");

    assert!(
        wait_until(Duration::from_secs(5), || {
            let ipc = ipc.clone();
            async move { matches!(item_of(&ipc, "pin-me", 4).await, Some((_, true))) }
        })
        .await,
        "favorite flag never set in-memory"
    );
    let hist_file = keystore.join("history.enc");
    assert!(
        wait_until(Duration::from_secs(5), || {
            let f = hist_file.clone();
            async move { f.exists() }
        })
        .await
    );

    sd1.cancel();
    let _ = timeout(Duration::from_secs(5), h1).await.expect("v1 shutdown hung");

    // Restart → the favorite flag must come back set.
    let port2 = pick_free_udp_port().await;
    let sd2 = CancellationToken::new();
    let h2 = tokio::spawn(run(cfg_for(&id, port2, &keystore, &ipc, "fav-d-v2"), sd2.clone()));
    assert!(wait_until(Duration::from_secs(5), || async { ipc.exists() }).await);

    assert!(
        wait_until(Duration::from_secs(5), || {
            let ipc = ipc.clone();
            async move { matches!(item_of(&ipc, "pin-me", 5).await, Some((_, true))) }
        })
        .await,
        "favorite flag was not restored after restart"
    );

    sd2.cancel();
    let _ = timeout(Duration::from_secs(5), h2).await.expect("v2 shutdown hung");
}

/// Read the daemon's own `device_name` from its State.
async fn device_name_of(ipc: &Path, id: u64) -> Option<String> {
    let r = ipc_send_recv(ipc, CmdRequest { id, op: CmdOp::Status }).await;
    match r.data {
        Some(CmdData::State(s)) => Some(s.device_name),
        _ => None,
    }
}

/// DIR-P3-01: a `SetDeviceName` must be written to `device_name.json` and
/// rehydrated on the next boot, so a rename is not silently lost on
/// restart — same contract as `firewall_policy_survives_restart`.
#[tokio::test]
async fn device_name_survives_restart() {
    let id = Identity::generate();
    let port = pick_free_udp_port().await;
    let dir = tempdir().unwrap();
    let keystore = dir.path().join("ks");
    std::fs::create_dir(&keystore).unwrap();
    let ipc = keystore.join("d.sock");

    // ── v1: boots with the CLI-style default, then renames ──
    let sd1 = CancellationToken::new();
    let h1 = tokio::spawn(run(cfg_for(&id, port, &keystore, &ipc, "name-d"), sd1.clone()));
    assert!(wait_until(Duration::from_secs(5), || async { ipc.exists() }).await);

    assert_eq!(device_name_of(&ipc, 1).await, Some("name-d".to_string()));

    let r = ipc_send_recv(
        &ipc,
        CmdRequest {
            id: 2,
            op: CmdOp::SetDeviceName {
                name: "Dethie's MacBook".into(),
            },
        },
    )
    .await;
    assert!(r.ok, "set-device-name failed: {r:?}");

    let name_file = keystore.join("device_name.json");
    assert!(
        wait_until(Duration::from_secs(5), || {
            let f = name_file.clone();
            async move { f.exists() }
        })
        .await,
        "device_name.json was never written"
    );
    assert_eq!(
        device_name_of(&ipc, 3).await,
        Some("Dethie's MacBook".to_string()),
        "rename not reflected in v1 State"
    );

    sd1.cancel();
    let _ = timeout(Duration::from_secs(5), h1).await.expect("v1 shutdown hung");

    // ── v2: same keystore, DIFFERENT `--peer-name`-style default → the
    // persisted rename wins (disk is authoritative, same as firewall). ──
    let port2 = pick_free_udp_port().await;
    let sd2 = CancellationToken::new();
    let h2 = tokio::spawn(run(
        cfg_for(&id, port2, &keystore, &ipc, "name-d-v2-should-be-overridden"),
        sd2.clone(),
    ));
    assert!(wait_until(Duration::from_secs(5), || async { ipc.exists() }).await);

    assert!(
        wait_until(Duration::from_secs(5), || {
            let ipc = ipc.clone();
            async move {
                device_name_of(&ipc, 4).await == Some("Dethie's MacBook".to_string())
            }
        })
        .await,
        "device name was not restored after restart"
    );

    sd2.cancel();
    let _ = timeout(Duration::from_secs(5), h2).await.expect("v2 shutdown hung");
}

/// DIR-P3-01: empty/whitespace-only and over-the-wire-bound names are
/// rejected, and a rejection must not clobber the name already in effect.
#[tokio::test]
async fn set_device_name_rejects_invalid() {
    let id = Identity::generate();
    let port = pick_free_udp_port().await;
    let dir = tempdir().unwrap();
    let keystore = dir.path().join("ks");
    std::fs::create_dir(&keystore).unwrap();
    let ipc = keystore.join("d.sock");

    let sd = CancellationToken::new();
    let h = tokio::spawn(run(cfg_for(&id, port, &keystore, &ipc, "reject-d"), sd.clone()));
    assert!(wait_until(Duration::from_secs(5), || async { ipc.exists() }).await);

    let empty = ipc_send_recv(
        &ipc,
        CmdRequest {
            id: 1,
            op: CmdOp::SetDeviceName { name: "  ".into() },
        },
    )
    .await;
    assert!(!empty.ok, "empty/whitespace-only name must be rejected");

    let oversized = ipc_send_recv(
        &ipc,
        CmdRequest {
            id: 2,
            op: CmdOp::SetDeviceName {
                name: "x".repeat(fluxsync_proto::MAX_HELLO_NAME + 1),
            },
        },
    )
    .await;
    assert!(!oversized.ok, "over-bound name must be rejected");

    // Neither rejected attempt may have clobbered the boot-time name.
    assert_eq!(device_name_of(&ipc, 3).await, Some("reject-d".to_string()));

    sd.cancel();
    let _ = timeout(Duration::from_secs(5), h).await.expect("shutdown hung");
}
