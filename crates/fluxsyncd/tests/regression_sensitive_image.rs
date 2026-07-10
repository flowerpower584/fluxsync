//! Integration test: DIR-P2-05 sensitive images.
//!
//! Before this slice, `CmdOp::PushImage` hardcoded `sensitive: false` in
//! the daemon (`driver.rs`), so a screenshotted secret/2FA-QR pushed as an
//! image could never be marked sensitive — it landed in history, the
//! encrypted vault, and the resync outbox like any ordinary item. This test
//! proves the fix end to end: a sensitive image pushed on A
//!   * still syncs to the linked peer B (`Action::SendItem` /
//!     `Action::WriteClipboard` fire regardless of `sensitive` — only
//!     history/vault/outbox insertion cares), proven via the
//!     `items_sent`/`items_received` connection counters, since the item
//!     is deliberately excluded from both sides' history and so cannot be
//!     observed there;
//!   * never appears in either side's `State.history`;
//!   * never appears in either side's on-disk vault (`history.enc`), read
//!     back through the real `history_store::load` + at-rest key (not a
//!     mock) — mirrors `regression_vault_security_wipe.rs`'s
//!     `disk_history` helper.
//!
//! The resync-outbox exclusion for this same `sensitive`-gated code path is
//! covered separately, and more directly, by `driver.rs`'s in-process unit
//! test `complete_reassembled_item_gates_outbox_on_sensitivity_for_images`:
//! there is no IPC-observable way to peek a live daemon's in-memory outbox
//! from outside the process, and in a plain two-node topology the outbox is
//! only ever populated by the *sender's* own `SendItem` path (offered to a
//! peer that reconnects later), never by a direct receipt — proving its
//! exclusion here would require reintroducing the same slow
//! kill-B/wait-past-retransmit/restart-B dance `resync_on_reconnect.rs`
//! already uses for text's `sensitive_item_never_resyncs`, which this file
//! deliberately avoids duplicating.
//!
//! Two in-process daemons, linked via the `test_pair` shortcut (same as
//! `two_daemons.rs`) rather than a real handshake — this test isn't
//! exercising pairing. `SetThreshold { value: 5 }` is issued on both right
//! after boot so a real host's battery level can never gate the sync this
//! test depends on.

#![cfg(unix)]

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use fluxsync_core::{HistoryItem, Kind};
use fluxsync_crypto::{test_util::pair_for_test, Identity};
use fluxsyncd::{
    cmd::{CmdData, CmdOp, CmdRequest, CmdResponse},
    history_store, run, DaemonConfig, TestPair,
};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
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
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn status(ipc: &Path) -> Box<fluxsync_core::State> {
    match ipc_send_recv(
        ipc,
        CmdRequest {
            id: 1,
            op: CmdOp::Status,
        },
    )
    .await
    .data
    {
        Some(CmdData::State(s)) => s,
        other => panic!("expected State, got {other:?}"),
    }
}

async fn set_threshold(ipc: &Path, value: u8) {
    let r = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 0,
            op: CmdOp::SetThreshold { value },
        },
    )
    .await;
    assert!(r.ok, "set-threshold failed: {r:?}");
}

/// A tiny, genuinely-decodable PNG (not a synthetic byte string) so the
/// daemon's `decode_png_to_rgba` accepts it. `fill` varies the pixel data so
/// the control and secret images have different content hashes.
fn tiny_png(fill: u8) -> Vec<u8> {
    let rgba = vec![fill; 2 * 2 * 4];
    let img = image::RgbaImage::from_raw(2, 2, rgba).expect("build tiny RGBA buffer");
    let mut out = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut out, image::ImageFormat::Png)
        .expect("encode tiny PNG");
    out.into_inner()
}

async fn push_image(ipc: &Path, png: &[u8], sensitive: bool) -> CmdResponse {
    ipc_send_recv(
        ipc,
        CmdRequest {
            id: 42,
            op: CmdOp::PushImage {
                data: B64.encode(png),
                sensitive,
            },
        },
    )
    .await
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .expect("current time in ms exceeds u64 range")
}

/// Read the on-disk vault with the REAL load path + REAL at-rest key —
/// mirrors `regression_vault_security_wipe.rs`'s `disk_history` helper.
fn disk_history(dir: &Path, id: &Identity) -> Vec<HistoryItem> {
    let key = id.derive_at_rest_key(history_store::AT_REST_CONTEXT);
    history_store::load(dir, &key, now_ms(), history_store::DEFAULT_TTL_SECS)
        .map(|v| v.into_iter().map(|e| e.item).collect())
        .unwrap_or_default()
}

fn image_count(items: &[HistoryItem]) -> usize {
    items.iter().filter(|h| h.kind == Kind::Image).count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sensitive_image_syncs_but_excluded_from_history_and_vault() {
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
    let keystore_a = dir.path().join("ks-a");
    let keystore_b = dir.path().join("ks-b");
    std::fs::create_dir(&keystore_a).unwrap();
    std::fs::create_dir(&keystore_b).unwrap();
    let ipc_a = keystore_a.join("a.sock");
    let ipc_b = keystore_b.join("b.sock");

    let addr_a: SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();
    let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();

    let mut cfg_a = DaemonConfig::new(id_a.clone(), port_a, ipc_a.clone());
    cfg_a.udp_bind = "127.0.0.1".into();
    cfg_a.disable_clipboard = true;
    cfg_a.disable_mdns = true;
    cfg_a.peer_name_self = "device-a".into();
    cfg_a.keystore_dir = Some(keystore_a.clone());
    cfg_a.test_pair = Some(TestPair {
        session: sess_a,
        peer_addr: addr_b,
        peer_name: "device-b".into(),
        peer_id: peer_id_b,
    });

    let mut cfg_b = DaemonConfig::new(id_b.clone(), port_b, ipc_b.clone());
    cfg_b.udp_bind = "127.0.0.1".into();
    cfg_b.disable_clipboard = true;
    cfg_b.disable_mdns = true;
    cfg_b.peer_name_self = "device-b".into();
    cfg_b.keystore_dir = Some(keystore_b.clone());
    cfg_b.test_pair = Some(TestPair {
        session: sess_b,
        peer_addr: addr_a,
        peer_name: "device-a".into(),
        peer_id: peer_id_a,
    });

    let shutdown_a = CancellationToken::new();
    let shutdown_b = CancellationToken::new();
    let h_a = tokio::spawn(run(cfg_a, shutdown_a.clone()));
    let h_b = tokio::spawn(run(cfg_b, shutdown_b.clone()));

    let linked_a = wait_until(Duration::from_secs(3), || async {
        ipc_a.exists() && status(&ipc_a).await.peer_name == "device-b"
    })
    .await;
    assert!(linked_a, "daemon A did not link to B in 3s");
    let linked_b = wait_until(Duration::from_secs(3), || async {
        ipc_b.exists() && status(&ipc_b).await.peer_name == "device-a"
    })
    .await;
    assert!(linked_b, "daemon B did not link to A in 3s");

    // Host battery gates sync — floor the threshold on both immediately,
    // matching resync_on_reconnect.rs's harness convention, so this test's
    // pass/fail never depends on the machine's actual charge level.
    set_threshold(&ipc_a, 5).await;
    set_threshold(&ipc_b, 5).await;

    // ── Control: a non-sensitive image proves the pipeline (live sync +
    // history + on-disk vault persistence) actually works end to end,
    // before this test leans on the ABSENCE of the same signals for the
    // sensitive case below. ──
    let control_png = tiny_png(0x11);
    let control_resp = push_image(&ipc_a, &control_png, false).await;
    assert!(
        control_resp.ok,
        "control image push failed: {control_resp:?}"
    );

    assert!(
        wait_until(Duration::from_secs(5), || async {
            image_count(&status(&ipc_b).await.history) == 1
        })
        .await,
        "control image never reached B's history within 5s"
    );
    assert!(
        wait_until(Duration::from_secs(5), || async {
            image_count(&disk_history(&keystore_a, &id_a)) == 1
        })
        .await,
        "control image never persisted to A's on-disk vault"
    );
    assert!(
        wait_until(Duration::from_secs(5), || async {
            image_count(&disk_history(&keystore_b, &id_b)) == 1
        })
        .await,
        "control image never persisted to B's on-disk vault"
    );

    // ── The sensitive image: baseline the sync counters first, since
    // history/vault can never be used to observe its arrival. ──
    let sent_before = status(&ipc_a)
        .await
        .metrics
        .as_ref()
        .map_or(0, |m| m.items_sent);
    let received_before = status(&ipc_b)
        .await
        .metrics
        .as_ref()
        .map_or(0, |m| m.items_received);

    let secret_png = tiny_png(0x99);
    let secret_resp = push_image(&ipc_a, &secret_png, true).await;
    assert!(
        secret_resp.ok,
        "sensitive image push failed: {secret_resp:?}"
    );

    // Proof the item actually crossed the wire and was applied on B — the
    // only signal available, since by design it must never touch history.
    assert!(
        wait_until(Duration::from_secs(5), || async {
            status(&ipc_a)
                .await
                .metrics
                .as_ref()
                .map_or(0, |m| m.items_sent)
                > sent_before
        })
        .await,
        "A's items_sent never advanced for the sensitive image push"
    );
    assert!(
        wait_until(Duration::from_secs(5), || async {
            status(&ipc_b)
                .await
                .metrics
                .as_ref()
                .map_or(0, |m| m.items_received)
                > received_before
        })
        .await,
        "B's items_received never advanced — sensitive image did not sync"
    );

    // Give the vault persister (watch-channel driven, near-instant per
    // regression_vault_security_wipe.rs's own 3s poll budget) a moment to
    // settle, then assert exclusion on BOTH sides' history AND vault.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let hist_a = status(&ipc_a).await.history;
    let hist_b = status(&ipc_b).await.history;
    assert_eq!(
        image_count(&hist_a),
        1,
        "sender A must not retain the sensitive image in history (only the control image)"
    );
    assert_eq!(
        image_count(&hist_b),
        1,
        "receiver B must not retain the sensitive image in history (only the control image)"
    );

    assert_eq!(
        image_count(&disk_history(&keystore_a, &id_a)),
        1,
        "sensitive image leaked into A's on-disk vault"
    );
    assert_eq!(
        image_count(&disk_history(&keystore_b, &id_b)),
        1,
        "sensitive image leaked into B's on-disk vault"
    );

    shutdown_a.cancel();
    shutdown_b.cancel();
    let _ = timeout(Duration::from_secs(5), h_a).await;
    let _ = timeout(Duration::from_secs(5), h_b).await;
}
