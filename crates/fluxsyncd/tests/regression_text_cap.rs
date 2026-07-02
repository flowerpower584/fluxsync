//! REGRESSION C4: an over-cap text Push is rejected, not silently truncated.
//!
//! Pushes a 20 MiB text from A (over MAX_PAYLOAD = 16 MiB) and asserts the
//! FIXED behavior: the IPC call returns ok=false with a "too large" error,
//! A stores NOTHING locally, and B receives NOTHING (no partial/truncated
//! item, no panic). A control push of a normal-sized text then proves the
//! happy path still works end-to-end.
//!
//! Helpers copied verbatim from two_daemons.rs.

#![cfg(unix)]

use fluxsync_crypto::{test_util::pair_for_test, Identity};
use fluxsyncd::{
    cmd::{Channel, CmdData, CmdRequest, CmdResponse, Subscribe},
    run, DaemonConfig, TestPair,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UdpSocket, UnixStream};
use tokio_util::sync::CancellationToken;

// MAX_PAYLOAD from fluxsync_proto (lib.rs:30) = 16 MiB.
const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

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
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// True if `ipc` reports at least one history item before `deadline`.
async fn has_history_item(ipc: &PathBuf, deadline: Duration) -> bool {
    wait_until(deadline, || async {
        let resp = ipc_send_recv(ipc, CmdRequest { id: 7, op: fluxsyncd::cmd::CmdOp::Status }).await;
        matches!(resp.data, Some(CmdData::State(s)) if s.history.first().is_some())
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn over_cap_text_push_is_rejected_not_truncated() {
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

    let shutdown_a = CancellationToken::new();
    let shutdown_b = CancellationToken::new();
    let s_a = shutdown_a.clone();
    let s_b = shutdown_b.clone();

    let h_a = tokio::spawn(async move { run(cfg_a, s_a).await });
    let h_b = tokio::spawn(async move { run(cfg_b, s_b).await });

    // Wait for both to link.
    let linked_a = wait_until(Duration::from_secs(3), || async {
        if !ipc_a.exists() {
            return false;
        }
        let resp = ipc_send_recv(
            &ipc_a,
            CmdRequest { id: 1, op: fluxsyncd::cmd::CmdOp::Status },
        )
        .await;
        matches!(resp.data, Some(CmdData::State(s)) if s.peer_name == "device-b")
    })
    .await;
    assert!(linked_a, "daemon A did not link in 3s");

    let linked_b = wait_until(Duration::from_secs(3), || async {
        if !ipc_b.exists() {
            return false;
        }
        let resp = ipc_send_recv(
            &ipc_b,
            CmdRequest { id: 1, op: fluxsyncd::cmd::CmdOp::Status },
        )
        .await;
        matches!(resp.data, Some(CmdData::State(s)) if s.peer_name == "device-a")
    })
    .await;
    assert!(linked_b, "daemon B did not link in 3s");

    // ── Build a 20 MiB ASCII text (over the 16 MiB MAX_PAYLOAD). ──
    let big_len = 20 * 1024 * 1024;
    let big_text = "A".repeat(big_len);
    eprintln!("REGRESSION: pushing {big_len} bytes (MAX_PAYLOAD = {MAX_PAYLOAD})");

    let push_resp = ipc_send_recv(
        &ipc_a,
        CmdRequest {
            id: 42,
            op: fluxsyncd::cmd::CmdOp::Push { text: big_text },
        },
    )
    .await;
    eprintln!(
        "REGRESSION: over-cap push response ok={} err={:?}",
        push_resp.ok, push_resp.err
    );

    // ── FIXED behavior assertions for C4 ──

    // No panic at any point.
    assert!(
        !PANIC_TRIGGERED.load(Ordering::SeqCst),
        "a panic was captured by the test panic hook"
    );

    // 1) The push is REJECTED: ok=false with an error surfaced to the caller.
    assert!(
        !push_resp.ok,
        "expected over-cap push to be rejected (ok=false), got ok=true"
    );
    let err = push_resp
        .err
        .as_deref()
        .expect("expected an error message on the rejected push");
    assert!(
        err.contains("too large"),
        "expected a 'too large' rejection error, got: {err:?}"
    );

    // 2) A stored NOTHING locally — the over-cap item never entered history.
    let a_stored = has_history_item(&ipc_a, Duration::from_secs(2)).await;
    assert!(
        !a_stored,
        "expected A to store nothing for the over-cap push, but a history item appeared"
    );

    // 3) B received NOTHING — no partial/truncated item crossed the wire.
    let b_received = has_history_item(&ipc_b, Duration::from_secs(2)).await;
    assert!(
        !b_received,
        "expected B to receive nothing for the over-cap push, but a history item appeared"
    );

    // ── CONTROL: a normal-sized push still works end-to-end. ──
    let small_text = "regression-control-payload".to_string();
    let small_resp = ipc_send_recv(
        &ipc_a,
        CmdRequest {
            id: 43,
            op: fluxsyncd::cmd::CmdOp::Push { text: small_text.clone() },
        },
    )
    .await;
    assert!(
        small_resp.ok,
        "control: normal-sized push should succeed, got ok=false err={:?}",
        small_resp.err
    );

    // Control item appears on A and crosses to B with the exact bytes.
    let a_small = wait_until(Duration::from_secs(3), || async {
        let resp = ipc_send_recv(&ipc_a, CmdRequest { id: 8, op: fluxsyncd::cmd::CmdOp::Status }).await;
        matches!(resp.data, Some(CmdData::State(s)) if s.history.first().map(|h| h.preview.as_str()) == Some(small_text.as_str()))
    })
    .await;
    assert!(a_small, "control: A did not store the normal-sized item");

    let b_small = wait_until(Duration::from_secs(15), || async {
        let resp = ipc_send_recv(&ipc_b, CmdRequest { id: 9, op: fluxsyncd::cmd::CmdOp::Status }).await;
        matches!(resp.data, Some(CmdData::State(s)) if s.history.first().map(|h| h.preview.as_str()) == Some(small_text.as_str()))
    })
    .await;
    assert!(b_small, "control: B did not receive the normal-sized item");

    eprintln!(
        "REGRESSION RESULT: over-cap push rejected (ok={}, err={:?}); A stored nothing, B got nothing; control push round-tripped.",
        push_resp.ok, err
    );

    shutdown_a.cancel();
    shutdown_b.cancel();
    let _ = h_a.await;
    let _ = h_b.await;
}

/// REGRESSION (C4 sibling): an over-cap IMAGE push is rejected, not silently
/// truncated. C4 capped `CmdOp::Push` (text) but `CmdOp::PushImage` had no
/// size guard, so an over-cap PNG reached `Action::SendItem` and was truncated
/// to `payload[..MAX_PAYLOAD]` — a corrupt PNG on the wire. The fix rejects the
/// push at the IPC handler (before any decode or send). One daemon suffices:
/// the rejection happens at the IPC boundary, before anything crosses the wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn over_cap_image_push_is_rejected_not_truncated() {
    let _ = tracing_subscriber::fmt::try_init();
    install_panic_hook();

    let id_a = Identity::generate();
    let port_a = pick_free_udp_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let ipc_a = dir.path().join("a.sock");

    let mut cfg_a = DaemonConfig::new(id_a, port_a, ipc_a.clone());
    cfg_a.udp_bind = "127.0.0.1".into();
    cfg_a.disable_clipboard = true;
    cfg_a.disable_mdns = true;
    cfg_a.peer_name_self = "device-a".into();

    let shutdown_a = CancellationToken::new();
    let s_a = shutdown_a.clone();
    let h_a = tokio::spawn(async move { run(cfg_a, s_a).await });

    let up = wait_until(Duration::from_secs(3), || async {
        if !ipc_a.exists() {
            return false;
        }
        let resp = ipc_send_recv(&ipc_a, CmdRequest { id: 1, op: fluxsyncd::cmd::CmdOp::Status }).await;
        matches!(resp.data, Some(CmdData::State(_)))
    })
    .await;
    assert!(up, "daemon A IPC did not come up in 3s");

    // "AAAA" base64-decodes to three 0x00 bytes, so "A" * 4N decodes to 3N
    // bytes. Pick a multiple of 3 over the cap (21 MiB) → a valid, padding-free
    // base64 string with no base64 crate dependency. The cap is checked on the
    // decoded length BEFORE PNG decode, so the bytes need not be a valid PNG.
    let decoded_len = 21 * 1024 * 1024; // > 16 MiB MAX_PAYLOAD, divisible by 3
    let b64 = "A".repeat(decoded_len / 3 * 4);
    eprintln!("REGRESSION: pushing image of {decoded_len} decoded bytes (cap = {MAX_PAYLOAD})");

    let resp = ipc_send_recv(
        &ipc_a,
        CmdRequest { id: 42, op: fluxsyncd::cmd::CmdOp::PushImage { data: b64 } },
    )
    .await;
    eprintln!("REGRESSION: over-cap image push ok={} err={:?}", resp.ok, resp.err);

    assert!(
        !PANIC_TRIGGERED.load(Ordering::SeqCst),
        "a panic was captured by the test panic hook"
    );
    assert!(!resp.ok, "expected over-cap image push to be rejected (ok=false)");
    let err = resp.err.as_deref().expect("expected an error on rejected image push");
    assert!(
        err.contains("too large"),
        "expected a 'too large' rejection (not a PNG-decode error), got: {err:?}"
    );

    // Nothing was stored locally — the over-cap image never entered history.
    let stored = has_history_item(&ipc_a, Duration::from_secs(2)).await;
    assert!(!stored, "expected A to store nothing for the over-cap image push");

    shutdown_a.cancel();
    let _ = h_a.await;
}
