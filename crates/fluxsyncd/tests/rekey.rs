//! DIR-P2-03 integration test: automatic session rekey.
//!
//! Mirrors `two_daemons.rs`'s in-process, loopback, `test_pair`-seeded
//! setup, but additionally injects the real Noise static pubkeys via
//! `DaemonConfig::test_peer_static_pub` — `test_pair` alone bypasses the
//! handshake entirely and trusts a `[0u8; 32]` placeholder key, which is
//! fine for a sync-path test but useless here: a rekey performs a *real*
//! Noise IK exchange, so both sides need to trust each other's genuine
//! key for it to succeed. `rekey_max_age_ms` is also overridden to a tiny
//! value so the rekey fires within the test's timeout instead of the real
//! 24h default.
//!
//! Asserts the two DIR-P2-03 acceptance criteria:
//! 1. Continuity: clipboard items pushed before, during, and after the
//!    forced rekey all arrive in the peer's history exactly once.
//! 2. Invisibility: `phase` never leaves `"linked"` on either daemon while
//!    the rekey happens (no visible disconnect/reconnect flap), and the
//!    handshake bookkeeping (`ConnectionMetrics.reconnects`, which both
//!    the rekey initiator and the rekey responder bump via
//!    `Event::HandshakeOk`) shows a second completed handshake landed on
//!    both sides. `session_generation`'s own advance/CAS mechanics are
//!    covered directly by unit tests in `transport.rs` (the daemon does
//!    not expose the raw counter over IPC).

#![cfg(unix)]

use fluxsync_crypto::{test_util::pair_for_test, Identity};
use fluxsyncd::{
    cmd::{CmdData, CmdOp, CmdRequest, CmdResponse},
    run, DaemonConfig, TestPair,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UdpSocket, UnixStream};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

static PANIC_TRIGGERED: AtomicBool = AtomicBool::new(false);

// DIR-P2-03: force the age trigger almost immediately; leave the bytes
// trigger at its real (huge) default so only age fires here — the bytes
// trigger has its own unit-test coverage in `transport.rs`.
const FORCED_REKEY_AGE_MS: u64 = 300;

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

async fn reconnects(ipc: &PathBuf) -> u64 {
    status(ipc)
        .await
        .metrics
        .as_ref()
        .map_or(0, |m| m.reconnects)
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

async fn history_has_exactly_once(ipc: &PathBuf, text: &str) -> bool {
    status(ipc)
        .await
        .history
        .iter()
        .filter(|h| h.preview == text)
        .count()
        == 1
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rekey_mid_traffic_loses_no_items_and_stays_invisible() {
    let _ = tracing_subscriber::fmt::try_init();
    install_panic_hook();

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

    let mut cfg_a = DaemonConfig::new(id_a.clone(), port_a, ipc_a.clone());
    cfg_a.udp_bind = "127.0.0.1".into();
    cfg_a.disable_clipboard = true;
    cfg_a.disable_mdns = true;
    cfg_a.peer_name_self = "device-a".into();
    cfg_a.rekey_max_age_ms = FORCED_REKEY_AGE_MS;
    cfg_a.test_pair = Some(TestPair {
        session: sess_a,
        peer_addr: addr_b,
        peer_name: "device-b".into(),
        peer_id: peer_id_b,
    });
    cfg_a.test_peer_static_pub = Some(id_b.public_key());

    let mut cfg_b = DaemonConfig::new(id_b.clone(), port_b, ipc_b.clone());
    cfg_b.udp_bind = "127.0.0.1".into();
    cfg_b.disable_clipboard = true;
    cfg_b.disable_mdns = true;
    cfg_b.peer_name_self = "device-b".into();
    cfg_b.rekey_max_age_ms = FORCED_REKEY_AGE_MS;
    cfg_b.test_pair = Some(TestPair {
        session: sess_b,
        peer_addr: addr_a,
        peer_name: "device-a".into(),
        peer_id: peer_id_a,
    });
    cfg_b.test_peer_static_pub = Some(id_a.public_key());

    let shutdown_a = CancellationToken::new();
    let shutdown_b = CancellationToken::new();
    let s_a = shutdown_a.clone();
    let s_b = shutdown_b.clone();

    let h_a = tokio::spawn(async move { run(cfg_a, s_a).await });
    let h_b = tokio::spawn(async move { run(cfg_b, s_b).await });

    // ── 1. both daemons reach Linked within 2s ──
    let linked_a = wait_until(Duration::from_secs(2), || async {
        ipc_a.exists() && status(&ipc_a).await.peer_name == "device-b"
    })
    .await;
    assert!(linked_a, "daemon A did not link in 2s");
    let linked_b = wait_until(Duration::from_secs(2), || async {
        ipc_b.exists() && status(&ipc_b).await.peer_name == "device-a"
    })
    .await;
    assert!(linked_b, "daemon B did not link in 2s");

    // `test_pair` injects one synthetic `HandshakeOk` at boot on each side.
    assert_eq!(reconnects(&ipc_a).await, 1);
    assert_eq!(reconnects(&ipc_b).await, 1);

    // ── 2. background watcher: neither daemon's phase may ever leave
    //    "linked" from here until the test's final assertions — a planned
    //    rekey must stay invisible to the UI (DIR-P2-03 UX requirement).
    let watch_stop = Arc::new(AtomicBool::new(false));
    let flap_seen = Arc::new(AtomicBool::new(false));
    let watcher = {
        let ipc_a = ipc_a.clone();
        let ipc_b = ipc_b.clone();
        let watch_stop = watch_stop.clone();
        let flap_seen = flap_seen.clone();
        tokio::spawn(async move {
            while !watch_stop.load(Ordering::Relaxed) {
                let (pa, pb) = (status(&ipc_a).await.phase, status(&ipc_b).await.phase);
                if pa != "linked" || pb != "linked" {
                    tracing::error!(phase_a = %pa, phase_b = %pb, "DIR-P2-03: visible phase flap during rekey");
                    flap_seen.store(true, Ordering::SeqCst);
                }
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
        })
    };

    // ── 3. push "before", then wait for it to land on B ──
    push(&ipc_a, "before-rekey").await;
    assert!(
        wait_until(Duration::from_secs(2), || async {
            history_has_exactly_once(&ipc_b, "before-rekey").await
        })
        .await,
        "'before-rekey' did not arrive on B"
    );

    // ── 4. cross the forced age threshold, push "during" right as the
    //    rekey watchdog is expected to fire, then wait for BOTH daemons to
    //    show a second completed handshake (reconnects: 1 -> 2) — the
    //    initiator side bumps it via `run_rekey_initiator`'s
    //    `Event::HandshakeOk`, the responder side via `run_responder`'s
    //    (pre-existing, unconditional) one. Neither side's identity as
    //    initiator is deterministic from the test's point of view (it
    //    depends on the two randomly generated peer_ids), so this waits
    //    on both symmetrically instead of assuming which one acts.
    tokio::time::sleep(Duration::from_millis(FORCED_REKEY_AGE_MS)).await;
    push(&ipc_a, "during-rekey").await;

    let rekeyed = wait_until(Duration::from_secs(5), || async {
        reconnects(&ipc_a).await >= 2 && reconnects(&ipc_b).await >= 2
    })
    .await;
    assert!(
        rekeyed,
        "planned rekey did not complete on both sides within 5s (reconnects A={}, B={})",
        reconnects(&ipc_a).await,
        reconnects(&ipc_b).await
    );

    // ── 5. push "after" once the rekey has landed ──
    push(&ipc_a, "after-rekey").await;

    // ── 6. all three items arrive on B exactly once ──
    for text in ["before-rekey", "during-rekey", "after-rekey"] {
        let ok = wait_until(Duration::from_secs(5), || async {
            history_has_exactly_once(&ipc_b, text).await
        })
        .await;
        assert!(ok, "{text:?} did not arrive on B exactly once");
    }

    // Give the phase watcher one more sweep before tearing it down, then
    // check it never observed a flap.
    tokio::time::sleep(Duration::from_millis(50)).await;
    watch_stop.store(true, Ordering::SeqCst);
    let _ = timeout(Duration::from_secs(1), watcher).await;
    assert!(
        !flap_seen.load(Ordering::SeqCst),
        "phase left \"linked\" on at least one daemon during the rekey"
    );

    // Link is still fully functional post-rekey on the primary path too.
    assert_eq!(status(&ipc_a).await.peer_name, "device-b");
    assert_eq!(status(&ipc_b).await.peer_name, "device-a");

    // ── 7. clean shutdown ──
    shutdown_a.cancel();
    shutdown_b.cancel();
    timeout(Duration::from_millis(500), h_a)
        .await
        .expect("daemon A did not shut down in 500ms")
        .expect("daemon A task panic")
        .expect("daemon A run() returned Err");
    timeout(Duration::from_millis(500), h_b)
        .await
        .expect("daemon B did not shut down in 500ms")
        .expect("daemon B task panic")
        .expect("daemon B run() returned Err");

    assert!(
        !PANIC_TRIGGERED.load(Ordering::SeqCst),
        "a panic was captured by the test panic hook"
    );
}
