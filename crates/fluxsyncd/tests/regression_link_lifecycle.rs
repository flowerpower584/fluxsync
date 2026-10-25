//! Regressions on the primary link's lifecycle, between real daemons
//! (keystore, real pairing, mDNS off so links only come from the daemons'
//! own dials):
//!
//! - Pausing sync and resuming it must bring the link back:
//!   `Toggle{on:false}` closes the session (and tells the peer with a `Bye`);
//!   `Toggle{on:true}` must then relink on its own — same identity, same
//!   keystore, no `PairAccept` — and carry clipboard items again.
//! - Pairing another device is not a reconnect: the link that was already
//!   up keeps its `reconnects` count and session uptime.

#![cfg(unix)]

use fluxsync_crypto::Identity;
use fluxsyncd::{
    cmd::{CmdData, CmdOp, CmdRequest, CmdResponse},
    run, DaemonConfig,
};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UdpSocket, UnixStream};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

/// Generous envelope for "relinked after a restart", mirroring
/// `resync_on_reconnect.rs`'s `RECONNECT_ENVELOPE`. The proactive-probe
/// redial ticks every 200ms once ready, but the tie-break loser's side
/// only redials after its stale session times out via the heartbeat
/// watchdog (~9s) — 30s comfortably covers either path.
const RECONNECT_ENVELOPE: Duration = Duration::from_secs(30);

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

fn cfg_for(id: &Identity, port: u16, keystore: &Path, ipc: &Path, name: &str) -> DaemonConfig {
    let mut cfg = DaemonConfig::new(id.clone(), port, ipc.to_path_buf());
    cfg.udp_bind = "127.0.0.1".into();
    cfg.keystore_dir = Some(keystore.to_path_buf());
    cfg.disable_mdns = true;
    cfg.disable_clipboard = true;
    cfg.peer_name_self = name.into();
    cfg
}

async fn status(ipc: &Path) -> Box<fluxsync_core::State> {
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

/// Fallible sibling of `ipc_send_recv`: a freshly-spawned daemon can have
/// its ipc socket *file* created slightly before the listener actually
/// accepts connections, so probing this during startup must treat a
/// connection refusal as "not up yet", not a hard test failure.
async fn ipc_try_send_recv(path: &Path, req: CmdRequest) -> Option<CmdResponse> {
    let mut stream = UnixStream::connect(path).await.ok()?;
    stream.write_all(b"{\"subscribe\":\"cmd\"}\n").await.ok()?;
    stream.flush().await.ok()?;
    let line = serde_json::to_string(&req).unwrap() + "\n";
    stream.write_all(line.as_bytes()).await.ok()?;
    stream.flush().await.ok()?;
    let (read, _w) = stream.into_split();
    let mut reader = BufReader::new(read);
    let mut buf = String::new();
    reader.read_line(&mut buf).await.ok()?;
    serde_json::from_str(buf.trim()).ok()
}

async fn ipc_up(ipc: &Path, dur: Duration) -> bool {
    wait_until(dur, || async {
        if !ipc.exists() {
            return false;
        }
        ipc_try_send_recv(
            ipc,
            CmdRequest {
                id: 0,
                op: CmdOp::Status,
            },
        )
        .await
        .is_some_and(|r| r.ok)
    })
    .await
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

async fn push(ipc: &Path, text: &str) {
    let r = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 2,
            op: CmdOp::Push { text: text.into() },
        },
    )
    .await;
    assert!(r.ok, "push {text:?} failed: {r:?}");
}

async fn history_has(ipc: &Path, preview: &str) -> bool {
    status(ipc)
        .await
        .history
        .iter()
        .any(|h| h.preview == preview)
}

async fn phase_linked(ipc: &Path) -> bool {
    status(ipc).await.phase == "linked"
}

// ── Real IPC pairing (PairShow -> PairAccept -> PairConfirm x2) ──
// Mirrors resync_on_reconnect.rs / chaos_harness.rs's helpers of the same
// names/shape. Used ONLY for the initial pairing here — the whole point of
// this test is that the SUBSEQUENT relink after B's restart happens with
// NONE of this driving it.

async fn pair_show(ipc: &Path) -> (String, String) {
    let resp = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 10,
            op: CmdOp::PairShow {},
        },
    )
    .await;
    match resp.data {
        Some(CmdData::PairInfo {
            peer_id_hex,
            pubkey_b32,
            ..
        }) => (peer_id_hex, pubkey_b32),
        other => panic!("unexpected pair_show response: {other:?}"),
    }
}

async fn pair_accept(ipc: &Path, pubkey_b32: String, peer_name: &str, addr: SocketAddr) {
    let resp = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 11,
            op: CmdOp::PairAccept {
                pubkey_b32,
                name: peer_name.to_string(),
                addr: Some(addr.to_string()),
            },
        },
    )
    .await;
    assert!(resp.ok, "pair_accept failed: {resp:?}");
}

async fn pending_peer_id(ipc: &Path) -> Option<String> {
    let resp = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 12,
            op: CmdOp::PairPending {},
        },
    )
    .await;
    match resp.data {
        Some(CmdData::PendingPairs(v)) if !v.is_empty() => Some(v[0].peer_id.clone()),
        _ => None,
    }
}

/// FS-052: a fresh pair (either side) lands in `PairPending` and must be
/// explicitly confirmed or the 90s reaper revokes it.
async fn confirm_pending(ipc: &Path, dur: Duration) {
    let start = std::time::Instant::now();
    loop {
        if let Some(peer_id) = pending_peer_id(ipc).await {
            let resp = ipc_send_recv(
                ipc,
                CmdRequest {
                    id: 13,
                    op: CmdOp::PairConfirm {
                        peer_id,
                        accept: true,
                    },
                },
            )
            .await;
            assert!(resp.ok, "pair_confirm failed: {resp:?}");
            return;
        }
        assert!(
            start.elapsed() < dur,
            "no pending pair to confirm within {dur:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Full real pairing over loopback: `a` shows its pairing info, `b`
/// explicitly trusts + dials `a` (manual-address path — used only to
/// bootstrap the initial pairing in this test, never for the relink under
/// test), both land `Linked` via a real Noise handshake, then both confirm
/// the FS-052 pending entry. Returns `a`'s base32 static pubkey (unused by
/// the relink itself, kept for parity with the other harness files /
/// possible future scenarios in this file).
async fn pair_daemons(ipc_a: &Path, addr_a: SocketAddr, ipc_b: &Path) -> String {
    let (_a_id, a_pub) = pair_show(ipc_a).await;
    pair_accept(ipc_b, a_pub.clone(), "device-a", addr_a).await;

    let linked_a = wait_until(Duration::from_secs(10), || async {
        phase_linked(ipc_a).await
    })
    .await;
    let linked_b = wait_until(Duration::from_secs(10), || async {
        phase_linked(ipc_b).await
    })
    .await;
    assert!(linked_a, "a: did not reach linked phase while pairing");
    assert!(linked_b, "b: did not reach linked phase while pairing");

    confirm_pending(ipc_a, Duration::from_secs(10)).await;
    confirm_pending(ipc_b, Duration::from_secs(10)).await;
    a_pub
}

async fn toggle(ipc: &Path, on: bool) {
    let r = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 3,
            op: CmdOp::Toggle { on },
        },
    )
    .await;
    assert!(r.ok, "toggle {on} failed: {r:?}");
}

async fn item_reaches(from: &Path, to: &Path, tag: &str) -> bool {
    let deadline = std::time::Instant::now() + RECONNECT_ENVELOPE;
    let mut attempt = 0u32;
    while std::time::Instant::now() < deadline {
        attempt += 1;
        let payload = format!("{tag}-{attempt}");
        push(from, &payload).await;
        if wait_until(Duration::from_secs(3), || async {
            history_has(to, &payload).await
        })
        .await
        {
            return true;
        }
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn toggle_off_then_on_relinks_and_syncs_again() {
    let _ = tracing_subscriber::fmt::try_init();

    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let port_a = pick_free_udp_port().await;
    let port_b = pick_free_udp_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let keystore_a = dir.path().join("ks-a");
    let keystore_b = dir.path().join("ks-b");
    std::fs::create_dir(&keystore_a).unwrap();
    std::fs::create_dir(&keystore_b).unwrap();
    let ipc_a = keystore_a.join("a.sock");
    let ipc_b = keystore_b.join("b.sock");
    let addr_a: SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();

    let shutdown = CancellationToken::new();
    let h_a = tokio::spawn(run(
        cfg_for(&id_a, port_a, &keystore_a, &ipc_a, "device-a"),
        shutdown.clone(),
    ));
    let h_b = tokio::spawn(run(
        cfg_for(&id_b, port_b, &keystore_b, &ipc_b, "device-b"),
        shutdown.clone(),
    ));
    assert!(
        ipc_up(&ipc_a, Duration::from_secs(5)).await,
        "a: ipc not up"
    );
    assert!(
        ipc_up(&ipc_b, Duration::from_secs(5)).await,
        "b: ipc not up"
    );
    set_threshold(&ipc_a, 5).await;
    set_threshold(&ipc_b, 5).await;
    pair_daemons(&ipc_a, addr_a, &ipc_b).await;
    assert!(
        item_reaches(&ipc_a, &ipc_b, "before-pause").await,
        "link never live"
    );

    for (side, ipc, other) in [("b", &ipc_b, &ipc_a), ("a", &ipc_a, &ipc_b)] {
        toggle(ipc, false).await;
        assert!(
            wait_until(Duration::from_secs(5), || async {
                status(ipc).await.phase == "idle"
            })
            .await,
            "{side}: toggle off did not reach idle"
        );
        // Off means off: the other side's redials must find nobody home,
        // rather than re-linking to a daemon whose FSM sits in Idle.
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_ne!(
            status(other).await.phase,
            "linked",
            "{side} switched sync off, yet its peer re-linked to it"
        );
        toggle(ipc, true).await;

        let relinked = wait_until(RECONNECT_ENVELOPE, || async {
            phase_linked(&ipc_a).await && phase_linked(&ipc_b).await
        })
        .await;
        assert!(
            relinked,
            "{side} paused then resumed: link did not come back within {RECONNECT_ENVELOPE:?} \
             (a={}, b={})",
            status(&ipc_a).await.phase,
            status(&ipc_b).await.phase
        );
        assert!(
            item_reaches(&ipc_a, &ipc_b, &format!("after-{side}-resume-ab")).await,
            "{side} resumed: a→b never synced again"
        );
        assert!(
            item_reaches(&ipc_b, &ipc_a, &format!("after-{side}-resume-ba")).await,
            "{side} resumed: b→a never synced again"
        );
    }

    shutdown.cancel();
    let _ = timeout(Duration::from_secs(5), h_a).await;
    let _ = timeout(Duration::from_secs(5), h_b).await;
}

async fn reconnects(ipc: &Path) -> u64 {
    status(ipc)
        .await
        .metrics
        .as_ref()
        .map_or(0, |m| m.reconnects)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn pairing_another_device_is_not_a_reconnect() {
    let _ = tracing_subscriber::fmt::try_init();

    let dir = tempfile::tempdir().expect("tempdir");
    let mut ipcs = Vec::new();
    let mut ports = Vec::new();
    let shutdown = CancellationToken::new();
    let mut handles = Vec::new();
    for name in ["a", "b", "c"] {
        let id = Identity::generate();
        let port = pick_free_udp_port().await;
        let ks = dir.path().join(format!("ks-{name}"));
        std::fs::create_dir(&ks).unwrap();
        let ipc = ks.join(format!("{name}.sock"));
        handles.push(tokio::spawn(run(
            cfg_for(&id, port, &ks, &ipc, &format!("device-{name}")),
            shutdown.clone(),
        )));
        ipcs.push(ipc);
        ports.push(port);
    }
    for ipc in &ipcs {
        assert!(ipc_up(ipc, Duration::from_secs(5)).await, "ipc not up");
        set_threshold(ipc, 5).await;
    }
    let (ipc_a, ipc_b, ipc_c) = (&ipcs[0], &ipcs[1], &ipcs[2]);
    let addr_a: SocketAddr = format!("127.0.0.1:{}", ports[0]).parse().unwrap();

    pair_daemons(ipc_a, addr_a, ipc_b).await;
    assert_eq!(reconnects(ipc_a).await, 1, "A's link to B came up once");
    tokio::time::sleep(Duration::from_millis(1_100)).await;

    // C pairs with A while A's link to B is up.
    pair_daemons(ipc_a, addr_a, ipc_c).await;
    assert!(
        wait_until(Duration::from_secs(5), || async {
            status(ipc_a).await.peers.len() == 2
        })
        .await,
        "C never joined A's mesh"
    );

    let m = status(ipc_a).await.metrics.clone().expect("metrics");
    assert_eq!(
        m.reconnects, 1,
        "C joining was counted as a reconnect of A's link"
    );
    assert!(
        m.uptime_session_secs >= 1,
        "C joining reset the session uptime of A's link ({} s)",
        m.uptime_session_secs
    );

    shutdown.cancel();
    for h in handles {
        let _ = timeout(Duration::from_secs(5), h).await;
    }
}
