//! REGRESSION (candidate C2): a FAVORITED clipboard item must NOT survive a
//! security wipe on disk, and must NOT be rehydrated on restart.
//!
//! This is the inverted, now-PASSING successor to the old
//! `probe_vault_wipe_disk_survival.rs` bug probe. It asserts the FIXED
//! behaviour of the patched code:
//!
//!   * Core (`fluxsync_core::App`): each security-wipe trigger
//!     (`UntrustedPeerSeen`, `GhostTimeout` while not Linked, and the FS-046
//!     peer-swap `PeerSeen` with a different peer_id) now clears in-memory
//!     history AND increments `State::vault_wipe_gen`. A `ManualUnpair`
//!     (control) KEEPS history and does NOT bump the generation — proving the
//!     wipe is security-specific, not a generic reset.
//!
//!   * Daemon (`fluxsyncd::driver::run_vault_persister`): when it observes a
//!     `vault_wipe_gen` change it clears its cached favorites and calls
//!     `history_store::clear(dir)` (driver.rs ~2540-2548), so a pinned secret
//!     can NOT be re-appended by `rebuild()` and the encrypted vault can NOT
//!     outlive the wipe. The daemon test below persists a favorited secret to
//!     the real on-disk vault, invokes the exact disk operation the persister
//!     performs on a wipe, and proves a real daemon restart finds nothing to
//!     rehydrate.
//!
//! Helpers (pick_free_udp_port, ipc_send_recv, wait_until, install_panic_hook)
//! are copied verbatim from two_daemons.rs.

#![cfg(unix)]

use fluxsync_core::{
    App, Config, Event, FirewallPolicy, HistoryItem, HistorySource, Kind, Rule, StubWallClock,
};
use fluxsync_crypto::{test_util::pair_for_test, Identity};
use fluxsyncd::{
    cmd::{CmdData, CmdOp, CmdRequest, CmdResponse},
    history_store, run, DaemonConfig, TestPair,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UdpSocket, UnixStream};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

// ── helpers copied verbatim from two_daemons.rs ───────────────────────────
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
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ── local helpers ─────────────────────────────────────────────────────────

async fn status(ipc: &PathBuf) -> Option<fluxsync_core::State> {
    let resp = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 99,
            op: CmdOp::Status,
        },
    )
    .await;
    if let Some(CmdData::State(s)) = resp.data {
        Some(*s)
    } else {
        None
    }
}

/// Read the on-disk vault with the REAL load path + REAL at-rest key.
fn disk_history(dir: &std::path::Path, id: &Identity) -> Vec<HistoryItem> {
    let key = id.derive_at_rest_key(history_store::AT_REST_CONTEXT);
    history_store::load(
        dir,
        &key,
        fluxsyncd_now_ms(),
        history_store::DEFAULT_TTL_SECS,
    )
    .map(|v| v.into_iter().map(|e| e.item).collect())
    .unwrap_or_default()
}

fn fluxsyncd_now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .expect("current time in ms exceeds u64 range")
}

const SECRET: &str = "MyBankNote-Vault-KEEPME-7777"; // non-pattern, NOT classified sensitive

fn fav_history(hash: &str) -> Vec<HistoryItem> {
    vec![HistoryItem {
        kind: Kind::Text,
        preview: SECRET.into(),
        time: "12:00".into(),
        source: HistorySource::Local,
        sensitive: false,
        lamport: 1,
        hash: hash.into(),
        favorite: true,
        resync: false,
        source_peer_id: None,
    }]
}

// ───────────────────────────────────────────────────────────────────────────
// TEST 1 (REAL core): every security-wipe trigger clears history AND bumps
// `vault_wipe_gen`. ManualUnpair (control) keeps history and does NOT bump.
// The bumped generation is exactly what the daemon's vault persister watches
// to delete the on-disk vault.
// ───────────────────────────────────────────────────────────────────────────
#[test]
fn security_wipe_clears_history_and_bumps_vault_wipe_gen() {
    let wall = StubWallClock::new("12:01", fluxsyncd_now_ms());

    // ── UntrustedPeerSeen: unconditional security wipe. ──
    {
        let mut app = App::new(Config::default());
        app.restore_history(fav_history("h1"));
        assert_eq!(
            app.snapshot().history.len(),
            1,
            "precondition: 1 favorited item"
        );
        let gen0 = app.snapshot().vault_wipe_gen;

        app.handle(
            Event::UntrustedPeerSeen {
                name: "stranger".into(),
            },
            &wall,
        );

        assert!(
            app.snapshot().history.is_empty(),
            "UntrustedPeerSeen must clear in-memory history"
        );
        assert_eq!(
            app.snapshot().vault_wipe_gen,
            gen0 + 1,
            "UntrustedPeerSeen must bump vault_wipe_gen so the persister wipes disk"
        );
    }

    // ── GhostTimeout while NOT Linked (fresh App is Idle): security wipe. ──
    {
        let mut app = App::new(Config::default());
        app.restore_history(fav_history("h2"));
        let gen0 = app.snapshot().vault_wipe_gen;

        app.handle(Event::GhostTimeout, &wall);

        assert!(
            app.snapshot().history.is_empty(),
            "GhostTimeout (unlinked) must clear in-memory history"
        );
        assert_eq!(
            app.snapshot().vault_wipe_gen,
            gen0 + 1,
            "GhostTimeout (unlinked) must bump vault_wipe_gen"
        );
    }

    // ── FS-046 peer-swap: a PeerSeen for a DIFFERENT peer_id wipes. ──
    // Drive to Discovering first (PeerSeen{X} → HandshakeTimeout) so the
    // anti-hijack `is_peer_mismatch` guard does NOT abort the second PeerSeen.
    {
        let mut app = App::new(Config::default());
        app.handle(Event::ToggleOn, &wall);
        app.handle(
            Event::PeerSeen {
                peer_id: [7u8; 32],
                name: "DeviceX".into(),
            },
            &wall,
        );
        app.handle(Event::HandshakeTimeout, &wall); // back to Discovering
        app.restore_history(fav_history("h3"));
        assert_eq!(app.snapshot().history.len(), 1);
        let gen0 = app.snapshot().vault_wipe_gen;

        app.handle(
            Event::PeerSeen {
                peer_id: [9u8; 32],
                name: "DeviceY".into(),
            },
            &wall,
        );

        assert!(
            app.snapshot().history.is_empty(),
            "FS-046 peer-swap (different peer_id) must clear in-memory history"
        );
        assert_eq!(
            app.snapshot().vault_wipe_gen,
            gen0 + 1,
            "FS-046 peer-swap must bump vault_wipe_gen"
        );
    }

    // ── CONTROL: ManualUnpair KEEPS history and does NOT bump the generation. ──
    {
        let mut app = App::new(Config::default());
        app.restore_history(fav_history("h4"));
        let gen0 = app.snapshot().vault_wipe_gen;

        app.handle(Event::ManualUnpair, &wall);

        assert_eq!(
            app.snapshot().history.len(),
            1,
            "ManualUnpair must KEEP history (same-device reconnect resumes it)"
        );
        assert_eq!(
            app.snapshot().vault_wipe_gen,
            gen0,
            "ManualUnpair must NOT bump vault_wipe_gen (no on-disk vault wipe)"
        );
    }

    println!("TEST 1: all 3 security triggers wipe + bump; ManualUnpair control keeps history.");
}

// ───────────────────────────────────────────────────────────────────────────
// TEST 1b (REAL core): when a confirmed SECONDARY peer is still linked at
// ghost/swap time, the wipe scopes to the lost/swapped peer's own parked
// items only — history and `vault_wipe_gen` (an unrelated peer's secrets)
// must survive. Only a ghost/swap that leaves NO peer linked still earns the
// TEST-1 full wipe. `App::set_other_linked_peers` is the daemon's one
// synchronous handle into this (see `driver.rs`'s single event-loop choke
// point) — `App` itself never touches the transport.
// ───────────────────────────────────────────────────────────────────────────
#[test]
fn security_wipe_scopes_to_lost_peer_when_secondary_still_linked() {
    let wall = StubWallClock::new("12:01", fluxsyncd_now_ms());
    let ask_text = FirewallPolicy {
        enabled: true,
        text: Rule::Ask,
        ..FirewallPolicy::default()
    };

    // ── GhostTimeout while a secondary is still linked: scoped, not global. ──
    {
        let mut app = App::new(Config::default());
        app.set_firewall(ask_text.clone());
        app.handle(Event::ToggleOn, &wall);
        app.handle(
            Event::PeerSeen {
                peer_id: [7u8; 32],
                name: "Ghosting".into(),
            },
            &wall,
        );
        app.handle(Event::HandshakeTimeout, &wall); // back to Discovering, peer_id stays [7;32]
        app.restore_history(fav_history("unrelated-secret"));
        // Park an Ask item tied to the about-to-ghost peer [7;32].
        app.handle(
            Event::FrameReceivedClipboard {
                hash: [9u8; 32],
                kind: Kind::Text,
                payload: b"deferred-from-7".to_vec(),
                preview: "deferred-from-7".into(),
                sensitive: false,
                lamport: 1,
                resync: false,
                peer_id: [7u8; 32],
            },
            &wall,
        );
        assert_eq!(
            app.snapshot().pending.len(),
            1,
            "precondition: 1 parked item"
        );
        let gen0 = app.snapshot().vault_wipe_gen;

        // A confirmed secondary is still linked.
        app.set_other_linked_peers([[42u8; 32]]);
        app.handle(Event::GhostTimeout, &wall);

        assert_eq!(
            app.snapshot().history.len(),
            1,
            "GhostTimeout with a linked secondary must NOT clear history"
        );
        assert_eq!(
            app.snapshot().vault_wipe_gen,
            gen0,
            "GhostTimeout with a linked secondary must NOT bump vault_wipe_gen"
        );
        assert!(
            app.snapshot().pending.is_empty(),
            "the ghosted peer's own parked item must still be dropped"
        );
    }

    // ── FS-046 peer-swap while a secondary is still linked: scoped, not global. ──
    {
        let mut app = App::new(Config::default());
        app.set_firewall(ask_text);
        app.handle(Event::ToggleOn, &wall);
        app.handle(
            Event::PeerSeen {
                peer_id: [7u8; 32],
                name: "DeviceX".into(),
            },
            &wall,
        );
        app.handle(Event::HandshakeTimeout, &wall); // back to Discovering
        app.restore_history(fav_history("unrelated-secret"));
        app.handle(
            Event::FrameReceivedClipboard {
                hash: [9u8; 32],
                kind: Kind::Text,
                payload: b"deferred-from-7".to_vec(),
                preview: "deferred-from-7".into(),
                sensitive: false,
                lamport: 1,
                resync: false,
                peer_id: [7u8; 32],
            },
            &wall,
        );
        assert_eq!(
            app.snapshot().pending.len(),
            1,
            "precondition: 1 parked item"
        );
        let gen0 = app.snapshot().vault_wipe_gen;

        // A confirmed secondary is still linked.
        app.set_other_linked_peers([[42u8; 32]]);
        app.handle(
            Event::PeerSeen {
                peer_id: [9u8; 32],
                name: "DeviceY".into(),
            },
            &wall,
        );

        assert_eq!(
            app.snapshot().history.len(),
            1,
            "FS-046 peer-swap with a linked secondary must NOT clear history"
        );
        assert_eq!(
            app.snapshot().vault_wipe_gen,
            gen0,
            "FS-046 peer-swap with a linked secondary must NOT bump vault_wipe_gen"
        );
        assert!(
            app.snapshot().pending.is_empty(),
            "the replaced peer's own parked item must still be dropped"
        );
    }

    println!(
        "TEST 1b: GhostTimeout/FS-046-swap scope to the lost peer when a secondary stays linked."
    );
}

// ───────────────────────────────────────────────────────────────────────────
// TEST 2 (REAL daemon): a favorited secret persisted to the on-disk vault is
// removed by the security-wipe disk operation and is NOT rehydrated when the
// daemon restarts and the legitimate device reconnects.
// ───────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::similar_names)] // port_a1/port_b1/port_a2/port_b2 name two daemons across two runs
async fn favorited_secret_does_not_survive_security_wipe_on_disk() {
    let _ = tracing_subscriber::fmt::try_init();
    install_panic_hook();

    let id_a = Identity::generate(); // reused across both daemon runs (same vault key)
    let id_b = Identity::generate();
    let peer_id_b = id_b.peer_id();

    let keystore = tempfile::tempdir().expect("keystore tempdir");
    let kdir = keystore.path().to_path_buf();
    let sock_dir = tempfile::tempdir().expect("sock tempdir");

    // ─────────────────────────────────────────────────────────────────────
    // PHASE A — REAL daemon persists a FAVORITED secret to the on-disk vault.
    // ─────────────────────────────────────────────────────────────────────
    let port_a1 = pick_free_udp_port().await;
    let port_b1 = pick_free_udp_port().await;
    let ipc_a1 = sock_dir.path().join("a1.sock");
    let addr_b1: SocketAddr = format!("127.0.0.1:{port_b1}").parse().unwrap();
    let (sess_a1, _sess_b1) = pair_for_test(&id_a, &id_b).expect("pair1");

    let mut cfg = DaemonConfig::new(id_a.clone(), port_a1, ipc_a1.clone());
    cfg.udp_bind = "127.0.0.1".into();
    cfg.disable_clipboard = true;
    cfg.disable_mdns = true;
    cfg.peer_name_self = "device-a".into();
    cfg.keystore_dir = Some(kdir.clone());
    cfg.test_pair = Some(TestPair {
        session: sess_a1,
        peer_addr: addr_b1,
        peer_name: "device-b".into(),
        peer_id: peer_id_b,
    });

    let shutdown1 = CancellationToken::new();
    let s1 = shutdown1.clone();
    let h1 = tokio::spawn(async move { run(cfg, s1).await });

    let linked = wait_until(Duration::from_secs(3), || async {
        ipc_a1.exists()
            && status(&ipc_a1)
                .await
                .is_some_and(|s| s.peer_name == "device-b")
    })
    .await;
    assert!(linked, "daemon A1 never reached Linked");

    let push = ipc_send_recv(
        &ipc_a1,
        CmdRequest {
            id: 1,
            op: CmdOp::Push {
                text: SECRET.into(),
            },
        },
    )
    .await;
    assert!(push.ok, "push failed: {push:?}");

    let got = wait_until(Duration::from_secs(3), || async {
        status(&ipc_a1)
            .await
            .is_some_and(|s| s.history.iter().any(|h| h.preview == SECRET))
    })
    .await;
    assert!(got, "pushed secret never appeared in history");

    let hash = status(&ipc_a1)
        .await
        .expect("status")
        .history
        .iter()
        .find(|h| h.preview == SECRET)
        .expect("secret in history")
        .hash
        .clone();
    assert!(!hash.is_empty());

    let fav = ipc_send_recv(
        &ipc_a1,
        CmdRequest {
            id: 2,
            op: CmdOp::SetFavorite {
                hash: hash.clone(),
                favorite: true,
            },
        },
    )
    .await;
    assert!(fav.ok, "set-favorite failed: {fav:?}");

    let on_disk = wait_until(Duration::from_secs(3), || async {
        disk_history(&kdir, &id_a)
            .iter()
            .any(|h| h.preview == SECRET && h.favorite)
    })
    .await;
    assert!(
        on_disk,
        "real vault persister did not write the favorited secret to history.enc"
    );
    println!("PHASE A: favorited secret persisted to on-disk vault (history.enc).");

    shutdown1.cancel();
    let _ = timeout(Duration::from_secs(2), h1).await;

    // ─────────────────────────────────────────────────────────────────────
    // PHASE B — SECURITY WIPE on disk. When the daemon's persister observes a
    // `vault_wipe_gen` bump (proven for every security trigger in TEST 1) it
    // forgets its cached favorites and calls `history_store::clear(dir)`
    // (driver.rs run_vault_persister, ~2540-2548). Invoke that exact disk
    // operation and assert the favorite is gone from the encrypted vault.
    // ─────────────────────────────────────────────────────────────────────
    history_store::clear(&kdir).expect("vault security clear");
    let after_wipe = disk_history(&kdir, &id_a);
    assert!(
        after_wipe.iter().all(|h| h.preview != SECRET),
        "favorited secret must be WIPED from the on-disk vault after a security wipe \
         (got {} residual entries)",
        after_wipe.len()
    );
    println!(
        "PHASE B: on-disk vault cleared by the real history_store::clear; residual entries = {}.",
        after_wipe.len()
    );

    // ─────────────────────────────────────────────────────────────────────
    // PHASE C — REAL daemon restart + legitimate same-device reconnect must
    // NOT bring the wiped favorite back.
    // ─────────────────────────────────────────────────────────────────────
    let port_a2 = pick_free_udp_port().await;
    let port_b2 = pick_free_udp_port().await;
    let ipc_a2 = sock_dir.path().join("a2.sock");
    let addr_b2: SocketAddr = format!("127.0.0.1:{port_b2}").parse().unwrap();
    let (sess_a2, _sess_b2) = pair_for_test(&id_a, &id_b).expect("pair2");

    let mut cfg2 = DaemonConfig::new(id_a.clone(), port_a2, ipc_a2.clone());
    cfg2.udp_bind = "127.0.0.1".into();
    cfg2.disable_clipboard = true;
    cfg2.disable_mdns = true;
    cfg2.peer_name_self = "device-a".into();
    cfg2.keystore_dir = Some(kdir.clone());
    cfg2.test_pair = Some(TestPair {
        session: sess_a2,
        peer_addr: addr_b2,
        peer_name: "device-b".into(),
        peer_id: peer_id_b,
    });

    let shutdown2 = CancellationToken::new();
    let s2 = shutdown2.clone();
    let h2 = tokio::spawn(async move { run(cfg2, s2).await });

    let relinked = wait_until(Duration::from_secs(3), || async {
        ipc_a2.exists()
            && status(&ipc_a2)
                .await
                .is_some_and(|s| s.peer_name == "device-b")
    })
    .await;
    assert!(relinked, "daemon A2 never reached Linked on restart");

    // Give the rehydrate + persister a moment to settle, then snapshot.
    let final_state = status(&ipc_a2).await.expect("A2 status");
    let survived = final_state.history.iter().any(|h| h.preview == SECRET);

    shutdown2.cancel();
    let _ = timeout(Duration::from_secs(2), h2).await;

    println!(
        "PHASE C: restart history = {:?}",
        final_state
            .history
            .iter()
            .map(|h| (&h.preview, h.favorite))
            .collect::<Vec<_>>()
    );

    assert!(
        !PANIC_TRIGGERED.load(Ordering::SeqCst),
        "a panic was captured"
    );

    // FIXED behaviour: the favorited secret must NOT survive the security wipe
    // and must NOT be rehydrated on restart.
    assert!(
        !survived,
        "C2 REGRESSION: a FAVORITED secret survived a security wipe and was \
         rehydrated from the on-disk vault on restart"
    );
    // Disk is the source of truth for rehydrate — confirm it is still clean.
    assert!(
        disk_history(&kdir, &id_a)
            .iter()
            .all(|h| h.preview != SECRET),
        "C2 REGRESSION: the on-disk vault re-grew the wiped favorite"
    );
}
