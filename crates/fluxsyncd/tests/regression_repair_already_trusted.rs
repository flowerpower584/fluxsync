//! Regression tests for the asymmetric-trust pairing fix:
//!
//! 1. `pair_from_uri_on_already_trusted_peer_silently_reconnects` —
//!    `CmdOp::PairFromUri` against a peer that is already trusted (and has
//!    no fresh `PendingSet` entry) must take the silent-reconnect path,
//!    exactly like `PairAccept`/`PairFromPin` already did: no new pending
//!    entry, `sas_phase` never visits `"showing"`, and the response reports
//!    `already_paired: true`. Before the fix, `PairFromUri` ALWAYS passed
//!    `Some(pending_pairs)` to the initiator, so re-scanning a known peer's
//!    QR (e.g. after it dropped its session and auto-discovery is off)
//!    wrongly re-engaged the SAS gate on the scanning side only.
//!
//! 2. `verify_restart_reopens_scanner_verify_screen_after_peer_side_revoke`
//!    — the asymmetric-trust scenario: side B revokes/resets while
//!    disconnected from side A, so the best-effort wire `Msg::Revoke` never
//!    reaches A and A keeps trusting B. A re-pairs via `PairFromUri` and
//!    takes the silent-reconnect path (fix #1); B TOFUs A fresh (pending +
//!    SAS words on B's side only). Without `verify-restart`, only B's human
//!    would see words — verification theater. With it, B announces the
//!    fresh pairing over the wire (`Msg::PairVerifyStarted`) once it learns
//!    A's caps, and A re-opens its own verify screen: a REAL pending entry
//!    with the SAME 6 words (both ends derive them from the shared Noise
//!    transcript hash), `sas_phase = "showing"`, and the FS-052 clipboard
//!    gate re-armed until A's human confirms. Both sides then confirm and
//!    both reach `"confirmed"`, after which sync works in both directions.
//!    (The wire echo-ack for legacy `sas-confirm`-only peers still exists;
//!    it is covered by driver-level unit tests, since two working-tree
//!    daemons both negotiate `verify-restart` and never exercise it here.)
//!
//! Both scenarios need the redial to install a genuinely NEW session (the
//! initiator's `Transport::try_install_session` only fills an EMPTY slot —
//! unlike a rekey, it does not replace a live one), so each daemon's session
//! with the other is explicitly dropped via `CmdOp::Reconnect` before the
//! `PairFromUri` under test. Neither daemon is given a `keystore_dir`, so
//! there is no persisted `last_addr` and (with mDNS disabled) no automatic
//! background redial that could race the explicit `PairFromUri` call —
//! matching `two_daemons.rs`/`rekey.rs`'s in-process loopback pattern, with
//! `DaemonConfig::test_peer_static_pub` set on both sides (like `rekey.rs`)
//! so the real Noise IK re-handshake actually completes.

#![cfg(unix)]

use fluxsync_crypto::{test_util::pair_for_test, Identity};
use fluxsyncd::{
    cmd::{CmdData, CmdOp, CmdRequest, CmdResponse},
    run, DaemonConfig, TestPair,
};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UdpSocket, UnixStream};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

static PANIC_TRIGGERED: AtomicBool = AtomicBool::new(false);

fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        PANIC_TRIGGERED.store(true, Ordering::SeqCst);
        prev(info);
    }));
}

const BASE32_ALPHA: base32::Alphabet = base32::Alphabet::Rfc4648 { padding: false };

fn pair_uri(pubkey: [u8; 32], addr: SocketAddr) -> String {
    format!(
        "fluxsync://pair/{}?a={addr}",
        base32::encode(BASE32_ALPHA, &pubkey)
    )
}

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

async fn peer_name(ipc: &Path) -> Option<String> {
    if !ipc.exists() {
        return None;
    }
    Some(status(ipc).await.peer_name)
}

async fn phase_linked(ipc: &Path) -> bool {
    status(ipc).await.phase == "linked"
}

async fn sas_phase(ipc: &Path) -> String {
    status(ipc).await.sas_phase
}

async fn history_has(ipc: &Path, preview: &str) -> bool {
    status(ipc)
        .await
        .history
        .iter()
        .any(|h| h.preview == preview)
}

async fn set_threshold(ipc: &Path, value: u8) {
    let r = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 2,
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
            id: 3,
            op: CmdOp::Push { text: text.into() },
        },
    )
    .await;
    assert!(r.ok, "push {text:?} failed: {r:?}");
}

/// `CmdData` is `#[serde(untagged)]`, so an empty `Vec<PendingPairEntry>` is
/// indistinguishable from an empty `Vec<PeerEntry>` after a JSON round-trip
/// — both serialize to `[]`. Mirrors `pair_confirm.rs`'s helper of the same
/// name/shape.
async fn pending_entries(ipc: &Path) -> Vec<fluxsyncd::cmd::PendingPairEntry> {
    let resp = ipc_send_recv(
        ipc,
        CmdRequest {
            id: 4,
            op: CmdOp::PairPending {},
        },
    )
    .await;
    match resp.data {
        Some(CmdData::PendingPairs(entries)) => entries,
        Some(CmdData::Peers(entries)) if entries.is_empty() => Vec::new(),
        None => Vec::new(),
        other => panic!("expected PendingPairs, got {other:?}"),
    }
}

async fn pending_peer_ids(ipc: &Path) -> Vec<String> {
    pending_entries(ipc)
        .await
        .into_iter()
        .map(|e| e.peer_id)
        .collect()
}

/// The 6 SAS words of the pending entry for `peer_id_hex`, if present.
async fn pending_sas_words(ipc: &Path, peer_id_hex: &str) -> Option<Vec<String>> {
    pending_entries(ipc)
        .await
        .into_iter()
        .find(|e| e.peer_id == peer_id_hex)
        .map(|e| e.sas_words)
}

async fn reconnect(ipc: &Path, id: u64) {
    let r = ipc_send_recv(
        ipc,
        CmdRequest {
            id,
            op: CmdOp::Reconnect {},
        },
    )
    .await;
    assert!(r.ok, "reconnect failed: {r:?}");
}

async fn revoke(ipc: &Path, id: u64, peer_id_hex: &str) {
    let r = ipc_send_recv(
        ipc,
        CmdRequest {
            id,
            op: CmdOp::Revoke {
                peer_id: peer_id_hex.to_string(),
            },
        },
    )
    .await;
    assert!(r.ok, "revoke failed: {r:?}");
}

async fn pair_show(ipc: &Path, id: u64) {
    let r = ipc_send_recv(
        ipc,
        CmdRequest {
            id,
            op: CmdOp::PairShow {},
        },
    )
    .await;
    assert!(r.ok, "pair_show failed: {r:?}");
}

async fn pair_from_uri(ipc: &Path, id: u64, uri: String, name: &str) -> CmdResponse {
    ipc_send_recv(
        ipc,
        CmdRequest {
            id,
            op: CmdOp::PairFromUri {
                uri,
                name: name.to_string(),
            },
        },
    )
    .await
}

async fn pair_confirm(ipc: &Path, id: u64, peer_id_hex: &str, accept: bool) -> CmdResponse {
    ipc_send_recv(
        ipc,
        CmdRequest {
            id,
            op: CmdOp::PairConfirm {
                peer_id: peer_id_hex.to_string(),
                accept,
            },
        },
    )
    .await
}

fn already_paired(resp: &CmdResponse) -> bool {
    match &resp.data {
        Some(CmdData::PairResult { already_paired }) => *already_paired,
        other => panic!("expected PairResult, got {other:?}"),
    }
}

fn base_cfg(id: Identity, port: u16, ipc: PathBuf, name: &str) -> DaemonConfig {
    let mut cfg = DaemonConfig::new(id, port, ipc);
    cfg.udp_bind = "127.0.0.1".into();
    cfg.disable_clipboard = true;
    cfg.disable_mdns = true;
    cfg.peer_name_self = name.into();
    cfg
}

struct Booted {
    ipc_a: PathBuf,
    ipc_b: PathBuf,
    addr_b: SocketAddr,
    pub_b: [u8; 32],
    peer_id_a_hex: String,
    peer_id_b_hex: String,
    shutdown_a: CancellationToken,
    shutdown_b: CancellationToken,
    h_a: tokio::task::JoinHandle<anyhow::Result<()>>,
    h_b: tokio::task::JoinHandle<anyhow::Result<()>>,
}

/// Boots two daemons already trusting + linked to each other via injected
/// `test_pair` sessions (bypassing the real first-pair handshake, like
/// `two_daemons.rs`/`rekey.rs`), with `test_peer_static_pub` set on BOTH
/// sides to the peer's REAL Noise static key — required for the SUBSEQUENT
/// real re-handshake each test drives via `CmdOp::PairFromUri` to actually
/// succeed. No `keystore_dir` (no persisted `last_addr`, no on-disk trust)
/// and mDNS disabled, so nothing auto-redials in the background.
async fn boot_paired_daemons(tag: &str) -> Booted {
    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let pub_a = id_a.public_key();
    let pub_b = id_b.public_key();
    let peer_id_a = id_a.peer_id();
    let peer_id_b = id_b.peer_id();
    let (sess_a, sess_b) = pair_for_test(&id_a, &id_b).expect("pair");

    let port_a = pick_free_udp_port().await;
    let port_b = pick_free_udp_port().await;
    assert_ne!(port_a, port_b);

    let dir = tempfile::tempdir().expect("tempdir");
    // Leak the tempdir so it (and the sockets inside it) outlive this
    // function — same pattern as `pair_confirm.rs`'s spawn helper.
    let dir = Box::leak(Box::new(dir));
    let ipc_a = dir.path().join(format!("{tag}-a.sock"));
    let ipc_b = dir.path().join(format!("{tag}-b.sock"));

    let addr_a: SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();
    let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();

    let mut cfg_a = base_cfg(id_a, port_a, ipc_a.clone(), "device-a");
    cfg_a.test_pair = Some(TestPair {
        session: sess_a,
        peer_addr: addr_b,
        peer_name: "device-b".into(),
        peer_id: peer_id_b,
    });
    cfg_a.test_peer_static_pub = Some(pub_b);

    let mut cfg_b = base_cfg(id_b, port_b, ipc_b.clone(), "device-b");
    cfg_b.test_pair = Some(TestPair {
        session: sess_b,
        peer_addr: addr_a,
        peer_name: "device-a".into(),
        peer_id: peer_id_a,
    });
    cfg_b.test_peer_static_pub = Some(pub_a);

    let shutdown_a = CancellationToken::new();
    let shutdown_b = CancellationToken::new();
    let s_a = shutdown_a.clone();
    let s_b = shutdown_b.clone();
    let h_a = tokio::spawn(async move { run(cfg_a, s_a).await });
    let h_b = tokio::spawn(async move { run(cfg_b, s_b).await });

    let linked_a = wait_until(Duration::from_secs(2), || async {
        ipc_a.exists() && peer_name(&ipc_a).await.as_deref() == Some("device-b")
    })
    .await;
    assert!(linked_a, "a did not link within 2s");
    let linked_b = wait_until(Duration::from_secs(2), || async {
        ipc_b.exists() && peer_name(&ipc_b).await.as_deref() == Some("device-a")
    })
    .await;
    assert!(linked_b, "b did not link within 2s");

    // Host-battery pause trap: floor the threshold on both before any push.
    set_threshold(&ipc_a, 5).await;
    set_threshold(&ipc_b, 5).await;

    Booted {
        ipc_a,
        ipc_b,
        addr_b,
        pub_b,
        peer_id_a_hex: hex::encode(peer_id_a),
        peer_id_b_hex: hex::encode(peer_id_b),
        shutdown_a,
        shutdown_b,
        h_a,
        h_b,
    }
}

async fn shutdown_both(b: Booted) {
    b.shutdown_a.cancel();
    b.shutdown_b.cancel();
    let _ = timeout(Duration::from_millis(500), b.h_a).await;
    let _ = timeout(Duration::from_millis(500), b.h_b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pair_from_uri_on_already_trusted_peer_silently_reconnects() {
    let _ = tracing_subscriber::fmt::try_init();
    install_panic_hook();

    let b = boot_paired_daemons("repair").await;

    // Prove the link works before touching it.
    push(&b.ipc_a, "repair-sanity").await;
    assert!(
        wait_until(Duration::from_secs(3), || async {
            history_has(&b.ipc_b, "repair-sanity").await
        })
        .await,
        "sanity item never reached b before the repair scenario started"
    );

    // Drop A's session with B (trust untouched) so the redial below installs
    // a genuinely NEW session — `try_install_session` only fills an EMPTY
    // slot, so without this the handshake would short-circuit before ever
    // reaching the `already_confirmed` branch under test.
    reconnect(&b.ipc_a, 90).await;

    // Watch A's sas_phase across the whole redial: it must never visit
    // "showing" — that would mean the SAS gate wrongly re-engaged for an
    // already-trusted peer (the exact bug this test guards against).
    let watch_stop = Arc::new(AtomicBool::new(false));
    let saw_showing = Arc::new(AtomicBool::new(false));
    let watcher = {
        let ipc_a = b.ipc_a.clone();
        let watch_stop = watch_stop.clone();
        let saw_showing = saw_showing.clone();
        tokio::spawn(async move {
            while !watch_stop.load(Ordering::Relaxed) {
                if sas_phase(&ipc_a).await == "showing" {
                    saw_showing.store(true, Ordering::SeqCst);
                }
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
        })
    };

    let uri = pair_uri(b.pub_b, b.addr_b);
    let resp = pair_from_uri(&b.ipc_a, 91, uri, "device-b").await;
    assert!(resp.ok, "pair_from_uri failed: {resp:?}");
    assert!(
        already_paired(&resp),
        "re-pairing an already-trusted, non-pending peer must report already_paired=true"
    );

    assert!(
        !pending_peer_ids(&b.ipc_a).await.contains(&b.peer_id_b_hex),
        "already-trusted repair must not create a pending entry immediately"
    );

    let relinked = wait_until(Duration::from_secs(5), || async {
        phase_linked(&b.ipc_a).await
    })
    .await;
    assert!(
        relinked,
        "a did not relink to b after the repair PairFromUri"
    );

    assert!(
        !pending_peer_ids(&b.ipc_a).await.contains(&b.peer_id_b_hex),
        "still no pending entry once relinked"
    );

    // Give the watcher a final sweep, then check it never saw "showing".
    tokio::time::sleep(Duration::from_millis(100)).await;
    watch_stop.store(true, Ordering::SeqCst);
    let _ = timeout(Duration::from_secs(1), watcher).await;
    assert!(
        !saw_showing.load(Ordering::SeqCst),
        "sas_phase visited \"showing\" during an already-trusted repair"
    );

    // Session/sync still works after the repair.
    push(&b.ipc_a, "repair-post-item").await;
    assert!(
        wait_until(Duration::from_secs(5), || async {
            history_has(&b.ipc_b, "repair-post-item").await
        })
        .await,
        "post-repair item never reached b"
    );

    shutdown_both(b).await;
    assert!(
        !PANIC_TRIGGERED.load(Ordering::SeqCst),
        "a panic was captured by the test panic hook"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verify_restart_reopens_scanner_verify_screen_after_peer_side_revoke() {
    let _ = tracing_subscriber::fmt::try_init();
    install_panic_hook();

    let b = boot_paired_daemons("verifyrestart").await;

    // B revokes A WITHOUT a live session, so the best-effort wire
    // `Msg::Revoke` has nowhere to go and A is never told. (If B still held
    // a live session, `CmdOp::Revoke` would notify A over the wire and A
    // would auto-revoke B too via the inbound `Msg::Revoke` handler — a
    // different, symmetric-revoke scenario, not the asymmetric one here.)
    reconnect(&b.ipc_b, 90).await;
    revoke(&b.ipc_b, 91, &b.peer_id_a_hex).await;
    // Reopen B's TOFU window so A's incoming re-handshake below is accepted
    // as a fresh pair instead of being refused outright.
    pair_show(&b.ipc_b, 92).await;

    // A still trusts B, but (same reasoning as the repair test) its session
    // with B must also be dropped first so the redial installs a NEW one.
    reconnect(&b.ipc_a, 93).await;

    let uri = pair_uri(b.pub_b, b.addr_b);
    let resp = pair_from_uri(&b.ipc_a, 94, uri, "device-b").await;
    assert!(resp.ok, "pair_from_uri failed: {resp:?}");
    assert!(
        already_paired(&resp),
        "A already trusted B, so this must be the silent-reconnect path"
    );

    // B's responder TOFU-trusts A fresh (A was just revoked) and opens a
    // pending entry + SAS flow. Before `verify-restart`, that flow existed
    // on B ONLY — A silently reconnected and its human saw nothing.
    let b_pending = wait_until(Duration::from_secs(5), || async {
        pending_peer_ids(&b.ipc_b).await.contains(&b.peer_id_a_hex)
    })
    .await;
    assert!(
        b_pending,
        "b never created a pending entry for a's re-handshake"
    );

    // verify-restart under test: B announces the fresh pairing once it
    // learns A's caps (Hello), and A re-opens its own verify screen — a
    // real pending entry for B plus sas_phase "showing".
    let a_reopened = wait_until(Duration::from_secs(5), || async {
        pending_peer_ids(&b.ipc_a).await.contains(&b.peer_id_b_hex)
            && sas_phase(&b.ipc_a).await == "showing"
    })
    .await;
    assert!(
        a_reopened,
        "a never re-opened its verify screen (pending + sas_phase \"showing\") \
         after b's PairVerifyStarted"
    );

    // Both humans must be comparing the SAME 6 words: each end derives them
    // independently from the shared Noise transcript hash of the one
    // re-handshake, so any divergence here means the derivation broke.
    let words_a = pending_sas_words(&b.ipc_a, &b.peer_id_b_hex)
        .await
        .expect("a's pending entry vanished before its words were read");
    let words_b = pending_sas_words(&b.ipc_b, &b.peer_id_a_hex)
        .await
        .expect("b's pending entry vanished before its words were read");
    assert_eq!(
        words_a.len(),
        6,
        "expected 6 SAS words on a, got {words_a:?}"
    );
    assert_eq!(
        words_a, words_b,
        "the two sides derived DIFFERENT SAS words — the humans would be \
         comparing garbage"
    );

    // B's human confirms first (matches the live scenario: the freshly
    // reset device's user is the one driving the re-pair).
    let confirm_b = pair_confirm(&b.ipc_b, 95, &b.peer_id_a_hex, true).await;
    assert!(confirm_b.ok, "pair_confirm on b failed: {confirm_b:?}");

    // A is now in a real flow, so B's wire confirm advances A's phase to
    // "peer_confirmed" (NOT the legacy echo-ack path — A must still confirm).
    let a_peer_confirmed = wait_until(Duration::from_secs(5), || async {
        sas_phase(&b.ipc_a).await == "peer_confirmed"
    })
    .await;
    assert!(
        a_peer_confirmed,
        "a's sas_phase never reached \"peer_confirmed\" after b's confirm"
    );

    // A's human confirms too — the whole point of the symmetric re-verify.
    let confirm_a = pair_confirm(&b.ipc_a, 96, &b.peer_id_b_hex, true).await;
    assert!(confirm_a.ok, "pair_confirm on a failed: {confirm_a:?}");

    // Both sides converge on "confirmed" with empty pending sets.
    let both_confirmed = wait_until(Duration::from_secs(5), || async {
        sas_phase(&b.ipc_a).await == "confirmed" && sas_phase(&b.ipc_b).await == "confirmed"
    })
    .await;
    assert!(
        both_confirmed,
        "both sides never converged on sas_phase \"confirmed\" (a={}, b={})",
        sas_phase(&b.ipc_a).await,
        sas_phase(&b.ipc_b).await
    );
    assert!(
        pending_peer_ids(&b.ipc_a).await.is_empty(),
        "a's pending set must be empty once both confirmed"
    );
    assert!(
        pending_peer_ids(&b.ipc_b).await.is_empty(),
        "b's pending set must be empty once both confirmed"
    );

    // The re-verified link is genuinely live end to end, in BOTH directions
    // (the FS-052 gates on both sides must have disengaged).
    push(&b.ipc_b, "verifyrestart-b-to-a").await;
    assert!(
        wait_until(Duration::from_secs(5), || async {
            history_has(&b.ipc_a, "verifyrestart-b-to-a").await
        })
        .await,
        "post-confirm item never reached a"
    );
    push(&b.ipc_a, "verifyrestart-a-to-b").await;
    assert!(
        wait_until(Duration::from_secs(5), || async {
            history_has(&b.ipc_b, "verifyrestart-a-to-b").await
        })
        .await,
        "post-confirm item never reached b"
    );

    shutdown_both(b).await;
    assert!(
        !PANIC_TRIGGERED.load(Ordering::SeqCst),
        "a panic was captured by the test panic hook"
    );
}
