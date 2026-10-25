use super::load_trusted_peers;
use crate::handshake;
use crate::keystore::{save_peers, StoredPeer};

// ── Pre-`Shared` call shapes ───────────────────────────────────────────
// Most tests here predate `Shared` and hand each driver handle over one by
// one. These adapters fold those arguments into a `Shared` — cloning the very
// same Arcs and channels, so the test still observes every effect — and call
// the real function. Every scenario below keeps exercising production code.

/// `Shared` reads state through the watch *sender*; these tests hold a
/// receiver. The functions under test only ever read it, so a sender seeded
/// with the receiver's current value is observationally identical.
fn state_sender_from(
    rx: &tokio::sync::watch::Receiver<super::State>,
) -> tokio::sync::watch::Sender<super::State> {
    tokio::sync::watch::channel(rx.borrow().clone()).0
}

#[allow(clippy::too_many_arguments)]
async fn dispatch(
    actions: Vec<super::Action>,
    app: &mut super::App,
    transport: &std::sync::Arc<super::Transport>,
    trusted: &super::TrustedSet,
    keystore_dir: Option<&std::path::PathBuf>,
    state_watch_tx: &tokio::sync::watch::Sender<super::State>,
    logs_bcast_tx: &tokio::sync::broadcast::Sender<super::LogEntry>,
    log_tail: &std::sync::Arc<super::LogTail>,
    last_written_hashes: &std::sync::Arc<tokio::sync::Mutex<std::collections::VecDeque<[u8; 32]>>>,
    metrics: &std::sync::Arc<tokio::sync::Mutex<super::MetricsTracker>>,
    inflight: &super::InflightMap,
    peer_meta: &super::PeerMetaMap,
    outbox: &super::SharedOutbox,
    pending_pairs: &super::PendingSet,
    seq_store: &mut Option<super::SeqStore>,
) {
    let mut sh = super::Shared::for_test(transport.clone());
    sh.trusted = trusted.clone();
    sh.keystore_dir = keystore_dir.cloned();
    sh.state_watch_tx = state_watch_tx.clone();
    sh.logs_bcast_tx = logs_bcast_tx.clone();
    sh.log_tail = log_tail.clone();
    sh.last_written_hashes = last_written_hashes.clone();
    sh.metrics = metrics.clone();
    sh.inflight = inflight.clone();
    sh.peer_meta = peer_meta.clone();
    sh.outbox = outbox.clone();
    sh.pending_pairs = pending_pairs.clone();
    super::dispatch(actions, app, seq_store, &sh).await;
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_inbound_frame(
    frame: super::Frame,
    peer_id: [u8; 32],
    mesh_seen: &super::MeshSeen,
    event_tx: &tokio::sync::mpsc::Sender<super::Event>,
    transport: &std::sync::Arc<super::Transport>,
    reassembly: &super::ReassemblyMap,
    metrics: &std::sync::Arc<tokio::sync::Mutex<super::MetricsTracker>>,
    inflight: &super::InflightMap,
    pending_pairs: &super::PendingSet,
    trusted: &super::TrustedSet,
    disc_cache: &super::DiscoveryCache,
    backoff: &super::BackoffMap,
    peer_meta: &super::PeerMetaMap,
    keystore_dir: Option<&std::path::PathBuf>,
    outbox: &super::SharedOutbox,
    pending_pulls: &super::PendingPulls,
    outbox_stage: &super::PendingOutboxStage,
    state_rx: &tokio::sync::watch::Receiver<super::State>,
    deferred_sas_confirm: &super::DeferredSasConfirm,
    echo_ack_sent: &super::EchoAckSent,
    cleared_tombstone: &super::ClearedTombstone,
) {
    let mut sh = super::Shared::for_test(transport.clone());
    sh.mesh_seen = mesh_seen.clone();
    sh.event_tx = event_tx.clone();
    sh.reassembly = reassembly.clone();
    sh.metrics = metrics.clone();
    sh.inflight = inflight.clone();
    sh.pending_pairs = pending_pairs.clone();
    sh.trusted = trusted.clone();
    sh.disc_cache = disc_cache.clone();
    sh.backoff = backoff.clone();
    sh.peer_meta = peer_meta.clone();
    sh.keystore_dir = keystore_dir.cloned();
    sh.outbox = outbox.clone();
    sh.pending_pulls = pending_pulls.clone();
    sh.outbox_stage = outbox_stage.clone();
    sh.state_watch_tx = state_sender_from(state_rx);
    sh.deferred_sas_confirm = deferred_sas_confirm.clone();
    sh.echo_ack_sent = echo_ack_sent.clone();
    sh.cleared_tombstone = cleared_tombstone.clone();
    super::dispatch_inbound_frame(frame, peer_id, &sh).await;
}

#[allow(clippy::too_many_arguments)]
async fn complete_reassembled_item(
    transport: &std::sync::Arc<super::Transport>,
    inflight: &super::InflightMap,
    mesh_seen: &super::MeshSeen,
    event_tx: &tokio::sync::mpsc::Sender<super::Event>,
    source: [u8; 32],
    origin: [u8; 32],
    event_seq: u64,
    hash: [u8; 32],
    kind: super::Kind,
    sensitive: bool,
    lamport: u64,
    payload: Vec<u8>,
    outbox: &super::SharedOutbox,
    outbox_stage: &super::PendingOutboxStage,
    pending_pulls: &super::PendingPulls,
    state_rx: &tokio::sync::watch::Receiver<super::State>,
    pending_pairs: &super::PendingSet,
) {
    let mut sh = super::Shared::for_test(transport.clone());
    sh.inflight = inflight.clone();
    sh.mesh_seen = mesh_seen.clone();
    sh.event_tx = event_tx.clone();
    sh.outbox = outbox.clone();
    sh.outbox_stage = outbox_stage.clone();
    sh.pending_pulls = pending_pulls.clone();
    sh.state_watch_tx = state_sender_from(state_rx);
    sh.pending_pairs = pending_pairs.clone();
    let item = super::CompleteItem {
        source,
        origin,
        event_seq,
        hash,
        kind,
        sensitive,
        lamport,
        payload,
    };
    super::complete_reassembled_item(&sh, item).await;
}

#[allow(clippy::too_many_arguments)]
async fn rekey_watchdog(
    identity: super::Identity,
    transport: std::sync::Arc<super::Transport>,
    trusted: super::TrustedSet,
    pending_initiator_tx: std::sync::Arc<
        tokio::sync::Mutex<Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>>,
    >,
    event_tx: tokio::sync::mpsc::Sender<super::Event>,
    backoff: super::BackoffMap,
    max_age_ms: u64,
    max_bytes: u64,
    keystore_dir: Option<std::path::PathBuf>,
    shutdown: super::CancellationToken,
) -> anyhow::Result<()> {
    let mut sh = super::Shared::for_test(transport);
    sh.identity = identity;
    sh.trusted = trusted;
    sh.pending_initiator_tx = pending_initiator_tx;
    sh.event_tx = event_tx;
    sh.backoff = backoff;
    sh.keystore_dir = keystore_dir;
    sh.shutdown = shutdown;
    super::rekey_watchdog(std::sync::Arc::new(sh), max_age_ms, max_bytes).await
}

/// FS-039: a peer persisted to `peers.json` must be back in the
/// trusted set after a restart (i.e. via the boot reload path).
#[test]
fn fs039_trusted_peer_reloads_after_restart() {
    let dir = tempfile::tempdir().expect("create temp keystore dir");

    let static_pub = [0x42u8; 32];
    let peer_id = handshake::peer_id_for(&static_pub);
    save_peers(
        dir.path(),
        &[StoredPeer {
            peer_id_hex: hex::encode(peer_id),
            static_pub_hex: hex::encode(static_pub),
            name: "Galaxy S21".to_owned(),
            last_addr: Some("10.0.0.7:41889".to_owned()),
        }],
    )
    .expect("persist peer to peers.json");

    let loaded = load_trusted_peers(dir.path());

    assert_eq!(loaded.len(), 1, "the persisted peer must reload");
    let (id, peer, last_addr) = &loaded[0];
    assert_eq!(*id, peer_id, "peer_id must round-trip");
    assert_eq!(peer.static_pub, static_pub, "static_pub must round-trip");
    assert_eq!(peer.name, "Galaxy S21", "name must round-trip");
    assert_eq!(
        *last_addr,
        Some("10.0.0.7:41889".parse().unwrap()),
        "last_addr must parse and round-trip"
    );
}

/// Item 3: the boot-time `SetTrustedPeer` UI hint must be deterministic
/// across restarts, not `HashMap`-iteration-order luck. Two cases: the
/// primary's own entry wins when its id is already known, and otherwise
/// the choice falls back to the lowest peer id — computed here
/// independently of insertion order so the assertion cannot pass by
/// coincidentally matching whatever order the map happens to iterate in.
#[test]
fn choose_boot_trusted_peer_is_deterministic() {
    use super::choose_boot_trusted_peer;
    use std::collections::HashMap;

    fn peer(name: &str) -> handshake::TrustedPeer {
        handshake::TrustedPeer {
            static_pub: [0u8; 32],
            name: name.to_string(),
        }
    }

    // Scattered ids (not insertion-order-adjacent to the true min) so a
    // `HashMap`-iteration-order bug (`.values().next()`) is very unlikely
    // to coincidentally reproduce the correct answer.
    let ids: [[u8; 32]; 8] = [
        [0x90; 32], [0x20; 32], [0xF0; 32], [0x01; 32], [0x77; 32], [0xAA; 32], [0x55; 32],
        [0xC3; 32],
    ];
    let mut trusted = HashMap::new();
    for (i, id) in ids.iter().enumerate() {
        trusted.insert(*id, peer(&format!("peer-{i}")));
    }
    let true_min_id = *ids.iter().min().unwrap();
    let true_min_name = trusted[&true_min_id].name.clone();

    // ── Case 1: primary id known — its own entry must win, regardless
    //            of whether it's the min id. ──
    let primary_id = ids[5]; // [0xAA; 32] — not the min
    let chosen = choose_boot_trusted_peer(&trusted, Some(primary_id))
        .expect("primary's entry must be found");
    assert_eq!(
        chosen.name, trusted[&primary_id].name,
        "known primary id must win over the deterministic fallback"
    );

    // ── Case 2: no primary known — must fall back to the lowest peer
    //            id, deterministically. ──
    let chosen = choose_boot_trusted_peer(&trusted, None).expect("fallback must find an entry");
    assert_eq!(
        chosen.name, true_min_name,
        "FIXED: no known primary must deterministically pick the lowest peer id, \
         not whatever HashMap iteration happens to yield first"
    );

    // ── Case 3: primary id given but NOT in the trusted set (stale) —
    //            must still fall back to the deterministic minimum. ──
    let chosen = choose_boot_trusted_peer(&trusted, Some([0xEEu8; 32]))
        .expect("fallback must still find an entry for an unknown primary id");
    assert_eq!(chosen.name, true_min_name);
}

/// L4: `persist_last_addr` must reject loopback/link-local/multicast/
/// unspecified addresses outright (never even attempt the write),
/// while a normal LAN address persists exactly as before.
#[tokio::test]
async fn l4_persist_last_addr_filters_bogus_address_classes() {
    use super::{is_redialable_addr, persist_last_addr};
    use crate::handshake::{TrustedPeer, TrustedSet};
    use crate::transport::Transport;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    assert!(
        !is_redialable_addr("169.254.1.1".parse().unwrap()),
        "link-local must be rejected"
    );
    assert!(
        !is_redialable_addr("224.0.0.1".parse().unwrap()),
        "multicast must be rejected"
    );
    assert!(
        !is_redialable_addr("0.0.0.0".parse().unwrap()),
        "unspecified must be rejected"
    );
    assert!(
        !is_redialable_addr("fe80::1".parse().unwrap()),
        "IPv6 link-local must be rejected"
    );
    assert!(
        is_redialable_addr("192.168.1.42".parse().unwrap()),
        "a normal LAN address must pass"
    );
    // Loopback is intentionally allowed: an off-host attacker cannot forge
    // a loopback source, and the in-process harness redials over it.
    assert!(
        is_redialable_addr("127.0.0.1".parse().unwrap()),
        "loopback must be allowed"
    );
    assert!(
        is_redialable_addr("::1".parse().unwrap()),
        "IPv6 loopback must be allowed"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind transport");
    let peer_id = [0x11u8; 32];
    let trusted: TrustedSet = Arc::new(Mutex::new(HashMap::new()));
    trusted.lock().await.insert(
        peer_id,
        TrustedPeer {
            static_pub: [0x22u8; 32],
            name: "peer".into(),
        },
    );

    // A link-local source (the LAN-spoofable class the fix targets)
    // must never be written to peers.json.
    persist_last_addr(
        Some(dir.path()),
        &transport,
        &trusted,
        peer_id,
        "169.254.1.1:9999".parse().unwrap(),
    )
    .await;
    assert!(
        crate::keystore::load_peers(dir.path())
            .expect("load peers")
            .is_empty(),
        "L4: a link-local last_addr must never be persisted"
    );

    // A genuine LAN address persists exactly as before the fix.
    let lan_addr: std::net::SocketAddr = "192.168.1.42:9999".parse().unwrap();
    persist_last_addr(Some(dir.path()), &transport, &trusted, peer_id, lan_addr).await;
    let stored = crate::keystore::load_peers(dir.path()).expect("load peers");
    assert_eq!(stored.len(), 1, "a normal LAN address must persist");
    assert_eq!(stored[0].last_addr, Some(lan_addr.to_string()));
}

/// "Clear clipboard history": `CmdOp::ClearHistory` purges cleared
/// hashes from `IMAGE_CACHE` so a cleared image can't still be fetched
/// via `FetchItem` afterwards. Seeds the process-global cache directly
/// through `image_cache()` (rather than going through a `WriteClipboard`
/// action) to keep the test focused on `purge_cached_images` alone.
#[test]
fn clear_history_purges_cached_images_for_cleared_hashes() {
    use super::{image_cache, lookup_cached_image, purge_cached_images};

    let keep = "bb".repeat(32);
    let drop = "aa".repeat(32);
    {
        let mut g = image_cache().lock().expect("lock image cache");
        g.clear();
        g.push_back((drop.clone(), vec![1, 2, 3]));
        g.push_back((keep.clone(), vec![4, 5, 6]));
    }

    purge_cached_images(std::slice::from_ref(&drop));

    assert!(
        lookup_cached_image(&drop).is_none(),
        "cleared hash must be purged from IMAGE_CACHE"
    );
    assert!(
        lookup_cached_image(&keep).is_some(),
        "an untouched hash must survive the purge"
    );

    // Don't leak this process-global cache's state into other tests in
    // the same binary.
    image_cache().lock().expect("lock image cache").clear();
}

/// FS-026: the write side records `clipboard_dedup_hash(preview)` and
/// the watcher looks up `clipboard_dedup_hash(raw_text)`. A payload that
/// only differs by surrounding whitespace must hash equal, or a peer
/// item with a trailing newline echoes straight back to the sender.
#[test]
fn fs026_clipboard_dedup_hash_is_trim_symmetric() {
    use super::clipboard_dedup_hash;
    assert_eq!(
        clipboard_dedup_hash("hello\n"),
        clipboard_dedup_hash("hello"),
        "trailing newline must not change the dedup hash",
    );
    assert_eq!(
        clipboard_dedup_hash("  hello  "),
        clipboard_dedup_hash("hello"),
        "surrounding spaces must not change the dedup hash",
    );
    assert_ne!(
        clipboard_dedup_hash("hello"),
        clipboard_dedup_hash("world"),
        "distinct payloads must still hash differently",
    );
}

/// C1: the dedup hash CRLF-canonicalizes, so the SAME text copied with
/// Windows `\r\n` vs Unix `\n` line endings dedups instead of bouncing.
#[test]
fn c1_clipboard_dedup_hash_canonicalizes_crlf() {
    use super::clipboard_dedup_hash;
    assert_eq!(
        clipboard_dedup_hash("line1\r\nline2"),
        clipboard_dedup_hash("line1\nline2"),
        "CRLF and LF of the same text must hash equal",
    );
    assert_eq!(
        clipboard_dedup_hash("a\rb"),
        clipboard_dedup_hash("a\nb"),
        "lone CR must canonicalize to LF",
    );
}

/// C2: the vault persister mirrors a security wipe onto disk. When the
/// published `State.vault_wipe_gen` increments, the persister must delete
/// the encrypted vault AND forget its cached favorites — otherwise a
/// previously-favorited secret is re-appended by `rebuild()` and the file
/// outlives the in-memory wipe. This exercises the real persister glue
/// end-to-end (the only line the integration test couldn't reach).
#[tokio::test]
async fn c2_persister_clears_disk_vault_and_favorites_on_wipe_gen_bump() {
    use super::{run_vault_persister, BackoffMap, DiscoveryCache, ResolvedPeer, VaultCtx};
    use crate::history_store;
    use fluxsync_core::{Config, HistoryItem, HistorySource, Kind, State};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::{watch, Mutex};

    let dir = tempfile::tempdir().expect("tempdir");
    let key = zeroize::Zeroizing::new([0x11u8; 32]);
    let now = 1_000_000u64;
    let ttl = history_store::DEFAULT_TTL_SECS;
    let disk_len =
        |d: &std::path::Path| history_store::load(d, &key, now, ttl).map_or(0, |v| v.len());

    let secret = HistoryItem {
        kind: Kind::Text,
        preview: "favorited secret".into(),
        time: "12:00".into(),
        source: HistorySource::Local,
        sensitive: false,
        lamport: 1,
        hash: "aa".repeat(32),
        favorite: true,
        resync: false,
        source_peer_id: None,
    };

    // Persister starts empty (ctx.last empty) so the baseline publish below
    // forces a save we can poll on — a deterministic sync point that proves
    // the loop captured wipe_gen=0 BEFORE we bump it (avoids a watch-init
    // race where borrow() reads the post-send value).
    let ctx = VaultCtx {
        dir: dir.path().to_path_buf(),
        key: key.clone(),
        last: Vec::new(),
        entries: Vec::new(),
    };

    // DIR-P2-04a: pre-seed the discovery cache (as a real mDNS resolve
    // would) so this test also proves the security-wipe path purges it,
    // not just the on-disk vault + cached favorites.
    let disc_cache: DiscoveryCache = Arc::new(Mutex::new(HashMap::new()));
    disc_cache.lock().await.insert(
        [0x77u8; 32],
        ResolvedPeer {
            static_pub: [0x88u8; 32],
            addr: "127.0.0.1:1".parse().unwrap(),
            name: "stale-peer".into(),
            pair_pin: Some("123456".into()),
            last_seen: Instant::now(),
        },
    );
    // DIR-P1-02: same rationale — pre-seed a backoff timer for the same
    // peer so this test also proves the security-wipe path purges it.
    let backoff: BackoffMap = Arc::new(Mutex::new(HashMap::new()));
    let mut pb = crate::backoff::PeerBackoff::new();
    pb.on_attempt_failed(Instant::now(), &mut rand_core::OsRng);
    backoff.lock().await.insert([0x77u8; 32], pb);

    // Channel init: empty, gen=0. Persister records last_wipe_gen=0.
    let (tx, rx) = watch::channel(State::initial(&Config::default()));
    // Never-cancelled token: this test ends the persister the old way
    // (dropping `tx` below), exercising that path still works unchanged.
    let shutdown = tokio_util::sync::CancellationToken::new();
    let persister = tokio::spawn(run_vault_persister(
        ctx,
        rx,
        0,
        disc_cache.clone(),
        backoff.clone(),
        shutdown,
    ));

    // Baseline: publish the favorited secret (gen still 0) → persister saves
    // it to disk and caches it as a favorite in ctx.entries.
    let mut base = State::initial(&Config::default());
    base.history = vec![secret.clone()];
    base.vault_wipe_gen = 0;
    tx.send(base).expect("publish baseline");
    let mut saved = false;
    for _ in 0..200 {
        if disk_len(dir.path()) == 1 {
            saved = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        saved,
        "baseline favorite must reach the on-disk vault first"
    );

    // Security wipe with a NON-EMPTY post-wipe history (a peer-swap starts
    // a fresh, non-favorite item). This is what makes ctx.entries.clear()
    // load-bearing: with a non-empty history the persister does NOT
    // short-circuit on `history == ctx.last`, so it runs rebuild(). If
    // ctx.entries still held the favorited secret, rebuild()'s favorite
    // re-append loop would resurrect it onto disk — so this test fails iff
    // the cached favorites are not forgotten on the wipe.
    let fresh = HistoryItem {
        kind: Kind::Text,
        preview: "post-swap item".into(),
        time: "12:01".into(),
        source: HistorySource::Local,
        sensitive: false,
        lamport: 2,
        hash: "bb".repeat(32),
        favorite: false,
        resync: false,
        source_peer_id: None,
    };
    let mut wiped = State::initial(&Config::default());
    wiped.history = vec![fresh.clone()];
    wiped.vault_wipe_gen = 1;
    tx.send(wiped).expect("publish wipe");

    // Poll until the on-disk vault reflects the wipe: the fresh item is
    // persisted and the previously-favorited secret is GONE.
    let disk_previews = |d: &std::path::Path| -> Vec<String> {
        history_store::load(d, &key, now, ttl)
            .map(|v| v.into_iter().map(|e| e.item.preview).collect())
            .unwrap_or_default()
    };
    let mut cleared = false;
    for _ in 0..200 {
        let p = disk_previews(dir.path());
        if p.iter().any(|x| x == "post-swap item") && !p.iter().any(|x| x == "favorited secret") {
            cleared = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        cleared,
        "security wipe must drop the cached favorite: on-disk vault should hold only \
         the fresh post-swap item, never the previously-favorited secret. Got: {:?}",
        disk_previews(dir.path()),
    );
    assert!(
        disc_cache.lock().await.is_empty(),
        "security wipe must purge the mDNS discovery cache (DIR-P2-04a): a stale \
         pubkey/name/addrs/pairing PIN must not survive the wipe"
    );
    assert!(
        backoff.lock().await.is_empty(),
        "security wipe must purge per-peer reconnect backoff state (DIR-P1-02)"
    );

    drop(tx);
    let _ = persister.await;
}

/// FIX3: `sync_security_wipe_if_needed` (the driver's inline,
/// synchronous belt for the vault persister's async braces) must, by
/// the time it RETURNS — no polling needed — have both fully cleared
/// the resync outbox (real + `Ask`-staged) and deleted `history.enc`
/// from disk, exactly once per `vault_wipe_gen` advance. A call with no
/// gen change must touch neither.
#[tokio::test]
async fn sync_security_wipe_if_needed_clears_outbox_and_disk_synchronously() {
    use super::{sync_security_wipe_if_needed, Outbox, OutboxEntry, PendingOutboxStage};
    use crate::history_store;
    use fluxsync_core::{App, Config, Event, HistoryItem, HistorySource, StubWallClock};
    use fluxsync_proto::Kind;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::Mutex;

    let dir = tempfile::tempdir().expect("tempdir");
    let key = [0x22u8; 32];
    // Seed a real on-disk vault, exactly like a running persister would
    // have already written before the wipe.
    let entry = history_store::VaultEntry {
        item: HistoryItem {
            kind: Kind::Text,
            preview: "pre-wipe secret".into(),
            time: "12:00".into(),
            source: HistorySource::Local,
            sensitive: false,
            lamport: 1,
            hash: "cc".repeat(32),
            favorite: false,
            resync: false,
            source_peer_id: None,
        },
        created_ms: 1_000,
    };
    history_store::save(
        dir.path(),
        &key,
        &[entry],
        1_000,
        history_store::DEFAULT_TTL_SECS,
        history_store::DEFAULT_DISK_CAP,
    )
    .expect("seed on-disk vault");
    assert!(
        dir.path().join("history.enc").exists(),
        "precondition: vault file must exist before the wipe"
    );

    let outbox = Arc::new(Mutex::new(Outbox::new()));
    outbox.lock().await.insert(
        [1u8; 32],
        OutboxEntry {
            payload: b"held item".to_vec(),
            kind: Kind::Text,
            origin: [9u8; 32],
            seq: 1,
            created: Instant::now(),
        },
    );
    let outbox_stage: PendingOutboxStage = Arc::new(Mutex::new(HashMap::new()));
    outbox_stage.lock().await.insert(
        [2u8; 32],
        OutboxEntry {
            payload: b"staged item".to_vec(),
            kind: Kind::Text,
            origin: [9u8; 32],
            seq: 2,
            created: Instant::now(),
        },
    );
    // Bug #9: an inflight entry (unrelated `sensitive` gating on the
    // outbox insert notwithstanding) must not survive a security wipe —
    // its plaintext frames would otherwise keep retransmitting.
    let inflight: super::InflightMap = Arc::new(Mutex::new(HashMap::new()));
    inflight.lock().await.insert(
        [3u8; 32],
        super::Inflight {
            frames: vec![vec![1, 2, 3]],
            attempts: 0,
            last_sent: Instant::now(),
            first_sent: Instant::now(),
            pending_peers: std::iter::once([4u8; 32]).collect(),
        },
    );

    let mut app = App::new(Config::default());
    let wall = StubWallClock::new("12:00", 1_000);
    let mut last_wipe_gen = app.snapshot().vault_wipe_gen;
    let dir_buf = dir.path().to_path_buf();

    // No gen change yet: must be a complete no-op.
    let wiped = sync_security_wipe_if_needed(
        &app,
        &mut last_wipe_gen,
        &outbox,
        &outbox_stage,
        &inflight,
        Some(&dir_buf),
    )
    .await;
    assert!(!wiped, "must not fire when vault_wipe_gen hasn't advanced");
    assert!(
        outbox.lock().await.get([1u8; 32]).is_some(),
        "an unrelated call must not touch the outbox"
    );
    assert!(
        dir.path().join("history.enc").exists(),
        "an unrelated call must not touch disk"
    );
    assert!(
        inflight.lock().await.get(&[3u8; 32]).is_some(),
        "an unrelated call must not touch inflight"
    );

    // Bump vault_wipe_gen. `ClearHistory` is the simplest reliable way to
    // do this in a unit test; this test only exercises the driver's
    // REACTION to the bump, not which fluxsync_core events cause one —
    // that is fluxsync_core::app's own test coverage (and
    // regression_vault_security_wipe.rs's TEST 1 for the real security
    // triggers specifically).
    app.handle(
        Event::ClearHistory {
            include_favorites: true,
        },
        &wall,
    );
    assert_eq!(app.snapshot().vault_wipe_gen, 1);

    let wiped = sync_security_wipe_if_needed(
        &app,
        &mut last_wipe_gen,
        &outbox,
        &outbox_stage,
        &inflight,
        Some(&dir_buf),
    )
    .await;
    assert!(wiped, "must fire once vault_wipe_gen advances");
    assert_eq!(last_wipe_gen, 1, "must record the new generation");
    assert!(
        outbox.lock().await.is_empty(),
        "the real outbox must be fully cleared"
    );
    assert!(
        outbox_stage.lock().await.is_empty(),
        "Ask-staged entries must be fully cleared too"
    );
    assert!(
        !dir.path().join("history.enc").exists(),
        "history.enc must already be gone from disk by the time this call \
         returns — no polling/sleep needed, proving the clear is synchronous"
    );
    assert!(
        inflight.lock().await.is_empty(),
        "FIXED (bug #9): inflight must be fully cleared by a security wipe too"
    );

    // A second call at the same (already-recorded) generation must be a
    // no-op again — it must not re-run the disk clear or error out on an
    // already-missing file.
    let wiped_again = sync_security_wipe_if_needed(
        &app,
        &mut last_wipe_gen,
        &outbox,
        &outbox_stage,
        &inflight,
        Some(&dir_buf),
    )
    .await;
    assert!(
        !wiped_again,
        "must not re-fire for a generation already handled"
    );
}

/// L1 fix: `sync_security_wipe_if_needed` must also empty `IMAGE_CACHE`
/// (`WriteClipboard`'s image stash) — otherwise a wiped peer's cached
/// image bytes stay fetchable via `CmdOp::FetchItem` after the rest of
/// the vault is already gone. Seeds the process-global cache directly,
/// same as `clear_history_purges_cached_images_for_cleared_hashes`.
#[tokio::test]
async fn sync_security_wipe_if_needed_clears_image_cache() {
    use super::{
        image_cache, lookup_cached_image, sync_security_wipe_if_needed, Outbox, PendingOutboxStage,
    };
    use fluxsync_core::{App, Config, Event, StubWallClock};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    let stashed = "dd".repeat(32);
    {
        let mut g = image_cache().lock().expect("lock image cache");
        g.clear();
        g.push_back((stashed.clone(), vec![7, 8, 9]));
    }

    let outbox = Arc::new(Mutex::new(Outbox::new()));
    let outbox_stage: PendingOutboxStage = Arc::new(Mutex::new(HashMap::new()));
    let inflight: super::InflightMap = Arc::new(Mutex::new(HashMap::new()));

    let mut app = App::new(Config::default());
    let wall = StubWallClock::new("12:00", 1_000);
    let mut last_wipe_gen = app.snapshot().vault_wipe_gen;

    // Bump vault_wipe_gen the same way the outbox/disk test does.
    app.handle(
        Event::ClearHistory {
            include_favorites: true,
        },
        &wall,
    );
    assert_eq!(app.snapshot().vault_wipe_gen, 1);

    let wiped = sync_security_wipe_if_needed(
        &app,
        &mut last_wipe_gen,
        &outbox,
        &outbox_stage,
        &inflight,
        None,
    )
    .await;
    assert!(wiped, "must fire once vault_wipe_gen advances");
    assert!(
        lookup_cached_image(&stashed).is_none(),
        "a security wipe must purge IMAGE_CACHE, not just the outbox/disk vault"
    );

    // Don't leak this process-global cache's state into other tests in
    // the same binary.
    image_cache().lock().expect("lock image cache").clear();
}

/// DIR-P3-02(b) (desktop `FetchItem`): `WriteClipboard`'s image handler
/// now populates `IMAGE_CACHE` on every target, not just Android — this
/// is what lets the tray's `fetch_item` (`CmdOp::FetchItem` ->
/// `lookup_cached_image`) serve history thumbnails/re-copy on
/// macOS/Linux/Windows. Proves all three invariants through the real
/// `dispatch` path (not a direct cache seed, unlike the two tests
/// above): a non-sensitive image is fetchable byte-for-byte, a sensitive
/// one never enters the cache at all (mirrors the Android sensitivity
/// gate), and a security wipe purges whatever was cached before it.
#[tokio::test]
async fn write_clipboard_populates_desktop_image_cache_gated_by_sensitivity_and_wipe() {
    use super::{
        encode_png, image_cache, image_rgba_hash, lookup_cached_image,
        sync_security_wipe_if_needed, Outbox, PendingOutboxStage,
    };
    use crate::transport::Transport;
    use fluxsync_core::{Action, App, Config, Event, StubWallClock};
    use fluxsync_proto::Kind;
    use std::collections::{BTreeMap, HashMap, VecDeque};
    use std::sync::Arc;
    use tokio::sync::{broadcast, watch, Mutex};

    // Other tests in this binary share the process-global cache.
    image_cache().lock().expect("lock image cache").clear();

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);

    let mut app = App::new(Config::default());
    let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
    let (state_watch_tx, _state_watch_rx) =
        watch::channel(fluxsync_core::State::initial(&Config::default()));
    let (logs_bcast_tx, _logs_rx) = broadcast::channel(16);
    let log_tail = Arc::new(super::LogTail::new());
    let last_written_hashes = Arc::new(Mutex::new(VecDeque::new()));
    let metrics = Arc::new(Mutex::new(crate::metrics::MetricsTracker::new()));
    let inflight = Arc::new(Mutex::new(HashMap::new()));
    let peer_meta: super::PeerMetaMap = Arc::new(Mutex::new(BTreeMap::new()));
    let outbox = Arc::new(Mutex::new(Outbox::new()));
    let outbox_stage: PendingOutboxStage = Arc::new(Mutex::new(HashMap::new()));
    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
    let mut seq_store: Option<crate::seq_store::SeqStore> = None;

    // A tiny 1x1 opaque-red PNG — a real, non-sensitive image.
    let rgba = vec![0xff, 0x00, 0x00, 0xff];
    let png = encode_png(1, 1, rgba.clone()).expect("encode test PNG");
    let hash_hex = hex::encode(image_rgba_hash(1, 1, &rgba));

    dispatch(
        vec![Action::WriteClipboard {
            kind: Kind::Image,
            payload: png.clone(),
            sensitive: false,
        }],
        &mut app,
        &transport,
        &trusted,
        None,
        &state_watch_tx,
        &logs_bcast_tx,
        &log_tail,
        &last_written_hashes,
        &metrics,
        &inflight,
        &peer_meta,
        &outbox,
        &pending_pairs,
        &mut seq_store,
    )
    .await;

    assert_eq!(
        lookup_cached_image(&hash_hex),
        Some(png),
        "a non-sensitive desktop image must be FetchItem-fetchable byte-for-byte"
    );

    // A second, sensitive image must never enter the cache at all.
    let rgba2 = vec![0x00, 0xff, 0x00, 0xff];
    let png2 = encode_png(1, 1, rgba2.clone()).expect("encode test PNG 2");
    let hash2_hex = hex::encode(image_rgba_hash(1, 1, &rgba2));

    dispatch(
        vec![Action::WriteClipboard {
            kind: Kind::Image,
            payload: png2,
            sensitive: true,
        }],
        &mut app,
        &transport,
        &trusted,
        None,
        &state_watch_tx,
        &logs_bcast_tx,
        &log_tail,
        &last_written_hashes,
        &metrics,
        &inflight,
        &peer_meta,
        &outbox,
        &pending_pairs,
        &mut seq_store,
    )
    .await;

    assert!(
        lookup_cached_image(&hash2_hex).is_none(),
        "a sensitive image must never be cached on desktop either"
    );

    // A security wipe must purge the non-sensitive image cached above.
    let mut last_wipe_gen = app.snapshot().vault_wipe_gen;
    let wall = StubWallClock::new("12:00", 1_000);
    app.handle(
        Event::ClearHistory {
            include_favorites: true,
        },
        &wall,
    );
    let wiped = sync_security_wipe_if_needed(
        &app,
        &mut last_wipe_gen,
        &outbox,
        &outbox_stage,
        &inflight,
        None,
    )
    .await;
    assert!(wiped, "must fire once vault_wipe_gen advances");
    assert!(
        lookup_cached_image(&hash_hex).is_none(),
        "a security wipe must purge a previously cached desktop image too"
    );

    image_cache().lock().expect("lock image cache").clear();
}

/// Phase 5: reassembly is namespaced per source peer, so two paired peers
/// sending the same item_id get DISTINCT reassembly slots (no cross-peer
/// chunk overwrite), while a given (peer, item_id) pair is stable.
#[test]
fn reassembly_key_namespaces_by_source_peer() {
    use super::reassembly_key;
    let item = [0xAAu8; 32];
    let peer_a = [1u8; 32];
    let peer_b = [2u8; 32];

    // Same peer + same item ⇒ stable key (header and chunks collate).
    assert_eq!(reassembly_key(peer_a, item), reassembly_key(peer_a, item));
    // Different source peers, same item_id ⇒ different keys (the fix).
    assert_ne!(reassembly_key(peer_a, item), reassembly_key(peer_b, item));
    // Same peer, different items ⇒ different keys.
    assert_ne!(
        reassembly_key(peer_a, item),
        reassembly_key(peer_a, [0xBBu8; 32])
    );
    // The key is not just the item_id passed through.
    assert_ne!(reassembly_key(peer_a, item), item);
}

/// FS-041: an inbound `Msg::Bye` must emit `Event::PeerLost` so the FSM
/// closes the session and re-discovers. On `main` the shared empty match
/// arm (`Bye | HandshakeInit | HandshakeResp`) dropped `Bye` silently.
#[tokio::test]
async fn fs041_bye_frame_emits_peer_lost() {
    use super::{Event, Reassembly};
    use crate::metrics::MetricsTracker;
    use crate::transport::Transport;
    use fluxsync_proto::{Frame, Msg, PROTOCOL_VERSION};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);
    // Make the Bye sender the primary peer so the primary-gated PeerLost
    // fires (FluxMesh 2C-b: only the primary peer drives the single FSM).
    let peer_id = [7u8; 32];
    transport.set_cached_peer_id(peer_id).await;
    let (event_tx, mut event_rx) = mpsc::channel(1024);
    let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let inflight = Arc::new(Mutex::new(HashMap::new()));
    let metrics = Arc::new(Mutex::new(MetricsTracker::new()));
    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
    let outbox = Arc::new(Mutex::new(super::Outbox::new()));
    let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
        &fluxsync_core::Config::default(),
    ));

    let frame = Frame {
        version: PROTOCOL_VERSION,
        msg: Msg::Bye,
    };
    dispatch_inbound_frame(
        frame,
        peer_id,
        &Arc::new(Mutex::new(super::SeenSet::default())),
        &event_tx,
        &transport,
        &reassembly,
        &metrics,
        &inflight,
        &pending_pairs,
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Mutex::new(std::collections::BTreeMap::new())),
        None,
        &outbox,
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &state_rx,
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(HashMap::new())),
    )
    .await;

    assert!(
        matches!(event_rx.try_recv(), Ok(Event::PeerLost { peer_id: p }) if p == peer_id),
        "Msg::Bye must emit Event::PeerLost with the sender's peer_id"
    );
}

/// An inbound `Msg::Revoke` must remove the sending peer from the
/// trust store (so we don't auto-reconnect into its TOFU window)
/// and emit `Event::PeerLost`.
#[tokio::test]
async fn revoke_frame_removes_trust_and_emits_peer_lost() {
    use super::{BackoffMap, DiscoveryCache, Event, Reassembly, ResolvedPeer};
    use crate::backoff::PeerBackoff;
    use crate::handshake::tofu_trusted_peer;
    use crate::metrics::MetricsTracker;
    use crate::transport::Transport;
    use fluxsync_proto::{Frame, Msg, PROTOCOL_VERSION};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::{mpsc, Mutex};

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);
    let peer_id = [7u8; 32];
    transport.set_cached_peer_id(peer_id).await;

    let (event_tx, mut event_rx) = mpsc::channel(1024);
    let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let inflight = Arc::new(Mutex::new(HashMap::new()));
    let metrics = Arc::new(Mutex::new(MetricsTracker::new()));
    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
    let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
    trusted
        .lock()
        .await
        .insert(peer_id, tofu_trusted_peer(peer_id));
    // DIR-P2-04a: pre-seed a stale discovery-cache entry for this peer
    // (as a real mDNS resolve would) so the test can prove Msg::Revoke
    // purges it, not just the trust store.
    let disc_cache: DiscoveryCache = Arc::new(Mutex::new(HashMap::new()));
    disc_cache.lock().await.insert(
        peer_id,
        ResolvedPeer {
            static_pub: [0x42u8; 32],
            addr: "127.0.0.1:1".parse().unwrap(),
            name: "stale-peer".into(),
            pair_pin: Some("123456".into()),
            last_seen: Instant::now(),
        },
    );
    // DIR-P1-02: pre-seed a backoff timer for this peer too, so the
    // test can prove Msg::Revoke purges it alongside disc_cache
    // (mirrors DIR-P2-04a's purge-on-revoke).
    let backoff: BackoffMap = Arc::new(Mutex::new(HashMap::new()));
    let mut pb = PeerBackoff::new();
    pb.on_attempt_failed(Instant::now(), &mut rand_core::OsRng);
    backoff.lock().await.insert(peer_id, pb);
    let outbox = Arc::new(Mutex::new(super::Outbox::new()));
    let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
        &fluxsync_core::Config::default(),
    ));

    dispatch_inbound_frame(
        Frame {
            version: PROTOCOL_VERSION,
            msg: Msg::Revoke,
        },
        peer_id,
        &Arc::new(Mutex::new(super::SeenSet::default())),
        &event_tx,
        &transport,
        &reassembly,
        &metrics,
        &inflight,
        &pending_pairs,
        &trusted,
        &disc_cache,
        &backoff,
        &Arc::new(Mutex::new(std::collections::BTreeMap::new())),
        None,
        &outbox,
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &state_rx,
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(HashMap::new())),
    )
    .await;

    assert!(
        !trusted.lock().await.contains_key(&peer_id),
        "Msg::Revoke must remove the sender from the trust store"
    );
    assert!(
        !disc_cache.lock().await.contains_key(&peer_id),
        "Msg::Revoke must purge the sender's mDNS discovery-cache entry (DIR-P2-04a)"
    );
    assert!(
        !backoff.lock().await.contains_key(&peer_id),
        "Msg::Revoke must purge the sender's backoff timer (DIR-P1-02)"
    );
    assert!(
        matches!(event_rx.try_recv(), Ok(Event::PeerLost { peer_id: p }) if p == peer_id),
        "Msg::Revoke must emit Event::PeerLost with the sender's peer_id"
    );
}

/// Hardening sibling of the `run_pending_reaper` fix: the FS-052 gate
/// used to check `pending_pairs` membership ONLY, so a peer in NEITHER
/// `trusted` NOR `pending_pairs` — exactly what a reaped/expired peer
/// looks like once the reaper sweeps its pending entry away while its
/// live `extra` session survives — fell through as "not pending, so
/// allowed" and could still push clipboard data. The gate must
/// fail-closed: a clipboard-bearing frame is only accepted from a peer
/// that IS trusted AND is NOT still pending confirmation.
#[tokio::test]
async fn fs052_gate_blocks_clipboard_from_untrusted_non_pending_peer() {
    use super::{Outbox, Reassembly};
    use crate::metrics::MetricsTracker;
    use crate::transport::Transport;
    use fluxsync_core::SeenSet;
    use fluxsync_proto::{ClipboardItem, Frame, Kind, Msg, PROTOCOL_VERSION};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);
    let peer_id = [4u8; 32];

    let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
    let (event_tx, _event_rx) = mpsc::channel(1024);
    let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let metrics = Arc::new(Mutex::new(MetricsTracker::new()));
    let inflight = Arc::new(Mutex::new(HashMap::new()));
    // Neither trusted nor pending — exactly what a reaped/expired peer
    // looks like once its entries are swept from both maps, while its
    // live session (not modeled here — irrelevant to this gate) survives.
    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
    let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
    let disc_cache = Arc::new(Mutex::new(HashMap::new()));
    let backoff = Arc::new(Mutex::new(HashMap::new()));
    let peer_meta = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    let outbox = Arc::new(Mutex::new(Outbox::new()));
    let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
    let outbox_stage = Arc::new(Mutex::new(HashMap::new()));
    let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
        &fluxsync_core::Config::default(),
    ));

    let hash = super::clipboard_dedup_hash("should be blocked");
    let item = ClipboardItem {
        lamport: 1,
        hash,
        kind: Kind::Text,
        payload: b"should be blocked".to_vec(),
        sensitive: false,
        wall_time_ms: 0,
        origin: peer_id,
        event_seq: 1,
    };

    dispatch_inbound_frame(
        Frame {
            version: PROTOCOL_VERSION,
            msg: Msg::ClipboardItem(item),
        },
        peer_id,
        &mesh_seen,
        &event_tx,
        &transport,
        &reassembly,
        &metrics,
        &inflight,
        &pending_pairs,
        &trusted,
        &disc_cache,
        &backoff,
        &peer_meta,
        None,
        &outbox,
        &pending_pulls,
        &outbox_stage,
        &state_rx,
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(HashMap::new())),
    )
    .await;

    assert!(
        outbox.lock().await.is_empty(),
        "FS-052 hardening: a clipboard frame from a peer that is neither \
         trusted nor pending must be dropped, not admitted to the outbox"
    );
    assert!(
        inflight.lock().await.is_empty(),
        "a dropped frame must never be relayed either"
    );
}

// ── sas-confirm (FS-052 wire mutual confirm) ─────────────────

fn test_pending_pair(expires_at: std::time::Instant) -> crate::handshake::PendingPair {
    crate::handshake::PendingPair {
        static_pub: [0x42u8; 32],
        name: "pending-peer".into(),
        sas_words: std::array::from_fn(|i| format!("word{i}")),
        from: "127.0.0.1:1".parse().unwrap(),
        expires_at,
    }
}

/// Inbound `Msg::PairConfirm { accept: true }` while our own pending
/// entry still exists must refresh its 90s window (the peer's human is
/// engaged) and emit `Event::SasPeerConfirmed`. Trust is untouched.
#[tokio::test]
async fn inbound_pair_confirm_accept_refreshes_pending_and_emits_peer_confirmed() {
    use super::{Event, Reassembly};
    use crate::handshake::tofu_trusted_peer;
    use crate::metrics::MetricsTracker;
    use crate::transport::Transport;
    use fluxsync_proto::{Frame, Msg, PairConfirm, PROTOCOL_VERSION};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::{mpsc, Mutex};

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);
    let peer_id = [8u8; 32];
    transport.set_cached_peer_id(peer_id).await;

    let (event_tx, mut event_rx) = mpsc::channel(1024);
    let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
    trusted
        .lock()
        .await
        .insert(peer_id, tofu_trusted_peer(peer_id));
    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
    // Nearly-expired entry: the refresh must push it back out to ~90s.
    let soon = Instant::now() + Duration::from_secs(5);
    pending_pairs
        .lock()
        .await
        .insert(peer_id, test_pending_pair(soon));
    let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
        &fluxsync_core::Config::default(),
    ));

    dispatch_inbound_frame(
        Frame {
            version: PROTOCOL_VERSION,
            msg: Msg::PairConfirm(PairConfirm { accept: true }),
        },
        peer_id,
        &Arc::new(Mutex::new(super::SeenSet::default())),
        &event_tx,
        &transport,
        &reassembly,
        &Arc::new(Mutex::new(MetricsTracker::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &pending_pairs,
        &trusted,
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Mutex::new(std::collections::BTreeMap::new())),
        None,
        &Arc::new(Mutex::new(super::Outbox::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &state_rx,
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(HashMap::new())),
    )
    .await;

    let refreshed = pending_pairs
        .lock()
        .await
        .get(&peer_id)
        .expect("pending entry must survive an accept")
        .expires_at;
    assert!(
        refreshed > Instant::now() + Duration::from_secs(80),
        "accept must refresh the pending window to ~90s"
    );
    assert!(
        trusted.lock().await.contains_key(&peer_id),
        "accept must not touch the trust store"
    );
    assert!(
        matches!(event_rx.try_recv(), Ok(Event::SasPeerConfirmed { peer_id: p }) if p == peer_id),
        "accept must emit Event::SasPeerConfirmed with the matching peer_id"
    );
}

/// Legacy echo-ack path (peers with `sas-confirm` but not
/// `verify-restart` — two working-tree builds never reach it, so the
/// loopback tests can't cover it): an inbound `PairConfirm{accept:true}`
/// from a TRUSTED peer with NO pending entry and NO live SAS flow gets
/// exactly one once-per-session echo-ack (loop guard), never advances
/// our own sas_phase, and never fires for an untrusted or
/// legacy-without-sas-confirm sender.
#[tokio::test]
async fn inbound_pair_confirm_accept_outside_flow_echo_acks_once_for_trusted_sas_peer() {
    use super::Reassembly;
    use crate::handshake::tofu_trusted_peer;
    use crate::metrics::MetricsTracker;
    use crate::transport::Transport;
    use fluxsync_proto::{Frame, Msg, PairConfirm, PROTOCOL_VERSION};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);
    let peer_id = [11u8; 32];
    transport.set_cached_peer_id(peer_id).await;

    let (event_tx, mut event_rx) = mpsc::channel(1024);
    let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
    trusted
        .lock()
        .await
        .insert(peer_id, tofu_trusted_peer(peer_id));
    // NO pending entry, idle sas_phase — the outside-a-flow case.
    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
    let peer_meta: super::PeerMetaMap = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    {
        let mut meta = peer_meta.lock().await;
        let e = meta.entry(peer_id).or_insert_with(super::PeerMeta::new);
        e.caps = vec!["core-1".into(), "sas-confirm".into()];
        e.hello_seen = true;
    }
    let echo_ack: super::EchoAckSent = Arc::new(Mutex::new(std::collections::HashSet::new()));
    let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
        &fluxsync_core::Config::default(),
    ));

    let frame = || Frame {
        version: PROTOCOL_VERSION,
        msg: Msg::PairConfirm(PairConfirm { accept: true }),
    };
    // Twice: the second delivery must be swallowed by the loop guard.
    for _ in 0..2 {
        dispatch_inbound_frame(
            frame(),
            peer_id,
            &Arc::new(Mutex::new(super::SeenSet::default())),
            &event_tx,
            &transport,
            &reassembly,
            &Arc::new(Mutex::new(MetricsTracker::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &pending_pairs,
            &trusted,
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &peer_meta,
            None,
            &Arc::new(Mutex::new(super::Outbox::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &state_rx,
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &echo_ack,
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .await;
    }
    assert!(
        echo_ack.lock().await.contains(&peer_id),
        "trusted+sas-confirm sender outside a flow must be echo-acked"
    );
    assert_eq!(
        echo_ack.lock().await.len(),
        1,
        "the loop guard must keep the echo to once per session"
    );
    assert!(
        event_rx.try_recv().is_err(),
        "an outside-a-flow accept must not advance our own sas_phase"
    );

    // Untrusted sender: same shape, different peer — never acked.
    let stranger = [12u8; 32];
    dispatch_inbound_frame(
        frame(),
        stranger,
        &Arc::new(Mutex::new(super::SeenSet::default())),
        &event_tx,
        &transport,
        &reassembly,
        &Arc::new(Mutex::new(MetricsTracker::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &pending_pairs,
        &trusted,
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &peer_meta,
        None,
        &Arc::new(Mutex::new(super::Outbox::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &state_rx,
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &echo_ack,
        &Arc::new(Mutex::new(HashMap::new())),
    )
    .await;
    assert!(
        !echo_ack.lock().await.contains(&stranger),
        "an untrusted sender must never be echo-acked"
    );

    // Trusted but WITHOUT the `sas-confirm` cap: also never acked (an
    // old build could not decode the echo anyway).
    let legacy = [13u8; 32];
    trusted
        .lock()
        .await
        .insert(legacy, tofu_trusted_peer(legacy));
    {
        let mut meta = peer_meta.lock().await;
        let e = meta.entry(legacy).or_insert_with(super::PeerMeta::new);
        e.caps = vec!["core-1".into()];
        e.hello_seen = true;
    }
    dispatch_inbound_frame(
        frame(),
        legacy,
        &Arc::new(Mutex::new(super::SeenSet::default())),
        &event_tx,
        &transport,
        &reassembly,
        &Arc::new(Mutex::new(MetricsTracker::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &pending_pairs,
        &trusted,
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &peer_meta,
        None,
        &Arc::new(Mutex::new(super::Outbox::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &state_rx,
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &echo_ack,
        &Arc::new(Mutex::new(HashMap::new())),
    )
    .await;
    assert!(
        !echo_ack.lock().await.contains(&legacy),
        "a trusted peer without `sas-confirm` must never be echo-acked"
    );
}

/// verify-restart: an inbound `Msg::PairVerifyStarted` from a TRUSTED
/// peer with a live session and no pending/flow on our side must insert
/// a real pending pair whose 6 SAS words derive from the session's
/// Noise transcript hash, and fire `Event::SasPairingStarted`. An
/// untrusted sender is ignored, and a duplicate announcement does not
/// reset an existing flow.
#[tokio::test]
async fn inbound_pair_verify_started_reopens_pending_for_trusted_peer_only() {
    use super::{Event, Reassembly};
    use crate::handshake::tofu_trusted_peer;
    use crate::metrics::MetricsTracker;
    use crate::transport::Transport;
    use fluxsync_crypto::{test_util::pair_for_test, Identity};
    use fluxsync_proto::{Frame, Msg, PROTOCOL_VERSION};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);
    let peer_id = [21u8; 32];

    // A real session so the handler has a transcript hash to derive
    // words from; the expected words come from the same hash.
    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let (sess_local, _sess_peer) = pair_for_test(&id_a, &id_b).expect("pair");
    let expected_words: Vec<String> =
        fluxsync_crypto::fingerprint_from_handshake_hash(sess_local.handshake_hash())
            .iter()
            .map(|w| (*w).to_string())
            .collect();
    transport.install_session(peer_id, sess_local).await;
    transport
        .set_peer_info(peer_id, "127.0.0.1:1".parse().unwrap())
        .await;

    let (event_tx, mut event_rx) = mpsc::channel(1024);
    let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
    let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
        &fluxsync_core::Config::default(),
    ));

    let dispatch = |sender: [u8; 32]| {
        let event_tx = event_tx.clone();
        let transport = transport.clone();
        let reassembly = reassembly.clone();
        let trusted = trusted.clone();
        let pending_pairs = pending_pairs.clone();
        let state_rx = state_rx.clone();
        async move {
            dispatch_inbound_frame(
                Frame {
                    version: PROTOCOL_VERSION,
                    msg: Msg::PairVerifyStarted,
                },
                sender,
                &Arc::new(Mutex::new(super::SeenSet::default())),
                &event_tx,
                &transport,
                &reassembly,
                &Arc::new(Mutex::new(MetricsTracker::new())),
                &Arc::new(Mutex::new(HashMap::new())),
                &pending_pairs,
                &trusted,
                &Arc::new(Mutex::new(HashMap::new())),
                &Arc::new(Mutex::new(HashMap::new())),
                &Arc::new(Mutex::new(std::collections::BTreeMap::new())),
                None,
                &Arc::new(Mutex::new(super::Outbox::new())),
                &Arc::new(Mutex::new(HashMap::new())),
                &Arc::new(Mutex::new(HashMap::new())),
                &state_rx,
                &Arc::new(Mutex::new(std::collections::HashSet::new())),
                &Arc::new(Mutex::new(std::collections::HashSet::new())),
                &Arc::new(Mutex::new(HashMap::new())),
            )
            .await;
        }
    };

    // Untrusted sender first: must be ignored outright.
    dispatch(peer_id).await;
    assert!(
        pending_pairs.lock().await.is_empty(),
        "an untrusted PairVerifyStarted must never create a pending pair"
    );
    assert!(
        event_rx.try_recv().is_err(),
        "an untrusted PairVerifyStarted must not fire SasPairingStarted"
    );

    // Trusted sender: pending inserted with the transcript-derived
    // words + SasPairingStarted fired.
    trusted
        .lock()
        .await
        .insert(peer_id, tofu_trusted_peer(peer_id));
    dispatch(peer_id).await;
    {
        let g = pending_pairs.lock().await;
        let p = g
            .get(&peer_id)
            .expect("trusted PairVerifyStarted must insert a pending pair");
        assert_eq!(
            p.sas_words.to_vec(),
            expected_words,
            "pending words must derive from the session's Noise transcript hash"
        );
    }
    assert!(
        matches!(event_rx.try_recv(), Ok(Event::SasPairingStarted { peer_id: p }) if p == peer_id),
        "trusted PairVerifyStarted must fire Event::SasPairingStarted"
    );

    // Duplicate announcement: the existing pending must survive
    // untouched and no second SasPairingStarted may fire.
    let expires_before = pending_pairs.lock().await.get(&peer_id).unwrap().expires_at;
    dispatch(peer_id).await;
    assert_eq!(
        pending_pairs.lock().await.get(&peer_id).unwrap().expires_at,
        expires_before,
        "a duplicate PairVerifyStarted must not reset the pending entry"
    );
    assert!(
        event_rx.try_recv().is_err(),
        "a duplicate PairVerifyStarted must not re-fire SasPairingStarted"
    );
}

/// Inbound `Msg::PairConfirm { accept: false }` is a wire-level reject:
/// same effect as a local reject — pending + trust purged, session
/// dropped — plus `Event::SasPeerRejected` so the UI can say why.
#[tokio::test]
async fn inbound_pair_confirm_reject_revokes_trust_and_emits_peer_rejected() {
    use super::{Event, Reassembly};
    use crate::handshake::tofu_trusted_peer;
    use crate::metrics::MetricsTracker;
    use crate::transport::Transport;
    use fluxsync_proto::{Frame, Msg, PairConfirm, PROTOCOL_VERSION};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::{mpsc, Mutex};

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);
    let peer_id = [9u8; 32];
    transport.set_cached_peer_id(peer_id).await;

    let (event_tx, mut event_rx) = mpsc::channel(1024);
    let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
    trusted
        .lock()
        .await
        .insert(peer_id, tofu_trusted_peer(peer_id));
    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
    pending_pairs.lock().await.insert(
        peer_id,
        test_pending_pair(Instant::now() + Duration::from_secs(60)),
    );
    let deferred: super::DeferredSasConfirm =
        Arc::new(Mutex::new(std::collections::HashSet::new()));
    deferred.lock().await.insert(peer_id);
    let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
        &fluxsync_core::Config::default(),
    ));

    dispatch_inbound_frame(
        Frame {
            version: PROTOCOL_VERSION,
            msg: Msg::PairConfirm(PairConfirm { accept: false }),
        },
        peer_id,
        &Arc::new(Mutex::new(super::SeenSet::default())),
        &event_tx,
        &transport,
        &reassembly,
        &Arc::new(Mutex::new(MetricsTracker::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &pending_pairs,
        &trusted,
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Mutex::new(std::collections::BTreeMap::new())),
        None,
        &Arc::new(Mutex::new(super::Outbox::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &state_rx,
        &deferred,
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(HashMap::new())),
    )
    .await;

    assert!(
        !pending_pairs.lock().await.contains_key(&peer_id),
        "reject must remove the pending entry"
    );
    assert!(
        !trusted.lock().await.contains_key(&peer_id),
        "reject must revoke the sender from the trust store"
    );
    assert!(
        !deferred.lock().await.contains(&peer_id),
        "reject must clear any deferred local accept"
    );
    assert!(
        matches!(event_rx.try_recv(), Ok(Event::SasPeerRejected { peer_id: p }) if p == peer_id),
        "reject must emit Event::SasPeerRejected with the matching peer_id first"
    );
    assert!(
        matches!(event_rx.try_recv(), Ok(Event::PeerLost { peer_id: p }) if p == peer_id),
        "reject must emit Event::PeerLost with the matching peer_id after the teardown"
    );
}

/// L3 fix: an inbound reject from a peer with no pending entry of its
/// own — the "again-trusted peer" case the bug describes — must NOT
/// emit `Event::SasPeerRejected` while a DIFFERENT peer's SAS flow is
/// the one actually live (`State.sas_peer` names someone else). Trust
/// revocation for the stray peer is unconditional and untouched by
/// this fix; only the phase-stomping event is suppressed.
#[tokio::test]
async fn inbound_pair_confirm_reject_from_non_pairing_peer_does_not_emit_sas_event() {
    use super::Reassembly;
    use crate::handshake::tofu_trusted_peer;
    use crate::metrics::MetricsTracker;
    use crate::transport::Transport;
    use fluxsync_proto::{Frame, Msg, PairConfirm, PROTOCOL_VERSION};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);
    let stray_peer = [21u8; 32];
    let other_pairing_peer = [22u8; 32];
    // Cache the OTHER peer as primary, not the stray one, so the
    // reject branch's final `PeerLost` emission is skipped too —
    // isolating this test to just the `SasPeerRejected` guard.
    transport.set_cached_peer_id(other_pairing_peer).await;

    let (event_tx, mut event_rx) = mpsc::channel(1024);
    let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
    trusted
        .lock()
        .await
        .insert(stray_peer, tofu_trusted_peer(stray_peer));
    // No pending entry for `stray_peer` at all.
    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));

    // A DIFFERENT peer's pairing is the one actually live.
    let mut live_state = fluxsync_core::State::initial(&fluxsync_core::Config::default());
    live_state.sas_phase = "showing".to_string();
    live_state.sas_peer = Some(other_pairing_peer);
    let (_state_tx, state_rx) = tokio::sync::watch::channel(live_state);

    dispatch_inbound_frame(
        Frame {
            version: PROTOCOL_VERSION,
            msg: Msg::PairConfirm(PairConfirm { accept: false }),
        },
        stray_peer,
        &Arc::new(Mutex::new(super::SeenSet::default())),
        &event_tx,
        &transport,
        &reassembly,
        &Arc::new(Mutex::new(MetricsTracker::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &pending_pairs,
        &trusted,
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Mutex::new(std::collections::BTreeMap::new())),
        None,
        &Arc::new(Mutex::new(super::Outbox::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &state_rx,
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(HashMap::new())),
    )
    .await;

    // Trust revocation is unconditional and untouched by this fix.
    assert!(
        !trusted.lock().await.contains_key(&stray_peer),
        "an explicit reject still revokes trust regardless of the SAS-flow guard"
    );
    assert!(
        event_rx.try_recv().is_err(),
        "a stray reject outside any live SAS flow for THIS peer must not emit \
         SasPeerRejected — nor anything else, since it isn't cached as primary"
    );
}

// ── resync-1 ─────────────────────────────────────────────────

/// resync-1: hashes we don't hold are returned in the offer's original
/// order, with held hashes (history or outbox) filtered out.
#[test]
fn missing_resync_hashes_filters_held_and_preserves_order() {
    use super::missing_resync_hashes;
    let offered = vec![
        "aa".to_string(),
        "bb".to_string(),
        "cc".to_string(),
        "dd".to_string(),
    ];
    let history = vec!["bb".to_string()];
    let outbox_hashes = vec!["dd".to_string()];
    let missing = missing_resync_hashes(&offered, &history, &outbox_hashes, &[], &[]);
    assert_eq!(missing, vec!["aa".to_string(), "cc".to_string()]);
}

/// resync-1: nothing missing when every offered hash is already held.
#[test]
fn missing_resync_hashes_empty_when_all_held() {
    use super::missing_resync_hashes;
    let offered = vec!["aa".to_string(), "bb".to_string()];
    let history = vec!["aa".to_string()];
    let outbox_hashes = vec!["bb".to_string()];
    assert!(missing_resync_hashes(&offered, &history, &outbox_hashes, &[], &[]).is_empty());
}

/// H2: a deliberately-cleared hash is excluded from the pull list even
/// though the peer still offers it, while a genuinely-missing, never
/// cleared hash is still returned — proves the tombstone gates exactly
/// the cleared hash(es), not resync in general.
#[test]
fn missing_resync_hashes_excludes_cleared_but_keeps_genuinely_missing() {
    use super::missing_resync_hashes;
    let cleared_x = "aa".repeat(32);
    let missing_y = "bb".repeat(32);
    let offered = vec![cleared_x.clone(), missing_y.clone()];
    let missing = missing_resync_hashes(&offered, &[], &[], std::slice::from_ref(&cleared_x), &[]);
    assert_eq!(
        missing,
        vec![missing_y],
        "cleared hash X must be excluded; genuinely-missing hash Y must still be pulled"
    );
}

/// resync-1: defensive cap — even if a caller hands in more than
/// `MAX_RESYNC_HASHES` offered hashes, the result never exceeds it.
#[test]
fn missing_resync_hashes_caps_at_max_resync_hashes() {
    use super::{missing_resync_hashes, MAX_RESYNC_HASHES};
    let offered: Vec<String> = (0..(MAX_RESYNC_HASHES + 5))
        .map(|i| format!("{i:064x}"))
        .collect();
    let missing = missing_resync_hashes(&offered, &[], &[], &[], &[]);
    assert_eq!(missing.len(), MAX_RESYNC_HASHES);
    assert_eq!(
        missing[0], offered[0],
        "must keep the offer's original order"
    );
}

/// resync-1: a `ResyncOffer` hex-encodes each outbox hash, preserving
/// `Outbox::hashes`' (newest-first) order.
#[test]
fn build_resync_offer_hex_encodes_in_given_order() {
    use super::build_resync_offer;
    let h1 = [0x11u8; 32];
    let h2 = [0x22u8; 32];
    let offer = build_resync_offer(&[h1, h2]);
    assert_eq!(offer.hashes, vec![hex::encode(h1), hex::encode(h2)]);
}

/// resync-1: an empty outbox produces an empty offer (the `Msg::Hello`
/// handler is expected to skip sending one in that case).
#[test]
fn build_resync_offer_empty_outbox_yields_empty_offer() {
    use super::build_resync_offer;
    assert!(build_resync_offer(&[]).hashes.is_empty());
}

/// resync-1 security invariant: a sensitive item must never enter the
/// outbox on first-sight reception, while a non-sensitive one does —
/// mirrors the same gate `app.rs` already applies before history
/// insertion (see `crate::outbox`'s module doc).
#[tokio::test]
async fn complete_reassembled_item_gates_outbox_on_sensitivity() {
    use super::Outbox;
    use crate::transport::Transport;
    use fluxsync_core::SeenSet;
    use fluxsync_proto::Kind;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);
    let inflight = Arc::new(Mutex::new(HashMap::new()));
    let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
    let (event_tx, _event_rx) = mpsc::channel(1024);
    let outbox = Arc::new(Mutex::new(Outbox::new()));
    let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
    let outbox_stage = Arc::new(Mutex::new(HashMap::new()));
    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
    // Default (disabled) firewall decides Pass for any non-sensitive
    // item, so this exercises the immediate-insert branch of the
    // Pass/Ask/Block mirror in `complete_reassembled_item`.
    let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
        &fluxsync_core::Config::default(),
    ));

    // SE-14 (Fix D): `complete_reassembled_item` now verifies the claimed
    // hash against the payload before doing anything else, so these must
    // be real `clipboard_dedup_hash` values, not arbitrary constants.
    let sensitive_hash = super::clipboard_dedup_hash("secret");
    complete_reassembled_item(
        &transport,
        &inflight,
        &mesh_seen,
        &event_tx,
        [1u8; 32],
        [2u8; 32],
        1,
        sensitive_hash,
        Kind::Text,
        true,
        0,
        b"secret".to_vec(),
        &outbox,
        &outbox_stage,
        &pending_pulls,
        &state_rx,
        &pending_pairs,
    )
    .await;
    assert!(
        outbox.lock().await.get(sensitive_hash).is_none(),
        "sensitive item must not enter the outbox"
    );

    let plain_hash = super::clipboard_dedup_hash("hello");
    complete_reassembled_item(
        &transport,
        &inflight,
        &mesh_seen,
        &event_tx,
        [1u8; 32],
        [2u8; 32],
        2,
        plain_hash,
        Kind::Text,
        false,
        0,
        b"hello".to_vec(),
        &outbox,
        &outbox_stage,
        &pending_pulls,
        &state_rx,
        &pending_pairs,
    )
    .await;
    assert!(
        outbox.lock().await.get(plain_hash).is_some(),
        "non-sensitive item must enter the outbox"
    );
}

/// DIR-P2-05 sibling of `complete_reassembled_item_gates_outbox_on_sensitivity`:
/// the outbox gate is keyed on `sensitive` alone, not on `Kind` — so a
/// sensitive IMAGE (the new `CmdOp::PushImage { sensitive: true }` path)
/// must be excluded exactly like a sensitive text item, while a
/// non-sensitive image still populates the outbox normally.
#[tokio::test]
async fn complete_reassembled_item_gates_outbox_on_sensitivity_for_images() {
    use super::Outbox;
    use crate::transport::Transport;
    use fluxsync_core::SeenSet;
    use fluxsync_proto::Kind;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);
    let inflight = Arc::new(Mutex::new(HashMap::new()));
    let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
    let (event_tx, _event_rx) = mpsc::channel(1024);
    let outbox = Arc::new(Mutex::new(Outbox::new()));
    let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
    let outbox_stage = Arc::new(Mutex::new(HashMap::new()));
    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
    let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
        &fluxsync_core::Config::default(),
    ));

    // SE-14 (Fix D): `complete_reassembled_item` now verifies an image's
    // claimed hash against its decoded RGBA before anything else, so
    // these need a real (tiny, 1x1) PNG + its matching `image_rgba_hash`
    // instead of arbitrary constants over non-PNG bytes.
    let secret_rgba = vec![10u8, 20, 30, 255];
    let secret_png = super::encode_png(1, 1, secret_rgba.clone()).expect("encode test png");
    let sensitive_hash = super::image_rgba_hash(1, 1, &secret_rgba);
    complete_reassembled_item(
        &transport,
        &inflight,
        &mesh_seen,
        &event_tx,
        [1u8; 32],
        [2u8; 32],
        1,
        sensitive_hash,
        Kind::Image,
        true,
        0,
        secret_png,
        &outbox,
        &outbox_stage,
        &pending_pulls,
        &state_rx,
        &pending_pairs,
    )
    .await;
    assert!(
        outbox.lock().await.get(sensitive_hash).is_none(),
        "sensitive image must not enter the outbox"
    );

    let plain_rgba = vec![40u8, 50, 60, 255];
    let plain_png = super::encode_png(1, 1, plain_rgba.clone()).expect("encode test png");
    let plain_hash = super::image_rgba_hash(1, 1, &plain_rgba);
    complete_reassembled_item(
        &transport,
        &inflight,
        &mesh_seen,
        &event_tx,
        [1u8; 32],
        [2u8; 32],
        2,
        plain_hash,
        Kind::Image,
        false,
        0,
        plain_png,
        &outbox,
        &outbox_stage,
        &pending_pulls,
        &state_rx,
        &pending_pairs,
    )
    .await;
    assert!(
        outbox.lock().await.get(plain_hash).is_some(),
        "non-sensitive image must enter the outbox"
    );
}

/// FIX1 (P0 parked-payload leak), integration point (b): a revoked
/// peer's `PendingOutboxStage` entry — staged by the REAL
/// `complete_reassembled_item` admission-gate path when the firewall
/// parks an inbound item under `Ask` — must be purged by
/// `purge_dropped_pending_from_outbox_stage` once `fluxsync_core`
/// reports it dropped via `Event::PeerRevoked`'s `Action::
/// PendingDropped`. A DIFFERENT peer's staged entry must survive.
///
/// This can't be proven as a daemon-level black-box IPC test: an
/// already-purged pending row and a leaked-but-orphaned
/// `PendingOutboxStage` entry are externally indistinguishable (neither
/// is ever promoted without a live `state.pending` row to approve, and
/// that row is gone in both cases) — the leak is a pure process-memory
/// residency issue. So this drives the exact real functions instead:
/// the daemon's own staging path (`complete_reassembled_item`) plus the
/// core's own revoke path (`App::handle(Event::PeerRevoked)`) plus the
/// daemon's own purge helper, wired together exactly as `run()`'s main
/// loop and `CmdOp::Revoke` do.
#[tokio::test]
async fn revoke_purges_only_that_peers_staged_outbox_entry() {
    use super::{purge_dropped_pending_from_outbox_stage, Outbox};
    use crate::transport::Transport;
    use fluxsync_core::{Action, App, Config, Event, FirewallPolicy, Rule, SeenSet, StubWallClock};
    use fluxsync_proto::Kind;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};

    const PEER_A: [u8; 32] = [0xAAu8; 32];
    const PEER_B: [u8; 32] = [0xBBu8; 32];
    // SE-14 (Fix D): must be the real content hash of each payload below,
    // not arbitrary constants — `complete_reassembled_item` now verifies
    // it before staging anything.
    let hash_a = super::clipboard_dedup_hash("secret-a");
    let hash_b = super::clipboard_dedup_hash("secret-b");

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);
    let inflight = Arc::new(Mutex::new(HashMap::new()));
    let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
    let (event_tx, _event_rx) = mpsc::channel(1024);
    let outbox = Arc::new(Mutex::new(Outbox::new()));
    let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
    let outbox_stage = Arc::new(Mutex::new(HashMap::new()));
    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));

    let firewall = FirewallPolicy {
        enabled: true,
        text: Rule::Ask,
        ..FirewallPolicy::default()
    };
    let (_state_tx, state_rx) =
        tokio::sync::watch::channel(fluxsync_core::State::initial(&Config {
            firewall: firewall.clone(),
            ..Config::default()
        }));

    // Real staging path: both items are Ask-deferred, so both land in
    // `outbox_stage`, neither in the real `outbox`.
    complete_reassembled_item(
        &transport,
        &inflight,
        &mesh_seen,
        &event_tx,
        PEER_A,
        PEER_A,
        1,
        hash_a,
        Kind::Text,
        false,
        0,
        b"secret-a".to_vec(),
        &outbox,
        &outbox_stage,
        &pending_pulls,
        &state_rx,
        &pending_pairs,
    )
    .await;
    complete_reassembled_item(
        &transport,
        &inflight,
        &mesh_seen,
        &event_tx,
        PEER_B,
        PEER_B,
        1,
        hash_b,
        Kind::Text,
        false,
        0,
        b"secret-b".to_vec(),
        &outbox,
        &outbox_stage,
        &pending_pulls,
        &state_rx,
        &pending_pairs,
    )
    .await;
    assert_eq!(
        outbox_stage.lock().await.len(),
        2,
        "precondition: both peers' Ask-deferred items must be staged"
    );
    assert!(
        outbox.lock().await.is_empty(),
        "precondition: neither is admitted to the real outbox yet"
    );

    // Real core-side park: mirrors what the main loop's `app.handle`
    // would have done with the `Event::FrameReceivedClipboard` that
    // `complete_reassembled_item` sent via `event_tx` above.
    let mut app = App::new(Config {
        firewall,
        ..Config::default()
    });
    let wall = StubWallClock::new("12:00", 1_000);
    // Distinct payloads per peer — the core content-dedup ring keys on
    // the PAYLOAD, not the hash param, so two identical payloads here
    // would make the second `handle` call a no-op duplicate and never
    // reach the firewall park at all.
    for (peer_id, hash, text) in [
        (PEER_A, hash_a, "irrelevant-a"),
        (PEER_B, hash_b, "irrelevant-b"),
    ] {
        app.handle(
            Event::FrameReceivedClipboard {
                peer_id,
                hash,
                kind: Kind::Text,
                payload: text.as_bytes().to_vec(),
                preview: text.into(),
                sensitive: false,
                lamport: 1,
                resync: false,
            },
            &wall,
        );
    }
    assert_eq!(app.snapshot().pending.len(), 2, "precondition: both parked");

    // Real revoke path + real purge helper.
    let actions = app.handle(Event::PeerRevoked { peer_id: PEER_A }, &wall);
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::PendingDropped { hashes } if hashes == &[hash_a])),
        "PeerRevoked must report exactly A's dropped hash"
    );
    purge_dropped_pending_from_outbox_stage(&actions, &outbox_stage).await;

    let stage = outbox_stage.lock().await;
    assert!(
        stage.get(&hash_a).is_none(),
        "FIXED: A's revoked staged outbox entry must be purged"
    );
    assert!(
        stage.get(&hash_b).is_some(),
        "B's staged outbox entry must survive A's revoke"
    );
}

/// Item 2 (firewall-enforcing relay): an inbound item the LOCAL firewall
/// Blocks must not reach any OTHER mesh peer either. `forward_frames`
/// used to run unconditionally in `complete_reassembled_item`, ignoring
/// the exact same Pass/Ask/Block decision it had just computed a few
/// lines above for outbox admission. `sensitive` items are deliberately
/// exempt from this gate (ephemeral; the destination must still receive
/// them) — case 3 below proves that invariant survives the fix.
#[tokio::test]
async fn complete_reassembled_item_does_not_relay_a_firewall_blocked_item() {
    use super::Outbox;
    use crate::transport::Transport;
    use fluxsync_core::{Config, FirewallPolicy, Rule, SeenSet};
    use fluxsync_crypto::{test_util::pair_for_test, Identity};
    use fluxsync_proto::Kind;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};

    const SOURCE: [u8; 32] = [0x11u8; 32]; // direct sender, also origin here

    let self_id = Identity::generate();
    let downstream_id = Identity::generate();
    let downstream_peer = downstream_id.peer_id();
    let (sess_downstream, _) = pair_for_test(&self_id, &downstream_id).expect("pair downstream");

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);
    // A second mesh peer with a live session — the relay TARGET that
    // must NOT receive a firewall-Blocked item.
    transport
        .install_session(downstream_peer, sess_downstream)
        .await;

    let inflight = Arc::new(Mutex::new(HashMap::new()));
    let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
    let (event_tx, _event_rx) = mpsc::channel(1024);
    let outbox = Arc::new(Mutex::new(Outbox::new()));
    let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
    let outbox_stage = Arc::new(Mutex::new(HashMap::new()));
    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));

    // ── 1. Blocked (non-sensitive text): must NOT relay downstream. ──
    let block_firewall = FirewallPolicy {
        enabled: true,
        text: Rule::Deny,
        ..FirewallPolicy::default()
    };
    let (_tx1, state_rx1) = tokio::sync::watch::channel(fluxsync_core::State::initial(&Config {
        firewall: block_firewall,
        ..Config::default()
    }));
    let hash_blocked = super::clipboard_dedup_hash("relay-blocked-text");
    complete_reassembled_item(
        &transport,
        &inflight,
        &mesh_seen,
        &event_tx,
        SOURCE,
        SOURCE,
        1,
        hash_blocked,
        Kind::Text,
        false,
        0,
        b"relay-blocked-text".to_vec(),
        &outbox,
        &outbox_stage,
        &pending_pulls,
        &state_rx1,
        &pending_pairs,
    )
    .await;
    assert!(
        inflight.lock().await.get(&hash_blocked).is_none(),
        "FIXED: a firewall-Blocked item must NOT be relayed to another mesh peer"
    );

    // ── 2. control: Allow (Pass) — must relay downstream. ──
    let pass_firewall = FirewallPolicy {
        enabled: true,
        text: Rule::Allow,
        ..FirewallPolicy::default()
    };
    let (_tx2, state_rx2) = tokio::sync::watch::channel(fluxsync_core::State::initial(&Config {
        firewall: pass_firewall,
        ..Config::default()
    }));
    let hash_passed = super::clipboard_dedup_hash("relay-passed-text");
    complete_reassembled_item(
        &transport,
        &inflight,
        &mesh_seen,
        &event_tx,
        SOURCE,
        SOURCE,
        2,
        hash_passed,
        Kind::Text,
        false,
        0,
        b"relay-passed-text".to_vec(),
        &outbox,
        &outbox_stage,
        &pending_pulls,
        &state_rx2,
        &pending_pairs,
    )
    .await;
    assert!(
        inflight
            .lock()
            .await
            .get(&hash_passed)
            .is_some_and(|inf| inf.pending_peers.contains(&downstream_peer)),
        "control: a firewall-Passed item must still relay to the other mesh peer"
    );

    // ── 3. CRITICAL INVARIANT: sensitive items always relay, even under
    //        a Blocking firewall (they're ephemeral; the destination
    //        must still receive them — never gated by content policy). ──
    let hash_sensitive = super::clipboard_dedup_hash("relay-sensitive-secret");
    complete_reassembled_item(
        &transport,
        &inflight,
        &mesh_seen,
        &event_tx,
        SOURCE,
        SOURCE,
        3,
        hash_sensitive,
        Kind::Text,
        true,
        0,
        b"relay-sensitive-secret".to_vec(),
        &outbox,
        &outbox_stage,
        &pending_pulls,
        &state_rx1,
        &pending_pairs,
    )
    .await;
    assert!(
        inflight
            .lock()
            .await
            .get(&hash_sensitive)
            .is_some_and(|inf| inf.pending_peers.contains(&downstream_peer)),
        "CRITICAL INVARIANT: a sensitive item must still relay even under a Blocking firewall"
    );
}

/// resync-1: the common case — a small clipboard item arrives as a
/// single `ClipboardItem` frame (payload non-empty) and never touches
/// `complete_reassembled_item`, which only runs for chunked/reassembled
/// transfers. This path must independently populate the outbox on
/// first sight, gated on sensitivity the same way.
#[tokio::test]
async fn dispatch_inbound_frame_single_frame_item_populates_outbox_when_not_sensitive() {
    use super::{Outbox, Reassembly};
    use crate::metrics::MetricsTracker;
    use crate::transport::Transport;
    use fluxsync_core::SeenSet;
    use fluxsync_proto::{ClipboardItem, Frame, Kind, Msg, PROTOCOL_VERSION};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);
    let peer_id = [9u8; 32];
    let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
    let (event_tx, _event_rx) = mpsc::channel(1024);
    let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let metrics = Arc::new(Mutex::new(MetricsTracker::new()));
    let inflight = Arc::new(Mutex::new(HashMap::new()));
    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
    // The hardened FS-052 gate drops clipboard frames from a peer that
    // is not in `trusted`; this test targets the outbox population
    // downstream of it, so the sender must be trusted.
    let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
    trusted
        .lock()
        .await
        .insert(peer_id, crate::handshake::tofu_trusted_peer(peer_id));
    let disc_cache = Arc::new(Mutex::new(HashMap::new()));
    let backoff = Arc::new(Mutex::new(HashMap::new()));
    let peer_meta = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    let outbox = Arc::new(Mutex::new(Outbox::new()));
    let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
    let outbox_stage = Arc::new(Mutex::new(HashMap::new()));
    let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
        &fluxsync_core::Config::default(),
    ));

    // SE-14 (Fix D): must be the real content hash of the payload below —
    // `dispatch_inbound_frame` now verifies it before touching the outbox.
    let hash = super::clipboard_dedup_hash("hello resync");
    let item = ClipboardItem {
        lamport: 1,
        hash,
        kind: Kind::Text,
        payload: b"hello resync".to_vec(),
        sensitive: false,
        wall_time_ms: 0,
        origin: [3u8; 32],
        event_seq: 5,
    };
    dispatch_inbound_frame(
        Frame {
            version: PROTOCOL_VERSION,
            msg: Msg::ClipboardItem(item),
        },
        peer_id,
        &mesh_seen,
        &event_tx,
        &transport,
        &reassembly,
        &metrics,
        &inflight,
        &pending_pairs,
        &trusted,
        &disc_cache,
        &backoff,
        &peer_meta,
        None,
        &outbox,
        &pending_pulls,
        &outbox_stage,
        &state_rx,
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(HashMap::new())),
    )
    .await;

    let entry = outbox
        .lock()
        .await
        .get(hash)
        .cloned()
        .expect("non-sensitive single-frame item must populate the outbox");
    assert_eq!(entry.origin, [3u8; 32]);
    assert_eq!(entry.seq, 5);
    assert_eq!(entry.payload, b"hello resync");
}

/// Item 2 (firewall-enforcing relay), single-frame `ClipboardItem` site:
/// the sibling gate to `complete_reassembled_item_does_not_relay_a_
/// firewall_blocked_item` above, but for the path most clipboard items
/// actually take (small enough to arrive as one frame, never touching
/// `complete_reassembled_item`). `forward_item` used to run
/// unconditionally here too.
#[tokio::test]
async fn dispatch_inbound_frame_single_frame_item_does_not_relay_when_firewall_blocks() {
    use super::{Outbox, Reassembly};
    use crate::metrics::MetricsTracker;
    use crate::transport::Transport;
    use fluxsync_core::{Config, FirewallPolicy, Rule, SeenSet};
    use fluxsync_crypto::{test_util::pair_for_test, Identity};
    use fluxsync_proto::{ClipboardItem, Frame, Kind, Msg, PROTOCOL_VERSION};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};

    let sender_id = Identity::generate();
    let downstream_id = Identity::generate();
    let peer_id = sender_id.peer_id();
    let downstream_peer = downstream_id.peer_id();
    let (sess_downstream, _) = pair_for_test(&sender_id, &downstream_id).expect("pair downstream");

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);
    // A second mesh peer with a live session — the relay TARGET that
    // must NOT receive a firewall-Blocked item.
    transport
        .install_session(downstream_peer, sess_downstream)
        .await;

    let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
    let (event_tx, _event_rx) = mpsc::channel(1024);
    let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let metrics = Arc::new(Mutex::new(MetricsTracker::new()));
    let inflight = Arc::new(Mutex::new(HashMap::new()));
    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
    let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
    trusted
        .lock()
        .await
        .insert(peer_id, crate::handshake::tofu_trusted_peer(peer_id));
    let disc_cache = Arc::new(Mutex::new(HashMap::new()));
    let backoff = Arc::new(Mutex::new(HashMap::new()));
    let peer_meta = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    let outbox = Arc::new(Mutex::new(Outbox::new()));
    let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
    let outbox_stage = Arc::new(Mutex::new(HashMap::new()));

    let block_firewall = FirewallPolicy {
        enabled: true,
        text: Rule::Deny,
        ..FirewallPolicy::default()
    };
    let (_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(&Config {
        firewall: block_firewall,
        ..Config::default()
    }));

    let hash = super::clipboard_dedup_hash("single-frame-relay-blocked");
    let item = ClipboardItem {
        lamport: 1,
        hash,
        kind: Kind::Text,
        payload: b"single-frame-relay-blocked".to_vec(),
        sensitive: false,
        wall_time_ms: 0,
        origin: peer_id,
        event_seq: 7,
    };
    dispatch_inbound_frame(
        Frame {
            version: PROTOCOL_VERSION,
            msg: Msg::ClipboardItem(item),
        },
        peer_id,
        &mesh_seen,
        &event_tx,
        &transport,
        &reassembly,
        &metrics,
        &inflight,
        &pending_pairs,
        &trusted,
        &disc_cache,
        &backoff,
        &peer_meta,
        None,
        &outbox,
        &pending_pulls,
        &outbox_stage,
        &state_rx,
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(HashMap::new())),
    )
    .await;

    assert!(
        outbox.lock().await.get(hash).is_none(),
        "precondition: a firewall-Blocked item must not enter this node's own outbox"
    );
    assert!(
        inflight.lock().await.get(&hash).is_none(),
        "FIXED: a firewall-Blocked single-frame item must NOT be relayed to another mesh peer"
    );
}

// ── Phase 5 round 3 regressions ─────────────────────────────

/// FS-052 egress hole fix (Fix A, part 1): `Action::SendItem`'s fan-out
/// used to send to every `transport.linked_peer_ids()` peer regardless
/// of pending status — `gate_outbound` only suppresses the whole action
/// when the PRIMARY peer is pending. A pending SECONDARY mesh peer with
/// a live session must now be excluded from both the wire send and the
/// `Inflight::pending_peers` ack-tracking set.
#[tokio::test]
async fn send_item_fan_out_excludes_pending_secondary_peer() {
    use super::Outbox;
    use crate::transport::Transport;
    use fluxsync_core::{Action, App, Config};
    use fluxsync_crypto::{test_util::pair_for_test, Identity};
    use fluxsync_proto::Kind;
    use std::collections::{BTreeMap, HashMap, VecDeque};
    use std::sync::Arc;
    use tokio::sync::{broadcast, watch, Mutex};

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);

    let self_id = Identity::generate();
    let confirmed_id = Identity::generate();
    let pending_id = Identity::generate();
    let confirmed_peer = confirmed_id.peer_id();
    let pending_peer = pending_id.peer_id();

    let (sess_confirmed, _) = pair_for_test(&self_id, &confirmed_id).expect("pair confirmed");
    let (sess_pending, _) = pair_for_test(&self_id, &pending_id).expect("pair pending");
    // First install claims the primary slot, the second lands in `extra`
    // — both then show up in `linked_peer_ids()` (FluxMesh 2C-b).
    transport
        .install_session(confirmed_peer, sess_confirmed)
        .await;
    transport.install_session(pending_peer, sess_pending).await;
    assert_eq!(
        transport.linked_peer_ids().await.len(),
        2,
        "precondition: two live sessions"
    );

    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
    pending_pairs.lock().await.insert(
        pending_peer,
        test_pending_pair(std::time::Instant::now() + std::time::Duration::from_secs(60)),
    );

    let mut app = App::new(Config::default());
    let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
    let (state_watch_tx, _state_watch_rx) =
        watch::channel(fluxsync_core::State::initial(&Config::default()));
    let (logs_bcast_tx, _logs_rx) = broadcast::channel(16);
    let log_tail = Arc::new(super::LogTail::new());
    let last_written_hashes = Arc::new(Mutex::new(VecDeque::new()));
    let metrics = Arc::new(Mutex::new(crate::metrics::MetricsTracker::new()));
    let inflight = Arc::new(Mutex::new(HashMap::new()));
    let peer_meta: super::PeerMetaMap = Arc::new(Mutex::new(BTreeMap::new()));
    let outbox = Arc::new(Mutex::new(Outbox::new()));
    let mut seq_store: Option<crate::seq_store::SeqStore> = None;

    let hash = super::clipboard_dedup_hash("mesh secret");
    let actions = vec![Action::SendItem {
        hash,
        kind: Kind::Text,
        payload: b"mesh secret".to_vec(),
        sensitive: false,
    }];

    dispatch(
        actions,
        &mut app,
        &transport,
        &trusted,
        None,
        &state_watch_tx,
        &logs_bcast_tx,
        &log_tail,
        &last_written_hashes,
        &metrics,
        &inflight,
        &peer_meta,
        &outbox,
        &pending_pairs,
        &mut seq_store,
    )
    .await;

    let inf = inflight.lock().await;
    let entry = inf
        .get(&hash)
        .expect("item must still be inflight for the confirmed peer");
    assert!(
        entry.pending_peers.contains(&confirmed_peer),
        "the confirmed peer must be awaited for an ack"
    );
    assert!(
        !entry.pending_peers.contains(&pending_peer),
        "FS-052: an unconfirmed pending peer must NOT be in the SendItem fan-out"
    );
}

/// Sibling of `send_item_fan_out_excludes_pending_secondary_peer` for the
/// MESH RELAY path (`forward_frames`/`forward_item`, driven by an inbound
/// `Msg::ClipboardItem` from a third peer) rather than the local-origin
/// `Action::SendItem` path. Before the fix, `forward_frames` computed its
/// targets as `linked_peer_ids().filter(|d| *d != source && *d != origin)`
/// with no `pending_pairs` check at all, so a confirmed peer's relayed
/// clipboard reached any linked-but-unconfirmed TOFU secondary — bypassing
/// the FS-052 confirmation gate entirely.
#[tokio::test]
async fn mesh_relay_excludes_pending_secondary_peer() {
    use super::{Outbox, Reassembly};
    use crate::handshake::tofu_trusted_peer;
    use crate::metrics::MetricsTracker;
    use crate::transport::Transport;
    use fluxsync_core::SeenSet;
    use fluxsync_crypto::{test_util::pair_for_test, Identity};
    use fluxsync_proto::{ClipboardItem, Frame, Kind, Msg, PROTOCOL_VERSION};
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);

    let self_id = Identity::generate();
    let source_id = Identity::generate();
    let confirmed_id = Identity::generate();
    let pending_id = Identity::generate();
    let source_peer = source_id.peer_id();
    let confirmed_peer = confirmed_id.peer_id();
    let pending_peer = pending_id.peer_id();

    let (sess_confirmed, _) = pair_for_test(&self_id, &confirmed_id).expect("pair confirmed");
    let (sess_pending, _) = pair_for_test(&self_id, &pending_id).expect("pair pending");
    // First install claims the primary slot, the second lands in `extra`
    // (FluxMesh 2C-b) — both are candidate mesh-relay targets for an item
    // whose sender is a THIRD peer (`source_peer`). The source itself is
    // deliberately never installed with a session: `forward_item`'s
    // targets come from `linked_peer_ids()`, and `ack_source`/relay both
    // tolerate a sourceless send failing silently.
    transport
        .install_session(confirmed_peer, sess_confirmed)
        .await;
    transport.install_session(pending_peer, sess_pending).await;

    let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
    trusted
        .lock()
        .await
        .insert(source_peer, tofu_trusted_peer(source_peer));

    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
    pending_pairs.lock().await.insert(
        pending_peer,
        test_pending_pair(std::time::Instant::now() + std::time::Duration::from_secs(60)),
    );

    let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
    let (event_tx, _event_rx) = mpsc::channel(1024);
    let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let metrics = Arc::new(Mutex::new(MetricsTracker::new()));
    let inflight = Arc::new(Mutex::new(HashMap::new()));
    let disc_cache = Arc::new(Mutex::new(HashMap::new()));
    let backoff = Arc::new(Mutex::new(HashMap::new()));
    let peer_meta = Arc::new(Mutex::new(BTreeMap::new()));
    let outbox = Arc::new(Mutex::new(Outbox::new()));
    let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
    let outbox_stage = Arc::new(Mutex::new(HashMap::new()));
    let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
        &fluxsync_core::Config::default(),
    ));

    let hash = super::clipboard_dedup_hash("mesh relay secret");
    let item = ClipboardItem {
        lamport: 1,
        hash,
        kind: Kind::Text,
        payload: b"mesh relay secret".to_vec(),
        sensitive: false,
        wall_time_ms: 0,
        origin: source_peer,
        event_seq: 1,
    };

    dispatch_inbound_frame(
        Frame {
            version: PROTOCOL_VERSION,
            msg: Msg::ClipboardItem(item),
        },
        source_peer,
        &mesh_seen,
        &event_tx,
        &transport,
        &reassembly,
        &metrics,
        &inflight,
        &pending_pairs,
        &trusted,
        &disc_cache,
        &backoff,
        &peer_meta,
        None,
        &outbox,
        &pending_pulls,
        &outbox_stage,
        &state_rx,
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(HashMap::new())),
    )
    .await;

    let inf = inflight.lock().await;
    let entry = inf
        .get(&hash)
        .expect("relayed item must be inflight for the confirmed secondary");
    assert!(
        entry.pending_peers.contains(&confirmed_peer),
        "the confirmed secondary must receive the mesh relay"
    );
    assert!(
        !entry.pending_peers.contains(&pending_peer),
        "FS-052 mesh-relay hole: an unconfirmed pending secondary must NOT receive the relayed clipboard item"
    );
}

/// Inflight merge fix (Fix B): a `ResyncPull` serve used to blindly
/// `insert` into `inflight`, REPLACING any entry already tracking OTHER
/// peers still awaiting an ack for the same hash (from a concurrent live
/// `SendItem`/`forward_frames` fan-out) — silently dropping them from
/// `pending_peers` so they'd never get a retransmit. The serve must
/// instead merge: keep the pre-existing peer, add the puller.
#[tokio::test]
async fn resync_pull_serve_merges_inflight_pending_peers_instead_of_replacing() {
    use super::{Inflight, Outbox, PeerMeta, Reassembly};
    use crate::metrics::MetricsTracker;
    use crate::outbox::Entry as OutboxEntry;
    use crate::transport::Transport;
    use fluxsync_core::SeenSet;
    use fluxsync_crypto::{test_util::pair_for_test, Identity};
    use fluxsync_proto::{Frame, Kind, Msg, ResyncPull, PROTOCOL_VERSION};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::{mpsc, Mutex};

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);

    let self_id = Identity::generate();
    let puller_id = Identity::generate();
    let puller = puller_id.peer_id();
    let (sess_self_puller, _) = pair_for_test(&self_id, &puller_id).expect("pair puller");
    transport.install_session(puller, sess_self_puller).await;

    let peer_meta: super::PeerMetaMap = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    let mut pm = PeerMeta::new();
    pm.caps = vec!["resync-1".to_string()];
    peer_meta.lock().await.insert(puller, pm);

    let hash = super::clipboard_dedup_hash("resync-merge-item");
    let outbox = Arc::new(Mutex::new(Outbox::new()));
    outbox.lock().await.insert(
        hash,
        OutboxEntry {
            payload: b"resync-merge-item".to_vec(),
            kind: Kind::Text,
            origin: [9u8; 32],
            seq: 1,
            created: Instant::now(),
        },
    );

    // A DIFFERENT peer is already awaiting an ack for this same hash —
    // as if from a concurrent live SendItem/forward_frames fan-out.
    let other_peer = [0x55u8; 32];
    let inflight = Arc::new(Mutex::new(HashMap::new()));
    inflight.lock().await.insert(
        hash,
        Inflight {
            frames: vec![vec![1, 2, 3]],
            attempts: 2,
            last_sent: Instant::now()
                .checked_sub(std::time::Duration::from_secs(5))
                .unwrap(),
            first_sent: Instant::now()
                .checked_sub(std::time::Duration::from_secs(5))
                .unwrap(),
            pending_peers: std::iter::once(other_peer).collect(),
        },
    );

    let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
    let (event_tx, _event_rx) = mpsc::channel(1024);
    let metrics = Arc::new(Mutex::new(MetricsTracker::new()));
    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
    // The hardened FS-052 gate drops ResyncPull from a peer that is not
    // in `trusted`; this test targets the inflight-merge behavior
    // downstream of it, so the puller must be trusted.
    let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
    trusted
        .lock()
        .await
        .insert(puller, crate::handshake::tofu_trusted_peer(puller));
    let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
    let outbox_stage = Arc::new(Mutex::new(HashMap::new()));
    let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
        &fluxsync_core::Config::default(),
    ));

    dispatch_inbound_frame(
        Frame {
            version: PROTOCOL_VERSION,
            msg: Msg::ResyncPull(ResyncPull {
                hashes: vec![hex::encode(hash)],
            }),
        },
        puller,
        &mesh_seen,
        &event_tx,
        &transport,
        &reassembly,
        &metrics,
        &inflight,
        &pending_pairs,
        &trusted,
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &peer_meta,
        None,
        &outbox,
        &pending_pulls,
        &outbox_stage,
        &state_rx,
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(HashMap::new())),
    )
    .await;

    let inf = inflight.lock().await;
    let entry = inf.get(&hash).expect("hash must still be tracked inflight");
    assert!(
        entry.pending_peers.contains(&other_peer),
        "FIX B: the pre-existing peer must survive the ResyncPull serve's \
         inflight update, not be clobbered by a blind insert"
    );
    assert!(
        entry.pending_peers.contains(&puller),
        "the new puller must be folded into pending_peers too"
    );
}

/// Resync serve firewall gate (Fix C): an item cached in the outbox
/// before a policy tightened to Block afterward must not be re-served
/// via `ResyncPull` — the live firewall must be re-checked at serve
/// time, not just at admission time.
#[tokio::test]
async fn resync_pull_serve_skips_entries_blocked_by_live_firewall() {
    use super::{Outbox, PeerMeta, Reassembly};
    use crate::metrics::MetricsTracker;
    use crate::outbox::Entry as OutboxEntry;
    use crate::transport::Transport;
    use fluxsync_core::{Config, FirewallPolicy, Rule, SeenSet};
    use fluxsync_crypto::{test_util::pair_for_test, Identity};
    use fluxsync_proto::{Frame, Kind, Msg, ResyncPull, PROTOCOL_VERSION};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::{mpsc, Mutex};

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);

    let self_id = Identity::generate();
    let puller_id = Identity::generate();
    let puller = puller_id.peer_id();
    let (sess_self_puller, _) = pair_for_test(&self_id, &puller_id).expect("pair puller");
    transport.install_session(puller, sess_self_puller).await;

    let peer_meta: super::PeerMetaMap = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    let mut pm = PeerMeta::new();
    pm.caps = vec!["resync-1".to_string()];
    peer_meta.lock().await.insert(puller, pm);

    let hash = super::clipboard_dedup_hash("now-blocked-item");
    let outbox = Arc::new(Mutex::new(Outbox::new()));
    outbox.lock().await.insert(
        hash,
        OutboxEntry {
            payload: b"now-blocked-item".to_vec(),
            kind: Kind::Text,
            origin: [9u8; 32],
            seq: 1,
            created: Instant::now(),
        },
    );

    // The item was cached before the policy tightened; the LIVE
    // firewall now denies text outright.
    let firewall = FirewallPolicy {
        enabled: true,
        text: Rule::Deny,
        ..FirewallPolicy::default()
    };
    let (_state_tx, state_rx) =
        tokio::sync::watch::channel(fluxsync_core::State::initial(&Config {
            firewall,
            ..Config::default()
        }));

    let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
    let (event_tx, _event_rx) = mpsc::channel(1024);
    let metrics = Arc::new(Mutex::new(MetricsTracker::new()));
    let inflight = Arc::new(Mutex::new(HashMap::new()));
    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
    // The puller must be trusted so this ResyncPull passes the hardened
    // FS-052 gate — otherwise the serve would be skipped by the trust
    // check and the FIREWALL skip below would never be exercised.
    let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
    trusted
        .lock()
        .await
        .insert(puller, crate::handshake::tofu_trusted_peer(puller));
    let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
    let outbox_stage = Arc::new(Mutex::new(HashMap::new()));

    dispatch_inbound_frame(
        Frame {
            version: PROTOCOL_VERSION,
            msg: Msg::ResyncPull(ResyncPull {
                hashes: vec![hex::encode(hash)],
            }),
        },
        puller,
        &mesh_seen,
        &event_tx,
        &transport,
        &reassembly,
        &metrics,
        &inflight,
        &pending_pairs,
        &trusted,
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &peer_meta,
        None,
        &outbox,
        &pending_pulls,
        &outbox_stage,
        &state_rx,
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(HashMap::new())),
    )
    .await;

    assert!(
        inflight.lock().await.get(&hash).is_none(),
        "FIX C: an outbox entry the LIVE firewall now blocks must not be \
         re-served via ResyncPull"
    );
    assert_eq!(
        metrics.lock().await.snapshot().items_resynced,
        0,
        "a firewall-blocked entry must not count as resynced"
    );
}

/// SE-14 defense in depth (Fix D): `dispatch_inbound_frame` must verify
/// a `ClipboardItem`'s claimed hash against its payload before trusting
/// it. Honest text and image pushes (real sender-side hashes) must still
/// be accepted; a frame whose claimed hash does not match its payload
/// must be dropped before it ever reaches the outbox.
#[tokio::test]
async fn se14_verify_content_hash_gates_clipboard_item_ingestion() {
    use super::{Outbox, Reassembly};
    use crate::metrics::MetricsTracker;
    use crate::transport::Transport;
    use fluxsync_core::SeenSet;
    use fluxsync_proto::{ClipboardItem, Frame, Kind, Msg, PROTOCOL_VERSION};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};

    async fn dispatch_one(
        transport: &Arc<Transport>,
        peer_id: [u8; 32],
        item: ClipboardItem,
    ) -> super::SharedOutbox {
        let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
        let (event_tx, _event_rx) = mpsc::channel(1024);
        let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let metrics = Arc::new(Mutex::new(MetricsTracker::new()));
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
        // The hardened FS-052 gate drops clipboard frames from a peer
        // that is not in `trusted`; this test targets the SE-14 hash
        // check downstream of it, so the sender must be trusted.
        let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
        trusted
            .lock()
            .await
            .insert(peer_id, crate::handshake::tofu_trusted_peer(peer_id));
        let peer_meta: super::PeerMetaMap = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
        let outbox = Arc::new(Mutex::new(Outbox::new()));
        let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
        let outbox_stage = Arc::new(Mutex::new(HashMap::new()));
        let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
            &fluxsync_core::Config::default(),
        ));

        dispatch_inbound_frame(
            Frame {
                version: PROTOCOL_VERSION,
                msg: Msg::ClipboardItem(item),
            },
            peer_id,
            &mesh_seen,
            &event_tx,
            transport,
            &reassembly,
            &metrics,
            &inflight,
            &pending_pairs,
            &trusted,
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &peer_meta,
            None,
            &outbox,
            &pending_pulls,
            &outbox_stage,
            &state_rx,
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .await;
        outbox
    }

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);
    let peer_id = [0x21u8; 32];

    // Honest text: real sender-side hash, must be accepted.
    let honest_text_hash = super::clipboard_dedup_hash("legit text push");
    let outbox = dispatch_one(
        &transport,
        peer_id,
        ClipboardItem {
            lamport: 1,
            hash: honest_text_hash,
            kind: Kind::Text,
            payload: b"legit text push".to_vec(),
            sensitive: false,
            wall_time_ms: 0,
            origin: [1u8; 32],
            event_seq: 1,
        },
    )
    .await;
    assert!(
        outbox.lock().await.get(honest_text_hash).is_some(),
        "an honest text item (real hash) must be accepted"
    );

    // Honest image: real PNG + matching sender-side `image_rgba_hash`.
    let rgba = vec![1u8, 2, 3, 255];
    let png = super::encode_png(1, 1, rgba.clone()).expect("encode test png");
    let honest_image_hash = super::image_rgba_hash(1, 1, &rgba);
    let outbox = dispatch_one(
        &transport,
        peer_id,
        ClipboardItem {
            lamport: 1,
            hash: honest_image_hash,
            kind: Kind::Image,
            payload: png,
            sensitive: false,
            wall_time_ms: 0,
            origin: [1u8; 32],
            event_seq: 2,
        },
    )
    .await;
    assert!(
        outbox.lock().await.get(honest_image_hash).is_some(),
        "an honest image item (real hash) must be accepted"
    );

    // Forged: claimed hash does not match the payload — must be dropped
    // before ever touching the outbox.
    let forged_hash = [0xEEu8; 32];
    let outbox = dispatch_one(
        &transport,
        peer_id,
        ClipboardItem {
            lamport: 1,
            hash: forged_hash,
            kind: Kind::Text,
            payload: b"attacker-controlled bytes".to_vec(),
            sensitive: false,
            wall_time_ms: 0,
            origin: [1u8; 32],
            event_seq: 3,
        },
    )
    .await;
    assert!(
        outbox.lock().await.get(forged_hash).is_none(),
        "SE-14: a forged hash/payload pair must be dropped, never cached"
    );
}

/// `read_line_capped`'s bound is on the total line length AS READ FROM
/// THE WIRE, delimiter included (`bytes.len() + take > max` — the check
/// counts the newline). So a line whose content+`\n` together total
/// exactly `MAX_IPC_LINE` bytes is the largest accepted line, and one
/// byte more (content of `MAX_IPC_LINE` bytes, i.e. one longer, plus the
/// same trailing `\n`) is the smallest rejected one.
#[tokio::test]
async fn read_line_capped_accepts_exactly_the_cap() {
    use super::{read_line_capped, MAX_IPC_LINE};

    // Content is MAX_IPC_LINE - 1 bytes so content + '\n' == MAX_IPC_LINE.
    let mut data = vec![b'a'; MAX_IPC_LINE - 1];
    data.push(b'\n');
    let mut reader = tokio::io::BufReader::new(data.as_slice());
    let mut out = String::new();

    let n = read_line_capped(&mut reader, &mut out, MAX_IPC_LINE)
        .await
        .expect("a line totalling exactly MAX_IPC_LINE bytes must be accepted");

    assert_eq!(
        n, MAX_IPC_LINE,
        "accepted line must report its full byte count"
    );
    assert_eq!(out.len(), MAX_IPC_LINE);
}

/// One byte over the cap must be rejected with `InvalidData`, and the
/// caller's connection-teardown contract holds: `read_line_capped` never
/// returns a truncated `Ok` for an over-cap line. `handle_ipc_client`
/// propagates the `Err` via `?` and drops the connection on it, so a
/// caller must never be able to mistake a partial write into `out` for a
/// valid (if truncated) line — this asserts `out` is left untouched.
#[tokio::test]
async fn read_line_capped_rejects_one_byte_over_the_cap() {
    use super::{read_line_capped, MAX_IPC_LINE};

    // Content is MAX_IPC_LINE bytes so content + '\n' == MAX_IPC_LINE + 1.
    let mut data = vec![b'a'; MAX_IPC_LINE];
    data.push(b'\n');
    let mut reader = tokio::io::BufReader::new(data.as_slice());
    let mut out = String::new();

    let err = read_line_capped(&mut reader, &mut out, MAX_IPC_LINE)
        .await
        .expect_err("a line totalling MAX_IPC_LINE + 1 bytes must be rejected");

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        out.is_empty(),
        "on error, read_line_capped must never have written a truncated line into `out`"
    );
}

/// Bug #2 (NAK is born dead): the selective-NAK tick used to build
/// `Nak.item_id` from `reassembly`'s HashMap key — `reassembly_key
/// (source, item_hash)`, a composite BLAKE3 digest — which the sender's
/// `inflight` (keyed by the REAL content hash) can never match, and sent
/// it over the primary link instead of to the transfer's actual sender.
/// `build_pending_naks` must use `Reassembly::item_hash` /
/// `Reassembly::source` instead of the map key.
#[test]
fn build_pending_naks_uses_real_hash_and_true_sender_not_composite_key() {
    use super::{build_pending_naks, reassembly_key, Reassembly};
    use fluxsync_proto::Kind;
    use std::collections::HashMap;
    use std::time::Instant;

    let source = [7u8; 32];
    let item_hash = [9u8; 32];
    let key = reassembly_key(source, item_hash);
    let mut map: HashMap<[u8; 32], Reassembly> = HashMap::new();
    map.insert(
        key,
        Reassembly {
            metadata: Some((1, Kind::Text, false)),
            origin: [1u8; 32],
            event_seq: 1,
            chunks: vec![Some(vec![1]), None],
            last_update: Instant::now(),
            first_seen: Instant::now(),
            source,
            item_hash,
        },
    );

    let naks = build_pending_naks(&map);
    assert_eq!(
        naks.len(),
        1,
        "one incomplete chunked transfer must produce one NAK"
    );
    let (dest, nak) = &naks[0];
    assert_eq!(
        *dest, source,
        "the NAK must be routed to the transfer's actual sender, not the primary link"
    );
    assert_eq!(
        nak.item_id, item_hash,
        "the NAK must carry the real content hash, not the composite reassembly-map key"
    );
    assert_eq!(
        nak.missing,
        vec![1],
        "the NAK must list the still-missing chunk index"
    );
}

/// Bug #3 (inflight blind-insert clobber): `forward_frames` used to
/// blindly `insert` into `inflight`, REPLACING any entry a concurrent
/// relay or local `Action::SendItem` already created for the same hash —
/// silently dropping whichever peers that earlier entry was still
/// awaiting an ack from. Sibling of the already-fixed ResyncPull-serve
/// merge (`resync_pull_serve_merges_inflight_pending_peers_instead_of_replacing`).
#[tokio::test]
async fn forward_frames_merges_inflight_pending_peers_instead_of_replacing() {
    use super::{forward_frames, Inflight};
    use crate::transport::Transport;
    use fluxsync_crypto::{test_util::pair_for_test, Identity};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::Mutex;

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);

    let self_id = Identity::generate();
    let source_id = Identity::generate();
    let origin_id = Identity::generate();
    let new_id = Identity::generate();
    let source = source_id.peer_id();
    let origin = origin_id.peer_id();
    let new_peer = new_id.peer_id();
    let (sess_new, _) = pair_for_test(&self_id, &new_id).expect("pair new");
    transport.install_session(new_peer, sess_new).await;

    let hash = [0x33u8; 32];
    let existing_peer = [0x44u8; 32];
    let inflight = Arc::new(Mutex::new(HashMap::new()));
    inflight.lock().await.insert(
        hash,
        Inflight {
            frames: vec![vec![0u8; 1]],
            attempts: 0,
            last_sent: Instant::now(),
            first_sent: Instant::now(),
            pending_peers: std::iter::once(existing_peer).collect(),
        },
    );

    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));

    forward_frames(
        &transport,
        &inflight,
        &pending_pairs,
        source,
        origin,
        hash,
        vec![vec![9u8; 1]],
    )
    .await;

    let map = inflight.lock().await;
    let entry = map
        .get(&hash)
        .expect("inflight entry must survive the relay");
    assert!(
        entry.pending_peers.contains(&existing_peer),
        "FIXED: a concurrent relay must not drop a peer an earlier Inflight entry \
         was still awaiting an ack from"
    );
    assert!(
        entry.pending_peers.contains(&new_peer),
        "the newly relayed-to peer must also be tracked"
    );
}

/// Bug #3, second call site: `Action::SendItem`'s own inflight insert had
/// the identical blind-`insert` defect as `forward_frames` — a locally
/// copied item hashing to the same value as one already tracked inflight
/// (e.g. a concurrent mesh relay of that exact hash) would clobber the
/// existing entry's `pending_peers` instead of merging into it.
#[tokio::test]
async fn send_item_merges_inflight_pending_peers_instead_of_replacing() {
    use super::{Inflight, Outbox};
    use crate::transport::Transport;
    use fluxsync_core::{Action, App, Config};
    use fluxsync_crypto::{test_util::pair_for_test, Identity};
    use fluxsync_proto::Kind;
    use std::collections::{BTreeMap, HashMap, VecDeque};
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::{broadcast, watch, Mutex};

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);

    let self_id = Identity::generate();
    let confirmed_id = Identity::generate();
    let confirmed_peer = confirmed_id.peer_id();
    let (sess_confirmed, _) = pair_for_test(&self_id, &confirmed_id).expect("pair confirmed");
    transport
        .install_session(confirmed_peer, sess_confirmed)
        .await;

    let hash = super::clipboard_dedup_hash("send-item-merge secret");
    let existing_peer = [0x66u8; 32];
    let inflight = Arc::new(Mutex::new(HashMap::new()));
    inflight.lock().await.insert(
        hash,
        Inflight {
            frames: vec![vec![0u8; 1]],
            attempts: 0,
            last_sent: Instant::now(),
            first_sent: Instant::now(),
            pending_peers: std::iter::once(existing_peer).collect(),
        },
    );

    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
    let mut app = App::new(Config::default());
    let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
    let (state_watch_tx, _state_watch_rx) =
        watch::channel(fluxsync_core::State::initial(&Config::default()));
    let (logs_bcast_tx, _logs_rx) = broadcast::channel(16);
    let log_tail = Arc::new(super::LogTail::new());
    let last_written_hashes = Arc::new(Mutex::new(VecDeque::new()));
    let metrics = Arc::new(Mutex::new(crate::metrics::MetricsTracker::new()));
    let peer_meta: super::PeerMetaMap = Arc::new(Mutex::new(BTreeMap::new()));
    let outbox = Arc::new(Mutex::new(Outbox::new()));
    let mut seq_store: Option<crate::seq_store::SeqStore> = None;

    let actions = vec![Action::SendItem {
        hash,
        kind: Kind::Text,
        payload: b"send-item-merge secret".to_vec(),
        sensitive: false,
    }];

    dispatch(
        actions,
        &mut app,
        &transport,
        &trusted,
        None,
        &state_watch_tx,
        &logs_bcast_tx,
        &log_tail,
        &last_written_hashes,
        &metrics,
        &inflight,
        &peer_meta,
        &outbox,
        &pending_pairs,
        &mut seq_store,
    )
    .await;

    let inf = inflight.lock().await;
    let entry = inf
        .get(&hash)
        .expect("inflight entry must survive SendItem");
    assert!(
        entry.pending_peers.contains(&existing_peer),
        "FIXED: Action::SendItem must not drop a peer an earlier Inflight entry \
         was still awaiting an ack from"
    );
    assert!(
        entry.pending_peers.contains(&confirmed_peer),
        "the freshly targeted peer must also be tracked"
    );
}

/// Bug #7: a hash we already have an outstanding `ResyncPull` in flight
/// for (to ANY peer) must not be re-requested, even though it's neither
/// held nor cleared.
#[test]
fn missing_resync_hashes_excludes_hash_with_in_flight_pull() {
    use super::missing_resync_hashes;
    let already_pending = "aa".repeat(32);
    let genuinely_missing = "bb".repeat(32);
    let offered = vec![already_pending.clone(), genuinely_missing.clone()];
    let missing = missing_resync_hashes(
        &offered,
        &[],
        &[],
        &[],
        std::slice::from_ref(&already_pending),
    );
    assert_eq!(
        missing,
        vec![genuinely_missing],
        "a hash already pending from another peer must not trigger a second ResyncPull"
    );
}

/// Bug #7 (pending_pulls stale suppression), end to end: two peers both
/// offering the same hash via `Msg::ResyncOffer` used to BOTH get a
/// `ResyncPull` — `missing_resync_hashes` checked only history/outbox/
/// cleared, not hashes already being chased. Only one response can ever
/// be first-sight (`mesh_seen` drops the other, identical-`EventId`
/// arrival before it reaches `take_pending_pull`), so the loser's
/// `pending_pulls` entry was left stale for up to `RESYNC_PULL_TIMEOUT` —
/// long enough to misclassify that peer's next genuinely fresh copy of
/// the same content as resync catch-up and silently drop it. Fixed by
/// deduping offers against in-flight pulls before ever asking twice.
#[tokio::test]
async fn resync_offer_from_second_peer_does_not_duplicate_an_in_flight_pull() {
    use super::{Outbox, PeerMeta, Reassembly};
    use crate::metrics::MetricsTracker;
    use crate::transport::Transport;
    use fluxsync_core::SeenSet;
    use fluxsync_crypto::{test_util::pair_for_test, Identity};
    use fluxsync_proto::{Frame, Msg, ResyncOffer, PROTOCOL_VERSION};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);

    let self_id = Identity::generate();
    let peer_a_id = Identity::generate();
    let peer_b_id = Identity::generate();
    let peer_a = peer_a_id.peer_id();
    let peer_b = peer_b_id.peer_id();
    let (sess_a, _) = pair_for_test(&self_id, &peer_a_id).expect("pair a");
    let (sess_b, _) = pair_for_test(&self_id, &peer_b_id).expect("pair b");
    transport.install_session(peer_a, sess_a).await;
    transport.install_session(peer_b, sess_b).await;

    let peer_meta: super::PeerMetaMap = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    for peer in [peer_a, peer_b] {
        let mut pm = PeerMeta::new();
        pm.caps = vec!["resync-1".to_string()];
        peer_meta.lock().await.insert(peer, pm);
    }

    let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
    for peer in [peer_a, peer_b] {
        trusted
            .lock()
            .await
            .insert(peer, crate::handshake::tofu_trusted_peer(peer));
    }

    let hash = super::clipboard_dedup_hash("both-peers-offer-this");
    let outbox = Arc::new(Mutex::new(Outbox::new()));
    let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
    let outbox_stage = Arc::new(Mutex::new(HashMap::new()));
    let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
    let (event_tx, _event_rx) = mpsc::channel(1024);
    let metrics = Arc::new(Mutex::new(MetricsTracker::new()));
    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
    let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
        &fluxsync_core::Config::default(),
    ));

    let offer = ResyncOffer {
        hashes: vec![hex::encode(hash)],
    };

    dispatch_inbound_frame(
        Frame {
            version: PROTOCOL_VERSION,
            msg: Msg::ResyncOffer(offer.clone()),
        },
        peer_a,
        &mesh_seen,
        &event_tx,
        &transport,
        &reassembly,
        &metrics,
        &Arc::new(Mutex::new(HashMap::new())),
        &pending_pairs,
        &trusted,
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &peer_meta,
        None,
        &outbox,
        &pending_pulls,
        &outbox_stage,
        &state_rx,
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(HashMap::new())),
    )
    .await;

    assert!(
        pending_pulls
            .lock()
            .await
            .get(&peer_a)
            .is_some_and(|m| m.contains_key(&hash)),
        "precondition: peer A's offer must start a ResyncPull"
    );

    dispatch_inbound_frame(
        Frame {
            version: PROTOCOL_VERSION,
            msg: Msg::ResyncOffer(offer),
        },
        peer_b,
        &mesh_seen,
        &event_tx,
        &transport,
        &reassembly,
        &metrics,
        &Arc::new(Mutex::new(HashMap::new())),
        &pending_pairs,
        &trusted,
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Mutex::new(HashMap::new())),
        &peer_meta,
        None,
        &outbox,
        &pending_pulls,
        &outbox_stage,
        &state_rx,
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(std::collections::HashSet::new())),
        &Arc::new(Mutex::new(HashMap::new())),
    )
    .await;

    assert!(
        !pending_pulls.lock().await.contains_key(&peer_b),
        "FIXED: a hash already pending from another peer must not trigger a second ResyncPull"
    );
}

/// Bug #8 (outbox_stage collision): two DIFFERENT peers independently
/// staging the IDENTICAL content hash (e.g. both relay/copy the same
/// text) used to let the second arrival silently overwrite the first's
/// `outbox_stage` entry via a blind `insert` — while `pending_payloads`
/// (`fluxsync_core::App::park_pending`) is always first-wins by hash.
/// The two stores could then credit DIFFERENT peers for the same
/// staged item, so revoking the peer `pending_payloads` credits purges
/// `outbox_stage`'s entry (`purge_dropped_pending_from_outbox_stage`)
/// based on the wrong assumption that it's the same peer's data.
/// `outbox_stage` must be first-wins too, exactly like `park_pending`.
#[tokio::test]
async fn outbox_stage_first_wins_matches_pending_payloads_on_same_hash_collision() {
    use super::Outbox;
    use crate::transport::Transport;
    use fluxsync_core::{App, Config, Event, FirewallPolicy, Rule, SeenSet, StubWallClock};
    use fluxsync_proto::Kind;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};

    const PEER_A: [u8; 32] = [0xAAu8; 32];
    const PEER_B: [u8; 32] = [0xBBu8; 32];
    let hash = super::clipboard_dedup_hash("collision-secret");
    let payload = b"collision-secret".to_vec();

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind loopback transport");
    let transport = Arc::new(transport);
    let inflight = Arc::new(Mutex::new(HashMap::new()));
    let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
    let (event_tx, _event_rx) = mpsc::channel(1024);
    let outbox = Arc::new(Mutex::new(Outbox::new()));
    let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
    let outbox_stage = Arc::new(Mutex::new(HashMap::new()));
    let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));

    let firewall = FirewallPolicy {
        enabled: true,
        text: Rule::Ask,
        ..FirewallPolicy::default()
    };
    let (_state_tx, state_rx) =
        tokio::sync::watch::channel(fluxsync_core::State::initial(&Config {
            firewall: firewall.clone(),
            ..Config::default()
        }));

    // A arrives first: stages the item under its own origin/seq.
    complete_reassembled_item(
        &transport,
        &inflight,
        &mesh_seen,
        &event_tx,
        PEER_A,
        PEER_A,
        1,
        hash,
        Kind::Text,
        false,
        0,
        payload.clone(),
        &outbox,
        &outbox_stage,
        &pending_pulls,
        &state_rx,
        &pending_pairs,
    )
    .await;
    // B independently relays/copies the IDENTICAL content: same wire
    // hash, different peer/origin.
    complete_reassembled_item(
        &transport,
        &inflight,
        &mesh_seen,
        &event_tx,
        PEER_B,
        PEER_B,
        1,
        hash,
        Kind::Text,
        false,
        0,
        payload.clone(),
        &outbox,
        &outbox_stage,
        &pending_pulls,
        &state_rx,
        &pending_pairs,
    )
    .await;

    // Real core-side park: mirrors what the main loop's `app.handle`
    // does with each `Event::FrameReceivedClipboard`. `park_pending`
    // (and, for this identical-payload case, the dedup ring too) is
    // first-wins: A is the one credited in `state.pending`/
    // `pending_payloads`.
    let mut app = App::new(Config {
        firewall,
        ..Config::default()
    });
    let wall = StubWallClock::new("12:00", 1_000);
    app.handle(
        Event::FrameReceivedClipboard {
            peer_id: PEER_A,
            hash,
            kind: Kind::Text,
            payload: payload.clone(),
            preview: "collision-secret".into(),
            sensitive: false,
            lamport: 1,
            resync: false,
        },
        &wall,
    );
    app.handle(
        Event::FrameReceivedClipboard {
            peer_id: PEER_B,
            hash,
            kind: Kind::Text,
            payload,
            preview: "collision-secret".into(),
            sensitive: false,
            lamport: 1,
            resync: false,
        },
        &wall,
    );
    assert_eq!(
        app.snapshot().pending.len(),
        1,
        "precondition: only ONE parked row for this hash"
    );
    assert_eq!(
        app.snapshot().pending[0].peer_id,
        Some(hex::encode(PEER_A)),
        "precondition: pending_payloads credits the FIRST peer (A)"
    );

    // FIXED: outbox_stage must agree with pending_payloads about who
    // owns this hash — the first peer, A — not silently adopt B's
    // later arrival.
    let staged = outbox_stage.lock().await;
    let entry = staged.get(&hash).expect("hash must still be staged");
    assert_eq!(
        entry.origin, PEER_A,
        "outbox_stage must keep the FIRST peer's entry (matching pending_payloads), \
         not the second peer's overwrite"
    );
}

/// Bug #9 (inflight survives revoke): revoking a peer must drop it from
/// every `Inflight.pending_peers` — otherwise the retransmit timer keeps
/// firing at a permanently-revoked peer, and a peer that later
/// re-TOFU-joins under the same id within `INFLIGHT_MAX_AGE` could
/// receive a stale retransmit into its new, unconfirmed session (a
/// second FS-052 bypass). An entry whose `pending_peers` becomes empty
/// must be dropped outright, not left orphaned.
#[tokio::test]
async fn purge_peer_from_inflight_drops_revoked_peer_and_empties_entries() {
    use super::{purge_peer_from_inflight, Inflight};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::Mutex;

    let revoked = [0xAAu8; 32];
    let other = [0xBBu8; 32];
    let solo_hash = [1u8; 32];
    let shared_hash = [2u8; 32];

    let inflight = Arc::new(Mutex::new(HashMap::new()));
    inflight.lock().await.insert(
        solo_hash,
        Inflight {
            frames: vec![vec![1]],
            attempts: 0,
            last_sent: Instant::now(),
            first_sent: Instant::now(),
            pending_peers: std::iter::once(revoked).collect(),
        },
    );
    inflight.lock().await.insert(
        shared_hash,
        Inflight {
            frames: vec![vec![2]],
            attempts: 0,
            last_sent: Instant::now(),
            first_sent: Instant::now(),
            pending_peers: [revoked, other].into_iter().collect(),
        },
    );

    purge_peer_from_inflight(revoked, &inflight).await;

    let map = inflight.lock().await;
    assert!(
        map.get(&solo_hash).is_none(),
        "FIXED: an entry left with no pending peers after the revoke must be dropped entirely"
    );
    let shared = map
        .get(&shared_hash)
        .expect("the other peer's item must survive");
    assert!(
        !shared.pending_peers.contains(&revoked),
        "the revoked peer must no longer be awaited"
    );
    assert!(
        shared.pending_peers.contains(&other),
        "an unrelated peer still awaiting this item must be untouched"
    );
}

/// FluxMesh bug fix (Bug #10a): `rekey_watchdog` used to read only the
/// PRIMARY's clock (`cached_peer_id`/`session_established_at`/
/// `session_bytes`) and only ever call `run_rekey_initiator` for that one
/// peer, so a SECONDARY session — however long-lived — never rotated,
/// violating the 24h/1GiB rekey policy for every mesh peer but the
/// primary. Drives the REAL `rekey_watchdog` (not a mock) against a
/// transport with a primary (A) and a secondary (B). Identities are
/// arranged so this daemon is NOT the deterministic initiator for A (it
/// must be correctly skipped — no responder is even bound for it) but IS
/// the initiator for B: the secondary must still receive a genuine rekey
/// handshake and end up with a bumped `session_generation`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rekey_watchdog_rekeys_a_secondary_session() {
    use super::BackoffMap;
    use crate::handshake::{peer_id_for, TrustedPeer, TrustedSet};
    use crate::transport::{Transport, TYPE_HANDSHAKE_INIT};
    use fluxsync_core::Event;
    use fluxsync_crypto::{test_util::pair_for_test, Identity, Responder};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::sync::{mpsc, Mutex};
    use tokio_util::sync::CancellationToken;

    // Arrange identities so THIS daemon is not the initiator for A (the
    // primary) but IS the initiator for B (the secondary) — isolates the
    // test to the secondary path while also proving the primary is
    // correctly left alone.
    let (self_identity, peer_a_identity, peer_b_identity) = loop {
        let s = Identity::generate();
        let a = Identity::generate();
        let b = Identity::generate();
        if s.peer_id() > a.peer_id() && s.peer_id() < b.peer_id() {
            break (s, a, b);
        }
    };
    let peer_id_a = peer_id_for(&peer_a_identity.public_key());
    let peer_id_b = peer_id_for(&peer_b_identity.public_key());

    let (transport, _port) = Transport::bind("127.0.0.1", 0)
        .await
        .expect("bind transport");
    let transport = Arc::new(transport);

    // Seed both sessions — A first (becomes primary), B second (routes
    // to `extra`, FluxMesh 2C-b) — with throwaway key material; only the
    // bookkeeping (established_at/generation) matters here, since the
    // rekey itself is a fresh, real Noise exchange against the genuine
    // identities registered in `trusted` below.
    let (sess_a, _) = pair_for_test(&self_identity, &Identity::generate()).unwrap();
    let (sess_b, _) = pair_for_test(&self_identity, &Identity::generate()).unwrap();
    transport.install_session(peer_id_a, sess_a).await;
    transport.install_session(peer_id_b, sess_b).await;
    assert_eq!(transport.cached_peer_id().await, Some(peer_id_a));

    let bare_a = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind bare peer A socket");
    let bare_b = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind bare peer B socket");
    transport
        .set_peer_addr_for(peer_id_a, bare_a.local_addr().unwrap())
        .await;
    transport
        .set_peer_addr_for(peer_id_b, bare_b.local_addr().unwrap())
        .await;

    let trusted: TrustedSet = Arc::new(Mutex::new(HashMap::new()));
    trusted.lock().await.insert(
        peer_id_a,
        TrustedPeer {
            static_pub: peer_a_identity.public_key(),
            name: "peer-a".into(),
        },
    );
    trusted.lock().await.insert(
        peer_id_b,
        TrustedPeer {
            static_pub: peer_b_identity.public_key(),
            name: "peer-b".into(),
        },
    );

    let generation_a_before = transport.session_generation_for(peer_id_a).await.unwrap();
    let generation_b_before = transport.session_generation_for(peer_id_b).await.unwrap();

    let pending_initiator_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>> =
        Arc::new(Mutex::new(None));
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(16);
    let backoff: BackoffMap = Arc::new(Mutex::new(HashMap::new()));
    let shutdown = CancellationToken::new();

    let watchdog = tokio::spawn(rekey_watchdog(
        self_identity.clone(),
        transport.clone(),
        trusted.clone(),
        pending_initiator_tx.clone(),
        event_tx.clone(),
        backoff.clone(),
        50,       // max_age_ms: force both sessions "due" almost immediately
        u64::MAX, // max_bytes: never trip the byte trigger
        None,
        shutdown.clone(),
    ));

    // Only B's bare socket should ever receive a HandshakeInit — A is
    // not this daemon's deterministic responsibility to initiate.
    let mut buf = [0u8; 2048];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(2), bare_b.recv_from(&mut buf))
        .await
        .expect("watchdog must send a rekey HandshakeInit to the secondary within 2s")
        .expect("recv msg1");
    assert_eq!(buf[0], TYPE_HANDSHAKE_INIT);
    let (_peer_session, msg2, _remote_static) =
        Responder::step(&peer_b_identity, &buf[1..n]).expect("responder step");

    // Deliver msg2 the way the real driver's `RecvFrame::HandshakeResp`
    // dispatch would — via the shared single-flight sender — without
    // needing a full receive-loop task for this test.
    let tx = pending_initiator_tx
        .lock()
        .await
        .clone()
        .expect("watchdog must have registered the single-flight sender for B's rekey");
    tx.send(msg2).expect("deliver msg2 to the rekey initiator");

    let mut rekeyed = false;
    for _ in 0..100 {
        if transport
            .session_generation_for(peer_id_b)
            .await
            .unwrap_or(generation_b_before)
            > generation_b_before
        {
            rekeyed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(rekeyed, "secondary session must be rekeyed within ~2s");

    assert_eq!(
        transport.session_generation_for(peer_id_a).await,
        Some(generation_a_before),
        "the primary — not due (this daemon isn't its deterministic initiator) — must be untouched"
    );

    // A HandshakeOk fired for the completed secondary rekey.
    let mut saw_handshake_ok = false;
    while let Ok(ev) = event_rx.try_recv() {
        if matches!(ev, Event::HandshakeOk) {
            saw_handshake_ok = true;
        }
    }
    assert!(
        saw_handshake_ok,
        "a completed secondary rekey must fire HandshakeOk"
    );

    // Prove the primary path was truly untouched, not just "generation
    // didn't change by luck": A's bare socket must never receive anything.
    let none_for_a =
        tokio::time::timeout(Duration::from_millis(200), bare_a.recv_from(&mut buf)).await;
    assert!(
        none_for_a.is_err(),
        "the primary must never receive a HandshakeInit from this daemon"
    );

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(1), watchdog).await;
}

/// Every frame `build_item_frames` emits must fit one sealed datagram:
/// a payload just under `MAX_CHUNK_DATA` used to go out as a single frame
/// that overflowed the MTU budget once the item header rode along.
#[test]
fn item_frames_always_fit_one_datagram() {
    for len in [0, 1, 500, 1000, 1023, 1024, 1025, 3000, 10_000] {
        let payload = vec![0xA5; len];
        let frames = super::build_item_frames(
            u64::MAX,
            [0xCD; 32],
            fluxsync_proto::Kind::Text,
            &payload,
            false,
            [0xEF; 32],
            u64::MAX,
        );
        assert!(!frames.is_empty(), "{len}: no frames");
        for f in &frames {
            assert!(
                f.len() <= fluxsync_proto::MAX_FRAME_PLAINTEXT,
                "{len}-byte payload produced a {}-byte frame",
                f.len()
            );
        }
    }
}
