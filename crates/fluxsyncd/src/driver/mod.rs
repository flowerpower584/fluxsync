// Image dims (image crate caps), packet idx (u16-bounded), and saturated
// durations are the cast sources here — all safe at runtime.
#![allow(clippy::cast_possible_truncation)]
// Every submodule opens with `use super::*;`: the driver/ split keeps the
// single namespace the code was written against.
#![allow(clippy::wildcard_imports)]

//! Daemon driver — composes [`fluxsync_core::App`] with IPC, transport,
//! mDNS discovery, and the Noise IK handshake.
//!
//! `run(cfg, shutdown)` is the public entry point. It spawns:
//! * IPC accept loop
//! * transport receive loop (typed wire dispatcher)
//! * mDNS discovery dispatcher (skipped in test mode or when disabled)
//! * the central event loop that owns the `App`
//!
//! Shutdown: a single `tokio_util::sync::CancellationToken`. Every loop
//! selects on `token.cancelled()` and exits. Cancellation is sticky —
//! a task that is not parked on `cancelled()` at the instant of
//! `cancel()` still observes it on its next poll, so no task can miss
//! the signal. The driver returns once all background tasks have
//! joined, so callers (test harness, `main.rs`) get a deterministic
//! shutdown deadline.

use crate::backoff::PeerBackoff;
use crate::cmd::{Channel, CmdData, CmdOp, CmdRequest, CmdResponse, PeerEntry, Subscribe};
use crate::config::{DaemonConfig, TestPair};
use crate::discovery::{self, DiscoveryEvent};
use crate::handshake::{
    self, PairingWindow, PendingSet, TrustedPeer, TrustedSet, MAX_PERSISTED_PEERS,
};
use crate::history_store::{self, VaultEntry};
use crate::ipc::{IpcConn, IpcServer};
use crate::logs::LogTail;
use crate::metrics::{DisconnectReason, MetricsTracker};
use crate::outbox::{Entry as OutboxEntry, Outbox};
use crate::rate_limit::HandshakeRateLimiter;
use crate::seq_store::SeqStore;
use crate::transport::{is_rekey_initiator, now_ms, rekey_due, RecvFrame, Transport};
use anyhow::{anyhow, Context, Result};
use base32::Alphabet;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use fluxsync_core::{
    dedup::DedupRing, kind_of, Action, App, Config as CoreConfig, Decision, DeviceId, Direction,
    Event, EventId, HistoryItem, LogEntry, LogLevel, PairedDevice, PeerInfo, SeenSet, State,
    WallClock,
};
use fluxsync_crypto::gen_pair_pin;
use fluxsync_crypto::{fingerprint, Identity};
use fluxsync_proto::{
    negotiate_caps, ClipboardItem, Frame, Kind, Msg, ResyncOffer, ResyncPull, MAX_CHUNK_DATA,
    MAX_PAYLOAD, MAX_RESYNC_HASHES, PROTOCOL_VERSION, SUPPORTED_CAPS,
};
use hex;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{broadcast, mpsc, oneshot, watch, Mutex, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

mod actions;
mod clipboard;
mod commands;
mod frames;
mod inbound;
mod ipc_server;
mod liveness;
mod pairing;
mod peers;
mod resync;
mod shared;
#[cfg(test)]
mod tests;
mod vault;

pub(crate) use self::peers::*;
pub use self::shared::*;
#[allow(unused_imports)]
use self::{
    actions::*, clipboard::*, commands::*, frames::*, inbound::*, ipc_server::*, liveness::*,
    pairing::*, resync::*, vault::*,
};

const BASE32_ALPHA: Alphabet = Alphabet::Rfc4648 { padding: false };

/// This device's OS family, sent in `Msg::Hello` so the peer renders the
/// correct device icon. Mobile builds compile `fluxsyncd` for `android`/`ios`
/// via `fluxsync-mobile-ffi`, so those arms are reachable too.
const fn self_platform() -> &'static str {
    if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "ios") {
        "ios"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    }
}

// ─────────────────────────────────────────────────────────────────
// PR2 — PIN-method pairing state
// ─────────────────────────────────────────────────────────────────

/// Drive a daemon to completion, returning once `shutdown` fires and
/// every background task has joined.
pub async fn run(cfg: DaemonConfig, shutdown: CancellationToken) -> Result<()> {
    let DaemonConfig {
        identity,
        peer_name_self,
        udp_port,
        udp_bind,
        ipc_path,
        // Plumbed for the upcoming peers.json wire-up. Both fields are
        // intentionally unused inside the driver right now: `main.rs`
        // already writes `identity.bin` via `keystore::load_or_create_identity`,
        // and the trusted-peer set will be persisted in `peers.json`
        // alongside it once the wire-up lands.
        trusted_peer_keys: _,
        keystore_dir,
        charge_override,
        wall_clock,
        disable_mdns,
        disable_clipboard,
        start_on,
        test_pair,
        test_pairs,
        test_pending_pair,
        test_peer_static_pub,
        rekey_max_age_ms,
        rekey_max_bytes,
        lan_only_handshakes,
        firewall,
    } = cfg;

    // Chantier A: the on-disk firewall policy is authoritative when a keystore
    // is present, so a SetFirewall survives restarts. With no keystore (tests),
    // keep whatever the caller injected.
    let firewall = match keystore_dir.as_ref() {
        Some(dir) => crate::keystore::load_firewall(dir),
        None => firewall,
    };

    // DIR-P3-01: same rationale as the firewall load above — a persisted
    // `CmdOp::SetDeviceName` is authoritative across restarts. Falls back to
    // whatever `main.rs` resolved (hostname or `--peer-name`) when no rename
    // has ever been persisted. This is the single source `CoreConfig`, mDNS
    // advertisement, and the initial `Msg::Hello` all read below.
    let peer_name_self = match keystore_dir.as_ref() {
        Some(dir) => crate::keystore::load_device_name(dir).unwrap_or(peer_name_self),
        None => peer_name_self,
    };

    // ── App + channels ────────────────────────────────────────────
    let mut app = App::new_with_device(
        CoreConfig {
            peer_name_self: peer_name_self.clone(),
            charge_override,
            version: String::from(env!("CARGO_PKG_VERSION")),
            build_id: String::from(env!("FLUXSYNCD_BUILD_ID")),
            cipher: String::from("chacha20-poly1305"),
            firewall,
            mdns_enabled: !disable_mdns,
        },
        // This daemon's stable mesh identity: the BLAKE3 id of its Noise
        // static key, the same bytes peers see as `peer_id`. Stamped as
        // `EventId.origin` on every locally-copied item.
        fluxsync_core::DeviceId::from(identity.peer_id()),
    );

    // ── Restore the persisted outgoing event-seq horizon ──────────
    // `App.local_seq` (stamped as `EventId.seq` on every locally-originated
    // item, see `next_local_event_id`) used to reset to 0 on every restart,
    // so a peer's mesh anti-loop `SeenSet` could wrongly treat freshly
    // re-issued low seqs as replays of items it had already recorded. See
    // `seq_store.rs` for the reserve-ahead persistence scheme. No keystore
    // dir (test mode) means no restored seq and no persistence — `app`
    // simply keeps its fresh `local_seq == 0`, same as before this fix.
    let mut seq_store: Option<SeqStore> = if let Some(dir) = keystore_dir.as_ref() {
        let (initial_seq, store) = SeqStore::load(dir);
        app.set_local_seq(initial_seq);
        Some(store)
    } else {
        None
    };

    // ── FluxVault: rehydrate persisted history ────────────────────
    // Decrypt the on-disk history (if any) and seed it into the App
    // *before* the first snapshot, so every consumer sees the restored
    // list immediately. Best-effort: a load failure (wrong identity,
    // tampered file) logs and starts empty rather than aborting boot.
    let vault: Option<(PathBuf, zeroize::Zeroizing<[u8; 32]>, Vec<VaultEntry>)> = if let Some(dir) =
        keystore_dir.as_ref()
    {
        let key = identity.derive_at_rest_key(history_store::AT_REST_CONTEXT);
        let entries =
            match history_store::load(dir, &key, now_ms(), history_store::DEFAULT_TTL_SECS) {
                Ok(entries) => {
                    app.restore_history(entries.iter().map(|e| e.item.clone()).collect());
                    tracing::info!(count = entries.len(), "rehydrated history from vault");
                    entries
                }
                Err(e) => {
                    tracing::warn!(error = %e, "vault load failed; starting with empty history");
                    Vec::new()
                }
            };
        Some((dir.clone(), key, entries))
    } else {
        None
    };

    let initial = app.snapshot().clone();
    let (state_watch_tx, state_watch_rx) = watch::channel(initial);

    let (logs_bcast_tx, _) = broadcast::channel::<LogEntry>(64);
    // M-DAEMON-11: bounded so a hostile LAN flood (mDNS spam → DiscoveryEvent,
    // or forged frames → Event) can't grow the daemon's memory without bound.
    // Every producer uses `try_send` and drops on full (all sends are already
    // fire-and-forget); the cap is far above any legitimate burst. The M-DAEMON-17
    // fix removed the per-frame fsync that used to stall this consumer.
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(EVENT_CHANNEL_CAP);
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<DriverCmd>();
    let log_tail = Arc::new(LogTail::new());

    // ── Trusted peers ─────────────────────────────────────────────
    // FS-039: persistent pairing. Reload the trusted set from
    // `peers.json` so a paired peer survives a daemon restart.
    let trusted: TrustedSet = Arc::new(Mutex::new(HashMap::new()));
    // Persisted redial hints (`last_addr` redial), collected
    // alongside the trust reload below and applied to `transport` once it
    // is bound (see the seed loop after `Transport::bind`). Relocated here
    // (rather than reviving `main.rs`'s old per-peer parse into a single
    // `DaemonConfig` field) because `run()` already independently reloads
    // `peers.json` via `load_trusted_peers` to build `trusted` — this is
    // the natural single place to also learn every peer's last address.
    let mut last_known_addrs: Vec<([u8; 32], SocketAddr)> = Vec::new();
    // Item 4 (secondary redial): the same persisted `last_addr` per trusted
    // peer, kept as a lookup map so the proactive redial tick can find a
    // SECONDARY's last known address even when it has never held a session
    // on `transport` this boot (so `roaming_history_snapshot_for` is empty
    // for it) — see `discovery_dispatcher`'s redial tick.
    let mut persisted_peer_addrs: HashMap<[u8; 32], SocketAddr> = HashMap::new();
    if let Some(dir) = keystore_dir.as_ref() {
        let loaded = load_trusted_peers(dir);
        let count = loaded.len();
        {
            let mut g = trusted.lock().await;
            for (peer_id, peer, last_addr) in loaded {
                g.insert(peer_id, peer);
                if let Some(addr) = last_addr {
                    last_known_addrs.push((peer_id, addr));
                    persisted_peer_addrs.insert(peer_id, addr);
                }
            }
        }
        tracing::info!(count, "loaded trusted peers from keystore");
    }

    // ── Transport (always bound; session/peer_addr filled later) ───
    let (transport_inner, actual_port) = Transport::bind(&udp_bind, udp_port)
        .await
        .with_context(|| format!("bind UDP {udp_bind}:{udp_port}"))?;
    let transport = Arc::new(transport_inner);
    let metrics = transport.metrics.clone();
    let udp_port = actual_port; // Shadow with the real port (in case it was 0)
    tracing::info!(port = udp_port, "UDP transport bound");

    // Pending initiator coordination: at most one handshake in flight
    // (single peer in v0.1.1). transport_recv routes msg2 here.
    let pending_initiator_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>> =
        Arc::new(Mutex::new(None));

    // Pairing window for TOFU on the responder side. Set by `PairShow`
    // to `now + 5 min`; outside the window the responder enforces strict
    // trust against `trusted_peer_keys` / previously-paired peers.
    let pairing_window: PairingWindow = Arc::new(Mutex::new(None));

    // FS-052: peers auto-trusted under TOFU but not yet verbally
    // confirmed by the user. Each entry carries the 6-word SAS computed
    // from the Noise handshake hash so `fluxctl pair pending` /
    // `fluxctl pair confirm` can surface and resolve them.
    let pending_pairs: PendingSet = Arc::new(Mutex::new(HashMap::new()));

    // FS-052 wire mutual confirm: peer-ids whose local `--accept` send is
    // deferred until their `Hello` (and therefore negotiated caps) arrives.
    // See `DeferredSasConfirm`.
    let deferred_sas_confirm: DeferredSasConfirm = Arc::new(Mutex::new(HashSet::new()));

    // Asymmetric-trust echo-ack: peer-ids we've already echoed a
    // `Msg::PairConfirm{accept:true}` back to during the current session.
    // See `EchoAckSent`.
    let echo_ack_sent: EchoAckSent = Arc::new(Mutex::new(HashSet::new()));

    // PR2: PIN-method pairing state. `pin_advert` holds the current
    // PIN + expiry; `disc_cache` lets `PairFromPin` resolve an
    // untrusted peer by its TXT `pair_pin`; `mdns_ctx` is populated
    // once mDNS is up so the PIN-rotation watchdog can re-publish.
    let pin_advert: PinAdvertisement = Arc::new(Mutex::new(None));
    let disc_cache: DiscoveryCache = Arc::new(Mutex::new(HashMap::new()));
    // DIR-P1-02: reconnect backoff, one entry per peer-id. Created
    // alongside `disc_cache` so it can be threaded to the same purge
    // sites (unpair/revoke/wipe) and the same reconnect call sites.
    let backoff: BackoffMap = Arc::new(Mutex::new(HashMap::new()));
    let mdns_ctx: MdnsCtx = Arc::new(Mutex::new(None));
    // H2 fix: content hashes deliberately cleared via `CmdOp::ClearHistory`,
    // so a peer's later `ResyncOffer` for one of them can never re-pull it.
    let cleared_tombstone: ClearedTombstone = Arc::new(Mutex::new(HashMap::new()));

    // ── Long-lived tasks ──────────────────────────────────────────
    // Declared here (rather than just before the IPC task below) so the
    // vault persister — which must be tracked in this `JoinSet` rather than
    // bare-`tokio::spawn`ed, see DEFECT 2's fix — can join it too.
    let mut tasks = JoinSet::new();

    // Persist history off the state-watch channel: a dedicated task wakes
    // on every state change, diffs the history list, and writes the vault
    // only when it actually changed (skipping the frequent battery /
    // heartbeat / peer-list EmitStates). Lives only when a keystore dir is
    // configured; exits on `shutdown` (or when the watch sender drops).
    // Spawned here (after `disc_cache` exists) so the persister can also
    // purge it on a security wipe (DIR-P2-04a).
    if let Some((dir, key, entries)) = vault {
        let ctx = VaultCtx {
            dir,
            key,
            last: app.snapshot().history.clone(),
            entries,
        };
        // Seed the persister's wipe-gen baseline from the snapshot it is
        // constructed against (0 at boot), so a security wipe published before
        // the task's first poll is still observed as a change (see the note in
        // run_vault_persister).
        let initial_wipe_gen = app.snapshot().vault_wipe_gen;
        // Clone every shared handle BEFORE the `async move` block: the
        // block captures by move, and `disc_cache`/`backoff`/`state_watch_tx`
        // are all still needed by later setup (the transport recv loop, the
        // main event loop) in the rest of `run()`.
        let state_rx_for_persister = state_watch_tx.subscribe();
        let disc_cache_for_persister = disc_cache.clone();
        let backoff_for_persister = backoff.clone();
        // DEFECT 2 fix: tracked in `tasks` (not a bare detached `tokio::spawn`)
        // and handed a clone of `shutdown`, so `run()`'s final
        // `while tasks.join_next().await.is_some() {}` actually waits for this
        // task's last-write flush before the caller can exit. See
        // `run_vault_persister`'s doc comment.
        let shutdown_for_persister = shutdown.clone();
        tasks.spawn(async move {
            run_vault_persister(
                ctx,
                state_rx_for_persister,
                initial_wipe_gen,
                disc_cache_for_persister,
                backoff_for_persister,
                shutdown_for_persister,
            )
            .await;
            Ok(())
        });
    }

    if let Some(tpp) = test_pending_pair {
        pending_pairs.lock().await.insert(
            tpp.peer_id,
            crate::handshake::PendingPair {
                static_pub: tpp.static_pub,
                name: tpp.name,
                sas_words: tpp.sas_words,
                from: tpp.from,
                expires_at: Instant::now() + tpp.expires_in,
            },
        );
    }

    // Last clipboard payload we wrote to the OS clipboard (i.e., received
    // from the peer). The clipboard watcher dedups against this so it
    // doesn't immediately read its own write back, fire LocalClipboardChange,
    // and ping-pong the same item back to the peer.
    let last_written_hashes: Arc<Mutex<RecentWrites>> =
        Arc::new(Mutex::new(RecentWrites::default()));

    // Outbound items awaiting acks. Shared between the action dispatch
    // (inserts on SendItem), the inbound frame handler (removes on Ack),
    // and the transport loop's retransmit timer.
    let inflight: InflightMap = Arc::new(Mutex::new(HashMap::new()));

    // FluxMesh 2C-b: shared mesh anti-loop guard (EventId seen-set). Used by
    // the recv loop to forward each item exactly once and never loop.
    let mesh_seen: MeshSeen = Arc::new(Mutex::new(SeenSet::default()));

    // FluxMesh Phase 3: per-peer UI metadata feeding the State `peers` list.
    // Written by the recv loop (every peer's Hello/Battery), read at EmitState.
    let peer_meta: PeerMetaMap = Arc::new(Mutex::new(BTreeMap::new()));

    // Resync-on-reconnect (resync-1): recent non-sensitive outbound/inbound
    // items, kept just long enough to re-offer to a peer that reconnects
    // after missing them. Written on SendItem and on first-sight reception,
    // read to build a ResyncOffer and to serve a ResyncPull.
    let outbox: SharedOutbox = Arc::new(Mutex::new(Outbox::new()));
    // resync-1 apply-suppression fix: hashes we've asked a peer for via
    // ResyncPull, so the receive path can tell "I requested this catch-up
    // item" apart from a fresh copy. See `PendingPulls`'s doc comment.
    let pending_pulls: PendingPulls = Arc::new(Mutex::new(HashMap::new()));
    // Outbox admission gate fix: an inbound item the firewall parks under
    // `Ask` is not yet admitted to history, so it must not enter `outbox`
    // yet either — but its (origin, seq) wire metadata is only known at
    // receive time, and is lost by the time a later `ResolvePending`
    // resolves it (`fluxsync_core`'s `PendingPayload` carries no such
    // fields). This staging map bridges that gap: `complete_reassembled_item`
    // / `dispatch_inbound_frame` park an `Ask`-decided item's full
    // `OutboxEntry` here instead of in `outbox`, and `CmdOp::ResolvePending`
    // promotes it into the real `outbox` on `allow: true` (or drops it
    // otherwise). See `PendingOutboxStage`'s doc comment.
    let outbox_stage: PendingOutboxStage = Arc::new(Mutex::new(HashMap::new()));

    // ── Shared context ─────────────────────────────────────────────
    // One Arc'd bundle of every long-lived handle (see `Shared`), handed to
    // each task and handler instead of threading them one by one. The local
    // bindings above alias the very same Arcs.
    let shared = Arc::new(Shared {
        identity: identity.clone(),
        wall_clock: wall_clock.clone(),
        keystore_dir: keystore_dir.clone(),
        udp_bind: udp_bind.clone(),
        udp_port,
        lan_only_handshakes,
        shutdown: shutdown.clone(),
        event_tx: event_tx.clone(),
        cmd_tx: cmd_tx.clone(),
        state_watch_tx: state_watch_tx.clone(),
        logs_bcast_tx: logs_bcast_tx.clone(),
        log_tail: log_tail.clone(),
        transport: transport.clone(),
        metrics: metrics.clone(),
        trusted: trusted.clone(),
        pairing_window: pairing_window.clone(),
        pending_pairs: pending_pairs.clone(),
        pending_initiator_tx: pending_initiator_tx.clone(),
        deferred_sas_confirm: deferred_sas_confirm.clone(),
        pin_advert: pin_advert.clone(),
        disc_cache: disc_cache.clone(),
        backoff: backoff.clone(),
        mdns_ctx: mdns_ctx.clone(),
        peer_meta: peer_meta.clone(),
        inflight: inflight.clone(),
        reassembly: Arc::new(Mutex::new(HashMap::new())),
        mesh_seen: mesh_seen.clone(),
        echo_ack_sent: echo_ack_sent.clone(),
        last_written_hashes: last_written_hashes.clone(),
        outbox: outbox.clone(),
        outbox_stage: outbox_stage.clone(),
        pending_pulls: pending_pulls.clone(),
        cleared_tombstone: cleared_tombstone.clone(),
        self_batt_level: std::sync::atomic::AtomicU8::new(255),
        self_batt_charging: std::sync::atomic::AtomicBool::new(false),
        hello_sent: Mutex::new(HashMap::new()),
        clipboard_writer: spawn_clipboard_writer(disable_clipboard),
    });

    // ── Test path: install session + jump to Linked ────────────────
    if let Some(tp) = test_pair {
        let TestPair {
            session,
            peer_addr,
            peer_name,
            peer_id,
        } = tp;
        transport.install_session(peer_id, session).await;
        transport.set_peer_addr(peer_addr).await;
        // Add peer to trusted set under a placeholder pubkey (or, if the
        // test injected one via `test_peer_static_pub`, the real key — a
        // DIR-P2-03 rekey test needs a genuine key so the forced rekey's
        // Noise IK exchange can actually complete against the peer) so the
        // App's peer_name lookup paths still find an entry.
        trusted.lock().await.insert(
            peer_id,
            TrustedPeer {
                static_pub: test_peer_static_pub.unwrap_or([0u8; 32]),
                name: peer_name.clone(),
            },
        );
        event_tx.try_send(Event::ToggleOn).ok();

        event_tx
            .try_send(Event::PeerSeen {
                peer_id,
                name: peer_name,
            })
            .ok();
        event_tx.try_send(Event::HandshakeOk).ok();
        event_tx
            .try_send(Event::BatteryChangedSelf {
                level: 80,
                charging: false,
            })
            .ok();
        event_tx
            .try_send(Event::BatteryChangedPeer {
                level: 80,
                charging: false,
            })
            .ok();
    }

    // FluxMesh 2C-b: install ADDITIONAL pre-paired peers (mesh test harness).
    // Secondary peers get a session + trust + address so clipboard fans out
    // and relays to them, but they do NOT drive the single FSM — the primary
    // `test_pair` already drove it to Linked.
    for tp in test_pairs {
        let TestPair {
            session,
            peer_addr,
            peer_name,
            peer_id,
        } = tp;
        transport.install_session(peer_id, session).await;
        transport.set_peer_addr_for(peer_id, peer_addr).await;
        trusted.lock().await.insert(
            peer_id,
            TrustedPeer {
                static_pub: [0u8; 32],
                name: peer_name,
            },
        );
    }

    // Seed the transport's per-peer reconnect cache from each trusted
    // peer's persisted `last_addr` (collected above, alongside the trust
    // reload). `set_peer_info` records both the address AND the peer id
    // together, which is what lets the always-on proactive-probe redial
    // (see `discovery_dispatcher`) recognize "no session yet, but we know
    // who and where to try" immediately at boot — with zero mDNS
    // involvement. If more than one trusted peer has a persisted address,
    // the last one processed here wins the shared "primary" redial slot;
    // this matches the rest of the driver's single-primary-peer reconnect
    // model (see `Transport::cached_peer_addr`/`cached_peer_id`).
    for (peer_id, addr) in last_known_addrs {
        // L4 fix: a `peers.json` written before this fix (or corrupted by
        // hand) could hold a bogus address class; never seed a redial from
        // one, matching the same-shape guard now in `persist_last_addr`.
        if is_redialable_addr(addr.ip()) {
            transport.set_peer_info(peer_id, addr).await;
        } else {
            tracing::warn!(
                peer = %hex::encode(&peer_id[..6]),
                %addr,
                "L4: refusing to seed a boot-time redial from a link-local/multicast/unspecified address"
            );
        }
    }

    // Inform App about trusted peers for UI hints.
    {
        let g = trusted.lock().await;
        let primary_id = transport.cached_peer_id().await;
        if let Some(peer) = choose_boot_trusted_peer(&g, primary_id) {
            tracing::info!(peer = %peer.name, "Boot: informing UI about trusted peer");
            event_tx
                .try_send(Event::SetTrustedPeer {
                    name: peer.name.clone(),
                })
                .ok();
        }
    }

    // ── State-Aware Boot: Auto-toggle ON if requested ─────────────
    if start_on {
        tracing::info!("State-Aware Boot: auto-starting sync");
        event_tx.try_send(Event::ToggleOn).ok();
    }

    // IPC.
    let ipc_server = IpcServer::bind(&ipc_path)
        .await
        .with_context(|| format!("bind ipc socket {}", ipc_path.display()))?;
    {
        let sh = shared.clone();
        tasks.spawn(async move { ipc_accept_loop(ipc_server, sh).await });
    }

    // Transport receive loop.
    {
        let sh = shared.clone();
        tasks.spawn(async move { transport_recv_loop(sh).await });
    }

    // FS-058: background reaper that drops expired PendingSet entries.
    // FS-052 strict gate (VULN-002): on expiry, revoke the matching
    // trusted entry + drop the live session + persist `peers.json` so a
    // pending peer the user never confirmed cannot survive across reboot.
    {
        let pending = pending_pairs.clone();
        let trusted_r = trusted.clone();
        let transport_r = transport.clone();
        let kd = keystore_dir.clone();
        let s = shutdown.clone();
        let event_tx_r = event_tx.clone();
        tasks.spawn(async move {
            handshake::run_pending_reaper(pending, trusted_r, transport_r, kd, s, event_tx_r).await;
            Ok(())
        });
    }

    // Heartbeat loop. It also re-broadcasts this device's latest battery
    // (`Shared::self_batt_*`, written by the event loop below) every tick:
    // battery is otherwise only sent on change (macOS poll) or via the
    // Android broadcast, so a steady level would never refresh on the peer
    // after the handshake. 255 = "not read yet" → nothing is sent.
    {
        let sh = shared.clone();
        tasks.spawn(async move {
            if let Err(e) = heartbeat_loop(sh).await {
                tracing::warn!(error = %e, "heartbeat loop exited");
            }
            Ok(())
        });
    }

    // DIR-P2-03: automatic session rekey watchdog.
    {
        let sh = shared.clone();
        tasks.spawn(async move { rekey_watchdog(sh, rekey_max_age_ms, rekey_max_bytes).await });
    }

    // mDNS discovery. The `discovery_dispatcher` task below is ALWAYS
    // spawned, regardless of `disable_mdns` or test mode: it also drives
    // the mDNS-independent proactive-probe redial (persisted `last_addr`
    // seeded above + roaming history), which must keep working with mDNS
    // fully off (`--disable-mdns` silences both directions,
    // but redial-by-persisted-address must not depend on mDNS at all).
    // Only the actual `discovery::start` call — binding a real
    // `ServiceDaemon`, registering (making us discoverable), and browsing
    // (making us discover others) — is gated: that is the "both
    // directions of mDNS" this flag controls. When gated off, `disc_tx`
    // is dropped immediately without ever being handed to a live mDNS
    // daemon, so `discovery_dispatcher`'s `disc_rx.recv()` branch cleanly
    // resolves to `None` (channel closed) forever after — `select!`
    // treats a non-matching `Some(x) = ...` pattern as "not ready" and
    // simply re-polls on the next loop iteration, so this never busy-loops.
    let mut _mdns_daemon = None;
    let we_are_test_mode = transport.has_session().await;
    let (disc_tx, disc_rx) = mpsc::channel::<DiscoveryEvent>(DISCOVERY_CHANNEL_CAP);
    if !disable_mdns && !we_are_test_mode {
        // mDNS must advertise (and egress on) the real LAN interface, not
        // 0.0.0.0. On multi-interface hosts (macOS awdl0/utunN) an
        // unspecified bind_ip makes mdns-sd announce on every interface and
        // pick a non-LAN one, so peers never see us. Resolve the egress LAN
        // IP and pin mDNS to it.
        let bind_ip: std::net::IpAddr = local_lan_addr(&udp_bind, udp_port)
            .rsplit_once(':')
            .and_then(|(ip, _)| ip.parse().ok())
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let peer_id_hex = hex::encode(identity.peer_id());
        let static_pub_hex = hex::encode(identity.public_key());
        match discovery::start(
            &peer_name_self,
            &peer_id_hex,
            &static_pub_hex,
            bind_ip,
            udp_port,
            disc_tx,
            shutdown.clone(),
        ) {
            Ok(daemon) => {
                _mdns_daemon = Some(daemon.clone());
                // PR2: record mDNS context so PIN rotations can re-publish
                // without re-binding the daemon.
                *mdns_ctx.lock().await = Some(MdnsContext {
                    daemon: daemon.clone(),
                    instance_name: peer_name_self.clone(),
                    peer_id_hex: peer_id_hex.clone(),
                    static_pub_hex: static_pub_hex.clone(),
                    bind_ip,
                    udp_port,
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "mDNS unavailable; pairing requires --addr in pair-accept");
            }
        }
    } else {
        drop(disc_tx);
    }
    let persisted_peer_addrs = Arc::new(persisted_peer_addrs);
    {
        let sh = shared.clone();
        tasks.spawn(async move { discovery_dispatcher(disc_rx, sh, persisted_peer_addrs).await });
    }

    // Clipboard watcher (read side). Polls the OS clipboard every
    // 200ms, dedups, and routes any change through the same `Push`
    // command path the IPC `push` op uses — so dedup + lamport
    // allocation + send-to-peer all reuse existing logic.
    //
    // Android target excluded: there's no daemon-side clipboard API
    // (it'd require background read which the OS denies anyway).
    // `MainActivity` registers a `ClipboardManager` listener instead
    // and pushes via the FFI's `push_text`.
    #[cfg(not(target_os = "android"))]
    if disable_clipboard {
        tracing::info!(disable_clipboard, "Clipboard watcher disabled by config");
    } else {
        tracing::info!("Spawning clipboard watcher task");
        let sh = shared.clone();
        tasks.spawn(async move {
            tracing::info!("Clipboard watcher task started");
            if let Err(e) = clipboard_watcher_loop(sh).await {
                tracing::error!(error = %e, "clipboard_watcher_loop exited with error");
            }
            Ok(())
        });
    }

    // Ghost Timeout watchdog.
    // If we are in Discovering phase with a known peer, and 10 minutes
    // pass without reconnecting, drop the peer to prevent permanent ghosting.
    //
    // The pairing window is NOT opened here: it opens only on an explicit
    // `PairShow` IPC command. A watchdog re-opening it would keep the TOFU
    // window permanently open while unpaired (FS-040).
    {
        let state_rx = state_watch_rx.clone();
        let event_tx_clone = event_tx.clone();
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            let mut rx = state_rx;
            let mut last_discovering_with_peer: Option<std::time::Instant> = None;
            loop {
                // Only two fields matter here; a full `clone()` copied the
                // whole history (full item text) on every heartbeat publish.
                let discovering_with_peer = {
                    let state = rx.borrow_and_update();
                    state.phase == "discovering" && !state.peer_name.is_empty()
                };

                // Ghost Timeout Check
                if discovering_with_peer {
                    if let Some(start) = last_discovering_with_peer {
                        if Instant::now().duration_since(start) > Duration::from_secs(600) {
                            tracing::warn!("Ghost Timeout: 10 minutes elapsed without reconnection. Unpairing.");
                            let _ = event_tx_clone.try_send(Event::GhostTimeout);
                            last_discovering_with_peer = None;
                        }
                    } else {
                        last_discovering_with_peer = Some(Instant::now());
                    }
                } else {
                    last_discovering_with_peer = None;
                }

                let loop_start = Instant::now();
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    _ = rx.changed() => {},
                    () = tokio::time::sleep(Duration::from_secs(5)) => {}
                }

                // [REMEDIATION] Wake Jump Protection: If the loop paused for >30s,
                // we likely just woke up from sleep. Reset the timer.
                if loop_start.elapsed() > Duration::from_secs(30) {
                    last_discovering_with_peer = None;
                }
            }
            Ok(())
        });
    }

    // Battery watcher (desktop OSes; Android is event-driven via the FFI).
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    {
        let event_tx = event_tx.clone();
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            if let Err(e) = crate::battery::battery_watcher_loop(event_tx, shutdown).await {
                tracing::warn!(error = %e, "battery watcher loop exited");
            }
            Ok(())
        });
    }

    // FIX3 (synchronous security-wipe disk clear): tracks the last
    // `vault_wipe_gen` this loop has already reacted to, so it can tell a
    // fresh bump apart from one it already handled. Seeded from the current
    // snapshot (0 at a fresh boot) — same rationale as the vault
    // persister's own `initial_wipe_gen` above.
    let mut last_wipe_gen_sync: u64 = app.snapshot().vault_wipe_gen;

    // ── Main event loop ────────────────────────────────────────────
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            Some(event) = event_rx.recv() => {
                if let Event::HandshakeOk = event {
                    metrics.lock().await.on_handshake_ok();
                }
                if let Event::BatteryChangedSelf { level, charging } = &event {
                    shared.self_batt_level.store(*level, std::sync::atomic::Ordering::Relaxed);
                    shared.self_batt_charging.store(*charging, std::sync::atomic::Ordering::Relaxed);
                }
                // FluxMesh: only `GhostTimeout`/`PeerSeen` (FS-046 swap) ever
                // consult the secondary-peer set (see `App::other_linked_peers`),
                // so only refresh it for those — avoids an extra transport lock
                // on every other event. `App` stays sync/transport-free; this is
                // its one source of truth for "are other peers still linked".
                if matches!(event, Event::GhostTimeout | Event::PeerSeen { .. }) {
                    app.set_other_linked_peers(
                        transport.secondary_liveness().await.into_iter().map(|(id, _)| id),
                    );
                }
                let actions = app.handle(event.clone(), &*wall_clock);
                if !actions.is_empty() {
                    tracing::debug!(?event, ?actions, phase=?app.snapshot().phase, "FSM transition");
                }
                // FIX1 (P0 parked-payload leak): the silent-secondary-timeout
                // path (`heartbeat_loop`) has no direct access to `app` or
                // `outbox_stage`, so it routes its `Event::PeerRevoked`
                // through `event_tx` instead of calling `app.handle`
                // inline like `CmdOp::Revoke` does. Purge here too so both
                // producers of that event converge on the same cleanup.
                purge_dropped_pending_from_outbox_stage(&actions, &outbox_stage).await;
                // FIX3: a security trigger (untrusted-peer, ghost-timeout,
                // peer-swap — the only events reaching this arm that bump
                // `vault_wipe_gen`; `CmdOp::ClearHistory` also bumps it but is
                // handled entirely in `handle_driver_cmd`, never here, so it
                // can't misfire this block) just cleared `App`'s in-memory
                // history synchronously inside `app.handle` above. Mirror
                // that to disk and purge the outbox HERE — before `dispatch`
                // below runs `Action::EmitState` and publishes the new state
                // to subscribers — so a crash right after this point leaves
                // disk wiped (safe) rather than memory wiped with the
                // secret still recoverable from disk or re-offered via
                // resync. The persister's own gen-check stays as
                // belt-and-braces (see `persist_history_change`).
                sync_security_wipe_if_needed(
                    &app,
                    &mut last_wipe_gen_sync,
                    &outbox,
                    &outbox_stage,
                    &inflight,
                    keystore_dir.as_ref(),
                )
                .await;
                // Bug #9: the silent-secondary-timeout path is the other
                // producer of `Event::PeerRevoked` (see
                // `purge_dropped_pending_from_outbox_stage`'s doc comment) —
                // mirror its inflight purge here too, or a revoked-by-timeout
                // peer keeps getting retransmits.
                if let Event::PeerRevoked { peer_id } = &event {
                    purge_peer_from_inflight(*peer_id, &inflight).await;
                }
                dispatch(actions, &mut app, &mut seq_store, &shared).await;
                if matches!(event, Event::HandshakeOk) {
                    shared.greet_new_sessions(&app.config().peer_name_self).await;
                }
            }
            Some(driver_cmd) = cmd_rx.recv() => {
                match driver_cmd {
                    DriverCmd::PushImage { hash, png, preview } => {
                        use fluxsync_core::Clock;
                        let lamport = app.clock.tick();
                        let actions = app.handle(
                            Event::LocalClipboardChange {
                                hash,
                                kind: Kind::Image,
                                payload: png,
                                preview,
                                // DIR-P2-05 boundary: an image copied to the OS
                                // clipboard and picked up by this watcher (as
                                // opposed to an explicit `fluxctl push-image
                                // --sensitive` / mobile FFI push) is never
                                // marked sensitive — unlike text's
                                // `is_sensitive`, there is no image-content
                                // classifier, so a screenshotted secret is
                                // only protected when the caller explicitly
                                // flags it via the IPC push path.
                                sensitive: false,
                                lamport,
                            },
                            &*wall_clock,
                        );
                        let actions = gate_outbound(actions, &transport, &pending_pairs).await;
                        dispatch(actions, &mut app, &mut seq_store, &shared).await;
                    }
                    run_cmd @ DriverCmd::Run { .. } => {
                        handle_driver_cmd(run_cmd, &mut app, &mut seq_store, &shared).await;
                    }
                }
                // `CmdOp::ClearHistory` (handled inside `handle_driver_cmd`,
                // above) also bumps `vault_wipe_gen` — it is a user-requested
                // "clear history" action with its own already-correct,
                // SELECTIVE outbox purge (`outbox.remove_many` on exactly the
                // cleared hashes), not a security wipe, and must NOT also
                // trigger `sync_security_wipe_if_needed`'s blanket
                // `clear_all`. `App`'s `vault_wipe_gen` is one shared counter
                // across both `tokio::select!` arms, though, so without this
                // resync the event-loop arm's NEXT event (an unrelated
                // battery tick, say) would see the gen it didn't itself bump
                // and wipe the outbox anyway as collateral damage. Re-sync
                // the tracked baseline to whatever `app` holds now so only a
                // bump made BY the event-loop arm's own `app.handle` (the
                // real security triggers) is ever observed as "new".
                last_wipe_gen_sync = app.snapshot().vault_wipe_gen;
            }
        }
    }

    while tasks.join_next().await.is_some() {}
    Ok(())
}

/// Internal request from an IPC handler to the driver.
pub(super) enum DriverCmd {
    Run {
        op: CmdOp,
        reply: oneshot::Sender<CmdResponse>,
        req_id: u64,
    },
    /// Image copied to the local OS clipboard, forwarded by the clipboard
    /// watcher. Carries the PNG-encoded payload, the RGBA-derived dedup
    /// hash, and the history label. No IPC reply — fire-and-forget.
    PushImage {
        hash: [u8; 32],
        png: Vec<u8>,
        preview: String,
    },
}

// ─────────────────────────────────────────────────────────────────
// Action dispatch
// ─────────────────────────────────────────────────────────────────

/// M-DAEMON-11: bounded capacity for the daemon's central `Event` channel.
/// One mono-task consumer drains it; 1024 is orders of magnitude above any
/// legitimate burst (chunk reassembly already caps concurrent inbound items at
/// 5), so it only ever fills under a hostile flood — at which point `try_send`
/// drops with a warning instead of growing memory without bound.
const EVENT_CHANNEL_CAP: usize = 1024;

/// M-DAEMON-11: bounded capacity for the mDNS `DiscoveryEvent` channel. A
/// dropped resolve under flood is harmless — mDNS re-announces, and the
/// downstream discovery cache is itself capped at 256.
const DISCOVERY_CHANNEL_CAP: usize = 256;

/// The serial OS-clipboard writer, unless the clipboard is disabled by config
/// (hermetic tests, headless runs) or this is Android, whose app writes the
/// clipboard itself.
fn spawn_clipboard_writer(disable_clipboard: bool) -> Option<ClipboardWriter> {
    #[cfg(not(target_os = "android"))]
    if !disable_clipboard {
        match ClipboardWriter::spawn() {
            Ok(w) => return Some(w),
            Err(e) => tracing::error!(error = %e, "could not start the clipboard writer"),
        }
    }
    let _ = disable_clipboard;
    None
}
