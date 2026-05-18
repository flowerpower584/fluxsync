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

use crate::cmd::{Channel, CmdData, CmdOp, CmdRequest, CmdResponse, PeerEntry, Subscribe};
use crate::config::{DaemonConfig, TestPair};
use crate::discovery::{self, DiscoveryEvent};
use crate::handshake::{self, PairingWindow, TrustedPeer, TrustedSet};
use crate::ipc::{IpcConn, IpcServer};
use crate::logs::LogTail;
use crate::metrics::{DisconnectReason, MetricsTracker};
use crate::transport::{RecvFrame, Transport};
use anyhow::{anyhow, Context, Result};
use base32::Alphabet;
use fluxsync_core::{
    dedup::DedupRing, kind_of, Action, App, Config as CoreConfig, Event, LogEntry, LogLevel, State,
    WallClock,
};
use fluxsync_crypto::{fingerprint, Identity};
use fluxsync_proto::{
    ClipboardItem, Frame, Kind, Msg, MAX_CHUNK_DATA, MAX_PAYLOAD, PROTOCOL_VERSION,
};
use hex;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{broadcast, mpsc, oneshot, watch, Mutex};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

const BASE32_ALPHA: Alphabet = Alphabet::Rfc4648 { padding: false };

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
        last_peer_addr: _,
        test_pair,
    } = cfg;

    // ── App + channels ────────────────────────────────────────────
    let mut app = App::new(CoreConfig {
        peer_name_self: peer_name_self.clone(),
        charge_override,
        version: String::from(env!("CARGO_PKG_VERSION")),
        cipher: String::from("chacha20-poly1305"),
    });

    let initial = app.snapshot().clone();
    let (state_watch_tx, state_watch_rx) = watch::channel(initial);
    let (logs_bcast_tx, _) = broadcast::channel::<LogEntry>(64);
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Event>();
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<DriverCmd>();
    let log_tail = Arc::new(LogTail::new());

    // ── Trusted peers ─────────────────────────────────────────────
    // FS-039: persistent pairing. Reload the trusted set from
    // `peers.json` so a paired peer survives a daemon restart.
    let trusted: TrustedSet = Arc::new(Mutex::new(HashMap::new()));
    if let Some(dir) = keystore_dir.as_ref() {
        let loaded = load_trusted_peers(dir);
        let count = loaded.len();
        {
            let mut g = trusted.lock().await;
            for (peer_id, peer) in loaded {
                g.insert(peer_id, peer);
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

    // Last clipboard payload we wrote to the OS clipboard (i.e., received
    // from the peer). The clipboard watcher dedups against this so it
    // doesn't immediately read its own write back, fire LocalClipboardChange,
    // and ping-pong the same item back to the peer.
    let last_written_hashes: Arc<Mutex<VecDeque<[u8; 32]>>> =
        Arc::new(Mutex::new(VecDeque::with_capacity(10)));

    // Outbound items awaiting acks. Shared between the action dispatch
    // (inserts on SendItem), the inbound frame handler (removes on Ack),
    // and the transport loop's retransmit timer.
    let inflight: InflightMap = Arc::new(Mutex::new(HashMap::new()));

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
        // Add peer to trusted set under a placeholder pubkey so the
        // App's peer_name lookup paths still find an entry.
        trusted.lock().await.insert(
            peer_id,
            TrustedPeer {
                static_pub: [0u8; 32],
                name: peer_name.clone(),
            },
        );
        event_tx.send(Event::ToggleOn).ok();

        event_tx
            .send(Event::PeerSeen {
                peer_id,
                name: peer_name,
            })
            .ok();
        event_tx.send(Event::HandshakeOk).ok();
        event_tx
            .send(Event::BatteryChangedSelf {
                level: 80,
                charging: false,
            })
            .ok();
        event_tx
            .send(Event::BatteryChangedPeer {
                level: 80,
                charging: false,
            })
            .ok();
    }

    if let Some(addr) = cfg.last_peer_addr {
        transport.set_peer_addr(addr).await;
    }

    // Inform App about trusted peers for UI hints.
    {
        let g = trusted.lock().await;
        if let Some(peer) = g.values().next() {
            tracing::info!(peer = %peer.name, "Boot: informing UI about trusted peer");
            event_tx
                .send(Event::SetTrustedPeer {
                    name: peer.name.clone(),
                })
                .ok();
        }
    }

    // ── State-Aware Boot: Auto-toggle ON if requested ─────────────
    if start_on {
        tracing::info!("State-Aware Boot: auto-starting sync");
        event_tx.send(Event::ToggleOn).ok();
    }

    // ── Long-lived tasks ──────────────────────────────────────────
    let mut tasks = JoinSet::new();

    // IPC.
    let ipc_server = IpcServer::bind(&ipc_path)
        .await
        .with_context(|| format!("bind ipc socket {}", ipc_path.display()))?;
    {
        let cmd_tx = cmd_tx.clone();
        let state_rx = state_watch_rx.clone();
        let logs_tx = logs_bcast_tx.clone();
        let log_tail = log_tail.clone();
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            ipc_accept_loop(ipc_server, cmd_tx, state_rx, logs_tx, log_tail, shutdown).await
        });
    }

    // Transport receive loop.
    {
        let transport = transport.clone();
        let identity = identity.clone();
        let trusted = trusted.clone();
        let pending = pending_initiator_tx.clone();
        let window = pairing_window.clone();
        let event_tx = event_tx.clone();
        let shutdown = shutdown.clone();
        let kd = keystore_dir.clone();
        let metrics = metrics.clone();
        let inflight = inflight.clone();
        tasks.spawn(async move {
            transport_recv_loop(
                transport, identity, trusted, window, pending, event_tx, shutdown, kd, metrics,
                inflight,
            )
            .await
        });
    }

    // Heartbeat loop.
    {
        let transport = transport.clone();
        let event_tx = event_tx.clone();
        let shutdown = shutdown.clone();
        let metrics = metrics.clone();
        tasks.spawn(async move {
            if let Err(e) = heartbeat_loop(transport, event_tx, shutdown, metrics).await {
                tracing::warn!(error = %e, "heartbeat loop exited");
            }
            Ok(())
        });
    }

    // mDNS discovery (skipped in test mode or when disabled).
    let mut _mdns_daemon = None;
    let we_are_test_mode = transport.session.lock().await.is_some();
    if !disable_mdns && !we_are_test_mode {
        let (disc_tx, disc_rx) = mpsc::unbounded_channel::<DiscoveryEvent>();
        let bind_ip: std::net::IpAddr = udp_bind
            .parse()
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
                _mdns_daemon = Some(daemon);
                let identity = identity.clone();
                let trusted = trusted.clone();
                let transport = transport.clone();
                let pending = pending_initiator_tx.clone();
                let event_tx = event_tx.clone();
                let shutdown = shutdown.clone();
                tasks.spawn(async move {
                    discovery_dispatcher(
                        disc_rx, identity, trusted, transport, pending, event_tx, shutdown,
                    )
                    .await
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "mDNS unavailable; pairing requires --addr in pair-accept");
            }
        }
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
        let cmd_tx = cmd_tx.clone();
        let transport = transport.clone();
        let last_written = last_written_hashes.clone();
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            tracing::info!("Clipboard watcher task started");
            if let Err(e) = clipboard_watcher_loop(transport, cmd_tx, last_written, shutdown).await
            {
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
                let state = rx.borrow().clone();

                // Ghost Timeout Check
                if state.phase == "discovering" && !state.peer_name.is_empty() {
                    if let Some(start) = last_discovering_with_peer {
                        if Instant::now().duration_since(start) > Duration::from_secs(600) {
                            tracing::warn!("Ghost Timeout: 10 minutes elapsed without reconnection. Unpairing.");
                            let _ = event_tx_clone.send(Event::GhostTimeout);
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

    // Battery watcher.
    #[cfg(target_os = "macos")]
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

    // ── Main event loop ────────────────────────────────────────────
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            Some(event) = event_rx.recv() => {
                if let Event::HandshakeOk = event {
                    metrics.lock().await.on_handshake_ok();
                }
                let actions = app.handle(event.clone(), &*wall_clock);
                if !actions.is_empty() {
                    tracing::debug!(?event, ?actions, phase=?app.snapshot().phase, "FSM transition");
                }
                dispatch(actions, &mut app, &transport, &trusted, keystore_dir.as_ref(), &state_watch_tx, &logs_bcast_tx, &log_tail, &last_written_hashes, &metrics, &inflight).await;
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
                                sensitive: false,
                                lamport,
                            },
                            &*wall_clock,
                        );
                        dispatch(actions, &mut app, &transport, &trusted, keystore_dir.as_ref(), &state_watch_tx, &logs_bcast_tx, &log_tail, &last_written_hashes, &metrics, &inflight).await;
                    }
                    run_cmd => {
                        handle_driver_cmd(
                            run_cmd,
                            &mut app,
                            &wall_clock,
                            &identity,
                            &trusted,
                            &pairing_window,
                            &transport,
                            &pending_initiator_tx,
                            &event_tx,
                            &state_watch_tx,
                            &logs_bcast_tx,
                            &log_tail,
                            &last_written_hashes,
                            keystore_dir.as_ref(),
                            &udp_bind,
                            udp_port,
                            &metrics,
                            &inflight,
                        ).await;
                    }
                }
            }
        }
    }

    while tasks.join_next().await.is_some() {}
    Ok(())
}

/// Internal request from an IPC handler to the driver.
enum DriverCmd {
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

#[allow(clippy::too_many_arguments, clippy::cast_possible_truncation)]
async fn dispatch(
    actions: Vec<Action>,
    app: &mut App,
    transport: &Arc<Transport>,
    trusted: &TrustedSet,
    _keystore_dir: Option<&std::path::PathBuf>,
    state_watch_tx: &watch::Sender<State>,
    logs_bcast_tx: &broadcast::Sender<LogEntry>,
    log_tail: &Arc<LogTail>,
    last_written_hashes: &Arc<Mutex<VecDeque<[u8; 32]>>>,
    metrics: &Arc<Mutex<MetricsTracker>>,
    inflight: &InflightMap,
) {
    for action in actions {
        tracing::debug!(?action, "dispatching action");
        match action {
            Action::EmitState => {
                let m = metrics.lock().await.snapshot();
                app.set_metrics(Some(m));
                let _ = state_watch_tx.send(app.snapshot().clone());
            }
            Action::EmitLog(entry) => {
                tracing::info!(level = ?entry.level, msg = %entry.msg, "log");
                log_tail.push(entry.clone());
                let _ = logs_bcast_tx.send(entry);
            }
            Action::SendItem {
                hash,
                kind,
                payload,
                sensitive,
            } => {
                use fluxsync_core::Clock;

                let payload = if payload.len() > MAX_PAYLOAD {
                    // Truncating a PNG yields garbage, but a payload over
                    // the 16 MiB cap can't go on the wire either — the
                    // watcher already refuses oversized images upstream,
                    // so this only guards text and is effectively dead
                    // code for images.
                    tracing::warn!(size = payload.len(), "payload too large; truncating");
                    payload[..MAX_PAYLOAD].to_vec()
                } else {
                    payload
                };

                // Build every datagram for this item up front, encoded.
                // The same bytes are kept in the inflight table so the
                // retransmit timer can re-send them verbatim until acked.
                let mut frames: Vec<Vec<u8>> = Vec::new();
                if payload.len() <= MAX_CHUNK_DATA {
                    let item = ClipboardItem {
                        lamport: app.clock.now(),
                        hash,
                        kind,
                        payload,
                        sensitive,
                        wall_time_ms: 0,
                    };
                    let frame = Frame {
                        version: PROTOCOL_VERSION,
                        msg: Msg::ClipboardItem(item),
                    };
                    match fluxsync_proto::encode(&frame) {
                        Ok(bytes) => frames.push(bytes),
                        Err(_) => tracing::error!("SendItem: CBOR encode failed"),
                    }
                } else {
                    // Large payload: a header frame (empty payload), then
                    // one frame per chunk.
                    let header = ClipboardItem {
                        lamport: app.clock.now(),
                        hash,
                        kind,
                        payload: Vec::new(),
                        sensitive,
                        wall_time_ms: 0,
                    };
                    let frame = Frame {
                        version: PROTOCOL_VERSION,
                        msg: Msg::ClipboardItem(header),
                    };
                    if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                        frames.push(bytes);
                    }

                    let chunks: Vec<_> = payload.chunks(MAX_CHUNK_DATA).collect();
                    let total = chunks.len() as u16;
                    for (idx, data) in chunks.into_iter().enumerate() {
                        let chunk = fluxsync_proto::Chunk {
                            item_id: hash,
                            idx: idx as u16,
                            total,
                            data: data.to_vec(),
                        };
                        let frame = Frame {
                            version: PROTOCOL_VERSION,
                            msg: Msg::Chunk(chunk),
                        };
                        if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                            frames.push(bytes);
                        }
                    }
                }

                if frames.is_empty() {
                    tracing::error!("SendItem: nothing to send (encode failed)");
                } else {
                    let peer = *transport.peer_addr.lock().await;
                    let has_session = transport.session.lock().await.is_some();
                    tracing::info!(
                        ?peer,
                        has_session,
                        frames = frames.len(),
                        "SendItem: sending item"
                    );
                    let multi = frames.len() > 1;
                    for (i, bytes) in frames.iter().enumerate() {
                        if let Err(e) = transport.send_encrypted(bytes).await {
                            tracing::error!(error = %e, "SendItem: send_encrypted FAILED");
                        }
                        // Pace multi-frame (chunked) items to avoid UDP
                        // congestion. A flat 10 ms per chunk would cost
                        // ~163 s for a 16 MiB image (16384 chunks); burst
                        // 16 frames then pause 2 ms instead (~2 s total).
                        if multi && (i + 1) % 16 == 0 {
                            tokio::time::sleep(Duration::from_millis(2)).await;
                        }
                    }
                    // Retransmit until the peer acks this hash. Without
                    // this a single dropped datagram loses the item — UDP
                    // gives no delivery guarantee.
                    inflight.lock().await.insert(
                        hash,
                        Inflight {
                            frames,
                            attempts: 0,
                            last_sent: Instant::now(),
                        },
                    );
                }
            }
            Action::AckItem { hash } => {
                use fluxsync_core::Clock;
                let frame = Frame {
                    version: PROTOCOL_VERSION,
                    msg: Msg::Ack(fluxsync_proto::Ack {
                        lamport: app.clock.now(),
                        hash,
                    }),
                };
                if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                    let _ = transport.send_encrypted(&bytes).await;
                }
            }
            Action::WriteClipboard { kind, payload } => {
                // Mark the hash before writing so the watcher's next
                // poll skips this exact payload — otherwise we'd read
                // back our own write, fire a LocalClipboardChange, and
                // ping-pong the same item back to the peer. The hash is
                // taken over the clipboard's *canonical* form (trimmed
                // UTF-8 for text, RGBA pixels for images) so it matches
                // what the watcher computes on read-back — a re-encoded
                // PNG would hash differently.
                match kind {
                    Kind::Image => {
                        #[cfg(not(target_os = "android"))]
                        match decode_png_to_rgba(&payload) {
                            Some((w, h, rgba)) => {
                                let hash = image_rgba_hash(w, h, &rgba);
                                {
                                    let mut g = last_written_hashes.lock().await;
                                    g.push_back(hash);
                                    if g.len() > 10 {
                                        g.pop_front();
                                    }
                                }
                                tokio::task::spawn_blocking(move || {
                                    match arboard::Clipboard::new() {
                                        Ok(mut cb) => {
                                            let img = arboard::ImageData {
                                                width: w as usize,
                                                height: h as usize,
                                                bytes: std::borrow::Cow::Owned(rgba),
                                            };
                                            if let Err(e) = cb.set_image(img) {
                                                tracing::warn!(error = %e, "clipboard set_image failed");
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(error = %e, "clipboard init failed");
                                        }
                                    }
                                });
                            }
                            None => tracing::warn!("WriteClipboard: PNG decode failed"),
                        }
                        #[cfg(target_os = "android")]
                        {
                            // Android writes images from `MainActivity` by
                            // observing `state.history`; nothing to do here.
                            let _ = payload;
                        }
                    }
                    _ => {
                        let text = String::from_utf8_lossy(&payload).to_string();
                        let hash = clipboard_dedup_hash(&text);
                        {
                            let mut g = last_written_hashes.lock().await;
                            g.push_back(hash);
                            if g.len() > 10 {
                                g.pop_front();
                            }
                        }
                        #[cfg(not(target_os = "android"))]
                        tokio::task::spawn_blocking(move || match arboard::Clipboard::new() {
                            Ok(mut cb) => {
                                if let Err(e) = cb.set_text(text) {
                                    tracing::warn!(error = %e, "clipboard set_text failed");
                                }
                            }
                            Err(e) => tracing::warn!(error = %e, "clipboard init failed"),
                        });
                        #[cfg(target_os = "android")]
                        {
                            // Android writes the OS clipboard from
                            // `MainActivity`; the daemon just records the
                            // hash for dedup symmetry with desktop.
                            let _ = text;
                        }
                    }
                }
            }
            Action::OpenSession => {
                // Both sides fire OpenSession on the Handshaking → Linked
                // transition. Take advantage of that to swap friendly
                // names: the Noise handshake only carries static pubkeys,
                // so without this the responder shows the TOFU placeholder
                // ("New Peer") instead of the peer's real device name.
                let name = app.config().peer_name_self.clone();
                let frame = Frame {
                    version: PROTOCOL_VERSION,
                    msg: Msg::Hello(fluxsync_proto::Hello { name }),
                };
                if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                    if let Err(e) = transport.send_encrypted(&bytes).await {
                        tracing::warn!(error = %e, "send hello failed");
                    }
                }
            }
            Action::CloseSession => {
                // [FIX] Handshake Ghosting: inform peer before dropping session
                let frame = Frame {
                    version: PROTOCOL_VERSION,
                    msg: Msg::Bye,
                };
                if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                    let _ = transport.send_encrypted(&bytes).await;
                }
                transport.drop_session().await;
            }
            Action::SendBattery { level, charging } => {
                let frame = Frame {
                    version: PROTOCOL_VERSION,
                    msg: Msg::BatteryStatus(fluxsync_proto::BatteryStatus {
                        lamport: 0,
                        level,
                        charging,
                    }),
                };
                if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                    let _ = transport.send_encrypted(&bytes).await;
                }
            }
            Action::DropPeer => {
                // [FIX] Handshake Ghosting: inform peer before dropping session
                let frame = Frame {
                    version: PROTOCOL_VERSION,
                    msg: Msg::Bye,
                };
                if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                    let _ = transport.send_encrypted(&bytes).await;
                }

                tracing::info!("DropPeer: clearing all trusted peers from memory");
                trusted.lock().await.clear();
                transport.drop_session().await;
            }
            Action::SendHandshake { .. } => {
                metrics.lock().await.on_handshake_start();
            }
            Action::StartDiscovery | Action::StopDiscovery | Action::BurstReplay => {
                // FSM-emitted but driven by discovery / pair-accept paths
                // directly in v0.1.1. v0.1.2 may wire these explicitly.
            }
        }
    }
}

/// Bump the FSM out of `Idle` if it's still there. Pairing operations
/// call this so that when the responder fires `HandshakeOk`, the FSM is
/// already in `Discovering`/`Handshaking` and the
/// `(Handshaking → Linked)` transition can fire — without it,
/// `(Idle, HandshakeOk)` is a no-op (see `fsm.rs::transition`) and the
/// Noise tunnel comes up but the FSM never reaches the `Linked` phase
/// where clipboard SendItem/WriteClipboard actions are emitted.
#[allow(clippy::too_many_arguments)]
async fn ensure_online(
    app: &mut App,
    wall: &Arc<dyn WallClock + Send + Sync>,
    transport: &Arc<Transport>,
    trusted: &TrustedSet,
    keystore_dir: Option<&std::path::PathBuf>,
    state_watch_tx: &watch::Sender<State>,
    logs_bcast_tx: &broadcast::Sender<LogEntry>,
    log_tail: &Arc<LogTail>,
    last_written_hashes: &Arc<Mutex<VecDeque<[u8; 32]>>>,
    metrics: &Arc<Mutex<MetricsTracker>>,
    inflight: &InflightMap,
) {
    if app.snapshot().on {
        return;
    }
    let actions = app.handle(Event::ToggleOn, &**wall);
    dispatch(
        actions,
        app,
        transport,
        trusted,
        keystore_dir,
        state_watch_tx,
        logs_bcast_tx,
        log_tail,
        last_written_hashes,
        metrics,
        inflight,
    )
    .await;
}

// ─────────────────────────────────────────────────────────────────
// IPC command dispatch
// ─────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn handle_driver_cmd(
    cmd: DriverCmd,
    app: &mut App,
    wall: &Arc<dyn WallClock + Send + Sync>,
    identity: &Identity,
    trusted: &TrustedSet,
    pairing_window: &PairingWindow,
    transport: &Arc<Transport>,
    pending_initiator_tx: &Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
    event_tx: &mpsc::UnboundedSender<Event>,
    state_watch_tx: &watch::Sender<State>,
    logs_bcast_tx: &broadcast::Sender<LogEntry>,
    log_tail: &Arc<LogTail>,
    last_written_hashes: &Arc<Mutex<VecDeque<[u8; 32]>>>,
    keystore_dir: Option<&std::path::PathBuf>,
    udp_bind: &str,
    udp_port: u16,
    metrics: &Arc<Mutex<MetricsTracker>>,
    inflight: &InflightMap,
) {
    let DriverCmd::Run { op, reply, req_id } = cmd else {
        return;
    };
    let resp = match op {
        CmdOp::Status => {
            let m = metrics.lock().await.snapshot();
            app.set_metrics(Some(m));
            CmdResponse::ok(
                req_id,
                Some(CmdData::State(Box::new(app.snapshot().clone()))),
            )
        }
        CmdOp::Reconnect {} => {
            tracing::info!("IPC: manual reconnect requested");
            transport.drop_session().await;
            let _ = event_tx.send(Event::PeerLost);
            CmdResponse::ok(req_id, Some(CmdData::Pong))
        }
        CmdOp::Push { text } => {
            use fluxsync_core::Clock;
            tracing::info!(len = text.len(), "IPC: push requested from local");
            let text = text.trim().to_string();
            if !text.is_empty() {
                let kind = kind_of(&text);
                let sensitive = fluxsync_core::is_sensitive(&text);
                let hash = DedupRing::hash(text.as_bytes());
                let lamport = app.clock.tick();
                let actions = app.handle(
                    Event::LocalClipboardChange {
                        hash,
                        kind,
                        payload: text.as_bytes().to_vec(),
                        preview: text,
                        sensitive,
                        lamport,
                    },
                    &**wall,
                );
                tracing::debug!(?actions, "LocalClipboardChange results");
                dispatch(
                    actions,
                    app,
                    transport,
                    trusted,
                    keystore_dir,
                    state_watch_tx,
                    logs_bcast_tx,
                    log_tail,
                    last_written_hashes,
                    metrics,
                    inflight,
                )
                .await;
            }
            CmdResponse::ok(req_id, None)
        }
        CmdOp::Pull => {
            let last = app.snapshot().history.first().cloned();
            CmdResponse::ok(req_id, Some(CmdData::Pull(last)))
        }
        CmdOp::Tail { n } => {
            let entries = log_tail.snapshot(n);
            CmdResponse::ok(req_id, Some(CmdData::Tail(entries)))
        }
        CmdOp::Peers => {
            let addr = *transport.peer_addr.lock().await;
            let peer = peer_entry(app.snapshot(), addr);
            CmdResponse::ok(req_id, Some(CmdData::Peers(peer.into_iter().collect())))
        }
        CmdOp::SetThreshold { value } => match app.state.set_threshold(value) {
            Ok(()) => {
                let actions = app.handle(
                    Event::BatteryChangedSelf {
                        level: app.snapshot().battery_level,
                        charging: app.snapshot().charging,
                    },
                    &**wall,
                );
                dispatch(
                    actions,
                    app,
                    transport,
                    trusted,
                    keystore_dir,
                    state_watch_tx,
                    logs_bcast_tx,
                    log_tail,
                    last_written_hashes,
                    metrics,
                    inflight,
                )
                .await;
                CmdResponse::ok(req_id, None)
            }
            Err(e) => CmdResponse::err(req_id, e.to_string()),
        },
        CmdOp::SetChargeOverride { value } => {
            app.set_charge_override(value);
            // Re-evaluate status with current battery so the new
            // charge_override takes effect immediately (and the EmitState
            // it triggers pushes the updated value to subscribers).
            let actions = app.handle(
                Event::BatteryChangedSelf {
                    level: app.snapshot().battery_level,
                    charging: app.snapshot().charging,
                },
                &**wall,
            );
            dispatch(
                actions,
                app,
                transport,
                trusted,
                keystore_dir,
                state_watch_tx,
                logs_bcast_tx,
                log_tail,
                last_written_hashes,
                metrics,
                inflight,
            )
            .await;
            CmdResponse::ok(req_id, None)
        }
        CmdOp::DebugCapture {} | CmdOp::Shutdown {} => CmdResponse::ok(req_id, None),
        CmdOp::Unpair {} => {
            tracing::info!("Manual unpair requested via IPC");
            trusted.lock().await.clear();
            if let Some(dir) = keystore_dir {
                if let Err(e) = save_current_peers(dir, trusted, transport).await {
                    tracing::warn!(error = %e, "failed to persist unpair to keystore");
                }
            }
            let actions = app.handle(Event::ManualUnpair, &**wall);
            dispatch(
                actions,
                app,
                transport,
                trusted,
                keystore_dir,
                state_watch_tx,
                logs_bcast_tx,
                log_tail,
                last_written_hashes,
                metrics,
                inflight,
            )
            .await;
            CmdResponse::ok(req_id, None)
        }
        CmdOp::Toggle { on } => {
            let ev = if on {
                Event::ToggleOn
            } else {
                Event::ToggleOff
            };
            let actions = app.handle(ev, &**wall);
            dispatch(
                actions,
                app,
                transport,
                trusted,
                keystore_dir,
                state_watch_tx,
                logs_bcast_tx,
                log_tail,
                last_written_hashes,
                metrics,
                inflight,
            )
            .await;
            CmdResponse::ok(req_id, None)
        }
        CmdOp::SetSelfBattery { level, charging } => {
            let actions = app.handle(Event::BatteryChangedSelf { level, charging }, &**wall);
            dispatch(
                actions,
                app,
                transport,
                trusted,
                keystore_dir,
                state_watch_tx,
                logs_bcast_tx,
                log_tail,
                last_written_hashes,
                metrics,
                inflight,
            )
            .await;
            CmdResponse::ok(req_id, None)
        }
        CmdOp::Revoke { peer_id } => {
            let Ok(bytes) = hex::decode(&peer_id) else {
                return reply_err(reply, req_id, "bad hex peer_id");
            };
            let arr: [u8; 32] = match bytes.try_into() {
                Ok(a) => a,
                Err(_) => return reply_err(reply, req_id, "expected 32-byte peer_id"),
            };
            trusted.lock().await.remove(&arr);
            if let Some(dir) = keystore_dir {
                if let Err(e) = save_current_peers(dir, trusted, transport).await {
                    tracing::warn!(error = %e, "failed to persist revocation to keystore");
                }
            }
            let actions = app.handle(Event::ManualUnpair, &**wall);
            dispatch(
                actions,
                app,
                transport,
                trusted,
                keystore_dir,
                state_watch_tx,
                logs_bcast_tx,
                log_tail,
                last_written_hashes,
                metrics,
                inflight,
            )
            .await;
            CmdResponse::ok(req_id, None)
        }
        CmdOp::SetLaunchAtLogin { value: _ } => {
            // [TODO] Persistence of this preference in config/peers.json
            CmdResponse::ok(req_id, None)
        }
        CmdOp::SetPreferLan { value: _ } => {
            // [TODO] Pass to transport layer
            CmdResponse::ok(req_id, None)
        }

        CmdOp::PairShow {} => {
            // Refuse to open the TOFU window while already paired: a
            // re-share of the QR would otherwise let a LAN attacker
            // handshake-join the trusted set. The proper two-step
            // pairing (pending_peer + pair_confirm) is tracked as FS-052.
            if !trusted.lock().await.is_empty() {
                return reply_err(reply, req_id, "already_paired");
            }
            let static_pub = identity.public_key();
            let peer_id = identity.peer_id();
            let pubkey_b32 = base32::encode(BASE32_ALPHA, &static_pub);
            let words = fingerprint(&static_pub);
            let words_vec: Vec<String> = words.iter().map(|s| (*s).to_string()).collect();
            let addr_hint = local_lan_addr(udp_bind, udp_port);
            let uri = build_pair_uri(&pubkey_b32, &addr_hint, &words_vec);
            // Open the TOFU window so the peer that scans this QR is
            // accepted on first handshake even though we don't know its
            // pubkey yet. Kept short (see `handshake::PAIRING_WINDOW`) so
            // a stale QR or a drive-by LAN handshake can't be exploited.
            *pairing_window.lock().await = Some(Instant::now() + handshake::PAIRING_WINDOW);
            tracing::info!("pairing window opened (90s)");
            // Showing the QR is implicit "I want to sync" — bump the
            // FSM out of Idle so when the responder fires HandshakeOk
            // the (Handshaking → Linked) transition can fire. Without
            // this, (Idle, HandshakeOk) is a no-op and clipboard sync
            // stays dead even though the Noise tunnel is up.
            ensure_online(
                app,
                wall,
                transport,
                trusted,
                keystore_dir,
                state_watch_tx,
                logs_bcast_tx,
                log_tail,
                last_written_hashes,
                metrics,
                inflight,
            )
            .await;
            CmdResponse::ok(
                req_id,
                Some(CmdData::PairInfo {
                    peer_id_hex: hex::encode(peer_id),
                    pubkey_b32,
                    fingerprint_words: words_vec,
                    addr_hint,
                    uri,
                }),
            )
        }
        CmdOp::PairFromUri { uri, name } => {
            let parsed = match parse_pair_uri(&uri) {
                Ok(p) => p,
                Err(e) => return reply_err(reply, req_id, &format!("bad pair uri: {e}")),
            };
            let Some(bytes) = base32::decode(BASE32_ALPHA, &parsed.pubkey_b32) else {
                return reply_err(reply, req_id, "bad base32 pubkey in uri");
            };
            let static_pub: [u8; 32] = match bytes.try_into() {
                Ok(a) => a,
                Err(_) => return reply_err(reply, req_id, "expected 32-byte pubkey"),
            };
            let peer_id = handshake::peer_id_for(&static_pub);
            trusted.lock().await.insert(
                peer_id,
                TrustedPeer {
                    static_pub,
                    name: name.clone(),
                },
            );

            // Persist the new peer to disk immediately.
            if let Some(dir) = keystore_dir {
                let mut stored = crate::keystore::load_peers(dir).unwrap_or_default();
                // Dedup by peer_id_hex
                let peer_id_hex = hex::encode(peer_id);
                stored.retain(|p| p.peer_id_hex != peer_id_hex);
                stored.push(crate::keystore::StoredPeer {
                    peer_id_hex,
                    static_pub_hex: hex::encode(static_pub),
                    name: name.clone(),
                    last_addr: None,
                });
                if let Err(e) = crate::keystore::save_peers(dir, &stored) {
                    tracing::warn!(error = %e, "failed to persist peer to keystore");
                }
            }

            // Scanning a peer's QR is implicit "I want to sync". Bump
            // the FSM into Discovering before we send msg1 so the
            // (Handshaking → Linked) chain can fire when msg2 arrives.
            ensure_online(
                app,
                wall,
                transport,
                trusted,
                keystore_dir,
                state_watch_tx,
                logs_bcast_tx,
                log_tail,
                last_written_hashes,
                metrics,
                inflight,
            )
            .await;
            // URI always carries an address hint; if it parses, kick off
            // the initiator immediately. If not, the trust has been
            // recorded and discovery (or a later pair-accept --addr) can
            // drive the handshake.
            if let Some(addr_str) = parsed.addr {
                if let Ok(parsed_addr) = addr_str.parse::<SocketAddr>() {
                    start_initiator(
                        identity.clone(),
                        static_pub,
                        parsed_addr,
                        peer_id,
                        name,
                        transport.clone(),
                        pending_initiator_tx.clone(),
                        event_tx.clone(),
                    )
                    .await;
                } else {
                    tracing::warn!(addr = %addr_str, "pair uri addr unparseable; deferring to discovery");
                }
            }
            CmdResponse::ok(req_id, None)
        }
        CmdOp::PairAccept {
            pubkey_b32,
            name,
            addr,
        } => {
            let Some(bytes) = base32::decode(BASE32_ALPHA, &pubkey_b32) else {
                return reply_err(reply, req_id, "bad base32 pubkey");
            };
            let static_pub: [u8; 32] = match bytes.try_into() {
                Ok(a) => a,
                Err(_) => return reply_err(reply, req_id, "expected 32-byte pubkey"),
            };
            let peer_id = handshake::peer_id_for(&static_pub);
            trusted.lock().await.insert(
                peer_id,
                TrustedPeer {
                    static_pub,
                    name: name.clone(),
                },
            );

            // Persist the new peer to disk immediately.
            if let Some(dir) = keystore_dir {
                let mut stored = crate::keystore::load_peers(dir).unwrap_or_default();
                // Dedup by peer_id_hex
                let peer_id_hex = hex::encode(peer_id);
                stored.retain(|p| p.peer_id_hex != peer_id_hex);
                stored.push(crate::keystore::StoredPeer {
                    peer_id_hex,
                    static_pub_hex: hex::encode(static_pub),
                    name: name.clone(),
                    last_addr: None,
                });
                if let Err(e) = crate::keystore::save_peers(dir, &stored) {
                    tracing::warn!(error = %e, "failed to persist peer to keystore");
                }
            }

            // Same intent as PairFromUri: caller wants the link live.
            ensure_online(
                app,
                wall,
                transport,
                trusted,
                keystore_dir,
                state_watch_tx,
                logs_bcast_tx,
                log_tail,
                last_written_hashes,
                metrics,
                inflight,
            )
            .await;

            // If addr supplied, kick off the initiator immediately
            // (skips mDNS discovery — useful for tests + for first-pair).
            if let Some(addr_str) = addr {
                match addr_str.parse::<SocketAddr>() {
                    Ok(parsed) => {
                        start_initiator(
                            identity.clone(),
                            static_pub,
                            parsed,
                            peer_id,
                            name,
                            transport.clone(),
                            pending_initiator_tx.clone(),
                            event_tx.clone(),
                        )
                        .await;
                    }
                    Err(_) => return reply_err(reply, req_id, "bad addr"),
                }
            }
            CmdResponse::ok(req_id, None)
        }
    };
    let _ = reply.send(resp);
}

fn reply_err(reply: oneshot::Sender<CmdResponse>, id: u64, msg: &str) {
    let _ = reply.send(CmdResponse::err(id, msg));
}

fn peer_entry(state: &State, addr: Option<SocketAddr>) -> Option<PeerEntry> {
    if state.peer_name.is_empty() {
        return None;
    }
    Some(PeerEntry {
        peer_id: String::from("paired"),
        name: state.peer_name.clone(),
        addr: addr.map(|a| a.to_string()).unwrap_or_default(),
        link_latency_ms: state.link_latency_ms,
        battery: state.peer_battery,
        charging: state.peer_charging,
        linked: state.status != fluxsync_core::Status::Inactive,
    })
}

// ─────────────────────────────────────────────────────────────────
// Transport receive loop — type-byte dispatch
// ─────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn transport_recv_loop(
    transport: Arc<Transport>,
    identity: Identity,
    trusted: TrustedSet,
    pairing_window: PairingWindow,
    pending_initiator_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
    event_tx: mpsc::UnboundedSender<Event>,
    shutdown: CancellationToken,
    keystore_dir: Option<PathBuf>,
    metrics: Arc<Mutex<MetricsTracker>>,
    inflight: InflightMap,
) -> Result<()> {
    let mut buf = vec![0u8; 65535];
    let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mut cleanup_interval = tokio::time::interval(Duration::from_secs(5));
    let mut retransmit_interval = tokio::time::interval(RETRANSMIT_INTERVAL);

    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            _ = retransmit_interval.tick() => {
                // Re-send any clipboard item the peer hasn't acked yet.
                // Frames whose item exceeds MAX_RETRANSMIT are dropped.
                let mut to_send: Vec<Vec<u8>> = Vec::new();
                {
                    let mut map = inflight.lock().await;
                    let mut done: Vec<[u8; 32]> = Vec::new();
                    for (hash, item) in map.iter_mut() {
                        if item.last_sent.elapsed() < RETRANSMIT_INTERVAL {
                            continue;
                        }
                        if item.attempts >= MAX_RETRANSMIT {
                            tracing::warn!(
                                item = ?&hash[..6],
                                "item dropped: peer never acked after max retransmits"
                            );
                            done.push(*hash);
                            continue;
                        }
                        item.attempts += 1;
                        item.last_sent = Instant::now();
                        tracing::debug!(
                            item = ?&hash[..6],
                            attempt = item.attempts,
                            "retransmitting unacked item"
                        );
                        to_send.extend(item.frames.iter().cloned());
                    }
                    for h in done {
                        map.remove(&h);
                    }
                }
                for bytes in &to_send {
                    let _ = transport.send_encrypted(bytes).await;
                }
            }
            _ = cleanup_interval.tick() => {
                let mut map = reassembly.lock().await;
                map.retain(|hash, r| {
                    let total_age = r.first_seen.elapsed();
                    let idle_age = r.last_update.elapsed();
                    let keep = total_age < Duration::from_secs(60) && idle_age < Duration::from_secs(5);
                    if !keep {
                        tracing::warn!(
                            item = ?&hash[..6],
                            chunks = ?r.chunks.iter().filter(|x| x.is_some()).count(),
                            total = ?r.chunks.len(),
                            "Reassembly timeout: dropping incomplete item (data loss due to packet loss)"
                        );
                    }
                    keep
                });
            }
            res = transport.recv(&mut buf) => {
                let frame = match res {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::warn!(error = %e, "transport recv error");
                        continue;
                    }
                };
                match frame {
                    RecvFrame::HandshakeInit { from, msg } => {
                        if transport.session.lock().await.is_some() {
                            // [FIX] Session Stability: NEVER accept a re-handshake while
                            // a session is active. The Android re-initiates handshakes
                            // every ~15s via mDNS rediscovery, which would destroy
                            // the Noise session and break Mac→Android clipboard sync.
                            //
                            // If the peer genuinely crashes/restarts, the heartbeat
                            // timeout (in heartbeat_loop) will fire Event::PeerLost,
                            // which drops the session via CloseSession. After that,
                            // transport.session will be None and the next HandshakeInit
                            // will be accepted normally.
                            tracing::debug!(
                                incoming=?from,
                                "HandshakeInit ignored: session already active (peer will re-pair after heartbeat timeout)"
                            );
                            continue;
                        }
                        let id = identity.clone();
                        let tr = transport.clone();
                        let trusted = trusted.clone();
                        let window = pairing_window.clone();
                        let evt = event_tx.clone();
                        let kd = keystore_dir.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handshake::run_responder(id, msg, from, tr, trusted, window, evt, kd).await {
                                tracing::warn!(error = %e, "responder failed");
                            }
                        });
                    }
                    RecvFrame::HandshakeResp { msg, .. } => {
                        let g = pending_initiator_tx.lock().await;
                        if let Some(tx) = g.as_ref() {
                            let _ = tx.send(msg);
                        } else {
                            tracing::debug!("HandshakeResp with no pending initiator");
                        }
                    }
                    RecvFrame::Encrypted { from, plaintext } => {
                        // ROAMING persistence: if the transport just updated its peer_addr,
                        // persist it to the keystore.
                        if let Some(dir) = &keystore_dir {
                            let current_p = *transport.peer_addr.lock().await;
                            if current_p == Some(from) {
                                // Decryption succeeded (implicit in RecvFrame::Encrypted)
                                // and the address matches the transport's peer_addr (which updates on roaming).
                                // We save the peers to ensure the new IP survives a reboot.
                                if let Err(e) = save_current_peers(dir, &trusted, &transport).await {
                                    tracing::warn!(error = %e, "failed to persist roaming update");
                                }
                            }
                        }

                        match fluxsync_proto::decode(&plaintext) {
                            Ok(f) => dispatch_inbound_frame(f, &event_tx, &transport, &reassembly, &metrics, &inflight).await,
                            Err(e) => tracing::warn!(error = %e, "decode encrypted"),
                        }
                    }
                    RecvFrame::Other { type_byte, .. } => {
                        tracing::debug!(type_byte, "unknown wire type byte");
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// Clipboard watcher (read side)
// ─────────────────────────────────────────────────────────────────

/// Dedup hash over the *trimmed* clipboard text, so the write side and
/// the watcher (which trims before hashing) agree — see FS-026.
fn clipboard_dedup_hash(text: &str) -> [u8; 32] {
    DedupRing::hash(text.trim().as_bytes())
}

/// Build the history label for a clipboard payload. Text-like kinds show
/// the (lossy) UTF-8 text; images show a byte-size descriptor since their
/// payload is binary PNG.
fn preview_label(kind: Kind, payload: &[u8]) -> String {
    match kind {
        Kind::Image => format!("Image, {} KB", payload.len().div_ceil(1024)),
        _ => String::from_utf8_lossy(payload).to_string(),
    }
}

/// Dedup hash over an image's raw RGBA pixels (prefixed with its
/// dimensions). Hashing the decoded pixels — not the PNG bytes — keeps the
/// hash stable across a PNG encode/decode round-trip, so a write followed
/// by the watcher's read-back is recognised as our own and not echoed back
/// to the peer.
#[cfg(not(target_os = "android"))]
fn image_rgba_hash(width: u32, height: u32, rgba: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + rgba.len());
    buf.extend_from_slice(&width.to_le_bytes());
    buf.extend_from_slice(&height.to_le_bytes());
    buf.extend_from_slice(rgba);
    DedupRing::hash(&buf)
}

/// Decode PNG bytes to `(width, height, rgba)`. `None` on any decode error.
#[cfg(not(target_os = "android"))]
fn decode_png_to_rgba(png: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    let img = image::load_from_memory_with_format(png, image::ImageFormat::Png).ok()?;
    let rgba = img.to_rgba8();
    let (w, h) = (rgba.width(), rgba.height());
    Some((w, h, rgba.into_raw()))
}

/// Encode RGBA pixels to PNG bytes. `None` on failure (e.g. the buffer
/// length doesn't match `width * height * 4`).
#[cfg(not(target_os = "android"))]
fn encode_png(width: u32, height: u32, rgba: Vec<u8>) -> Option<Vec<u8>> {
    let img = image::RgbaImage::from_raw(width, height, rgba)?;
    let mut out = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut out, image::ImageFormat::Png)
        .ok()?;
    Some(out.into_inner())
}

/// Polls the OS clipboard every 200ms and forwards new payloads through
/// the same `DriverCmd::Run { op: Push }` path the IPC `push` op uses.
/// Routing through the cmd channel (instead of firing
/// `Event::LocalClipboardChange` directly) lets us reuse the existing
/// lamport allocation, dedup, and SendItem dispatch — the watcher only
/// has to detect "the OS clipboard changed."
///
/// Dedup happens twice:
///   * `last_seen_hash` filters consecutive polls of the same payload.
///   * `last_written_hashes` (shared with `Action::WriteClipboard`)
///     filters out the immediate read-back of a payload we just wrote
///     ourselves after receiving it from the peer — without it, every
///     inbound item would ping-pong back to the sender.
///
/// Gated on `transport.session.is_some()` so we don't spam the FSM
/// before pairing completes.
///
/// Compiled out on Android — `arboard` doesn't ship an Android backend
/// and the platform forbids background clipboard reads anyway. The
/// Android `MainActivity` does the equivalent work in its
/// `ClipboardManager.OnPrimaryClipChangedListener`.
#[cfg(not(target_os = "android"))]
async fn clipboard_watcher_loop(
    transport: Arc<Transport>,
    cmd_tx: mpsc::UnboundedSender<DriverCmd>,
    last_written_hashes: Arc<Mutex<VecDeque<[u8; 32]>>>,
    shutdown: CancellationToken,
) -> Result<()> {
    let mut last_seen_hash: Option<[u8; 32]> = None;
    let mut interval = tokio::time::interval(Duration::from_millis(200));
    let mut last_session_est = 0u64;
    loop {
        // FS-048: while unpaired there is nothing to poll. Sleep on the
        // session-install pulse instead of waking every 200ms only to
        // observe `session.is_none()` and `continue`.
        if transport.session.lock().await.is_none() {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return Ok(()),
                () = transport.session_notify.notified() => {}
            }
            continue;
        }
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            _ = interval.tick() => {
                let est = transport.session_established_at_ms.load(std::sync::atomic::Ordering::SeqCst);
                let session_active = transport.session.lock().await.is_some();

                if !session_active {
                    continue;
                }

                // [REMEDIATION] Session Seeding: If this is a fresh session, seed last_seen_hash
                // with the current OS clipboard to avoid blasting disconnected-state copies to the peer.
                if est != last_session_est {
                    last_session_est = est;
                    let text_res = tokio::task::spawn_blocking(|| {
                        arboard::Clipboard::new().and_then(|mut cb| cb.get_text())
                    }).await;
                    if let Ok(Ok(raw_text)) = text_res {
                        last_seen_hash = Some(clipboard_dedup_hash(&raw_text));
                        tracing::debug!("Clipboard watcher seeded for new session");
                    } else {
                        let img_res = tokio::task::spawn_blocking(|| {
                            arboard::Clipboard::new().and_then(|mut cb| cb.get_image())
                        })
                        .await;
                        if let Ok(Ok(img)) = img_res {
                            last_seen_hash = Some(image_rgba_hash(
                                img.width as u32,
                                img.height as u32,
                                &img.bytes,
                            ));
                            tracing::debug!("Clipboard watcher seeded (image) for new session");
                        }
                    }
                }
                // ── Text ─────────────────────────────────────────────
                let text_res = tokio::task::spawn_blocking(|| {
                    arboard::Clipboard::new().and_then(|mut cb| cb.get_text())
                })
                .await;
                if let Ok(Ok(raw_text)) = text_res {
                    let text = raw_text.trim().to_string();
                    if !text.is_empty() {
                        let hash = clipboard_dedup_hash(&raw_text);
                        if last_seen_hash != Some(hash) {
                            let already =
                                last_written_hashes.lock().await.contains(&hash);
                            last_seen_hash = Some(hash);
                            if !already {
                                let (reply_tx, _reply_rx) = oneshot::channel();
                                if cmd_tx
                                    .send(DriverCmd::Run {
                                        op: CmdOp::Push { text },
                                        reply: reply_tx,
                                        req_id: 0,
                                    })
                                    .is_err()
                                {
                                    tracing::error!("clipboard_watcher_loop: failed to send Push command");
                                    return Ok(());
                                }
                                tracing::debug!("clipboard_watcher_loop: Push command sent");
                            }
                        }
                        // Had text this tick — skip the image probe.
                        continue;
                    }
                }

                // ── Image (only when the clipboard holds no text) ────
                let img_res = tokio::task::spawn_blocking(|| {
                    arboard::Clipboard::new().and_then(|mut cb| cb.get_image())
                })
                .await;
                let Ok(Ok(img)) = img_res else { continue };
                let w = img.width as u32;
                let h = img.height as u32;
                let rgba = img.bytes.into_owned();
                let hash = image_rgba_hash(w, h, &rgba);
                if last_seen_hash == Some(hash) {
                    continue;
                }
                let already = last_written_hashes.lock().await.contains(&hash);
                last_seen_hash = Some(hash);
                if already {
                    continue;
                }
                match encode_png(w, h, rgba) {
                    Some(png) if png.len() <= MAX_PAYLOAD => {
                        let preview =
                            format!("Image {w}×{h}, {} KB", png.len().div_ceil(1024));
                        if cmd_tx
                            .send(DriverCmd::PushImage { hash, png, preview })
                            .is_err()
                        {
                            tracing::error!("clipboard_watcher_loop: failed to send PushImage command");
                            return Ok(());
                        }
                        tracing::debug!("clipboard_watcher_loop: PushImage command sent");
                    }
                    Some(png) => tracing::warn!(
                        size = png.len(),
                        "clipboard image exceeds 16 MiB cap; skipped"
                    ),
                    None => tracing::warn!("clipboard image PNG encode failed"),
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// Heartbeat & Timeout loop
// ─────────────────────────────────────────────────────────────────

async fn heartbeat_loop(
    transport: Arc<Transport>,
    event_tx: mpsc::UnboundedSender<Event>,
    shutdown: CancellationToken,
    metrics: Arc<Mutex<MetricsTracker>>,
) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    let mut missed_pings = 0;

    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            _ = interval.tick() => {
                let session_active = transport.session.lock().await.is_some();

                if session_active {
                    // 1. Send Heartbeat (Ping)
                    let frame = fluxsync_proto::Frame {
                        version: fluxsync_proto::PROTOCOL_VERSION,
                        msg: fluxsync_proto::Msg::Heartbeat(fluxsync_proto::Heartbeat {
                            lamport: 0,
                            rtt_hint: None,
                        }),
                    };
                    if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                        tracing::debug!("Heartbeat: sending ping to peer");
                        metrics.lock().await.on_heartbeat_sent();
                        let _ = transport.send_encrypted(&bytes).await;
                    }

                    // 2. Check for receive timeout (10 seconds)
                    let last_rx = transport.last_rx_ms.load(std::sync::atomic::Ordering::Relaxed);
                    let now = crate::transport::now_ms();

                    if now.saturating_sub(last_rx) > 5_000 {
                        missed_pings += 1;
                        metrics.lock().await.on_heartbeat_missed();
                        if missed_pings >= 6 {
                            tracing::warn!("Peer timed out (6 missed pings/30s). Dropping link.");
                            metrics.lock().await.on_disconnect(DisconnectReason::HeartbeatTimeout);
                            transport.last_rx_ms.store(now, std::sync::atomic::Ordering::Relaxed);
                            let _ = event_tx.send(Event::PeerLost);
                            missed_pings = 0;
                        }
                    } else {
                        missed_pings = 0;
                    }
                } else {
                    // DISCOVERY PROBE: If no session but we have a last known peer IP,
                    // try a direct handshake poke.
                    if let Some(_addr) = *transport.last_peer_addr.lock().await {
                         // We don't initiate here because we lack the peer's static_pub,
                         // but we can log that we are waiting for that specific IP.
                         // In a future PR, we could cache the static_pub too.
                    }
                }
            }
        }
    }
}

/// Load the trusted-peer set from `peers.json` (FS-039); malformed entries are skipped with a warning.
fn load_trusted_peers(dir: &Path) -> Vec<([u8; 32], TrustedPeer)> {
    let stored = match crate::keystore::load_peers(dir) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "could not read peers.json; starting with no trusted peers");
            return Vec::new();
        }
    };
    let mut out = Vec::with_capacity(stored.len());
    for p in stored {
        let static_pub = match decode_hex32(&p.static_pub_hex) {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(error = %e, peer = %p.peer_id_hex, "skipping peers.json entry: bad static_pub");
                continue;
            }
        };
        let peer_id = handshake::peer_id_for(&static_pub);
        out.push((
            peer_id,
            TrustedPeer {
                static_pub,
                name: p.name,
            },
        ));
    }
    out
}

/// Persist the current trusted-peer set to `peers.json` (FS-039).
async fn save_current_peers(
    dir: &Path,
    trusted: &TrustedSet,
    _transport: &Transport,
) -> Result<()> {
    let stored: Vec<crate::keystore::StoredPeer> = {
        let g = trusted.lock().await;
        g.iter()
            .map(|(peer_id, peer)| crate::keystore::StoredPeer {
                peer_id_hex: hex::encode(peer_id),
                static_pub_hex: hex::encode(peer.static_pub),
                name: peer.name.clone(),
                last_addr: None,
            })
            .collect()
    };
    crate::keystore::save_peers(dir, &stored)
}

async fn dispatch_inbound_frame(
    frame: Frame,
    event_tx: &mpsc::UnboundedSender<Event>,
    transport: &Arc<Transport>,
    reassembly: &Arc<Mutex<HashMap<[u8; 32], Reassembly>>>,
    metrics: &Arc<Mutex<MetricsTracker>>,
    inflight: &InflightMap,
) {
    match frame.msg {
        Msg::ClipboardItem(item) => {
            if item.payload.is_empty() {
                // Header for a chunked transfer
                let mut map = reassembly.lock().await;
                let r = map.entry(item.hash).or_insert_with(|| Reassembly {
                    metadata: Some((item.lamport, item.kind, item.sensitive)),
                    chunks: Vec::new(),
                    last_update: Instant::now(),
                    first_seen: Instant::now(),
                });
                r.metadata = Some((item.lamport, item.kind, item.sensitive));
                r.last_update = Instant::now();
                // A header datagram can arrive AFTER all its chunks (UDP
                // reorders freely). Check completion here too — not only in
                // the Chunk arm — or a late header strands a full payload.
                if let Some((lamport, kind, sensitive)) = r
                    .metadata
                    .filter(|_| !r.chunks.is_empty())
                    .filter(|_| r.chunks.iter().all(std::option::Option::is_some))
                {
                    let mut full_payload = Vec::new();
                    for chunk in r.chunks.drain(..) {
                        full_payload.extend(chunk.unwrap());
                    }
                    map.remove(&item.hash);
                    drop(map);

                    let preview = preview_label(kind, &full_payload);
                    let _ = event_tx.send(Event::FrameReceivedClipboard {
                        hash: item.hash,
                        kind,
                        payload: full_payload,
                        preview,
                        sensitive,
                        lamport,
                    });
                }
            } else {
                let preview = preview_label(item.kind, &item.payload);
                let _ = event_tx.send(Event::FrameReceivedClipboard {
                    hash: item.hash,
                    kind: item.kind,
                    payload: item.payload,
                    preview,
                    sensitive: item.sensitive,
                    lamport: item.lamport,
                });
            }
        }
        Msg::Chunk(c) => {
            // [REMEDIATION] DoS Protection: Limit chunk count and concurrent reassemblies.
            // Using MAX_CHUNKS (256) instead of magic 1000 for consistency.
            if c.total > fluxsync_proto::MAX_CHUNKS || c.total == 0 {
                tracing::warn!(total=%c.total, "Rejecting Chunk: invalid total (DoS protection)");
                return;
            }

            let mut map = reassembly.lock().await;

            if !map.contains_key(&c.item_id) && map.len() >= 5 {
                let oldest = map
                    .iter()
                    .min_by_key(|(_, r)| r.last_update)
                    .map(|(k, _)| *k);
                if let Some(k) = oldest {
                    map.remove(&k);
                }
            }

            let r = map.entry(c.item_id).or_insert_with(|| Reassembly {
                metadata: None,
                chunks: vec![None; c.total as usize],
                last_update: Instant::now(),
                first_seen: Instant::now(),
            });

            r.last_update = Instant::now();
            if r.chunks.is_empty() {
                r.chunks = vec![None; c.total as usize];
            }

            if (c.idx as usize) < r.chunks.len() {
                r.chunks[c.idx as usize] = Some(c.data);
            }

            // Check if complete
            if let Some((lamport, kind, sensitive)) = r
                .metadata
                .filter(|_| r.chunks.iter().all(std::option::Option::is_some))
            {
                let mut full_payload = Vec::new();
                for chunk in r.chunks.drain(..) {
                    full_payload.extend(chunk.unwrap());
                }
                map.remove(&c.item_id);
                drop(map);

                let preview = preview_label(kind, &full_payload);
                let _ = event_tx.send(Event::FrameReceivedClipboard {
                    hash: c.item_id,
                    kind,
                    payload: full_payload,
                    preview,
                    sensitive,
                    lamport,
                });
            }
        }
        Msg::BatteryStatus(b) => {
            let _ = event_tx.send(Event::BatteryChangedPeer {
                level: b.level,
                charging: b.charging,
            });
        }
        Msg::Heartbeat(_) => {
            // Heartbeat Received (Ping) -> Send Ack (Pong)
            tracing::debug!("Heartbeat: received ping, sending ack");
            metrics.lock().await.on_heartbeat_received();
            let frame = fluxsync_proto::Frame {
                version: fluxsync_proto::PROTOCOL_VERSION,
                msg: fluxsync_proto::Msg::Ack(fluxsync_proto::Ack {
                    lamport: 0,
                    hash: [0u8; 32],
                }),
            };
            if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                let _ = transport.send_encrypted(&bytes).await;
            }
        }
        Msg::Ack(ack) => {
            metrics.lock().await.on_ack_received();
            if ack.hash == [0u8; 32] {
                // Heartbeat pong — no item to clear.
                tracing::debug!("Heartbeat: received ack (pong)");
            } else if inflight.lock().await.remove(&ack.hash).is_some() {
                // Item delivery confirmed — stop retransmitting it.
                tracing::debug!(item = ?&ack.hash[..6], "item acked; retransmit cleared");
            }
        }
        Msg::Bye => {
            // Peer announced a clean disconnect: tear down the session and
            // signal PeerLost so the FSM closes the session and re-discovers.
            transport.drop_session().await;
            let _ = event_tx.send(Event::PeerLost);
        }
        Msg::HandshakeInit(_) | Msg::HandshakeResp(_) => {
            // Handshake frames are driven by the handshake task, not here.
        }
        Msg::Hello(h) => {
            // Recover the real peer_id from the transport. If it is
            // unknown (a race before the handshake fully completed) we
            // must NOT fall back to an all-zero sentinel: that id
            // bypasses the FSM peer-mismatch check. Drop the Hello.
            match *transport.last_peer_id.lock().await {
                Some(peer_id) => {
                    let _ = event_tx.send(Event::PeerSeen {
                        peer_id,
                        name: h.name,
                    });
                }
                None => {
                    tracing::warn!("Received Hello with no last_peer_id; dropping");
                }
            }
        }
    }
}

struct Reassembly {
    metadata: Option<(u64, Kind, bool)>,
    chunks: Vec<Option<Vec<u8>>>,
    last_update: Instant,
    first_seen: Instant,
}

/// An outbound clipboard item awaiting the peer's `Msg::Ack`. Frames are
/// stored already-encoded so the retransmit timer can re-send them
/// verbatim until the ack lands or `MAX_RETRANSMIT` attempts elapse.
/// This is the only delivery guarantee on the UDP path — without it a
/// dropped datagram silently loses the item.
struct Inflight {
    frames: Vec<Vec<u8>>,
    attempts: u8,
    last_sent: Instant,
}

/// Map of clipboard items sent but not yet acked, keyed by item hash.
type InflightMap = Arc<Mutex<HashMap<[u8; 32], Inflight>>>;

/// Wait this long for an ack before re-sending an inflight item.
const RETRANSMIT_INTERVAL: Duration = Duration::from_secs(2);
/// Drop the item after this many re-sends with no ack.
const MAX_RETRANSMIT: u8 = 6;

// ─────────────────────────────────────────────────────────────────
// mDNS discovery dispatcher
// ─────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn discovery_dispatcher(
    mut rx: mpsc::UnboundedReceiver<DiscoveryEvent>,
    identity: Identity,
    trusted: TrustedSet,
    transport: Arc<Transport>,
    pending_initiator_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
    event_tx: mpsc::UnboundedSender<Event>,
    shutdown: CancellationToken,
) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            _ = interval.tick() => {
                // PROACTIVE PROBE: If no session, try the last known peer
                let has_session = transport.session.lock().await.is_some();
                if !has_session {
                    let addr_opt = *transport.last_peer_addr.lock().await;
                    let id_opt = *transport.last_peer_id.lock().await;

                    if let (Some(_addr), Some(id)) = (addr_opt, id_opt) {
                        let peer_opt = {
                            let g = trusted.lock().await;
                            g.get(&id).cloned()
                        };

                        if let Some(peer) = peer_opt {
                            let history = transport.roaming_history.lock().await.clone();
                            for h_addr in history {
                                let id_clone = identity.clone();
                                let static_pub = peer.static_pub;
                                let peer_id_clone = id;
                                let peer_name = peer.name.clone();
                                let transport_clone = transport.clone();
                                let pending_tx = pending_initiator_tx.clone();
                                let event_tx_clone = event_tx.clone();

                                // [REMEDIATION] Proactive Probe Tie-break: only one side initiates.
                                if id_clone.public_key() >= static_pub {
                                    tracing::debug!(peer = %hex::encode(&peer_id_clone[..4]), "proactive probe tie-break: peer initiates");
                                    continue;
                                }

                                tokio::spawn(async move {
                                    tracing::debug!(
                                        peer = %hex::encode(&peer_id_clone[..4]),
                                        addr = %h_addr,
                                        "proactive probe: trying known IP in parallel"
                                    );
                                    start_initiator(
                                        id_clone,
                                        static_pub,
                                        h_addr,
                                        peer_id_clone,
                                        peer_name,
                                        transport_clone,
                                        pending_tx,
                                        event_tx_clone,
                                    ).await;
                                });
                            }
                        }
                    }
                }
            }
            Some(disc) = rx.recv() => {
                match disc {
                    DiscoveryEvent::Resolved { peer_id_hex, static_pub_hex, name, addr } => {
                        let Ok(peer_id) = decode_hex32(&peer_id_hex) else { continue };
                        let Ok(static_pub) = decode_hex32(&static_pub_hex) else { continue };
                        if handshake::peer_id_for(&static_pub) != peer_id {
                            tracing::warn!("mDNS peer_id != BLAKE3(static_pub); ignoring");
                            continue;
                        }
                        let trusted_match = {
                            let g = trusted.lock().await;
                            g.get(&peer_id).is_some_and(|t| t.static_pub == static_pub)
                        };
                        if !trusted_match {
                            tracing::info!(peer = %peer_id_hex, "saw untrusted peer; checking for cryptographic reset...");
                            let _ = event_tx.send(Event::UntrustedPeerSeen { name: name.clone() });
                            continue;
                        }
                        // Skip if a session is already up to this peer.
                        if transport.session.lock().await.is_some() {
                            continue;
                        }
                        // Tie-break: only the side with the lower static_pub
                        // bytes initiates from a discovery resolve. The other
                        // side waits for the inbound HandshakeInit. Without
                        // this, two daemons that resolve each other at the
                        // same time both initiate, both responders complete
                        // first, and each ends up with a session keyed for
                        // the *opposite* role — encrypts on one side cannot
                        // decrypt on the other.
                        if identity.public_key() >= static_pub {
                            tracing::debug!(
                                peer = %peer_id_hex,
                                "tie-break: peer initiates; waiting for HandshakeInit"
                            );
                            continue;
                        }
                        start_initiator(
                            identity.clone(),
                            static_pub,
                            addr,
                            peer_id,
                            name,
                            transport.clone(),
                            pending_initiator_tx.clone(),
                            event_tx.clone(),
                        ).await;
                    }
                    DiscoveryEvent::Removed { .. } => {
                        let _ = event_tx.send(Event::PeerLost);
                    }
                }
            }
            else => return Ok(()),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn start_initiator(
    identity: Identity,
    static_pub: [u8; 32],
    addr: SocketAddr,
    peer_id: [u8; 32],
    name: String,
    transport: Arc<Transport>,
    pending_initiator_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
    event_tx: mpsc::UnboundedSender<Event>,
) {
    // Single-flight: refuse to start a second initiator while one is
    // still waiting on its msg2. The pending slot doubles as the route
    // for HandshakeResp datagrams (transport_recv_loop), so two
    // overlapping initiators would steer the second peer's reply to
    // the first peer's session and corrupt both.
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    {
        let mut g = pending_initiator_tx.lock().await;
        if g.is_some() {
            tracing::debug!("initiator already pending; skipping");
            return;
        }
        *g = Some(tx);
    }
    transport.set_peer_addr(addr).await;
    let pending_clear = pending_initiator_tx.clone();
    tokio::spawn(async move {
        let result = handshake::run_initiator(
            identity, static_pub, addr, transport, rx, event_tx, peer_id, name,
        )
        .await;
        // Clear the pending slot whether the handshake succeeded or
        // failed, so the next discovery resolve / PairAccept can retry.
        *pending_clear.lock().await = None;
        if let Err(e) = result {
            tracing::warn!(error = %e, "initiator failed");
        }
    });
}

fn decode_hex32(s: &str) -> Result<[u8; 32]> {
    let v = hex::decode(s)?;
    let arr: [u8; 32] = v.try_into().map_err(|_| anyhow!("hex not 32 bytes"))?;
    Ok(arr)
}

// ─────────────────────────────────────────────────────────────────
// Pair URI helpers
// ─────────────────────────────────────────────────────────────────

/// Best-guess `<ip>:<port>` the daemon is reachable at on the LAN.
///
/// If the daemon is bound to a specific address, that wins. Otherwise
/// the kernel's own routing table picks: open a UDP socket "to" a
/// public address — no packet leaves the box because UDP connect is
/// state-only — and read back the source IP the kernel chose. This is
/// the standard way to find the egress LAN IP without interface
/// enumeration.
fn local_lan_addr(udp_bind: &str, udp_port: u16) -> String {
    use std::net::{IpAddr, Ipv4Addr, UdpSocket};

    fn pick_local() -> IpAddr {
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            if sock.connect("1.1.1.1:80").is_ok() {
                if let Ok(local) = sock.local_addr() {
                    return local.ip();
                }
            }
        }
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    let ip = match udp_bind.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) if v4.is_unspecified() => pick_local(),
        Ok(IpAddr::V6(v6)) if v6.is_unspecified() => pick_local(),
        Ok(other) => other,
        Err(_) => pick_local(),
    };
    format!("{ip}:{udp_port}")
}

/// Render a `fluxsync://pair/<pubkey_b32>?a=<addr>&f=<w1.w2...>` URI.
fn build_pair_uri(pubkey_b32: &str, addr_hint: &str, fp_words: &[String]) -> String {
    format!(
        "fluxsync://pair/{pubkey_b32}?a={addr_hint}&f={}",
        fp_words.join(".")
    )
}

struct ParsedPairUri {
    pubkey_b32: String,
    addr: Option<String>,
    #[allow(dead_code)]
    fp_words: Vec<String>,
}

/// Parse a `fluxsync://pair/...` URI. Tolerant of missing/extra params:
/// only the pubkey segment is required. The fingerprint words are
/// returned for display-side comparison but the daemon does not enforce
/// them — the user does that visually.
fn parse_pair_uri(s: &str) -> Result<ParsedPairUri> {
    let rest = s
        .strip_prefix("fluxsync://pair/")
        .ok_or_else(|| anyhow!("scheme is not fluxsync://pair/"))?;
    let (pubkey_b32, query) = rest.split_once('?').unwrap_or((rest, ""));
    if pubkey_b32.is_empty() {
        return Err(anyhow!("missing pubkey segment"));
    }
    let mut addr = None;
    let mut fp_words: Vec<String> = Vec::new();
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        match k {
            "a" => addr = Some(v.to_string()),
            "f" => fp_words = v.split('.').map(str::to_string).collect(),
            _ => {}
        }
    }
    Ok(ParsedPairUri {
        pubkey_b32: pubkey_b32.to_string(),
        addr,
        fp_words,
    })
}

// ─────────────────────────────────────────────────────────────────
// IPC accept + per-client loop (unchanged from v0.1)
// ─────────────────────────────────────────────────────────────────

async fn ipc_accept_loop(
    server: IpcServer,
    cmd_tx: mpsc::UnboundedSender<DriverCmd>,
    state_rx: watch::Receiver<State>,
    logs_bcast_tx: broadcast::Sender<LogEntry>,
    log_tail: Arc<LogTail>,
    shutdown: CancellationToken,
) -> Result<()> {
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            accept = server.accept() => {
                let conn = match accept {
                    Ok(c) => c,
                    Err(e) => { tracing::warn!(error = %e, "ipc accept"); continue; }
                };
                let cmd_tx = cmd_tx.clone();
                let state_rx = state_rx.clone();
                let logs_bcast_rx = logs_bcast_tx.subscribe();
                let log_tail = log_tail.clone();
                let client_shutdown = shutdown.clone();
                clients.spawn(async move {
                    if let Err(e) = handle_ipc_client(conn, cmd_tx, state_rx, logs_bcast_rx, log_tail, client_shutdown).await {
                        tracing::debug!(error = %e, "ipc client end");
                    }
                });
            }
        }
    }
    while clients.join_next().await.is_some() {}
    Ok(())
}

async fn handle_ipc_client(
    conn: IpcConn,
    cmd_tx: mpsc::UnboundedSender<DriverCmd>,
    mut state_rx: watch::Receiver<State>,
    mut logs_bcast_rx: broadcast::Receiver<LogEntry>,
    _log_tail: Arc<LogTail>,
    shutdown: CancellationToken,
) -> Result<()> {
    let (read_half, mut write_half) = conn.split();
    let mut reader = BufReader::new(read_half);

    let mut opening = String::new();
    reader.read_line(&mut opening).await?;
    let sub: Subscribe = serde_json::from_str(opening.trim())
        .map_err(|e| anyhow!("opening line not a Subscribe: {e}"))?;

    match sub.subscribe {
        Channel::Cmd => {
            let mut line = String::new();
            loop {
                line.clear();
                tokio::select! {
                    () = shutdown.cancelled() => return Ok(()),
                    res = reader.read_line(&mut line) => {
                        let n = res?;
                        if n == 0 { return Ok(()); }
                        let req: CmdRequest = match serde_json::from_str(line.trim()) {
                            Ok(r) => r,
                            Err(e) => {
                                let resp = CmdResponse::err(0, format!("bad json: {e}"));
                                write_json_line(&mut write_half, &resp).await?;
                                continue;
                            }
                        };
                        let (reply_tx, reply_rx) = oneshot::channel();
                        cmd_tx.send(DriverCmd::Run { op: req.op, reply: reply_tx, req_id: req.id })
                            .map_err(|_| anyhow!("driver gone"))?;
                        let resp = reply_rx.await.map_err(|_| anyhow!("driver dropped reply"))?;
                        write_json_line(&mut write_half, &resp).await?;
                    }
                }
            }
        }
        Channel::State => {
            let snap = state_rx.borrow().clone();
            write_json_line(&mut write_half, &snap).await?;
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => return Ok(()),
                    changed = state_rx.changed() => {
                        if changed.is_err() { return Ok(()); }
                        let snap = state_rx.borrow().clone();
                        write_json_line(&mut write_half, &snap).await?;
                    }
                }
            }
        }
        Channel::Logs => loop {
            tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                entry = logs_bcast_rx.recv() => {
                    match entry {
                        Ok(e) => write_json_line(&mut write_half, &e).await?,
                        Err(broadcast::error::RecvError::Closed) => return Ok(()),
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            let warn = LogEntry { level: LogLevel::Warn, msg: String::from("(some log lines were dropped)") };
                            write_json_line(&mut write_half, &warn).await?;
                        }
                    }
                }
            }
        },
    }
}

async fn write_json_line<W, T>(writer: &mut W, value: &T) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
    T: serde::Serialize,
{
    let mut s = serde_json::to_string(value)?;
    s.push('\n');
    writer.write_all(s.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::load_trusted_peers;
    use crate::handshake;
    use crate::keystore::{save_peers, StoredPeer};

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
                last_addr: None,
            }],
        )
        .expect("persist peer to peers.json");

        let loaded = load_trusted_peers(dir.path());

        assert_eq!(loaded.len(), 1, "the persisted peer must reload");
        let (id, peer) = &loaded[0];
        assert_eq!(*id, peer_id, "peer_id must round-trip");
        assert_eq!(peer.static_pub, static_pub, "static_pub must round-trip");
        assert_eq!(peer.name, "Galaxy S21", "name must round-trip");
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

    /// FS-041: an inbound `Msg::Bye` must emit `Event::PeerLost` so the FSM
    /// closes the session and re-discovers. On `main` the shared empty match
    /// arm (`Bye | HandshakeInit | HandshakeResp`) dropped `Bye` silently.
    #[tokio::test]
    async fn fs041_bye_frame_emits_peer_lost() {
        use super::{dispatch_inbound_frame, Event, Reassembly};
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
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        let metrics = Arc::new(Mutex::new(MetricsTracker::new()));

        let frame = Frame {
            version: PROTOCOL_VERSION,
            msg: Msg::Bye,
        };
        dispatch_inbound_frame(frame, &event_tx, &transport, &reassembly, &metrics, &inflight).await;

        assert!(
            matches!(event_rx.try_recv(), Ok(Event::PeerLost)),
            "Msg::Bye must emit Event::PeerLost"
        );
    }
}
