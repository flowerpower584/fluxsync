//! Daemon driver — composes [`fluxsync_core::App`] with IPC, transport,
//! and the tokio task fan-out.
//!
//! `run(cfg, shutdown)` is the public entry point; it spawns:
//! * an IPC accept loop
//! * a transport receive loop (only when a session is paired)
//! * the central event loop that owns the `App`
//!
//! Shutdown: a single `tokio::sync::Notify`. Every loop selects on
//! `notify.notified()` and exits cleanly. The driver returns once all
//! background tasks have joined, so callers (test harness, `main.rs`)
//! get a deterministic shutdown deadline.

use crate::cmd::{Channel, CmdData, CmdOp, CmdRequest, CmdResponse, PeerEntry, Subscribe};
use crate::config::{DaemonConfig, TestPair};
use crate::ipc::{IpcConn, IpcServer};
use crate::logs::LogTail;
use crate::transport::Transport;
use anyhow::{anyhow, Context, Result};
use fluxsync_core::{
    dedup::DedupRing, kind_of, Action, App, Config as CoreConfig, Event, LogEntry, LogLevel, State,
    WallClock,
};
use fluxsync_proto::{ClipboardItem, Frame, Msg, PROTOCOL_VERSION};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{broadcast, mpsc, oneshot, watch, Notify};
use tokio::task::JoinSet;

/// Drive a daemon to completion, returning once `shutdown` fires and
/// every background task has joined.
pub async fn run(cfg: DaemonConfig, shutdown: Arc<Notify>) -> Result<()> {
    // ── State + channels ──────────────────────────────────────────
    let mut app = App::new(CoreConfig {
        peer_name_self: cfg.peer_name_self.clone(),
        charge_override: cfg.charge_override,
        version: String::from(env!("CARGO_PKG_VERSION")),
        cipher: String::from("chacha20-poly1305"),
    });

    let initial = app.snapshot().clone();
    let (state_watch_tx, state_watch_rx) = watch::channel(initial.clone());
    let (logs_bcast_tx, _) = broadcast::channel::<LogEntry>(64);
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Event>();
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<DriverCmd>();
    let log_tail = Arc::new(LogTail::new());

    // ── Transport (only if paired; v0.1 = test_pair only) ─────────
    let transport: Option<Arc<Transport>> = if let Some(tp) = cfg.test_pair {
        let TestPair {
            session,
            peer_addr,
            peer_name,
            peer_id,
        } = tp;
        let t = Transport::bind(&cfg.udp_bind, cfg.udp_port, session, peer_addr).await?;
        let t = Arc::new(t);
        // Inject the synthetic events the FSM needs to reach Linked.
        event_tx.send(Event::ToggleOn).ok();
        event_tx
            .send(Event::PeerSeen {
                peer_id,
                name: peer_name,
            })
            .ok();
        event_tx.send(Event::HandshakeOk).ok();
        // Healthy batteries so status lands on Syncing.
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
        Some(t)
    } else {
        None
    };

    // ── Spawn long-lived tasks ────────────────────────────────────
    let mut tasks = JoinSet::new();

    // IPC accept loop.
    let ipc_server = IpcServer::bind(&cfg.ipc_path)
        .await
        .with_context(|| format!("bind ipc socket {}", cfg.ipc_path.display()))?;
    let ipc_shutdown = shutdown.clone();
    let ipc_state_rx = state_watch_rx.clone();
    let ipc_logs_bcast_tx = logs_bcast_tx.clone();
    let ipc_log_tail = log_tail.clone();
    let ipc_cmd_tx = cmd_tx.clone();
    tasks.spawn(async move {
        ipc_accept_loop(
            ipc_server,
            ipc_cmd_tx,
            ipc_state_rx,
            ipc_logs_bcast_tx,
            ipc_log_tail,
            ipc_shutdown,
        )
        .await
    });

    // Transport receive loop (if a session is in flight).
    if let Some(t) = transport.clone() {
        let rx_shutdown = shutdown.clone();
        let rx_event_tx = event_tx.clone();
        tasks.spawn(async move { transport_recv_loop(t, rx_event_tx, rx_shutdown).await });
    }

    // ── Main event loop ───────────────────────────────────────────
    loop {
        tokio::select! {
            biased;
            () = shutdown.notified() => break,
            Some(event) = event_rx.recv() => {
                let actions = app.handle(event, &*cfg.wall_clock);
                dispatch(actions, &mut app, &transport, &state_watch_tx, &logs_bcast_tx, &log_tail).await;
            }
            Some(driver_cmd) = cmd_rx.recv() => {
                handle_driver_cmd(
                    driver_cmd,
                    &mut app,
                    &cfg.wall_clock,
                    &event_tx,
                    &transport,
                    &state_watch_tx,
                    &logs_bcast_tx,
                    &log_tail,
                ).await;
            }
        }
    }

    // ── Drain ──────────────────────────────────────────────────────
    while let Some(_res) = tasks.join_next().await {}
    Ok(())
}

/// Internal request from an IPC handler to the driver.
enum DriverCmd {
    Run {
        op: CmdOp,
        reply: oneshot::Sender<CmdResponse>,
        req_id: u64,
    },
}

async fn dispatch(
    actions: Vec<Action>,
    app: &mut App,
    transport: &Option<Arc<Transport>>,
    state_watch_tx: &watch::Sender<State>,
    logs_bcast_tx: &broadcast::Sender<LogEntry>,
    log_tail: &Arc<LogTail>,
) {
    for action in actions {
        match action {
            Action::EmitState => {
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
                preview,
                sensitive,
            } => {
                if let Some(t) = transport {
                    let item = ClipboardItem {
                        lamport: app.clock_value(),
                        hash,
                        kind,
                        payload: preview.into_bytes(),
                        sensitive,
                        wall_time_ms: 0,
                    };
                    let frame = Frame {
                        version: PROTOCOL_VERSION,
                        msg: Msg::ClipboardItem(item),
                    };
                    match fluxsync_proto::encode(&frame) {
                        Ok(bytes) => {
                            if let Err(e) = t.send(&bytes).await {
                                tracing::warn!(error = %e, "send_item failed");
                            }
                        }
                        Err(e) => tracing::warn!(error = %e, "encode_item failed"),
                    }
                }
            }
            Action::AckItem { hash } => {
                if let Some(t) = transport {
                    let frame = Frame {
                        version: PROTOCOL_VERSION,
                        msg: Msg::Ack(fluxsync_proto::Ack {
                            lamport: app.clock_value(),
                            hash,
                        }),
                    };
                    if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                        let _ = t.send(&bytes).await;
                    }
                }
            }
            Action::WriteClipboard { preview: _ } => {
                // TODO v0.1.1: arboard write. v0.1 emits log only.
                tracing::debug!("clipboard write skipped (v0.1 stub)");
            }
            Action::StartDiscovery
            | Action::StopDiscovery
            | Action::OpenSession
            | Action::CloseSession
            | Action::BurstReplay
            | Action::SendHandshake { .. } => {
                // No-ops in v0.1 (no mDNS/handshake driver yet — paired
                // peer is injected via TestPair). The FSM still emits
                // these; they'll wire up in v0.1.1.
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_driver_cmd(
    cmd: DriverCmd,
    app: &mut App,
    wall: &Arc<dyn WallClock + Send + Sync>,
    event_tx: &mpsc::UnboundedSender<Event>,
    transport: &Option<Arc<Transport>>,
    state_watch_tx: &watch::Sender<State>,
    logs_bcast_tx: &broadcast::Sender<LogEntry>,
    log_tail: &Arc<LogTail>,
) {
    let DriverCmd::Run { op, reply, req_id } = cmd;
    let resp = match op {
        CmdOp::Status => CmdResponse::ok(
            req_id,
            Some(CmdData::State(Box::new(app.snapshot().clone()))),
        ),
        CmdOp::Push { text } => {
            let kind = kind_of(&text);
            let sensitive = fluxsync_core::is_sensitive(&text);
            let hash = DedupRing::hash(text.as_bytes());
            let lamport = app.clock_tick();
            let actions = app.handle(
                Event::LocalClipboardChange {
                    hash,
                    kind,
                    preview: text.clone(),
                    sensitive,
                    lamport,
                },
                &**wall,
            );
            dispatch(
                actions,
                app,
                transport,
                state_watch_tx,
                logs_bcast_tx,
                log_tail,
            )
            .await;
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
            let peer = peer_entry(app.snapshot(), transport.as_ref().map(|t| t.peer_addr));
            CmdResponse::ok(req_id, Some(CmdData::Peers(peer.into_iter().collect())))
        }
        CmdOp::SetThreshold { value } => match app.state_mut().set_threshold(value) {
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
                    state_watch_tx,
                    logs_bcast_tx,
                    log_tail,
                )
                .await;
                CmdResponse::ok(req_id, None)
            }
            Err(e) => CmdResponse::err(req_id, e.to_string()),
        },
        CmdOp::SetChargeOverride { value: _ } => {
            // v0.1: no-op (charge_override is config-time).
            CmdResponse::ok(req_id, None)
        }
        CmdOp::Revoke { peer_id: _ } => {
            // v0.1: revocation = drop the peer key; integrated when keychain lands.
            CmdResponse::ok(req_id, None)
        }
        CmdOp::DebugCapture => {
            // v0.1: no-op stub. v0.1.1 produces .tar.gz.
            CmdResponse::ok(req_id, None)
        }
        CmdOp::Shutdown => {
            // Caller signals us to shut down.
            event_tx.send(Event::ToggleOff).ok();
            CmdResponse::ok(req_id, None)
        }
    };
    let _ = reply.send(resp);
}

fn peer_entry(state: &State, addr: Option<SocketAddr>) -> Option<PeerEntry> {
    if state.peer_name.is_empty() {
        return None;
    }
    Some(PeerEntry {
        peer_id: String::from("paired"), // TODO real hex id once keystore is wired
        name: state.peer_name.clone(),
        addr: addr.map(|a| a.to_string()).unwrap_or_default(),
        link_latency_ms: state.link_latency_ms,
        battery: state.peer_battery,
        charging: state.peer_charging,
        linked: state.status != fluxsync_core::Status::Inactive,
    })
}

async fn transport_recv_loop(
    t: Arc<Transport>,
    event_tx: mpsc::UnboundedSender<Event>,
    shutdown: Arc<Notify>,
) -> Result<()> {
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            biased;
            () = shutdown.notified() => return Ok(()),
            res = t.recv(&mut buf) => {
                let bytes = match res {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(error = %e, "transport recv error");
                        continue;
                    }
                };
                let frame = match fluxsync_proto::decode(&bytes) {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::warn!(error = %e, "decode failed");
                        continue;
                    }
                };
                match frame.msg {
                    Msg::ClipboardItem(item) => {
                        let preview = String::from_utf8_lossy(&item.payload).to_string();
                        event_tx.send(Event::FrameReceivedClipboard {
                            hash: item.hash,
                            kind: item.kind,
                            preview,
                            lamport: item.lamport,
                        }).ok();
                    }
                    Msg::Ack(_a) => {
                        // ack handling: drop from retry queue (not implemented v0.1).
                    }
                    Msg::Heartbeat(_) | Msg::Bye => {}
                    Msg::HandshakeInit(_) | Msg::HandshakeResp(_) => {
                        // v0.1: paired peers only via TestPair; ignore.
                    }
                    Msg::BatteryStatus(b) => {
                        event_tx.send(Event::BatteryChangedPeer {
                            level: b.level,
                            charging: b.charging,
                        }).ok();
                    }
                    Msg::Chunk(_) => {
                        // v0.1: chunk reassembly not implemented.
                    }
                }
            }
        }
    }
}

async fn ipc_accept_loop(
    server: IpcServer,
    cmd_tx: mpsc::UnboundedSender<DriverCmd>,
    state_rx: watch::Receiver<State>,
    logs_bcast_tx: broadcast::Sender<LogEntry>,
    log_tail: Arc<LogTail>,
    shutdown: Arc<Notify>,
) -> Result<()> {
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = shutdown.notified() => break,
            accept = server.accept() => {
                let conn = match accept {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(error = %e, "ipc accept");
                        continue;
                    }
                };
                let cmd_tx = cmd_tx.clone();
                let state_rx = state_rx.clone();
                let logs_bcast_rx = logs_bcast_tx.subscribe();
                let log_tail = log_tail.clone();
                let client_shutdown = shutdown.clone();
                clients.spawn(async move {
                    if let Err(e) = handle_ipc_client(
                        conn,
                        cmd_tx,
                        state_rx,
                        logs_bcast_rx,
                        log_tail,
                        client_shutdown,
                    ).await {
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
    shutdown: Arc<Notify>,
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
                    () = shutdown.notified() => return Ok(()),
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
            // Push initial then on every change.
            let snap = state_rx.borrow().clone();
            write_json_line(&mut write_half, &snap).await?;
            loop {
                tokio::select! {
                    () = shutdown.notified() => return Ok(()),
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
                () = shutdown.notified() => return Ok(()),
                entry = logs_bcast_rx.recv() => {
                    match entry {
                        Ok(e) => write_json_line(&mut write_half, &e).await?,
                        Err(broadcast::error::RecvError::Closed) => return Ok(()),
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            // Slow client; drop a synthetic warn and keep going.
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

// ── App helpers exposed to the driver ─────────────────────────────────
trait AppExt {
    fn clock_tick(&mut self) -> u64;
    fn clock_value(&self) -> u64;
    fn state_mut(&mut self) -> &mut State;
}

impl AppExt for App {
    fn clock_tick(&mut self) -> u64 {
        use fluxsync_core::Clock;
        self.clock.tick()
    }
    fn clock_value(&self) -> u64 {
        use fluxsync_core::Clock;
        self.clock.now()
    }
    fn state_mut(&mut self) -> &mut State {
        &mut self.state
    }
}
