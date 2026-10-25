//! IPC command handling (`CmdOp` → effects on the app, transport and stores).

use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_driver_cmd(
    cmd: DriverCmd,
    app: &mut App,
    wall: &Arc<dyn WallClock + Send + Sync>,
    identity: &Identity,
    trusted: &TrustedSet,
    pairing_window: &PairingWindow,
    transport: &Arc<Transport>,
    pending_initiator_tx: &Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
    event_tx: &mpsc::Sender<Event>,
    state_watch_tx: &watch::Sender<State>,
    logs_bcast_tx: &broadcast::Sender<LogEntry>,
    log_tail: &Arc<LogTail>,
    last_written_hashes: &Arc<Mutex<VecDeque<[u8; 32]>>>,
    keystore_dir: Option<&std::path::PathBuf>,
    udp_bind: &str,
    udp_port: u16,
    metrics: &Arc<Mutex<MetricsTracker>>,
    inflight: &InflightMap,
    peer_meta: &PeerMetaMap,
    pending_pairs: &PendingSet,
    pin_advert: &PinAdvertisement,
    disc_cache: &DiscoveryCache,
    backoff: &BackoffMap,
    mdns_ctx: &MdnsCtx,
    shutdown: &CancellationToken,
    outbox: &SharedOutbox,
    outbox_stage: &PendingOutboxStage,
    seq_store: &mut Option<SeqStore>,
    deferred_sas_confirm: &DeferredSasConfirm,
    cleared_tombstone: &ClearedTombstone,
) {
    let DriverCmd::Run { op, reply, req_id } = cmd else {
        return;
    };
    let resp = match op {
        CmdOp::Status => {
            let m = metrics.lock().await.snapshot();
            app.set_metrics(Some(m));
            // FluxMesh Phase 3: enrich with the live mesh peer list, same as
            // the watch-published snapshot (a direct Status poll bypasses it).
            let mut snap = app.snapshot().clone();
            let primary = transport.cached_peer_id().await;
            snap.peers = build_peers(transport, peer_meta, primary).await;
            CmdResponse::ok(req_id, Some(CmdData::State(Box::new(snap))))
        }
        CmdOp::Reconnect {} => {
            tracing::info!("IPC: manual reconnect requested");
            // Capture the primary's peer_id BEFORE dropping the session —
            // `drop_session` clears the session but not `last_peer_id`, so
            // this is really just for clarity/ordering symmetry with the
            // other teardown paths (heartbeat timeout, Bye, Revoke).
            let peer_id = transport.cached_peer_id().await;
            transport.drop_session().await;
            if let Some(peer_id) = peer_id {
                let _ = event_tx.try_send(Event::PeerLost { peer_id });
            }
            CmdResponse::ok(req_id, Some(CmdData::Pong))
        }
        CmdOp::SetFavorite { hash, favorite } => {
            tracing::info!(%hash, favorite, "IPC: set-favorite");
            let actions = app.handle(Event::SetFavorite { hash, favorite }, &**wall);
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
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
            )
            .await;
            CmdResponse::ok(req_id, None)
        }
        CmdOp::ClearHistory { include_favorites } => {
            tracing::info!(include_favorites, "IPC: clear-history");
            // Snapshot the hashes about to be dropped BEFORE mutating state,
            // so the outbox/image-cache purge below matches exactly what
            // leaves `State.history`.
            let cleared_hex: Vec<String> = app
                .snapshot()
                .history
                .iter()
                .filter(|h| include_favorites || !h.favorite)
                .map(|h| h.hash.clone())
                .collect();
            let cleared_bytes: Vec<[u8; 32]> = cleared_hex
                .iter()
                .filter_map(|h| decode_hex32(h).ok())
                .collect();
            // Purge the resync outbox first: a cleared item must not come
            // back into history via a later pull/resync.
            outbox.lock().await.remove_many(&cleared_bytes);
            // H2 fix: also tombstone the cleared hashes so a PEER that still
            // holds one in its own outbox (ClearHistory is local-only, never
            // propagated) can't resurrect it via its next ResyncOffer.
            mark_cleared(cleared_tombstone, &cleared_bytes).await;
            purge_cached_images(&cleared_hex);
            let actions = app.handle(Event::ClearHistory { include_favorites }, &**wall);
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
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
            )
            .await;
            CmdResponse::ok(req_id, None)
        }
        CmdOp::SetFirewall { policy } => {
            tracing::info!(enabled = policy.enabled, "IPC: set-firewall");
            app.set_firewall(policy);
            // Persist so the policy survives a daemon restart (best-effort: a
            // write failure logs but never fails the command).
            if let Some(dir) = keystore_dir {
                if let Err(e) = crate::keystore::save_firewall(dir, app.firewall()) {
                    tracing::warn!(error = %e, "failed to persist firewall policy");
                }
            }
            // Push the updated policy to every state subscriber.
            dispatch(
                vec![Action::EmitState],
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
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
            )
            .await;
            CmdResponse::ok(req_id, None)
        }
        CmdOp::ResolvePending { hash, allow } => {
            tracing::info!(%hash, allow, "IPC: resolve-pending");
            let actions = app.handle(
                Event::ResolvePending {
                    hash: hash.clone(),
                    allow,
                },
                &**wall,
            );
            // Outbox admission gate fix: a staged inbound item (see
            // `PendingOutboxStage`) is only admitted now if `App::handle`
            // actually re-emitted its held `WriteClipboard` — not merely
            // because the caller passed `allow: true`. A denied item, an
            // unknown/already-resolved hash, or an OUTBOUND approval
            // (`SendItem` instead) must never promote anything, and either
            // way the staged entry (if any) must not survive this call.
            let admitted_inbound = allow
                && actions
                    .iter()
                    .any(|a| matches!(a, Action::WriteClipboard { .. }));
            if let Ok(bytes) = decode_hex32(&hash) {
                match outbox_stage.lock().await.remove(&bytes) {
                    Some(entry) if admitted_inbound => {
                        outbox.lock().await.insert(bytes, entry);
                    }
                    _ => {}
                }
            }
            // An approved OUTBOUND item re-emits SendItem; route it through the
            // same SAS gate as a normal push so an unconfirmed peer can't be fed
            // the held secret.
            let actions = gate_outbound(actions, transport, pending_pairs).await;
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
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
            )
            .await;
            CmdResponse::ok(req_id, None)
        }
        CmdOp::Push { text } => {
            use fluxsync_core::Clock;
            tracing::info!(len = text.len(), "IPC: push requested from local");
            let text = text.trim().to_string();
            if text.len() > MAX_PAYLOAD {
                // Reject early so the caller learns the paste was too big,
                // instead of dispatch silently truncating the bytes mid-wire
                // (the receiver would otherwise get a corrupted partial item).
                CmdResponse::err(
                    req_id,
                    format!(
                        "clipboard text too large: {} bytes (max {} bytes)",
                        text.len(),
                        MAX_PAYLOAD
                    ),
                )
            } else if !text.is_empty() {
                let kind = kind_of(&text);
                let sensitive = fluxsync_core::is_sensitive(&text);
                // Canon hash so CRLF/LF copies dedup (see clipboard_dedup_hash).
                let hash = clipboard_dedup_hash(&text);
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
                let actions = gate_outbound(actions, transport, pending_pairs).await;
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
                    peer_meta,
                    outbox,
                    pending_pairs,
                    seq_store,
                )
                .await;
                CmdResponse::ok(req_id, None)
            } else {
                CmdResponse::ok(req_id, None)
            }
        }
        CmdOp::PushImage { data, sensitive } => {
            use fluxsync_core::Clock;
            tracing::info!(
                b64_len = data.len(),
                sensitive,
                "IPC: push_image requested from local"
            );
            match B64.decode(data.as_bytes()) {
                Ok(png) if png.len() > MAX_PAYLOAD => CmdResponse::err(
                    req_id,
                    format!(
                        "push_image: image too large ({} bytes > {MAX_PAYLOAD} cap)",
                        png.len()
                    ),
                ),
                Ok(png) => match decode_png_to_rgba(&png) {
                    Some((w, h, rgba)) => {
                        let hash = image_rgba_hash(w, h, &rgba);
                        let preview = preview_label(Kind::Image, &png);
                        let lamport = app.clock.tick();
                        let actions = app.handle(
                            Event::LocalClipboardChange {
                                hash,
                                kind: Kind::Image,
                                payload: png,
                                preview,
                                // DIR-P2-05: the caller (fluxctl `--sensitive`,
                                // or the mobile FFI) decides — there is no
                                // image-content classifier, so this is the
                                // only place an image can be marked sensitive.
                                sensitive,
                                lamport,
                            },
                            &**wall,
                        );
                        let actions = gate_outbound(actions, transport, pending_pairs).await;
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
                            peer_meta,
                            outbox,
                            pending_pairs,
                            seq_store,
                        )
                        .await;
                        CmdResponse::ok(req_id, None)
                    }
                    None => CmdResponse::err(req_id, "push_image: PNG decode failed"),
                },
                Err(e) => CmdResponse::err(req_id, format!("push_image: base64: {e}")),
            }
        }
        CmdOp::FetchItem { hash } => match lookup_cached_image(&hash) {
            Some(png) => CmdResponse::ok(
                req_id,
                Some(CmdData::ItemBytes {
                    bytes: B64.encode(&png),
                }),
            ),
            None => CmdResponse::err(req_id, "fetch_item: payload not cached"),
        },
        CmdOp::Pull => {
            let last = app.snapshot().history.first().cloned();
            CmdResponse::ok(req_id, Some(CmdData::Pull(last)))
        }
        CmdOp::Tail { n } => {
            let entries = log_tail.snapshot(n);
            CmdResponse::ok(req_id, Some(CmdData::Tail(entries)))
        }
        CmdOp::Peers => {
            let addr = transport.current_peer_addr().await;
            let peer = peer_entry(app.snapshot(), addr);
            CmdResponse::ok(req_id, Some(CmdData::Peers(peer.into_iter().collect())))
        }
        // H2: enumerate the persisted trust store. The `Peers` op above
        // only reflects the live session; this one reflects every entry
        // a malicious or unaware caller has managed to land in
        // `peers.json` via `pair from-uri` / `pair accept`. Render this
        // in the CLI so a silent extra-peer trust is immediately
        // visible to the user.
        CmdOp::TrustList {} => {
            let g = trusted.lock().await;
            let entries: Vec<crate::cmd::TrustedEntry> = g
                .iter()
                .map(|(pid, p)| crate::cmd::TrustedEntry {
                    peer_id_hex: hex::encode(pid),
                    static_pub_hex: hex::encode(p.static_pub),
                    name: p.name.clone(),
                })
                .collect();
            CmdResponse::ok(req_id, Some(CmdData::TrustList(entries)))
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
                    peer_meta,
                    outbox,
                    pending_pairs,
                    seq_store,
                )
                .await;
                CmdResponse::ok(req_id, None)
            }
            Err(e) => CmdResponse::err(req_id, e.to_string()),
        },
        CmdOp::SetDeviceName { name } => match app.set_device_name(&name) {
            Ok(()) => {
                let resolved = app.config().peer_name_self.clone();
                tracing::info!(name = %resolved, "IPC: set-device-name");
                // Best-effort: a write failure logs but never fails the
                // command — the rename is already live in memory (and will
                // ship in the next `Msg::Hello`) even if the disk write
                // doesn't survive a restart.
                if let Some(dir) = keystore_dir {
                    if let Err(e) = crate::keystore::save_device_name(dir, &resolved) {
                        tracing::warn!(error = %e, "failed to persist device name");
                    }
                }
                dispatch(
                    vec![Action::EmitState],
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
                    peer_meta,
                    outbox,
                    pending_pairs,
                    seq_store,
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
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
            )
            .await;
            CmdResponse::ok(req_id, None)
        }
        // M-TRAY-03: actually terminate. The tray's `restart_stale_daemon`
        // sends `shutdown` then waits for the socket to close before it
        // respawns the up-to-date binary; a no-op left the stale daemon
        // running forever. Cancelling the token breaks every loop; the ok
        // reply below still flushes (sent at the tail of this fn) before
        // `run()` returns and the process exits.
        CmdOp::Shutdown {} => {
            tracing::info!("Shutdown requested via IPC; cancelling daemon");
            shutdown.cancel();
            CmdResponse::ok(req_id, None)
        }
        CmdOp::Unpair {} => {
            tracing::info!("Manual unpair requested via IPC");
            // Tell the live peer to drop us from its trust store, otherwise
            // it auto-reconnects through the next TOFU window and re-pairs
            // without a QR scan. Best-effort: if the session is down the
            // peer keeps a stale entry, which only it can clean up.
            let revoke = Frame {
                version: PROTOCOL_VERSION,
                msg: Msg::Revoke,
            };
            if let Ok(bytes) = fluxsync_proto::encode(&revoke) {
                let _ = transport.send_encrypted(&bytes).await;
            }
            // VULN-001 variant V1: snapshot+retry+rollback. Without this,
            // a disk failure during unpair would clear live trust while
            // peers.json still trusts every peer; a daemon restart would
            // silently re-trust them.
            let snapshot = trusted.lock().await.clone();
            trusted.lock().await.clear();
            // DIR-P2-04a: the mDNS discovery cache holds every seen peer's
            // pubkey, name, addrs, and pairing PIN. Purge it unconditionally
            // on unpair — even if the disk persist below fails and trust is
            // rolled back, losing stale discovery data is harmless (mDNS
            // re-announces), never a regression from the pre-unpair state.
            disc_cache.lock().await.clear();
            // DIR-P1-02: same rationale — a stale backoff timer for a
            // now-untrusted peer must not survive to throttle a future
            // re-pair of that same peer-id.
            backoff.lock().await.clear();
            if let Some(dir) = keystore_dir {
                if let Err(e) = save_peers_with_retry(dir, trusted, transport).await {
                    *trusted.lock().await = snapshot;
                    return reply_err(
                        reply,
                        req_id,
                        &format!(
                            "persist failed after {PEERS_PERSIST_ATTEMPTS} attempts: {e}; unpair rolled back, retry once disk recovers"
                        ),
                    );
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
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
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
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
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
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
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
            // C1: surgical removal of a single peer. The previous flow
            // went through `Event::ManualUnpair` → `Action::DropPeer`
            // which `trusted.clear()`s the entire trust store, so
            // revoking one peer wiped every other paired device. We
            // now (a) remove only the target slot from the in-memory
            // set, (b) persist the new set under the disk lock, and
            // (c) tear down the live session **only if** the revoked
            // peer is the one currently linked. Other peers stay
            // trusted and reachable.
            //
            // VULN-001 variant V2 still applies: revoke must succeed on
            // disk before we acknowledge, otherwise a daemon restart
            // would re-trust the peer we just promised to drop.
            let removed_trusted = trusted.lock().await.remove(&arr);
            // DIR-P2-04a: purge this peer's mDNS discovery-cache entry
            // (pubkey, name, addrs, pairing PIN) so a revoked peer isn't
            // still resolvable via a stale cache hit (e.g. PairFromPin).
            disc_cache.lock().await.remove(&arr);
            // DIR-P1-02: same rationale — drop the revoked peer's backoff
            // timer too.
            backoff.lock().await.remove(&arr);
            if let Some(dir) = keystore_dir {
                if let Err(e) = save_peers_with_retry(dir, trusted, transport).await {
                    if let Some(p) = removed_trusted {
                        trusted.lock().await.insert(arr, p);
                    }
                    return reply_err(
                        reply,
                        req_id,
                        &format!(
                            "persist failed after {PEERS_PERSIST_ATTEMPTS} attempts: {e}; revoke rolled back, retry once disk recovers"
                        ),
                    );
                }
            }
            // FluxMesh robustness slice 4: per-peer unpair must work for a
            // SECONDARY too. Signal the target so it drops us from its own
            // trust + tears down, then drop our side. `drop_session_for` keys
            // by peer, so a revoked secondary no longer stays linked and
            // syncing — the old code only tore down the primary, leaving a
            // revoked secondary live. Finally delist it from the mesh.
            if transport.has_session_for(arr).await {
                if let Ok(b) = fluxsync_proto::encode(&Frame {
                    version: PROTOCOL_VERSION,
                    msg: Msg::Revoke,
                }) {
                    let _ = transport.send_encrypted_to(arr, &b).await;
                }
            }
            // Bug #16 fix: a revoke is permanent — this peer can never
            // legitimately reconnect, so unlike the transient Bye/
            // ghost-timeout teardowns, nothing depends on the `extra` stub
            // surviving. `purge_peer` drops the session AND removes the
            // whole `PeerConn` entry so repeated pair/revoke churn can't
            // grow `extra` unboundedly.
            transport.purge_peer(arr).await;
            if peer_meta.lock().await.remove(&arr).is_some() {
                let _ = event_tx.try_send(Event::MeshPeersChanged);
            }
            // FIX1 (P0 parked-payload leak): drop this peer's Ask-parked
            // pending items (both directions) whether it was the primary or
            // a secondary — nobody is left to deliver an inbound item to,
            // or to receive an outbound one. Unlike `Event::PeerLost` (a
            // transient disconnect, which must NOT drop pending — see its
            // doc comment), a revoke is permanent, so this always runs,
            // independent of the primary-failover branch below.
            let mut revoke_actions = app.handle(Event::PeerRevoked { peer_id: arr }, &**wall);
            purge_dropped_pending_from_outbox_stage(&revoke_actions, outbox_stage).await;
            purge_peer_from_inflight(arr, inflight).await;
            // If the revoked peer was the primary, rebind State: fail over to a
            // live secondary if one exists, else walk Linked → Discovering
            // (CloseSession touches only the session, not the trust store).
            let active = app.snapshot().peer_id;
            if active == arr && !try_primary_failover(transport, event_tx, peer_meta).await {
                revoke_actions.extend(app.handle(Event::PeerLost { peer_id: arr }, &**wall));
            }
            dispatch(
                revoke_actions,
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
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
            )
            .await;
            CmdResponse::ok(req_id, None)
        }
        // FS-052: list peers that landed in `trusted` under the TOFU
        // window but have not yet been verbally confirmed.
        CmdOp::PairPending {} => {
            let now = Instant::now();
            let entries: Vec<crate::cmd::PendingPairEntry> = {
                let mut g = pending_pairs.lock().await;
                // Expire stale entries before answering so callers never
                // see a pair the daemon would refuse to confirm anyway.
                g.retain(|_, p| p.expires_at > now);
                g.iter()
                    .map(|(peer_id, p)| crate::cmd::PendingPairEntry {
                        peer_id: hex::encode(peer_id),
                        name: p.name.clone(),
                        sas_words: p.sas_words.to_vec(),
                        addr: Some(p.from.to_string()),
                        expires_in_ms: Some(
                            p.expires_at
                                .saturating_duration_since(now)
                                .as_millis()
                                .min(u128::from(u64::MAX)) as u64,
                        ),
                    })
                    .collect()
            };
            CmdResponse::ok(req_id, Some(CmdData::PendingPairs(entries)))
        }

        // FS-052: resolve a pending pair. Accept = drop from the pending
        // map (peer keeps its trusted slot). Reject = revoke, same path
        // as `CmdOp::Revoke`, so an attacker that raced into the trusted
        // set is purged from `peers.json` and the live session is torn
        // down.
        CmdOp::PairConfirm { peer_id, accept } => {
            let Ok(bytes) = hex::decode(&peer_id) else {
                return reply_err(reply, req_id, "bad hex peer_id");
            };
            let arr: [u8; 32] = match bytes.try_into() {
                Ok(a) => a,
                Err(_) => return reply_err(reply, req_id, "expected 32-byte peer_id"),
            };
            let removed_pending = pending_pairs.lock().await.remove(&arr);
            if removed_pending.is_none() {
                return reply_err(reply, req_id, "no pending pair with that peer_id");
            }
            if accept {
                // FS-052 wire mutual confirm: tell the peer our human said
                // yes — but only if we know it understands `Msg::PairConfirm`.
                // Caps unknown (Hello not arrived yet) → defer the send to
                // the `Msg::Hello` handler; known-legacy → nothing to send,
                // and the peer counts as confirmed (the Hello handler
                // already fired `SasPeerConfirmed` when its caps arrived).
                let (hello_seen, supports_sas) = {
                    let meta = peer_meta.lock().await;
                    meta.get(&arr).map_or((false, false), |m| {
                        (m.hello_seen, m.caps.iter().any(|c| c == "sas-confirm"))
                    })
                };
                if hello_seen {
                    if supports_sas {
                        let frame = Frame {
                            version: PROTOCOL_VERSION,
                            msg: Msg::PairConfirm(fluxsync_proto::PairConfirm { accept: true }),
                        };
                        if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                            if let Err(e) = transport.send_encrypted_to(arr, &bytes).await {
                                tracing::warn!(
                                    peer = ?&arr[..6],
                                    error = %e,
                                    "sas-confirm: PairConfirm(accept) send failed"
                                );
                            }
                        }
                    } else {
                        // Legacy peer: defensively count it as confirmed in
                        // case its Hello landed before the pending insert and
                        // the Hello handler's legacy path never fired.
                        let actions = app.handle(Event::SasPeerConfirmed { peer_id: arr }, &**wall);
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
                            peer_meta,
                            outbox,
                            pending_pairs,
                            seq_store,
                        )
                        .await;
                    }
                } else {
                    deferred_sas_confirm.lock().await.insert(arr);
                }
                let actions = app.handle(Event::SasLocalConfirmed { peer_id: arr }, &**wall);
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
                    peer_meta,
                    outbox,
                    pending_pairs,
                    seq_store,
                )
                .await;
            } else {
                // FS-052 wire mutual confirm: best-effort tell the peer our
                // human said NO while the session is still alive — the
                // peer-scoped teardown below sends Bye and drops it. A
                // legacy peer fails to decode the unknown variant and just
                // logs a warn; the Bye that follows still cleans it up.
                deferred_sas_confirm.lock().await.remove(&arr);
                let frame = Frame {
                    version: PROTOCOL_VERSION,
                    msg: Msg::PairConfirm(fluxsync_proto::PairConfirm { accept: false }),
                };
                if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                    let _ = transport.send_encrypted_to(arr, &bytes).await;
                }
                let removed_trusted = trusted.lock().await.remove(&arr);
                // DIR-P2-04a: same rationale as `CmdOp::Revoke` — per the
                // comment above, this rejection IS a revoke, so purge the
                // peer's discovery-cache entry too.
                disc_cache.lock().await.remove(&arr);
                // DIR-P1-02: same rationale — purge its backoff timer too.
                backoff.lock().await.remove(&arr);
                if let Some(dir) = keystore_dir {
                    if let Err(e) = save_peers_with_retry(dir, trusted, transport).await {
                        // VULN-001 fix: roll back the in-memory removal
                        // so on-disk and in-memory state stay consistent.
                        // Otherwise a restart would re-trust the peer we
                        // just told the user we revoked.
                        if let Some(p) = removed_trusted {
                            trusted.lock().await.insert(arr, p);
                        }
                        if let Some(p) = removed_pending {
                            pending_pairs.lock().await.insert(arr, p);
                        }
                        return reply_err(
                            reply,
                            req_id,
                            &format!(
                                "persist failed after {PEERS_PERSIST_ATTEMPTS} attempts: {e}; reject rolled back, retry once disk recovers"
                            ),
                        );
                    }
                }
                // Peer-scoped teardown, mirroring `CmdOp::Revoke`: the
                // previous flow fired `Event::ManualUnpair`, whose FSM
                // actions (`CloseSession`/`DropPeer`) are unit/primary-only
                // (`send_encrypted` + `drop_session`, both hit `self.conn`).
                // Rejecting a SECONDARY's SAS was therefore sending Bye to
                // the PRIMARY and tearing down the primary's healthy
                // session, while the rejected secondary — which only ever
                // received the `PairConfirm{accept:false}` sent above, never
                // a session drop — stayed fully linked.
                if transport.has_session_for(arr).await {
                    if let Ok(b) = fluxsync_proto::encode(&Frame {
                        version: PROTOCOL_VERSION,
                        msg: Msg::Bye,
                    }) {
                        let _ = transport.send_encrypted_to(arr, &b).await;
                    }
                }
                // Bug #16 fix: a local reject revokes trust permanently,
                // same rationale as `CmdOp::Revoke` — purge the `extra`
                // stub too instead of leaving it to leak.
                transport.purge_peer(arr).await;
                if peer_meta.lock().await.remove(&arr).is_some() {
                    let _ = event_tx.try_send(Event::MeshPeersChanged);
                }
                let mut reject_actions = app.handle(Event::PeerRevoked { peer_id: arr }, &**wall);
                purge_dropped_pending_from_outbox_stage(&reject_actions, outbox_stage).await;
                purge_peer_from_inflight(arr, inflight).await;
                // If the rejected peer was the primary, rebind State the
                // same way `CmdOp::Revoke` does: fail over to a live
                // secondary if one exists, else walk Linked → Discovering.
                let active = app.snapshot().peer_id;
                if active == arr && !try_primary_failover(transport, event_tx, peer_meta).await {
                    reject_actions.extend(app.handle(Event::PeerLost { peer_id: arr }, &**wall));
                }
                dispatch(
                    reject_actions,
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
                    peer_meta,
                    outbox,
                    pending_pairs,
                    seq_store,
                )
                .await;
            }
            CmdResponse::ok(req_id, None)
        }

        CmdOp::PairShow {} => {
            // Re-pairing while already paired is allowed: FS-052 gates any
            // peer that TOFU-joins through this window behind the SAS verify
            // (pending entry + reaper revoke), so an attacker handshaking in
            // is no better off than during a first pair. Without this, a
            // device whose peer was reset or unreachable for a long time
            // could never re-pair (the old `already_paired` refusal).
            let static_pub = identity.public_key();
            let peer_id = identity.peer_id();
            let pubkey_b32 = base32::encode(BASE32_ALPHA, &static_pub);
            let words = fingerprint(&static_pub);
            let words_vec: Vec<String> = words.iter().map(|s| (*s).to_string()).collect();
            let addr_hint = local_lan_addr(udp_bind, udp_port);
            // Optional Tailscale path: if this host has a tailnet address,
            // fold it into the SAME uri (`a=lan,tailnet`) so a single QR
            // works on the LAN and across a tailnet — the initiator tries
            // each hint in order. Pure routing probe, no Tailscale
            // dependency — see tailnet_local_addr.
            let tailnet_addr_hint = tailnet_local_addr(udp_port);
            let addr_hints = match &tailnet_addr_hint {
                Some(t) => format!("{addr_hint},{t}"),
                None => addr_hint.clone(),
            };
            let uri = build_pair_uri(&pubkey_b32, &addr_hints, &words_vec);
            // Open the TOFU window so the peer that scans this QR is
            // accepted on first handshake even though we don't know its
            // pubkey yet. Kept short (see `handshake::PAIRING_WINDOW`) so
            // a stale QR or a drive-by LAN handshake can't be exploited.
            *pairing_window.lock().await = Some(Instant::now() + handshake::PAIRING_WINDOW);
            tracing::info!("pairing window opened (90s)");
            // PR2: generate a fresh PIN, advertise it on mDNS, and
            // spawn a rotation watchdog if one is not already running.
            // The watchdog regenerates the PIN every PAIRING_WINDOW
            // while the trusted set is still empty, then clears the
            // TXT when the user pairs or the window times out.
            let pin = gen_pair_pin();
            let expires_at = Instant::now() + handshake::PAIRING_WINDOW;
            let was_active = pin_advert
                .lock()
                .await
                .replace(PinAd {
                    pin: pin.clone(),
                    expires_at,
                })
                .is_some();
            if let Some(ctx) = mdns_ctx.lock().await.as_ref() {
                if let Err(e) = discovery::republish_with_pin(
                    &ctx.daemon,
                    &ctx.instance_name,
                    &ctx.peer_id_hex,
                    &ctx.static_pub_hex,
                    ctx.bind_ip,
                    ctx.udp_port,
                    Some(&pin),
                ) {
                    tracing::warn!(error = %e, "mDNS republish_with_pin failed");
                }
            }
            if !was_active {
                spawn_pin_watchdog(pin_advert.clone(), mdns_ctx.clone(), pairing_window.clone());
            }
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
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
            )
            .await;
            // PR2: surface the PIN + epoch-ms expiry to the UI so the
            // pair window can render the 6-digit code + countdown.
            let pin_expires_at_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_millis() as u64 + handshake::PAIRING_WINDOW.as_millis() as u64);
            CmdResponse::ok(
                req_id,
                Some(CmdData::PairInfo {
                    peer_id_hex: hex::encode(peer_id),
                    pubkey_b32,
                    fingerprint_words: words_vec,
                    addr_hint,
                    uri,
                    pin: Some(pin),
                    pin_expires_at_ms,
                    tailnet_addr_hint,
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
            // H1: reject all-zero + known low-order Curve25519 points
            // before they reach `trusted`. A degenerate pubkey would
            // pin Noise IK to predictable DH output; rejecting here is
            // cheaper than a SAS-time failure and avoids ever writing
            // such an entry to disk.
            if let Err(e) = fluxsync_crypto::validate_peer_pubkey(&static_pub) {
                return reply_err(reply, req_id, &format!("bad pubkey in uri: {e}"));
            }
            let peer_id = handshake::peer_id_for(&static_pub);
            // H3: cap the trust store so an attacker that lures the user
            // into repeated `pair from-uri` runs cannot indefinitely
            // grow peers.json. 64 distinct devices is well past any
            // realistic personal/family setup; raise via config later if
            // a real fleet use case shows up. The check is "len before
            // insert" so re-pairing the same peer (same peer_id) stays
            // legal — `upsert` just refreshes the existing slot.
            {
                let g = trusted.lock().await;
                if !g.contains_key(&peer_id) && g.len() >= MAX_PERSISTED_PEERS {
                    return reply_err(
                        reply,
                        req_id,
                        &format!(
                            "trust store full ({MAX_PERSISTED_PEERS} peers); revoke an existing peer first"
                        ),
                    );
                }
            }
            // Same reconnect-not-fresh-pair rule as PairAccept/PairFromPin:
            // rescanning an already-trusted peer's QR (no fresh pending pair
            // in flight for it) is a silent reconnect, not a re-verification.
            // Without this, re-scanning a known peer engaged the SAS gate on
            // the scanning side only — the responder's already-trusted branch
            // (handshake.rs) never inserts a pending entry or fires
            // `SasPairingStarted`, so the scanner's `PairConfirm` would land
            // on the responder's silent-ignore branch and the scanner would
            // stick at `sas_phase = "local_confirmed"` until the 90s pending
            // reaper fired `SasReset` AND revoked the peer's trust. A genuine
            // fresh pair (peer not yet trusted, or a still-open pending from
            // an in-progress verification) still engages the gate below.
            let already_confirmed = trusted.lock().await.contains_key(&peer_id)
                && !pending_pairs.lock().await.contains_key(&peer_id);
            trusted.lock().await.insert(
                peer_id,
                TrustedPeer {
                    static_pub,
                    name: name.clone(),
                },
            );

            // Persist the new peer to disk immediately.
            // VULN-001 variant V3: if disk write fails, in-mem trust would
            // silently vanish on next restart. Roll back the insert and
            // surface the failure so the user knows the pairing is not
            // durable. F-001/F-002 hardening: upsert under the
            // `peers_disk_lock` so a concurrent reaper revoke cannot race
            // against the load, and propagate parse errors instead of
            // silently overwriting a corrupt `peers.json`.
            if let Some(dir) = keystore_dir {
                if let Err(e) = upsert_peer_persist(
                    dir,
                    transport,
                    crate::keystore::StoredPeer {
                        peer_id_hex: hex::encode(peer_id),
                        static_pub_hex: hex::encode(static_pub),
                        name: name.clone(),
                        last_addr: None,
                    },
                )
                .await
                {
                    trusted.lock().await.remove(&peer_id);
                    return reply_err(
                        reply,
                        req_id,
                        &format!(
                            "persist failed after {PEERS_PERSIST_ATTEMPTS} attempts: {e}; pair rolled back, retry once disk recovers"
                        ),
                    );
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
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
            )
            .await;
            // URI carries one or more address hints; if any parsed, kick
            // off the initiator immediately (it tries each in order, LAN
            // before tailnet). If none, the trust has been recorded and
            // discovery (or a later pair-accept --addr) can drive it.
            if parsed.addrs.is_empty() {
                tracing::warn!("pair uri carried no usable addr; deferring to discovery");
            } else {
                start_initiator(
                    identity.clone(),
                    static_pub,
                    parsed.addrs,
                    peer_id,
                    name,
                    transport.clone(),
                    pending_initiator_tx.clone(),
                    event_tx.clone(),
                    // None on an already-trusted, not-pending peer → silent
                    // reconnect, same as PairAccept/PairFromPin. Otherwise
                    // Some so the SAS gate engages and the initiator's verify
                    // screen gets its 6 words.
                    if already_confirmed {
                        None
                    } else {
                        Some(pending_pairs.clone())
                    },
                    backoff.clone(),
                    trusted.clone(),
                    keystore_dir.cloned(),
                )
                .await;
            }
            CmdResponse::ok(
                req_id,
                Some(CmdData::PairResult {
                    already_paired: already_confirmed,
                }),
            )
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
            // H1: same validation as PairFromUri. PairAccept is the
            // manual `--addr` path; just as scriptable, just as risky.
            if let Err(e) = fluxsync_crypto::validate_peer_pubkey(&static_pub) {
                return reply_err(reply, req_id, &format!("bad pubkey: {e}"));
            }
            let peer_id = handshake::peer_id_for(&static_pub);
            // H3: trust-store cap. Same rationale as PairFromUri.
            {
                let g = trusted.lock().await;
                if !g.contains_key(&peer_id) && g.len() >= MAX_PERSISTED_PEERS {
                    return reply_err(
                        reply,
                        req_id,
                        &format!(
                            "trust store full ({MAX_PERSISTED_PEERS} peers); revoke an existing peer first"
                        ),
                    );
                }
            }
            // Same reconnect-not-fresh-pair rule as PairFromUri.
            let already_confirmed = trusted.lock().await.contains_key(&peer_id)
                && !pending_pairs.lock().await.contains_key(&peer_id);
            trusted.lock().await.insert(
                peer_id,
                TrustedPeer {
                    static_pub,
                    name: name.clone(),
                },
            );

            // Persist the new peer to disk immediately.
            // VULN-001 variant V4: same shape as PairFromUri — rollback
            // in-mem insert + reply_err on persist failure so the caller
            // knows the trust is not durable. F-001/F-002 hardening: see
            // PairFromUri above for the lock + parse-error rationale.
            if let Some(dir) = keystore_dir {
                if let Err(e) = upsert_peer_persist(
                    dir,
                    transport,
                    crate::keystore::StoredPeer {
                        peer_id_hex: hex::encode(peer_id),
                        static_pub_hex: hex::encode(static_pub),
                        name: name.clone(),
                        last_addr: None,
                    },
                )
                .await
                {
                    trusted.lock().await.remove(&peer_id);
                    return reply_err(
                        reply,
                        req_id,
                        &format!(
                            "persist failed after {PEERS_PERSIST_ATTEMPTS} attempts: {e}; pair rolled back, retry once disk recovers"
                        ),
                    );
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
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
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
                            vec![parsed],
                            peer_id,
                            name,
                            transport.clone(),
                            pending_initiator_tx.clone(),
                            event_tx.clone(),
                            if already_confirmed {
                                None
                            } else {
                                Some(pending_pairs.clone())
                            },
                            backoff.clone(),
                            trusted.clone(),
                            keystore_dir.cloned(),
                        )
                        .await;
                    }
                    Err(_) => return reply_err(reply, req_id, "bad addr"),
                }
            }
            CmdResponse::ok(req_id, None)
        }
        // PR2: PIN-method pair. Look up the discovery cache for a
        // peer whose mDNS `pair_pin` TXT matches, then take the same
        // path as `PairFromUri`: trust + persist + start_initiator.
        // The UI is expected to follow up with `PairPending` +
        // `PairConfirm` for verify-words gating — without that the
        // pair lands in `pending_pairs` and the reaper revokes it
        // after `PAIRING_WINDOW`.
        CmdOp::PairFromPin { pin, name } => {
            if pin.len() != 6 || !pin.bytes().all(|b| b.is_ascii_digit()) {
                return reply_err(reply, req_id, "bad pin format (6 digits)");
            }
            let target = {
                let cache = disc_cache.lock().await;
                let now = Instant::now();
                cache
                    .values()
                    .filter(|e| now.duration_since(e.last_seen) < DISCOVERY_CACHE_TTL)
                    .find(|e| e.pair_pin.as_deref() == Some(pin.as_str()))
                    .cloned()
            };
            let Some(target) = target else {
                return reply_err(reply, req_id, "no_peer_with_pin");
            };
            let static_pub = target.static_pub;
            // H1: even the PIN-method path needs to validate the
            // discovered peer's static pubkey. mDNS is unauthenticated;
            // an attacker controlling the LAN could advertise a
            // degenerate pubkey on a guessed PIN.
            if let Err(e) = fluxsync_crypto::validate_peer_pubkey(&static_pub) {
                return reply_err(reply, req_id, &format!("bad pubkey from discovery: {e}"));
            }
            let peer_id = handshake::peer_id_for(&static_pub);
            // H3: trust-store cap.
            {
                let g = trusted.lock().await;
                if !g.contains_key(&peer_id) && g.len() >= MAX_PERSISTED_PEERS {
                    return reply_err(
                        reply,
                        req_id,
                        &format!(
                            "trust store full ({MAX_PERSISTED_PEERS} peers); revoke an existing peer first"
                        ),
                    );
                }
            }
            // Same reconnect-not-fresh-pair rule as PairFromUri.
            let already_confirmed = trusted.lock().await.contains_key(&peer_id)
                && !pending_pairs.lock().await.contains_key(&peer_id);
            trusted.lock().await.insert(
                peer_id,
                TrustedPeer {
                    static_pub,
                    name: name.clone(),
                },
            );
            // Mirror PairFromUri's persist-or-rollback (VULN-001 V3 /
            // F-001 hardening). PIN-method pair has identical durability
            // requirements: on disk failure, drop the in-mem trust.
            if let Some(dir) = keystore_dir {
                if let Err(e) = upsert_peer_persist(
                    dir,
                    transport,
                    crate::keystore::StoredPeer {
                        peer_id_hex: hex::encode(peer_id),
                        static_pub_hex: hex::encode(static_pub),
                        name: name.clone(),
                        last_addr: None,
                    },
                )
                .await
                {
                    trusted.lock().await.remove(&peer_id);
                    return reply_err(
                        reply,
                        req_id,
                        &format!(
                            "persist failed after {PEERS_PERSIST_ATTEMPTS} attempts: {e}; pair rolled back, retry once disk recovers"
                        ),
                    );
                }
            }
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
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
            )
            .await;
            start_initiator(
                identity.clone(),
                static_pub,
                vec![target.addr],
                peer_id,
                name,
                transport.clone(),
                pending_initiator_tx.clone(),
                event_tx.clone(),
                if already_confirmed {
                    None
                } else {
                    Some(pending_pairs.clone())
                },
                backoff.clone(),
                trusted.clone(),
                keystore_dir.cloned(),
            )
            .await;
            CmdResponse::ok(
                req_id,
                Some(CmdData::PairResult {
                    already_paired: already_confirmed,
                }),
            )
        }
    };
    let _ = reply.send(resp);
}

pub(super) fn reply_err(reply: oneshot::Sender<CmdResponse>, id: u64, msg: &str) {
    let _ = reply.send(CmdResponse::err(id, msg));
}

pub(super) fn peer_entry(state: &State, addr: Option<SocketAddr>) -> Option<PeerEntry> {
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
