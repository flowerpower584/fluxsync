//! Executing the core's `Action`s: outbound gating, send/write/emit dispatch.

use super::*;

/// M-DAEMON-01 / H-DAEMON-01: strip outbound `SendItem` actions when the
/// active peer landed via TOFU but has not been verbally confirmed (SAS) yet.
/// Mirrors the inbound FS-052 gate in `dispatch_inbound_frame`, so clipboard
/// never flows in *either* direction to an unconfirmed peer during the pairing
/// window. Non-clipboard actions (state/log/battery) pass through untouched and
/// local history is unaffected — only the wire send is held back.
pub(super) async fn gate_outbound(
    actions: Vec<Action>,
    transport: &Arc<Transport>,
    pending_pairs: &PendingSet,
) -> Vec<Action> {
    let pending = match transport.cached_peer_id().await {
        Some(id) => pending_pairs.lock().await.contains_key(&id),
        None => false,
    };
    if !pending {
        return actions;
    }
    actions
        .into_iter()
        .filter(|a| {
            if matches!(a, Action::SendItem { .. }) {
                tracing::warn!(
                    "FS-052 gate: suppressing outbound clipboard — peer not yet verbally confirmed"
                );
                false
            } else {
                true
            }
        })
        .collect()
}

/// FIX3 (synchronous security-wipe mirror): if `app`'s `vault_wipe_gen`
/// has advanced past `*last_wipe_gen` since the last call, make everything
/// outside the in-memory history hold exactly what the wipe kept there —
/// nothing for an untrusted-peer or peer-swap wipe, the favorites for a ghost
/// timeout — AWAITING it before returning: the resync outbox (and its
/// `Ask`-staged entries) and in-flight frames are dropped, the image cache
/// keeps only the kept rows' bytes, and the on-disk vault is deleted, or
/// atomically rewritten with the kept rows when there are any (never "delete
/// then rewrite", which a crash in between would turn into losing them).
/// `vault` is the keystore dir and the at-rest key. Returns whether a wipe
/// actually ran.
///
/// Callers MUST run this after `app.handle` but before the resulting
/// `Action`s are `dispatch`ed — `dispatch`'s `Action::EmitState` is what
/// publishes the new state to IPC/watch subscribers, and this must finish
/// first so nobody can observe "history cleared" while the outbox or
/// `history.enc` still hold a wiped secret. See the call site in `run()`'s
/// main event loop.
///
/// Factored out of that loop (rather than left inline) so it is
/// independently unit-testable — see the tests below — the same rationale
/// `persist_history_change` is its own function for.
pub(super) async fn sync_security_wipe_if_needed(
    app: &App,
    last_wipe_gen: &mut u64,
    outbox: &SharedOutbox,
    outbox_stage: &PendingOutboxStage,
    inflight: &InflightMap,
    vault: Option<(&PathBuf, &[u8; 32])>,
) -> bool {
    let gen_now = app.snapshot().vault_wipe_gen;
    if gen_now == *last_wipe_gen {
        return false;
    }
    *last_wipe_gen = gen_now;
    let kept = app.snapshot().history.clone();
    outbox.lock().await.clear_all();
    outbox_stage.lock().await.clear();
    // Bug #9: a sensitive item's outbound frames are tracked in `inflight`
    // regardless of sensitivity (only the `outbox` insert is sensitive-
    // gated), so without this a wiped item's plaintext frames survive the
    // wipe in RAM and keep retransmitting to its targets.
    inflight.lock().await.clear();
    // L1 fix: a security wipe must also purge inbound image bytes stashed in
    // `IMAGE_CACHE` (`WriteClipboard`'s image handler, every platform) — a
    // process-wide store with no other trigger to clear it, so a wiped
    // image could otherwise still be pulled via `CmdOp::FetchItem`. Only a
    // kept row's bytes stay, so a kept (favorite) image still previews and
    // copies.
    if let Ok(mut g) = image_cache().lock() {
        g.retain(|(hash, _)| kept.iter().any(|h| &h.hash == hash));
    }
    if let Some((dir, key)) = vault {
        let (dir, key) = (dir.clone(), zeroize::Zeroizing::new(*key));
        let result = tokio::task::spawn_blocking(move || {
            if kept.is_empty() {
                return history_store::clear(&dir);
            }
            let now = now_ms();
            let entries: Vec<VaultEntry> = kept
                .into_iter()
                .map(|item| VaultEntry {
                    item,
                    created_ms: now,
                })
                .collect();
            history_store::save(
                &dir,
                &key,
                &entries,
                now,
                history_store::DEFAULT_TTL_SECS,
                history_store::DEFAULT_DISK_CAP,
            )
        })
        .await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(
                error = %e,
                "synchronous security-wipe disk mirror failed; persister will retry"
            ),
            Err(e) => tracing::warn!(
                error = %e,
                "synchronous security-wipe disk mirror task join failed"
            ),
        }
    }
    true
}

/// FIX1 (P0 parked-payload leak): scan `actions` for the `Action::
/// PendingDropped` signal `App::handle` emits when `Event::PeerRevoked`
/// drops a peer's parked `Ask` items (`App::drop_pending_for`), and purge
/// the matching `PendingOutboxStage` entries too — otherwise a revoked
/// peer's staged (not-yet-admitted-to-history) outbox entry has no other
/// trigger to clear it once the `state.pending` row it mirrored is gone,
/// and leaks in the stage map forever. Idempotent: removing an
/// already-absent hash is a no-op. Called at both places `Event::
/// PeerRevoked` can be produced: `CmdOp::Revoke` (direct `app.handle` call)
/// and `run()`'s main event loop (the silent-secondary-timeout path in
/// `heartbeat_loop` only has an `event_tx`, so it routes through there).
pub(super) async fn purge_dropped_pending_from_outbox_stage(
    actions: &[Action],
    outbox_stage: &PendingOutboxStage,
) {
    let mut stage = outbox_stage.lock().await;
    for action in actions {
        if let Action::PendingDropped { hashes } = action {
            for hash in hashes {
                stage.remove(hash);
            }
        }
    }
}

/// Bug #9 (inflight survives revoke): drop `peer_id` from every
/// `Inflight.pending_peers` — otherwise the retransmit timer keeps firing at
/// a permanently-revoked peer, and if that peer id later re-TOFU-joins
/// within `INFLIGHT_MAX_AGE` the stale retransmit delivers straight into its
/// new, unconfirmed session (a second FS-052 bypass). An entry whose
/// `pending_peers` becomes empty is dropped outright rather than left to
/// expire on its own. Called at every place a peer is permanently torn
/// down: `CmdOp::Revoke`, `CmdOp::PairConfirm{accept: false}` (mirrors
/// Revoke), and the silent-secondary-timeout `Event::PeerRevoked` path in
/// `run()`'s main loop.
pub(super) async fn purge_peer_from_inflight(peer_id: [u8; 32], inflight: &InflightMap) {
    inflight.lock().await.retain(|_, inf| {
        inf.pending_peers.remove(&peer_id);
        !inf.pending_peers.is_empty()
    });
}

#[allow(clippy::cast_possible_truncation)]
pub(super) async fn dispatch(
    actions: Vec<Action>,
    app: &mut App,
    seq_store: &mut Option<SeqStore>,
    sh: &Shared,
) {
    let Shared {
        transport,
        state_watch_tx,
        logs_bcast_tx,
        log_tail,
        last_written_hashes,
        metrics,
        inflight,
        outbox,
        pending_pairs,
        ..
    } = sh;
    for action in actions {
        tracing::debug!(?action, "dispatching action");
        match action {
            Action::EmitState => {
                let snap = sh.publishable_state(app).await;
                // Only wake subscribers (IPC clients re-serialize the whole
                // State, history included) when something actually changed.
                state_watch_tx.send_if_modified(|current| {
                    if *current == snap {
                        false
                    } else {
                        *current = snap;
                        true
                    }
                });
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

                if payload.len() > MAX_PAYLOAD {
                    // Unreachable backstop: every producer caps upstream now —
                    // the watcher (text + image), CmdOp::Push (text), and
                    // CmdOp::PushImage (image) all reject over-cap payloads
                    // before they reach here. Fail closed if one ever slips
                    // through anyway: drop the item rather than truncate (a
                    // truncated PNG/text blob is corrupt, and sending it
                    // would silently desync the peer). `debug_assert!` turns
                    // this into a hard test failure if an upstream cap is
                    // ever removed or bypassed.
                    tracing::error!(
                        size = payload.len(),
                        cap = MAX_PAYLOAD,
                        "BUG: over-cap payload reached SendItem; dropping item (an upstream cap was bypassed)"
                    );
                    debug_assert!(
                        false,
                        "over-cap payload ({} bytes > {MAX_PAYLOAD} cap) reached Action::SendItem",
                        payload.len()
                    );
                    continue;
                }

                // FluxMesh: stamp this item with its origin device + a
                // per-origin sequence so the mesh dedups/anti-loops on
                // identity rather than content hash. Allocated once per
                // item; the chunked header carries the same EventId.
                let event_id = app.next_local_event_id();
                let origin = event_id.origin.into_bytes();
                let event_seq = event_id.seq;

                // Persist the reserve-ahead horizon past this seq (cheap
                // no-op unless the counter just reached it) so a restart
                // never re-issues a seq a peer's SeenSet has already
                // recorded. See `seq_store.rs`.
                if let Some(store) = seq_store.as_mut() {
                    if let Err(e) = store.advance(event_seq + 1) {
                        tracing::warn!(
                            error = %e,
                            "seq_store: failed to persist advanced outgoing-seq horizon"
                        );
                    }
                }

                // Build every datagram for this item up front, encoded. The
                // same bytes are kept in the inflight table so the retransmit
                // timer can re-send them verbatim until acked.
                let frames = build_item_frames(
                    app.clock.now(),
                    hash,
                    kind,
                    &payload,
                    sensitive,
                    origin,
                    event_seq,
                );

                if frames.is_empty() {
                    tracing::error!("SendItem: nothing to send (encode failed)");
                } else {
                    // FluxMesh 2C-b: fan the item out to every linked peer.
                    let targets = transport.linked_peer_ids().await;
                    if targets.is_empty() {
                        // DEFECT 3 fix: an item copied while fully unlinked
                        // must never enter the outbox. The resync-1 promise is
                        // narrow — recover items whose DELIVERY was actually
                        // attempted but went unacked when the link dropped —
                        // not "resurface anything ever copied offline" (that
                        // was a privacy leak: an old private copy from hours
                        // earlier, made with no peer connected, would flush to
                        // whichever peer links next). Gating on a non-empty
                        // `targets` here, computed BEFORE the outbox write,
                        // is what proves delivery was attempted. Compare the
                        // receive-side inserts (`complete_reassembled_item`,
                        // the non-chunked first-sight path): those are
                        // inherently fine, since receiving/relaying a frame at
                        // all requires an active linked session with the peer
                        // that sent it.
                        tracing::warn!("SendItem: no linked peers; nothing to send");
                    } else {
                        // Resync-on-reconnect (resync-1): keep a resend copy so
                        // a *different* peer that reconnects later can be
                        // offered this item too. Sensitive items must never
                        // enter the outbox (see `crate::outbox`'s security
                        // invariant). Deliberately inside the `targets`
                        // non-empty branch — see the DEFECT 3 note above.
                        if !sensitive {
                            outbox.lock().await.insert(
                                hash,
                                OutboxEntry {
                                    payload: payload.clone(),
                                    kind,
                                    origin,
                                    seq: event_seq,
                                    created: Instant::now(),
                                },
                            );
                        }
                        // FS-052 gate (egress hole fix): `gate_outbound` above
                        // only suppresses this SendItem entirely when the
                        // PRIMARY peer is pending — a pending SECONDARY mesh
                        // peer still shows up in `targets` and must not get
                        // plaintext clipboard before its human verbally
                        // confirms the SAS words. Filter it out of the actual
                        // wire fan-out (and out of who we await an ack from)
                        // here, per-target.
                        let send_targets: Vec<[u8; 32]> = {
                            let pending = pending_pairs.lock().await;
                            targets
                                .iter()
                                .copied()
                                .filter(|p| !pending.contains_key(p))
                                .collect()
                        };
                        if send_targets.len() != targets.len() {
                            tracing::debug!(
                                suppressed = targets.len() - send_targets.len(),
                                "FS-052 gate: suppressing SendItem to unconfirmed pending peer(s)"
                            );
                        }
                        tracing::info!(
                            peers = send_targets.len(),
                            frames = frames.len(),
                            "SendItem: fanning item out to linked peers"
                        );
                        // DIR-P1-09: counts logical items handed to the
                        // transport, not wire frames — a chunked image is
                        // still one `items_sent`.
                        metrics.lock().await.on_item_sent();
                        let multi = frames.len() > 1;
                        for peer in &send_targets {
                            for (i, bytes) in frames.iter().enumerate() {
                                if let Err(e) = transport.send_encrypted_to(*peer, bytes).await {
                                    tracing::error!(error = %e, "SendItem: send_encrypted_to FAILED");
                                }
                                // Pace multi-frame (chunked) items to avoid UDP
                                // congestion. A flat 10 ms per chunk would cost
                                // ~163 s for a 16 MiB image (16384 chunks); burst
                                // 16 frames then pause 2 ms instead (~2 s total).
                                if multi && (i + 1) % 16 == 0 {
                                    tokio::time::sleep(Duration::from_millis(2)).await;
                                }
                            }
                        }
                        // Retransmit until every targeted peer acks this hash.
                        // Without this a single dropped datagram loses the item —
                        // UDP gives no delivery guarantee. Skipped if every
                        // target was pending-gated above: nobody is awaiting
                        // an ack, so no `Inflight` entry is needed.
                        if !send_targets.is_empty() {
                            // Merged into any entry already in flight for
                            // this hash — see `track_inflight`.
                            track_inflight(inflight, hash, frames, send_targets).await;
                        }
                    }
                }
            }
            Action::AckItem { hash } => {
                // FluxMesh 2C-b: acks are sent by the recv loop straight to the
                // source peer (the only place the source peer_id is known), so
                // the FSM-emitted AckItem is a no-op here. Kept as a variant so
                // the core FSM contract stays unchanged.
                let _ = hash;
            }
            Action::DuplicateDropped => {
                // DIR-P1-09: content-hash dedup suppressed this event (an
                // echo of our own local copy, or a peer retransmit already
                // applied). See `App::handle`'s `suppress_action` branches.
                metrics.lock().await.on_dedup_drop();
            }
            Action::ResyncApplySuppressed => {
                // resync-1 apply-suppression fix (DEFECT 1): a ResyncPull
                // response's WriteClipboard was dropped by `App::handle`.
                // History/vault/relay/ack already happened normally.
                metrics.lock().await.on_resync_apply_suppressed();
            }
            // FIX1: already handled by the caller BEFORE this `actions` vec
            // reached `dispatch` — see
            // `purge_dropped_pending_from_outbox_stage`'s call sites. It has
            // to run before `Action::EmitState` below publishes the new
            // (pending-item-shrunk) state, so it can't wait until this loop
            // reaches it here.
            #[allow(clippy::match_same_arms)]
            // empty body, but for an unrelated reason than the arm below
            Action::PendingDropped { .. } => {}
            Action::WriteClipboard {
                kind,
                payload,
                sensitive,
            } => {
                // DIR-P1-09: this is the "item apply" chokepoint — a
                // logical inbound item accepted and written to the local
                // OS clipboard, regardless of text/image kind.
                metrics.lock().await.on_item_received();
                // Mark the hash before writing so the watcher's next
                // poll skips this exact payload — otherwise we'd read
                // back our own write, fire a LocalClipboardChange, and
                // ping-pong the same item back to the peer. The hash is
                // taken over the clipboard's *canonical* form (trimmed
                // UTF-8 for text, RGBA pixels for images) so it matches
                // what the watcher computes on read-back — a re-encoded
                // PNG would hash differently.
                if matches!(kind, Kind::Image) {
                    #[cfg(not(target_os = "android"))]
                    if let Some((w, h, rgba)) = decode_png_to_rgba(&payload) {
                        let hash = image_rgba_hash(w, h, &rgba);
                        last_written_hashes.lock().await.record(hash);
                        // DIR-P3-02(b): stash the bytes under their hex hash so
                        // the tray's `fetch_item` IPC op (history thumbnails +
                        // image re-copy) can serve them on demand — the same
                        // bounded `IMAGE_CACHE` Android already relies on for
                        // its own `fetch_item` path. Mirrors the Android branch
                        // below: a sensitive image is never cached.
                        if sensitive {
                            tracing::debug!(
                                "WriteClipboard: sensitive image — skipping IMAGE_CACHE"
                            );
                        } else {
                            cache_image(hex::encode(hash), payload.clone());
                        }
                        if let Some(writer) = &sh.clipboard_writer {
                            writer.write(ClipWrite::Image {
                                width: w,
                                height: h,
                                rgba,
                            });
                        }
                    } else {
                        tracing::warn!("WriteClipboard: PNG decode failed");
                    }
                    #[cfg(target_os = "android")]
                    {
                        // Android can't put raw bytes on the OS
                        // clipboard, so the daemon stashes the PNG under
                        // its hex hash; the client pulls it via the
                        // `fetch_item` IPC op once the matching history
                        // row appears. The hash is recomputed off the
                        // decoded RGBA so it matches `HistoryItem::hash`
                        // (sender-side `image_rgba_hash`, stable across
                        // the PNG round-trip).
                        //
                        // L1 fix: a `sensitive` image is never cached — the
                        // whole point of firewall/history sensitivity is
                        // that the bytes never linger in memory past the
                        // immediate apply, and `IMAGE_CACHE` is a
                        // process-wide store that survives a security wipe
                        // otherwise (it has its own explicit clear now, but
                        // "never write it" is strictly stronger). The
                        // client-side MainActivity still receives the
                        // decoded bytes for the immediate OS-clipboard
                        // paste via its own path; only the persistent,
                        // re-fetchable cache is skipped here.
                        if sensitive {
                            tracing::debug!(
                                "WriteClipboard(android): sensitive image — skipping IMAGE_CACHE"
                            );
                        } else if let Some((w, h, rgba)) = decode_png_to_rgba(&payload) {
                            let hash = image_rgba_hash(w, h, &rgba);
                            cache_image(hex::encode(hash), payload);
                        } else {
                            tracing::warn!("WriteClipboard(android): PNG decode failed");
                        }
                    }
                } else {
                    let text = String::from_utf8_lossy(&payload).to_string();
                    let hash = clipboard_dedup_hash(&text);
                    last_written_hashes.lock().await.record(hash);
                    // Android writes the OS clipboard from `MainActivity`
                    // (no writer there); the daemon just records the hash
                    // for dedup symmetry with desktop.
                    if let Some(writer) = &sh.clipboard_writer {
                        writer.write(ClipWrite::Text(text));
                    }
                }
            }
            Action::OpenSession => {
                // Nothing to do here: our `Hello` goes out once per session
                // from `Shared::greet_new_sessions`, run after every
                // `HandshakeOk` — not only on this primary-link transition.
            }
            Action::CloseSession => {
                // Close the primary slot only if it still holds the peer the
                // FSM is closing. A `PeerLost` queued for a primary that has
                // since left can be processed after a DIFFERENT device took
                // the free slot; closing "the primary" then killed that
                // newcomer's fresh session instead.
                let tracked = app.snapshot().peer_id;
                let occupant = transport.cached_peer_id().await;
                if tracked != [0u8; 32]
                    && occupant.is_some_and(|id| id != tracked)
                    && transport.has_session().await
                {
                    tracing::debug!(
                        "CloseSession: primary slot now belongs to another peer; leaving it up"
                    );
                    continue;
                }
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

                // M-DAEMON-18: DropPeer tears down the live SESSION only — it
                // must NEVER wipe the trust store. GhostTimeout (peer offline
                // 10 min) reaches here and would otherwise erase every paired
                // device. Intentional unpair/revoke removes the specific peer
                // from `trusted` at its own call site (IPC Unpair, Revoke,
                // PairConfirm-reject) *before* dispatching the FSM actions.
                tracing::info!("DropPeer: dropping live session (trust store untouched)");
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
pub(super) async fn ensure_online(app: &mut App, seq_store: &mut Option<SeqStore>, sh: &Shared) {
    let wall = &sh.wall_clock;
    if app.snapshot().on {
        return;
    }
    let actions = app.handle(Event::ToggleOn, &**wall);
    dispatch(actions, app, seq_store, sh).await;
}

// ─────────────────────────────────────────────────────────────────
// IPC command dispatch
// ─────────────────────────────────────────────────────────────────
