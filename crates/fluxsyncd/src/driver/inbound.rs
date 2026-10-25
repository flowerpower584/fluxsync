//! Receive path: transport recv loop, inbound frame dispatch, reassembly, NAKs.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) async fn transport_recv_loop(
    transport: Arc<Transport>,
    identity: Identity,
    trusted: TrustedSet,
    pairing_window: PairingWindow,
    pending_initiator_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
    event_tx: mpsc::Sender<Event>,
    shutdown: CancellationToken,
    keystore_dir: Option<PathBuf>,
    metrics: Arc<Mutex<MetricsTracker>>,
    inflight: InflightMap,
    pending_pairs: PendingSet,
    mesh_seen: MeshSeen,
    peer_meta: PeerMetaMap,
    disc_cache: DiscoveryCache,
    backoff: BackoffMap,
    lan_only_handshakes: bool,
    outbox: SharedOutbox,
    pending_pulls: PendingPulls,
    outbox_stage: PendingOutboxStage,
    state_rx: watch::Receiver<State>,
    deferred_sas_confirm: DeferredSasConfirm,
    echo_ack_sent: EchoAckSent,
    cleared_tombstone: ClearedTombstone,
) -> Result<()> {
    let mut buf = vec![0u8; 65535];
    let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
        Arc::new(Mutex::new(HashMap::new()));
    // FS-058: per-source-IP handshake limiter. Local-mutable; recv loop is
    // single-task so no Arc<Mutex<>> needed.
    let mut handshake_limiter = HandshakeRateLimiter::new();
    let mut cleanup_interval = tokio::time::interval(Duration::from_secs(5));
    let mut retransmit_interval = tokio::time::interval(RETRANSMIT_INTERVAL);
    let mut nak_interval = tokio::time::interval(NAK_INTERVAL);
    // M-DAEMON-17: last peer address we persisted to peers.json. Used to
    // persist a roam ONLY when the address actually changes — otherwise every
    // encrypted frame (heartbeat each 5 s + every clipboard item) would
    // tmp+fsync+rename peers.json continuously, burning disk/SSD for nothing.
    let mut last_persisted_addr: Option<std::net::SocketAddr> = None;

    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            _ = retransmit_interval.tick() => {
                // Re-send any clipboard item a peer hasn't acked yet, to the
                // peers still pending. Frames whose item exceeds MAX_RETRANSMIT
                // are dropped.
                let mut to_send: Vec<([u8; 32], Vec<u8>)> = Vec::new();
                {
                    let mut map = inflight.lock().await;
                    let mut done: Vec<[u8; 32]> = Vec::new();
                    for (hash, item) in map.iter_mut() {
                        // Age backstop first: NAK resends keep `last_sent`
                        // fresh, so the `continue` below would otherwise
                        // shield a never-converging item from ever being
                        // dropped.
                        if item.first_sent.elapsed() > INFLIGHT_MAX_AGE {
                            tracing::warn!(
                                item = ?&hash[..6],
                                "item dropped: exceeded max age (transfer never converged)"
                            );
                            done.push(*hash);
                            continue;
                        }
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
                            pending = item.pending_peers.len(),
                            "retransmitting unacked item"
                        );
                        for peer in &item.pending_peers {
                            for f in &item.frames {
                                to_send.push((*peer, f.clone()));
                            }
                        }
                    }
                    for h in done {
                        map.remove(&h);
                    }
                }
                for (peer, bytes) in &to_send {
                    let _ = transport.send_encrypted_to(*peer, bytes).await;
                }
            }
            _ = nak_interval.tick() => {
                // Selective NAK: for every chunked transfer still in
                // reassembly, tell the ACTUAL SENDER (`Reassembly::source`,
                // never assumed to be the primary link) exactly which chunk
                // indices (and the header) are still missing so it resends
                // only those — whole-item retransmit can't converge under
                // steady UDP loss.
                let pending = {
                    let map = reassembly.lock().await;
                    build_pending_naks(&map)
                };
                for (source, nak) in pending {
                    let frame = Frame {
                        version: PROTOCOL_VERSION,
                        msg: Msg::Nak(nak),
                    };
                    if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                        let _ = transport.send_encrypted_to(source, &bytes).await;
                    }
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
                // H2 (Phase 3 audit): uniform `lan_only` filter applied
                // to EVERY frame, not just `HandshakeInit`. The UDP
                // socket binds 0.0.0.0 by default so multi-NIC users
                // get LAN reachability without configuration, but that
                // also exposes the Noise / replay-window state to WAN
                // probes. We drop non-local sources here, before any
                // decrypt or Noise step touches them.
                if lan_only_handshakes && !crate::config::is_local_ip(frame.from().ip()) {
                    tracing::warn!(
                        src = %frame.from(),
                        kind = frame.kind_label(),
                        "frame dropped: non-local source (lan_only)"
                    );
                    continue;
                }
                match frame {
                    RecvFrame::HandshakeInit { from, msg } => {
                        // FS-059: refuse handshakes from public-internet
                        // sources by default. LAN clipboard sync has no
                        // legitimate WAN peer; a routable IP here is
                        // almost certainly a scanner.
                        // (The blanket LAN filter above already covers
                        // this; the explicit check is retained as a
                        // defense-in-depth assertion in case someone
                        // later moves the filter or flips its scope.)
                        if lan_only_handshakes && !crate::config::is_local_ip(from.ip()) {
                            tracing::warn!(
                                src = %from,
                                "HandshakeInit dropped: non-local source"
                            );
                            continue;
                        }
                        // FS-058: per-source-IP rate-limit. Drop excess
                        // HandshakeInit datagrams BEFORE spawning the
                        // responder so neither the Noise step nor the
                        // PendingSet/trusted map are exposed to the flood.
                        if !handshake_limiter.check(from.ip()) {
                            tracing::warn!(
                                src = %from,
                                "HandshakeInit dropped: source rate-limited"
                            );
                            continue;
                        }
                        // FluxMesh 2C-b: no global "session active → reject"
                        // gate any more — that blocked a SECOND device from
                        // ever pairing. Per-peer admission is enforced in the
                        // responder via `try_install_session`'s CAS: a
                        // re-handshake from the SAME peer (e.g. Android's ~15s
                        // mDNS rediscovery) finds that peer's session already
                        // present and is dropped without replacing it (the
                        // Noise session is never destroyed), while a DIFFERENT
                        // peer is routed to its own connection slot. The
                        // FS-058 per-source rate-limit above still bounds how
                        // often a responder is spawned.
                        let id = identity.clone();
                        let tr = transport.clone();
                        let trusted = trusted.clone();
                        let window = pairing_window.clone();
                        let evt = event_tx.clone();
                        let kd = keystore_dir.clone();
                        let pending = pending_pairs.clone();
                        let responder_metrics = metrics.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handshake::run_responder(id, msg, from, tr, trusted, window, evt, kd, pending).await {
                                tracing::warn!(error = %e, "responder failed");
                                // DIR-P1-09: counted here (not inside
                                // `handshake::run_responder`) because
                                // `MetricsTracker` lives in `fluxsyncd`, while
                                // `handshake` only returns an error type —
                                // keeps the metrics dependency at the one
                                // call site instead of threading it through
                                // every handshake helper.
                                responder_metrics.lock().await.on_handshake_fail();
                            }
                        });
                    }
                    RecvFrame::HandshakeResp { msg, .. } => {
                        let g = pending_initiator_tx.lock().await;
                        if let Some(tx) = g.as_ref() {
                            let _ = tx.send(msg);
                            // On a fast/loopback link the peer's post-handshake
                            // traffic (its own `Msg::Hello`, sent the instant
                            // ITS side reaches Linked) can already be sitting
                            // in this socket's recv buffer right behind this
                            // `HandshakeResp` datagram. Forwarding to
                            // `run_initiator` above only wakes that task; it
                            // does not run it. Without yielding here, this
                            // loop can read the very next datagram (that
                            // Hello) and fail it with "encrypted frame but no
                            // session" before `run_initiator` ever gets
                            // scheduled to call `try_install_session`. Since
                            // `Msg::Hello` is sent exactly once per session
                            // establishment (resync-1 caps ride on it, never
                            // retried), losing that race silently and
                            // permanently drops resync-1 negotiation for the
                            // whole session. A single cooperative yield here
                            // gives `run_initiator` a real chance to finish
                            // installing the session first.
                            tokio::task::yield_now().await;
                        } else {
                            tracing::debug!("HandshakeResp with no pending initiator");
                        }
                    }
                    RecvFrame::Encrypted { from, peer_id, plaintext } => {
                        // ROAMING persistence (M-DAEMON-17): only when the peer
                        // address actually changed since the last write — not on
                        // every frame. `peer_addr` updates on roam; comparing
                        // against `last_persisted_addr` collapses the steady-state
                        // heartbeat/clipboard stream to zero disk writes.
                        //
                        // last_addr persistence + redial: this is
                        // the "peer address change" surface the transport exposes
                        // — use the single-entry atomic upsert (`persist_last_addr`)
                        // so this peer's `last_addr` is updated in place. The
                        // previous implementation called `save_current_peers`
                        // here, which rebuilds every `StoredPeer` purely from the
                        // in-memory `TrustedPeer` (no address field) and so
                        // unconditionally wrote `last_addr: None` for every
                        // trusted peer on every roam — silently erasing the very
                        // redial hint this call site exists to persist.
                        if last_persisted_addr != Some(from) {
                            if let Some(dir) = &keystore_dir {
                                let current_p = transport.current_peer_addr().await;
                                if current_p == Some(from) {
                                    persist_last_addr(Some(dir), &transport, &trusted, peer_id, from)
                                        .await;
                                    last_persisted_addr = Some(from);
                                }
                            }
                        }

                        match fluxsync_proto::decode(&plaintext) {
                            Ok(f) => dispatch_inbound_frame(f, peer_id, &mesh_seen, &event_tx, &transport, &reassembly, &metrics, &inflight, &pending_pairs, &trusted, &disc_cache, &backoff, &peer_meta, keystore_dir.as_ref(), &outbox, &pending_pulls, &outbox_stage, &state_rx, &deferred_sas_confirm, &echo_ack_sent, &cleared_tombstone).await,
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

#[allow(clippy::too_many_arguments)]
pub(super) async fn complete_reassembled_item(
    transport: &Arc<Transport>,
    inflight: &InflightMap,
    mesh_seen: &MeshSeen,
    event_tx: &mpsc::Sender<Event>,
    source: [u8; 32],
    origin: [u8; 32],
    event_seq: u64,
    hash: [u8; 32],
    kind: Kind,
    sensitive: bool,
    lamport: u64,
    payload: Vec<u8>,
    outbox: &SharedOutbox,
    outbox_stage: &PendingOutboxStage,
    pending_pulls: &PendingPulls,
    state_rx: &watch::Receiver<State>,
    pending_pairs: &PendingSet,
) {
    // SE-14 defense in depth: reject a reassembled item whose claimed hash
    // doesn't match its payload BEFORE acking, relaying, or caching it —
    // see `verify_content_hash`.
    if !verify_content_hash(kind, &payload, hash) {
        tracing::warn!(
            peer = ?&source[..6],
            "SE-14: dropping reassembled item — wire hash does not match recomputed content hash"
        );
        return;
    }
    ack_source(transport, source, hash).await;
    let eid = EventId::new(DeviceId::from(origin), event_seq);
    if !mesh_seen.lock().await.observe(eid) {
        // Already seen this item on the mesh — don't re-apply or re-loop it.
        return;
    }
    // Resync-on-reconnect (resync-1): first sight of this item. Outbox
    // admission gate fix: `Event::FrameReceivedClipboard` (sent below) has
    // not been through the firewall yet, so we mirror its Pass/Ask/Block
    // decision here ourselves rather than inserting unconditionally — the
    // outbox must only ever hold items admitted to history (see
    // `crate::outbox`'s security invariant). Sensitive items are excluded
    // outright, matching the same invariant.
    let mut block_relay = false;
    if !sensitive {
        let decision = state_rx
            .borrow()
            .firewall
            .decide(kind, sensitive, Direction::Inbound);
        let staged = OutboxEntry {
            payload: payload.clone(),
            kind,
            origin,
            seq: event_seq,
            created: Instant::now(),
        };
        match decision {
            Decision::Pass => {
                outbox.lock().await.insert(hash, staged);
            }
            Decision::Defer => {
                // Parked under `Ask`: not admitted yet. Stage it so
                // `CmdOp::ResolvePending{allow: true}` can promote it later —
                // see `PendingOutboxStage`'s doc comment. First-wins, same as
                // `fluxsync_core::App::park_pending`'s own idempotent guard:
                // a blind `insert` here could let a SECOND peer offering the
                // identical hash silently overwrite the first peer's staged
                // entry, so `outbox_stage` and `pending_payloads` end up
                // crediting different peers for the same hash — corrupting
                // whichever gets purged on revoke.
                outbox_stage.lock().await.entry(hash).or_insert(staged);
            }
            Decision::Block => {
                // Firewall-enforcing relay: a Blocked item must not reach
                // other mesh peers either — only local admission was gated
                // before, so a Blocked item still relayed straight through.
                // Sensitive items are exempt (`block_relay` stays false when
                // `sensitive` is true above) — they're ephemeral and the
                // destination must still receive them.
                block_relay = true;
            }
        }
    }
    let frames = build_item_frames(lamport, hash, kind, &payload, sensitive, origin, event_seq);
    if !block_relay {
        forward_frames(
            transport,
            inflight,
            pending_pairs,
            source,
            origin,
            hash,
            frames,
        )
        .await;
    }
    let preview = preview_label(kind, &payload);
    // resync-1 apply-suppression fix: did WE ask `source` for this exact
    // hash via ResyncPull? If so this is a catch-up delivery, not a fresh
    // copy — history/vault/relay/ack still happen (above/below), but
    // `App::handle` must drop the `WriteClipboard` action for it.
    let resync = take_pending_pull(pending_pulls, source, hash).await;
    let _ = event_tx.try_send(Event::FrameReceivedClipboard {
        hash,
        kind,
        payload,
        preview,
        sensitive,
        lamport,
        resync,
        // FIX1: `source` is the direct sender of THIS hop (see `ack_source`
        // above, which acks the same peer) — not necessarily the item's
        // mesh `origin` for a forwarded/relayed item. That's the right peer
        // to tag a parked `Ask` item with: it's who we'd need to hear from
        // again, and whose revoke should drop this item.
        peer_id: source,
    });
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn dispatch_inbound_frame(
    frame: Frame,
    peer_id: [u8; 32],
    mesh_seen: &MeshSeen,
    event_tx: &mpsc::Sender<Event>,
    transport: &Arc<Transport>,
    reassembly: &Arc<Mutex<HashMap<[u8; 32], Reassembly>>>,
    metrics: &Arc<Mutex<MetricsTracker>>,
    inflight: &InflightMap,
    pending_pairs: &PendingSet,
    trusted: &TrustedSet,
    disc_cache: &DiscoveryCache,
    backoff: &BackoffMap,
    peer_meta: &PeerMetaMap,
    keystore_dir: Option<&std::path::PathBuf>,
    outbox: &SharedOutbox,
    pending_pulls: &PendingPulls,
    outbox_stage: &PendingOutboxStage,
    state_rx: &watch::Receiver<State>,
    deferred_sas_confirm: &DeferredSasConfirm,
    echo_ack_sent: &EchoAckSent,
    cleared_tombstone: &ClearedTombstone,
) {
    // FS-052 strict gate (VULN-002 fix): if the active session's peer
    // landed via TOFU and has not been verbally confirmed yet, drop all
    // data-bearing frames (`ClipboardItem`, `Chunk`) until the user runs
    // `fluxctl pair confirm --accept`. Hello / Heartbeat / Ack / Nak /
    // Bye keep flowing so the link stays diagnosable and the FSM still
    // reacts to peer disconnects — and `PairConfirm` MUST flow too, since
    // its whole purpose is to resolve exactly this pending window. Matches
    // the design intent stated in `docs/THREAT-MODEL.md` §3 row B-S: *"a
    // hard gate that blocks Msg::Item processing until the user runs
    // --accept"*.
    //
    // FS-052 egress hole fix: `ResyncOffer`/`ResyncPull` are also
    // data-bearing (resync-1 catch-up delivery) — without gating them here
    // too, an unconfirmed peer could still trade offers/pulls with us and
    // have cached clipboard content served straight to it, bypassing the
    // gate entirely.
    let blocks_until_confirmed = matches!(
        frame.msg,
        Msg::ClipboardItem(_) | Msg::Chunk(_) | Msg::ResyncOffer(_) | Msg::ResyncPull(_)
    );
    if blocks_until_confirmed {
        // Hardening: a peer must be BOTH currently trusted AND not still
        // pending confirmation to receive clipboard data. Checking only
        // `pending_pairs` used to leave a hole once the reaper expired a
        // peer: it removes the `pending_pairs` entry (and the `trusted`
        // entry) but a secondary's live `extra` session survives independent
        // of that sweep, so a not-trusted / not-pending peer must be
        // rejected fail-closed rather than falling through as "not pending,
        // so allowed".
        let still_pending = pending_pairs.lock().await.contains_key(&peer_id);
        let is_trusted = trusted.lock().await.contains_key(&peer_id);
        if still_pending || !is_trusted {
            tracing::warn!(
                peer = ?&peer_id[..6],
                "FS-052 gate: dropping clipboard frame — peer not yet verbally confirmed or no longer trusted"
            );
            return;
        }
    }
    match frame.msg {
        Msg::ClipboardItem(item) => {
            if item.payload.is_empty() {
                // Header for a chunked transfer
                let mut map = reassembly.lock().await;
                // Per-source namespacing: same item_id from different peers
                // must not collide in one Reassembly (see reassembly_key).
                let key = reassembly_key(peer_id, item.hash);
                // FS-058 V2: mirror the chunk-arm cap. A flood of headers
                // for new items must not grow `reassembly` unbounded —
                // evict the least-recently-updated entry first.
                if !map.contains_key(&key) && map.len() >= 5 {
                    let oldest = map
                        .iter()
                        .min_by_key(|(_, r)| r.last_update)
                        .map(|(k, _)| *k);
                    if let Some(k) = oldest {
                        map.remove(&k);
                    }
                }
                let r = map.entry(key).or_insert_with(|| Reassembly {
                    metadata: Some((item.lamport, item.kind, item.sensitive)),
                    origin: item.origin,
                    event_seq: item.event_seq,
                    chunks: Vec::new(),
                    last_update: Instant::now(),
                    first_seen: Instant::now(),
                    source: peer_id,
                    item_hash: item.hash,
                });
                r.metadata = Some((item.lamport, item.kind, item.sensitive));
                r.origin = item.origin;
                r.event_seq = item.event_seq;
                r.last_update = Instant::now();
                // A header datagram can arrive AFTER all its chunks (UDP
                // reorders freely). Check completion here too — not only in
                // the Chunk arm — or a late header strands a full payload.
                if let Some((lamport, kind, sensitive)) = r
                    .metadata
                    .filter(|_| !r.chunks.is_empty())
                    .filter(|_| r.chunks.iter().all(std::option::Option::is_some))
                {
                    let (origin, event_seq) = (r.origin, r.event_seq);
                    let mut full_payload = Vec::new();
                    for chunk in r.chunks.drain(..) {
                        full_payload.extend(chunk.unwrap());
                    }
                    map.remove(&key);
                    drop(map);

                    complete_reassembled_item(
                        transport,
                        inflight,
                        mesh_seen,
                        event_tx,
                        peer_id,
                        origin,
                        event_seq,
                        item.hash,
                        kind,
                        sensitive,
                        lamport,
                        full_payload,
                        outbox,
                        outbox_stage,
                        pending_pulls,
                        state_rx,
                        pending_pairs,
                    )
                    .await;
                }
            } else {
                // SE-14 defense in depth: reject a single-frame item whose
                // claimed hash doesn't match its payload BEFORE acking,
                // relaying, or caching it — see `verify_content_hash`.
                if !verify_content_hash(item.kind, &item.payload, item.hash) {
                    tracing::warn!(
                        peer = ?&peer_id[..6],
                        "SE-14: dropping ClipboardItem — wire hash does not match recomputed content hash"
                    );
                    return;
                }
                // FluxMesh 2C-b: ack the sender, then ingest by EventId for mesh
                // anti-loop. Forward + apply only on first sight here; a later
                // arrival of the same id via another path is dropped (the ack
                // still goes out so the sender stops retransmitting).
                ack_source(transport, peer_id, item.hash).await;
                let eid = EventId::new(DeviceId::from(item.origin), item.event_seq);
                let first_sight = mesh_seen.lock().await.observe(eid);
                if first_sight {
                    // Resync-on-reconnect (resync-1): keep a resend copy of
                    // this first-sight item too — most clipboard items are
                    // small enough to arrive as a single `ClipboardItem`
                    // frame and never touch `complete_reassembled_item`
                    // (that path only runs for chunked/reassembled items).
                    // Outbox admission gate fix: same Pass/Ask/Block mirror as
                    // `complete_reassembled_item` — see its doc comment.
                    let mut block_relay = false;
                    if !item.sensitive {
                        let decision = state_rx.borrow().firewall.decide(
                            item.kind,
                            item.sensitive,
                            Direction::Inbound,
                        );
                        let staged = OutboxEntry {
                            payload: item.payload.clone(),
                            kind: item.kind,
                            origin: item.origin,
                            seq: item.event_seq,
                            created: Instant::now(),
                        };
                        match decision {
                            Decision::Pass => {
                                outbox.lock().await.insert(item.hash, staged);
                            }
                            Decision::Defer => {
                                // First-wins — see the identical-hash-two-
                                // peers rationale in `complete_reassembled_item`.
                                outbox_stage.lock().await.entry(item.hash).or_insert(staged);
                            }
                            Decision::Block => {
                                // Firewall-enforcing relay: see the identical
                                // gate + rationale in `complete_reassembled_item`.
                                block_relay = true;
                            }
                        }
                    }
                    if !block_relay {
                        if let Ok(bytes) = fluxsync_proto::encode(&Frame {
                            version: PROTOCOL_VERSION,
                            msg: Msg::ClipboardItem(item.clone()),
                        }) {
                            forward_item(
                                transport,
                                inflight,
                                pending_pairs,
                                peer_id,
                                item.origin,
                                item.hash,
                                bytes,
                            )
                            .await;
                        }
                    }
                    let preview = preview_label(item.kind, &item.payload);
                    // resync-1 apply-suppression fix: same check as
                    // `complete_reassembled_item` for the chunked path — see
                    // its doc comment.
                    let resync = take_pending_pull(pending_pulls, peer_id, item.hash).await;
                    let _ = event_tx.try_send(Event::FrameReceivedClipboard {
                        hash: item.hash,
                        kind: item.kind,
                        payload: item.payload,
                        preview,
                        sensitive: item.sensitive,
                        lamport: item.lamport,
                        resync,
                        // FIX1: `peer_id` here is the direct session peer
                        // this single-frame item arrived on (see the
                        // `ack_source`-equivalent handling above).
                        peer_id,
                    });
                }
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
            // Per-source namespacing (see reassembly_key): a peer can only fill
            // its own item_id's slots, never overwrite another peer's transfer.
            let key = reassembly_key(peer_id, c.item_id);

            if !map.contains_key(&key) && map.len() >= 5 {
                let oldest = map
                    .iter()
                    .min_by_key(|(_, r)| r.last_update)
                    .map(|(k, _)| *k);
                if let Some(k) = oldest {
                    map.remove(&k);
                }
            }

            let r = map.entry(key).or_insert_with(|| Reassembly {
                metadata: None,
                origin: [0u8; 32],
                event_seq: 0,
                chunks: vec![None; c.total as usize],
                last_update: Instant::now(),
                first_seen: Instant::now(),
                source: peer_id,
                item_hash: c.item_id,
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
                let (origin, event_seq) = (r.origin, r.event_seq);
                let mut full_payload = Vec::new();
                for chunk in r.chunks.drain(..) {
                    full_payload.extend(chunk.unwrap());
                }
                map.remove(&key);
                drop(map);

                complete_reassembled_item(
                    transport,
                    inflight,
                    mesh_seen,
                    event_tx,
                    peer_id,
                    origin,
                    event_seq,
                    c.item_id,
                    kind,
                    sensitive,
                    lamport,
                    full_payload,
                    outbox,
                    outbox_stage,
                    pending_pulls,
                    state_rx,
                    pending_pairs,
                )
                .await;
            }
        }
        Msg::BatteryStatus(b) => {
            // FluxMesh Phase 3: record every peer's battery in the mesh meta
            // map (drives the State `peers` list), republishing on change.
            {
                let mut meta = peer_meta.lock().await;
                let e = meta.entry(peer_id).or_insert_with(PeerMeta::new);
                if e.battery != b.level || e.charging != b.charging {
                    e.battery = b.level;
                    e.charging = b.charging;
                    let _ = event_tx.try_send(Event::MeshPeersChanged);
                }
            }
            // FluxMesh 2C-b: only the primary peer's battery drives the
            // single-peer State + the battery policy. A secondary mesh peer's
            // level must not overwrite the projected peer_battery or pause the
            // whole daemon.
            if transport.cached_peer_id().await == Some(peer_id) {
                let _ = event_tx.try_send(Event::BatteryChangedPeer {
                    level: b.level,
                    charging: b.charging,
                });
            }
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
                let _ = transport.send_encrypted_to(peer_id, &bytes).await;
            }
        }
        Msg::Ack(ack) => {
            metrics.lock().await.on_ack_received();
            if ack.hash == [0u8; 32] {
                // Heartbeat pong — no item to clear.
                tracing::debug!("Heartbeat: received ack (pong)");
            } else {
                // FluxMesh 2C-b: clear this peer from the item's pending set;
                // the item is removed only once every targeted peer has acked.
                let mut map = inflight.lock().await;
                if let Some(item) = map.get_mut(&ack.hash) {
                    item.pending_peers.remove(&peer_id);
                    if item.pending_peers.is_empty() {
                        map.remove(&ack.hash);
                        tracing::debug!(item = ?&ack.hash[..6], "item fully acked; retransmit cleared");
                    }
                }
            }
        }
        Msg::Nak(nak) => {
            // Peer is missing chunks of an item we sent. Resend only the
            // frames it asked for. Layout in `Inflight.frames`:
            // frames[0] = header, frames[idx + 1] = chunk `idx`.
            let mut to_send: Vec<Vec<u8>> = Vec::new();
            {
                let map = inflight.lock().await;
                if let Some(item) = map.get(&nak.item_id) {
                    if nak.want_header {
                        if let Some(header) = item.frames.first() {
                            to_send.push(header.clone());
                        }
                    }
                    for idx in &nak.missing {
                        if let Some(frame) = item.frames.get(*idx as usize + 1) {
                            to_send.push(frame.clone());
                        }
                    }
                }
            }
            if !to_send.is_empty() {
                tracing::debug!(
                    item = ?&nak.item_id[..6],
                    frames = to_send.len(),
                    "NAK: resending missing frames"
                );
                for (i, bytes) in to_send.iter().enumerate() {
                    let _ = transport.send_encrypted_to(peer_id, bytes).await;
                    // Same burst-16/pause-2ms pacing as the initial send.
                    if (i + 1) % 16 == 0 {
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                }
                // NAK is making progress — defer the whole-item retransmit
                // so it doesn't redundantly blast every frame again. The
                // INFLIGHT_MAX_AGE backstop still bounds total lifetime.
                if let Some(item) = inflight.lock().await.get_mut(&nak.item_id) {
                    item.last_sent = Instant::now();
                }
            }
        }
        Msg::Bye => {
            // Peer announced a clean disconnect: tear down THAT peer's session.
            let is_primary = transport.cached_peer_id().await == Some(peer_id);
            if is_primary {
                // M6 fix: a clean disconnect after a genuinely stable
                // session still resets backoff (so the next reconnect isn't
                // slow); a short-lived session keeps its escalation — same
                // policy as the heartbeat-timeout path.
                let uptime = Duration::from_millis(
                    now_ms().saturating_sub(transport.session_established_at()),
                );
                backoff
                    .lock()
                    .await
                    .entry(peer_id)
                    .or_insert_with(PeerBackoff::new)
                    .on_session_ended(uptime);
            } else if let Some(established) = transport.session_established_at_for(peer_id).await {
                // M6 residual fix: a secondary (FluxMesh `extra`) peer's clean
                // disconnect gets the same stability-gated backoff reset as
                // the primary above — computed from THIS peer's own
                // established time (the primary-only `session_established_at`
                // can't see a secondary), captured before `drop_session_for`
                // below clears its session.
                let uptime = Duration::from_millis(now_ms().saturating_sub(established));
                backoff
                    .lock()
                    .await
                    .entry(peer_id)
                    .or_insert_with(PeerBackoff::new)
                    .on_session_ended(uptime);
            }
            transport.drop_session_for(peer_id).await;
            // FluxMesh Phase 3: drop it from the mesh `peers` list too.
            if peer_meta.lock().await.remove(&peer_id).is_some() {
                let _ = event_tx.try_send(Event::MeshPeersChanged);
            }
            // Session torn down: clear the echo-ack loop guard so a fresh
            // session with this peer can echo-ack again if needed.
            echo_ack_sent.lock().await.remove(&peer_id);
            // Only the primary peer drives the single FSM's PeerLost (which
            // clears State + the primary session). A secondary mesh peer
            // leaving must not disturb the primary link (FluxMesh 2C-b).
            // Robustness slice 2: if the primary said Bye but a secondary is
            // still live, fail over to it instead of disconnecting.
            if is_primary && !try_primary_failover(transport, event_tx, peer_meta).await {
                let _ = event_tx.try_send(Event::PeerLost { peer_id });
            }
        }
        Msg::Revoke => {
            // Peer manually unpaired: remove it from our trust store so we
            // don't auto-reconnect into its next TOFU window. The frame
            // arrived over the established Noise session, so the sender is
            // authenticated (peer_id is whose session decrypted it) — only its
            // own entry is removed, never the rest.
            let removed = trusted.lock().await.remove(&peer_id);
            // DIR-P2-04a: the peer that just revoked us may still have a
            // stale entry in our mDNS discovery cache (pubkey, name, addrs,
            // pairing PIN) — drop it so a cache hit can't resurrect it.
            disc_cache.lock().await.remove(&peer_id);
            // DIR-P1-02: same rationale — drop its backoff timer too.
            backoff.lock().await.remove(&peer_id);
            if removed.is_some() {
                if let Some(dir) = keystore_dir {
                    if let Err(e) = save_peers_with_retry(dir, trusted, transport).await {
                        tracing::error!("Revoke: failed to persist peer removal: {e}");
                    }
                }
                tracing::info!(peer = ?&peer_id[..6], "Revoke: peer unpaired us; trust entry removed");
            }
            // FS-052 wire mutual confirm: a Revoke mid-pairing removes the
            // pending entry here, so the reaper would never fire the
            // `SasReset` for it — reset the phase now instead of leaving a
            // stale "showing"/"local_confirmed" in State.
            if pending_pairs.lock().await.remove(&peer_id).is_some() {
                let _ = event_tx.try_send(Event::SasReset);
            }
            deferred_sas_confirm.lock().await.remove(&peer_id);
            echo_ack_sent.lock().await.remove(&peer_id);
            // Bug #16 fix: the peer just revoked US, a permanent teardown —
            // purge the `extra` stub too (same rationale as `CmdOp::Revoke`).
            transport.purge_peer(peer_id).await;
            // FluxMesh Phase 3: drop it from the mesh `peers` list too.
            if peer_meta.lock().await.remove(&peer_id).is_some() {
                let _ = event_tx.try_send(Event::MeshPeersChanged);
            }
            // Primary-only PeerLost, as for Bye — a secondary peer revoking us
            // tears down only its own link (FluxMesh 2C-b). Robustness slice 2:
            // fail over to a live secondary before declaring the link lost.
            if transport.cached_peer_id().await == Some(peer_id)
                && !try_primary_failover(transport, event_tx, peer_meta).await
            {
                let _ = event_tx.try_send(Event::PeerLost { peer_id });
            }
        }
        Msg::HandshakeInit(_) | Msg::HandshakeResp(_) => {
            // Handshake frames are driven by the handshake task, not here.
        }
        Msg::Hello(h) => {
            // DIR-P1-01: negotiate the working capability set as the
            // intersection of what the peer sent and what this build
            // understands. Anything neither side recognizes is silently
            // dropped — logged at DEBUG, never a reason to refuse the Hello
            // or tear down the session.
            let caps = negotiate_caps(&h.caps);
            for c in &h.caps {
                if !SUPPORTED_CAPS.contains(&c.as_str()) {
                    tracing::debug!(peer = ?&peer_id[..6], cap = %c, "ignoring unknown Hello capability");
                }
            }
            // FluxMesh Phase 3: record every peer's name/platform in the mesh
            // meta map (drives the State `peers` list), republishing on change.
            {
                let mut meta = peer_meta.lock().await;
                let e = meta.entry(peer_id).or_insert_with(PeerMeta::new);
                let mut changed = false;
                if e.name != h.name {
                    e.name.clone_from(&h.name);
                    changed = true;
                }
                if !h.platform.is_empty() && e.platform != h.platform {
                    e.platform.clone_from(&h.platform);
                    changed = true;
                }
                if e.caps != caps {
                    e.caps.clone_from(&caps);
                    changed = true;
                }
                // FS-052 wire mutual confirm: from here on, `caps` is real
                // negotiated data, not "Hello not seen yet".
                e.hello_seen = true;
                if changed {
                    let _ = event_tx.try_send(Event::MeshPeersChanged);
                }
            }
            // FS-052 wire mutual confirm: now that the peer's caps are known,
            // resolve the two Hello-dependent cases for a fresh-pair peer
            // (identified by a live `PendingPair` entry or a deferred local
            // accept — an already-confirmed reconnect has neither, so it
            // never enters the SAS states here).
            {
                let peer_supports_sas = caps.iter().any(|c| c == "sas-confirm");
                let has_pending = pending_pairs.lock().await.contains_key(&peer_id);
                let had_deferred = deferred_sas_confirm.lock().await.remove(&peer_id);
                // A deferred accept is only flushable while no NEW pending
                // pair exists for this peer: a live pending entry means a
                // fresh pairing (with fresh SAS words) superseded the earlier
                // confirm, so replaying it would confirm words the local
                // human never compared.
                let flush_deferred = had_deferred && !has_pending;
                let is_fresh_pair = had_deferred || has_pending;
                if is_fresh_pair {
                    if peer_supports_sas {
                        // The local user accepted before this Hello arrived —
                        // flush the deferred Msg::PairConfirm{accept:true} now.
                        if flush_deferred {
                            let frame = Frame {
                                version: PROTOCOL_VERSION,
                                msg: Msg::PairConfirm(fluxsync_proto::PairConfirm { accept: true }),
                            };
                            if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                                if let Err(e) = transport.send_encrypted_to(peer_id, &bytes).await {
                                    tracing::warn!(
                                        peer = ?&peer_id[..6],
                                        error = %e,
                                        "sas-confirm: deferred PairConfirm send failed"
                                    );
                                }
                            }
                        }
                    } else {
                        // Legacy peer (no `sas-confirm` cap): treat it as
                        // having confirmed, so this build never waits forever
                        // on an old one. The app moves sas_phase to
                        // "confirmed" if the local user already confirmed,
                        // "peer_confirmed" otherwise.
                        tracing::info!(
                            peer = ?&peer_id[..6],
                            "sas-confirm: peer is a legacy build — treating as confirmed"
                        );
                        let _ = event_tx.try_send(Event::SasPeerConfirmed { peer_id });
                    }
                }
            }
            // verify-restart: this side holds a fresh TOFU pending for the
            // peer (its handshake just landed through our pairing window),
            // so OUR human is being shown 6 SAS words. If the peer trusted
            // us from a previous pairing, it reconnected SILENTLY (the
            // already-confirmed path never opens a verify screen) and its
            // human sees nothing — the verbal compare would be theater.
            // Announce the fresh pairing so a `verify-restart` peer re-opens
            // its own verify screen with the same words (derived on its side
            // from the shared Noise transcript hash). Guarded once per
            // session via `PeerMeta.verify_restart_sent` — Hello arrives
            // once per honest session, but a duplicate/malicious re-Hello
            // must not re-announce.
            {
                let has_pending = pending_pairs.lock().await.contains_key(&peer_id);
                let peer_supports_verify_restart = caps.iter().any(|c| c == "verify-restart");
                if has_pending && peer_supports_verify_restart {
                    let first_announce = {
                        let mut meta = peer_meta.lock().await;
                        let e = meta.entry(peer_id).or_insert_with(PeerMeta::new);
                        if e.verify_restart_sent {
                            false
                        } else {
                            e.verify_restart_sent = true;
                            true
                        }
                    };
                    if first_announce {
                        tracing::info!(
                            peer = ?&peer_id[..6],
                            "verify-restart: announcing fresh pairing so the peer re-opens its verify screen"
                        );
                        let frame = Frame {
                            version: PROTOCOL_VERSION,
                            msg: Msg::PairVerifyStarted,
                        };
                        if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                            if let Err(e) = transport.send_encrypted_to(peer_id, &bytes).await {
                                tracing::warn!(
                                    peer = ?&peer_id[..6],
                                    error = %e,
                                    "verify-restart: PairVerifyStarted send failed"
                                );
                            }
                        }
                    }
                }
            }
            // resync-1: offer our outbox to this peer once negotiated. Hello
            // arrives exactly once per session establishment (rekey never
            // re-sends it), so this can't spam a peer with repeated offers.
            //
            // FS-052 egress hole fix: never offer cached clipboard content to
            // a peer that completed TOFU but hasn't been verbally confirmed
            // yet — the offer itself doesn't carry plaintext, but it starts a
            // ResyncPull round-trip that would otherwise hand one over.
            let is_pending = pending_pairs.lock().await.contains_key(&peer_id);
            if !is_pending && caps.iter().any(|c| c == "resync-1") {
                let hashes = outbox.lock().await.hashes();
                if !hashes.is_empty() {
                    let offer = build_resync_offer(&hashes);
                    tracing::info!(
                        peer = ?&peer_id[..6],
                        count = offer.hashes.len(),
                        "resync-1: sending ResyncOffer"
                    );
                    let frame = Frame {
                        version: PROTOCOL_VERSION,
                        msg: Msg::ResyncOffer(offer),
                    };
                    if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                        let _ = transport.send_encrypted_to(peer_id, &bytes).await;
                    }
                }
            }
            // peer_id is whoever's session decrypted this Hello — always the
            // real id, no all-zero sentinel that would bypass the FSM
            // peer-mismatch check. FluxMesh 2C-b: only the primary peer's
            // identity is projected into the single-peer State DTO; secondary
            // mesh peers sync clipboard but are not shown (clients stay
            // single-peer-compatible).
            if transport.cached_peer_id().await == Some(peer_id) {
                let _ = event_tx.try_send(Event::PeerSeen {
                    peer_id,
                    name: h.name,
                });
                if !h.platform.is_empty() {
                    let _ = event_tx.try_send(Event::PeerPlatform {
                        platform: h.platform,
                    });
                }
                let _ = event_tx.try_send(Event::PeerCaps { caps });
            }
        }
        Msg::ResyncOffer(offer) => {
            if !resync_authorized(transport, peer_meta, peer_id).await {
                tracing::debug!(
                    peer = ?&peer_id[..6],
                    "resync-1: ignoring ResyncOffer (peer not linked or cap not negotiated)"
                );
                return;
            }
            let history_hashes: Vec<String> = state_rx
                .borrow()
                .history
                .iter()
                .map(|h| h.hash.clone())
                .collect();
            let outbox_hashes: Vec<String> = outbox
                .lock()
                .await
                .hashes()
                .iter()
                .map(hex::encode)
                .collect();
            // H2 fix: exclude anything we deliberately cleared via
            // `CmdOp::ClearHistory` — a peer's outbox is not told about a
            // local clear (by design), so without this a cleared item would
            // silently resurrect the moment that peer re-offers it.
            let cleared_hashes = cleared_hex_snapshot(cleared_tombstone).await;
            let pending_pull_hashes = in_flight_pull_hashes(pending_pulls).await;
            let missing = missing_resync_hashes(
                &offer.hashes,
                &history_hashes,
                &outbox_hashes,
                &cleared_hashes,
                &pending_pull_hashes,
            );
            if !missing.is_empty() {
                tracing::info!(
                    peer = ?&peer_id[..6],
                    count = missing.len(),
                    "resync-1: sending ResyncPull"
                );
                // resync-1 apply-suppression fix (DEFECT 1): remember every
                // hash we're about to ask this peer for, so when it comes
                // back as an ordinary ClipboardItem/Chunk we recognise it as
                // catch-up bookkeeping rather than a fresh copy — see
                // `PendingPulls` and `take_pending_pull`. Malformed hex (the
                // codec already bounds the string shape/count, but a corrupt
                // entry would still fail `decode_hex32`) is skipped rather
                // than tracked, matching `Msg::ResyncPull`'s own handling.
                {
                    let now = Instant::now();
                    let mut map = pending_pulls.lock().await;
                    let per_peer = map.entry(peer_id).or_default();
                    for hex_hash in &missing {
                        if let Ok(hash) = decode_hex32(hex_hash) {
                            per_peer.insert(hash, now);
                        }
                    }
                }
                let frame = Frame {
                    version: PROTOCOL_VERSION,
                    msg: Msg::ResyncPull(ResyncPull { hashes: missing }),
                };
                if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                    let _ = transport.send_encrypted_to(peer_id, &bytes).await;
                }
            }
        }
        Msg::ResyncPull(pull) => {
            if !resync_authorized(transport, peer_meta, peer_id).await {
                tracing::debug!(
                    peer = ?&peer_id[..6],
                    "resync-1: ignoring ResyncPull (peer not linked or cap not negotiated)"
                );
                return;
            }
            tracing::info!(
                peer = ?&peer_id[..6],
                count = pull.hashes.len(),
                "resync-1: received ResyncPull"
            );
            let mut served = 0usize;
            for hex_hash in pull.hashes.iter().take(MAX_RESYNC_HASHES) {
                let Ok(hash) = decode_hex32(hex_hash) else {
                    tracing::debug!(peer = ?&peer_id[..6], "resync-1: malformed hash in ResyncPull, skipping");
                    continue;
                };
                let Some(entry) = outbox.lock().await.get(hash).cloned() else {
                    // Not (or no longer) held — silently skip, no error.
                    continue;
                };
                // Resync serve firewall gate: a policy tightened to Block
                // AFTER this item was admitted must not be bypassed just
                // because it still sits in the outbox cache — re-check the
                // LIVE firewall before serving it, same `decide()` call
                // `gate_outbound`/admission use elsewhere in this file.
                let decision =
                    state_rx
                        .borrow()
                        .firewall
                        .decide(entry.kind, false, Direction::Outbound);
                if decision != Decision::Pass {
                    tracing::debug!(
                        peer = ?&peer_id[..6],
                        ?decision,
                        "resync-1: skipping cached entry — firewall no longer passes it"
                    );
                    continue;
                }
                // Lamport 0: `Entry` doesn't retain the original tick, and 0
                // is a safe no-op for the receiver's `LamportClock::observe`
                // (it only ever advances the clock forward via `max`).
                let frames = build_item_frames(
                    0,
                    hash,
                    entry.kind,
                    &entry.payload,
                    false,
                    entry.origin,
                    entry.seq,
                );
                if frames.is_empty() {
                    continue;
                }
                let multi = frames.len() > 1;
                for (i, bytes) in frames.iter().enumerate() {
                    let _ = transport.send_encrypted_to(peer_id, bytes).await;
                    if multi && (i + 1) % 16 == 0 {
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                }
                // Inflight merge fix: `inflight` is keyed by hash only. A
                // blind `insert` here would REPLACE any entry already
                // tracking OTHER peers still awaiting an ack for this same
                // hash (from a concurrent live `SendItem`/`forward_frames`
                // fan-out), silently dropping them from `pending_peers` so
                // they'd never get a retransmit. Merge instead: if an entry
                // exists, fold this peer into its `pending_peers` and refresh
                // the resend copy; only insert fresh when none exists.
                match inflight.lock().await.entry(hash) {
                    std::collections::hash_map::Entry::Occupied(mut e) => {
                        let inf = e.get_mut();
                        inf.pending_peers.insert(peer_id);
                        inf.frames = frames;
                        inf.last_sent = Instant::now();
                    }
                    std::collections::hash_map::Entry::Vacant(v) => {
                        v.insert(Inflight {
                            frames,
                            attempts: 0,
                            last_sent: Instant::now(),
                            first_sent: Instant::now(),
                            pending_peers: std::iter::once(peer_id).collect(),
                        });
                    }
                }
                metrics.lock().await.on_item_resynced();
                served += 1;
            }
            if served > 0 {
                tracing::info!(
                    peer = ?&peer_id[..6],
                    count = served,
                    "resync-1: served ResyncPull"
                );
            }
        }
        Msg::PairConfirm(pc) => {
            // FS-052 wire mutual confirm (`sas-confirm` capability). The
            // frame arrived over the established Noise session, so the
            // sender is authenticated — it can only resolve its OWN pairing.
            if pc.accept {
                // Peer's human confirmed the 6 SAS words. If our own pending
                // entry still exists, give the local human one natural
                // refresh of the 90s window — the peer side is engaged, so
                // the local user deserves the full window to compare words
                // instead of whatever remained of the original one.
                let had_pending = {
                    let mut g = pending_pairs.lock().await;
                    if let Some(p) = g.get_mut(&peer_id) {
                        p.expires_at = Instant::now() + handshake::PAIRING_WINDOW;
                        true
                    } else {
                        false
                    }
                };
                // Only move sas_phase while a SAS flow is actually live —
                // our own pending entry, or the local user already confirmed
                // (pending removed, phase advanced). An accept landing on an
                // idle reconnect (e.g. a peer flushing a deferred confirm
                // from a long-finished pairing) must NOT drag an
                // already-trusted link back into the SAS states. L3 fix:
                // peer-scoped via `sas_peer`, not just "some SAS flow is
                // live somewhere" — otherwise a confirm from a DIFFERENT
                // peer than the one `sas_phase` is currently tracking would
                // wrongly count as live and stomp that other pairing's UI.
                let in_sas_flow = {
                    let s = state_rx.borrow();
                    s.sas_peer == Some(peer_id)
                        && matches!(
                            s.sas_phase.as_str(),
                            "showing" | "local_confirmed" | "peer_confirmed" | "confirmed"
                        )
                };
                if had_pending || in_sas_flow {
                    tracing::info!(
                        peer = ?&peer_id[..6],
                        "sas-confirm: peer confirmed the pairing"
                    );
                    let _ = event_tx.try_send(Event::SasPeerConfirmed { peer_id });
                } else {
                    // Asymmetric-trust echo-ack. This accept landed with no
                    // live SAS flow on our side (no pending entry, no active
                    // sas_phase for this peer) — ordinarily a stray/late
                    // confirm to ignore. But this is exactly what happens
                    // when the OTHER side revoked-and-reconnected while WE
                    // still trust it: `CmdOp::PairFromUri` on our reconnect
                    // took the silent-reconnect path (already-trusted,
                    // no pending pair), so we never opened a SAS flow at
                    // all — yet the peer's human just verbally confirmed
                    // the pairing on their end and is waiting on us. Left
                    // unanswered, their pending entry sits until the 90s
                    // reaper fires and revokes OUR trust, breaking a link
                    // that was never actually compromised.
                    //
                    // Security rationale: the frame decrypted under this
                    // peer_id (= BLAKE3(static_pub)) over the established
                    // Noise session, which only the holder of the matching
                    // private key could complete — our trust entry already
                    // pins that exact static key. So "sender authenticated
                    // + sender is in our trusted store" together stand in
                    // for a fresh human confirmation: a prior completed
                    // verification still holds because the key has not
                    // changed. The echo below asserts "already verified,
                    // key unchanged", not a new SAS comparison — it is only
                    // sent to peers that negotiated `sas-confirm` (so we
                    // know they understand the message), and at most once
                    // per peer per session (guarded by `echo_ack_sent`) so
                    // a malformed/hostile peer resending PairConfirm can't
                    // turn this into an unbounded ping-pong.
                    let is_trusted = trusted.lock().await.contains_key(&peer_id);
                    let supports_sas = peer_meta
                        .lock()
                        .await
                        .get(&peer_id)
                        .is_some_and(|m| m.caps.iter().any(|c| c == "sas-confirm"));
                    if is_trusted && supports_sas {
                        let newly_acked = echo_ack_sent.lock().await.insert(peer_id);
                        if newly_acked {
                            tracing::info!(
                                peer = ?&peer_id[..6],
                                "sas-confirm: echoing accept back to an already-trusted peer \
                                 with no live SAS flow on our side (asymmetric-trust reconnect)"
                            );
                            let frame = Frame {
                                version: PROTOCOL_VERSION,
                                msg: Msg::PairConfirm(fluxsync_proto::PairConfirm { accept: true }),
                            };
                            if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                                if let Err(e) = transport.send_encrypted_to(peer_id, &bytes).await {
                                    tracing::warn!(
                                        peer = ?&peer_id[..6],
                                        error = %e,
                                        "sas-confirm: echo-ack send failed"
                                    );
                                }
                            }
                        } else {
                            tracing::debug!(
                                peer = ?&peer_id[..6],
                                "sas-confirm: already echoed an accept to this peer this \
                                 session; not repeating (loop guard)"
                            );
                        }
                    } else {
                        tracing::debug!(
                            peer = ?&peer_id[..6],
                            "sas-confirm: ignoring PairConfirm(accept) outside a SAS flow"
                        );
                    }
                }
            } else {
                // Peer's human explicitly rejected — same effect as a local
                // reject: purge pending + trust (+ discovery/backoff/deferred
                // residue), persist, and tear the session down.
                tracing::warn!(
                    peer = ?&peer_id[..6],
                    "sas-confirm: peer REJECTED the pairing; revoking trust"
                );
                // L3 fix: captured for the SAME peer-scoped guard the accept
                // branch uses below — trust/session teardown stays
                // unconditional (an authenticated peer's explicit reject
                // always revokes it, live SAS flow or not); only whether we
                // report it as THIS pairing's verdict is gated, so a
                // stray/already-trusted peer's reject can't stomp a
                // DIFFERENT, in-progress pairing's UI.
                let had_pending = pending_pairs.lock().await.remove(&peer_id).is_some();
                deferred_sas_confirm.lock().await.remove(&peer_id);
                echo_ack_sent.lock().await.remove(&peer_id);
                let removed = trusted.lock().await.remove(&peer_id);
                disc_cache.lock().await.remove(&peer_id);
                backoff.lock().await.remove(&peer_id);
                if removed.is_some() {
                    if let Some(dir) = keystore_dir {
                        if let Err(e) = save_peers_with_retry(dir, trusted, transport).await {
                            tracing::error!(
                                "sas-confirm: failed to persist peer removal after reject: {e}"
                            );
                        }
                    }
                }
                // Bug #16 fix: the peer just rejected the pairing, a
                // permanent teardown — purge the `extra` stub too (same
                // rationale as `CmdOp::Revoke`).
                transport.purge_peer(peer_id).await;
                if peer_meta.lock().await.remove(&peer_id).is_some() {
                    let _ = event_tx.try_send(Event::MeshPeersChanged);
                }
                // Surface "peer_rejected" BEFORE the PeerLost teardown so a
                // state subscriber never sees a disconnect with a stale
                // "showing"/"local_confirmed" phase in between. Same
                // peer-scoped guard as the accept branch (L3 fix).
                let in_sas_flow = {
                    let s = state_rx.borrow();
                    s.sas_peer == Some(peer_id)
                        && matches!(
                            s.sas_phase.as_str(),
                            "showing" | "local_confirmed" | "peer_confirmed" | "confirmed"
                        )
                };
                if had_pending || in_sas_flow {
                    let _ = event_tx.try_send(Event::SasPeerRejected { peer_id });
                } else {
                    tracing::debug!(
                        peer = ?&peer_id[..6],
                        "sas-confirm: reject outside a SAS flow — trust still revoked, \
                         but not reported as this pairing's verdict"
                    );
                }
                if transport.cached_peer_id().await == Some(peer_id)
                    && !try_primary_failover(transport, event_tx, peer_meta).await
                {
                    let _ = event_tx.try_send(Event::PeerLost { peer_id });
                }
            }
        }
        Msg::PairVerifyStarted => {
            // verify-restart: the peer just accepted us via a fresh TOFU —
            // its side holds a pending pair and is showing 6 SAS words —
            // while WE reconnected silently as already-trusted (e.g. the
            // peer was reset and we rescanned its QR). Re-open our own
            // verify screen so the human comparison is real on both ends:
            // derive the same 6 words from the shared Noise transcript hash
            // (identical on both sides of one handshake — see
            // `fingerprint_from_handshake_hash`) and insert a REAL pending
            // pair, which also re-arms the FS-052 clipboard gate for this
            // peer until our human confirms. Guards:
            //  * sender must be in our trusted store — the frame decrypted
            //    under its pinned static key, so an untrusted stranger can
            //    never conjure a verify screen;
            //  * no existing pending / live SAS flow for it — a fresh
            //    pairing of our own is already showing the right words, so
            //    a (duplicate or malicious) announcement must not reset it.
            let trusted_entry = trusted
                .lock()
                .await
                .get(&peer_id)
                .map(|p| (p.static_pub, p.name.clone()));
            let Some((static_pub, name)) = trusted_entry else {
                tracing::debug!(
                    peer = ?&peer_id[..6],
                    "verify-restart: ignoring PairVerifyStarted from untrusted peer"
                );
                return;
            };
            let already_pending = pending_pairs.lock().await.contains_key(&peer_id);
            let in_sas_flow = {
                let s = state_rx.borrow();
                s.sas_peer == Some(peer_id)
                    && matches!(
                        s.sas_phase.as_str(),
                        "showing" | "local_confirmed" | "peer_confirmed" | "confirmed"
                    )
            };
            if already_pending || in_sas_flow {
                tracing::debug!(
                    peer = ?&peer_id[..6],
                    "verify-restart: ignoring PairVerifyStarted — a SAS flow for this peer is already live"
                );
                return;
            }
            let Some(hash) = transport.session_handshake_hash_for(peer_id).await else {
                tracing::warn!(
                    peer = ?&peer_id[..6],
                    "verify-restart: no live session hash for PairVerifyStarted sender; ignoring"
                );
                return;
            };
            let sas_words: [String; 6] = fluxsync_crypto::fingerprint_from_handshake_hash(&hash)
                .map(std::string::ToString::to_string);
            let from = transport.peer_addr_for(peer_id).await;
            {
                // Same FS-058 hygiene as `run_initiator`/`run_responder`'s
                // inserts: sweep expired entries, then hard-cap by evicting
                // the soonest-to-expire one.
                let mut pending_guard = pending_pairs.lock().await;
                let now = Instant::now();
                pending_guard.retain(|_, p| p.expires_at > now);
                if pending_guard.len() >= handshake::MAX_PENDING_PAIRS {
                    if let Some(victim) = pending_guard
                        .iter()
                        .min_by_key(|(_, p)| p.expires_at)
                        .map(|(k, _)| *k)
                    {
                        pending_guard.remove(&victim);
                    }
                }
                pending_guard.insert(
                    peer_id,
                    handshake::PendingPair {
                        static_pub,
                        name,
                        sas_words,
                        // Fall back to an unspecified addr if the transport
                        // has no live route entry (shouldn't happen for an
                        // authenticated sender) — `from` is display-only.
                        from: from.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0))),
                        expires_at: now + handshake::PAIRING_WINDOW,
                    },
                );
            }
            tracing::info!(
                peer = ?&peer_id[..6],
                "verify-restart: peer re-paired fresh; re-opening our verify screen"
            );
            let _ = event_tx.try_send(Event::SasPairingStarted { peer_id });
        }
    }
}

/// Selective NAK: for every chunked transfer still in `reassembly` with at
/// least one missing chunk (or an unseen header), build the `Nak` to ask for
/// exactly those pieces, paired with the peer that must receive it — the
/// transfer's direct sender (`Reassembly::source`), not assumed to be the
/// primary link. Factored out of `transport_recv_loop`'s `nak_interval` tick
/// so it's unit-testable without a live transport.
pub(super) fn build_pending_naks(
    map: &HashMap<[u8; 32], Reassembly>,
) -> Vec<([u8; 32], fluxsync_proto::Nak)> {
    let mut naks = Vec::new();
    for r in map.values() {
        if r.chunks.is_empty() {
            // Only a header (or nothing) seen so far — total unknown,
            // nothing concrete to ask for.
            continue;
        }
        let missing: Vec<u16> = r
            .chunks
            .iter()
            .enumerate()
            .filter(|(_, c)| c.is_none())
            .map(|(i, _)| i as u16)
            .take(NAK_MISSING_PER_FRAME)
            .collect();
        let want_header = r.metadata.is_none();
        if missing.is_empty() && !want_header {
            continue;
        }
        naks.push((
            r.source,
            fluxsync_proto::Nak {
                item_id: r.item_hash,
                want_header,
                missing,
            },
        ));
    }
    naks
}
