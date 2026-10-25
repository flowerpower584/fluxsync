//! Heartbeats, ghost timeout, primary failover and session rekey.

use super::*;

/// FluxMesh robustness slice 2: the primary peer's link just died. If a
/// secondary mesh session is still live, promote it into the primary slot and
/// rebind State onto it (via `Event::PrimaryFailover`) so the link stays
/// connected instead of dropping to Discovering. Returns true when it failed
/// over — the caller then SKIPS `Event::PeerLost`.
pub(super) async fn try_primary_failover(
    transport: &Arc<Transport>,
    event_tx: &mpsc::Sender<Event>,
    peer_meta: &PeerMetaMap,
) -> bool {
    let Some(id) = transport.promote_secondary().await else {
        return false;
    };
    let (name, platform, caps) = match peer_meta.lock().await.get(&id) {
        Some(m) => (m.name.clone(), m.platform.clone(), m.caps.clone()),
        None => (String::new(), String::new(), Vec::new()),
    };
    tracing::warn!(
        peer = %hex::encode(id),
        "primary link lost; failing over to live secondary peer"
    );
    let _ = event_tx.try_send(Event::PrimaryFailover {
        peer_id: id,
        name,
        platform,
        caps,
    });
    let _ = event_tx.try_send(Event::MeshPeersChanged);
    true
}

pub(super) async fn heartbeat_loop(sh: Arc<Shared>) -> Result<()> {
    let Shared {
        transport,
        event_tx,
        shutdown,
        metrics,
        backoff,
        peer_meta,
        self_batt_level,
        self_batt_charging,
        ..
    } = &*sh;
    // 3s interval + 3-miss threshold ⇒ an ungraceful disconnect (crash,
    // sleep, Wi-Fi drop — no Bye) surfaces in ~9s instead of the old ~30s,
    // matching the "3 missed = offline" contract documented in state.rs.
    let mut interval = tokio::time::interval(Duration::from_secs(3));
    let mut missed_pings = 0;
    // FluxMesh robustness slice 1: per-secondary-peer missed-ping counters.
    // The primary's `missed_pings` lives above; each `extra` peer ghost-times
    // out on its own schedule so one silent secondary cannot stall another.
    let mut secondary_missed: std::collections::HashMap<[u8; 32], u32> =
        std::collections::HashMap::new();

    let ping_bytes = || {
        let frame = fluxsync_proto::Frame {
            version: fluxsync_proto::PROTOCOL_VERSION,
            msg: fluxsync_proto::Msg::Heartbeat(fluxsync_proto::Heartbeat {
                lamport: 0,
                rtt_hint: None,
            }),
        };
        fluxsync_proto::encode(&frame).ok()
    };

    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            _ = interval.tick() => {
                let now = crate::transport::now_ms();
                let session_active = transport.has_session().await;

                if session_active {
                    // 1. Send Heartbeat (Ping) to the primary peer.
                    if let Some(bytes) = ping_bytes() {
                        tracing::debug!("Heartbeat: sending ping to peer");
                        metrics.lock().await.on_heartbeat_sent();
                        let _ = transport.send_encrypted(&bytes).await;
                    }

                    // 1b. Re-broadcast this device's current battery so the peer
                    // stays fresh even when the level is steady (no change event
                    // would fire otherwise). 255 = not read yet → skip.
                    let level = self_batt_level.load(std::sync::atomic::Ordering::Relaxed);
                    if level != 255 {
                        let charging = self_batt_charging.load(std::sync::atomic::Ordering::Relaxed);
                        let frame = fluxsync_proto::Frame {
                            version: fluxsync_proto::PROTOCOL_VERSION,
                            msg: fluxsync_proto::Msg::BatteryStatus(fluxsync_proto::BatteryStatus {
                                lamport: 0,
                                level,
                                charging,
                            }),
                        };
                        if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                            let _ = transport.send_encrypted(&bytes).await;
                        }
                    }

                    // 2. Check the primary's receive timeout.
                    let last_rx = transport.last_rx();

                    if now.saturating_sub(last_rx) > 3_000 {
                        missed_pings += 1;
                        metrics.lock().await.on_heartbeat_missed();
                        if missed_pings >= 3 {
                            tracing::warn!("Peer timed out (3 missed pings/~9s). Dropping link.");
                            metrics.lock().await.on_disconnect(DisconnectReason::HeartbeatTimeout);
                            // M6 fix: capture the dying peer + its uptime BEFORE
                            // any failover swaps `cached_peer_id`/
                            // `session_established_at` to a promoted secondary.
                            // Only a session that proved stable (>= MIN_STABLE)
                            // resets backoff; a fast flap keeps its escalation.
                            // Also doubles as the `Event::PeerLost` peer_id below:
                            // `install_session` always sets `last_peer_id`
                            // together with the primary session, and we only
                            // reach this branch when `session_active` was true,
                            // so `dead_peer` is guaranteed `Some` here.
                            let dead_peer = transport.cached_peer_id().await;
                            if let Some(dead_peer) = dead_peer {
                                let uptime = Duration::from_millis(
                                    now.saturating_sub(transport.session_established_at()),
                                );
                                backoff
                                    .lock()
                                    .await
                                    .entry(dead_peer)
                                    .or_insert_with(PeerBackoff::new)
                                    .on_session_ended(uptime);
                            }
                            transport.set_last_rx(now);
                            // FluxMesh robustness slice 2: rebind to a live
                            // secondary if one exists; only fall to Discovering
                            // when the whole mesh is gone.
                            if !try_primary_failover(&transport, &event_tx, &peer_meta).await {
                                if let Some(peer_id) = dead_peer {
                                    let _ = event_tx.try_send(Event::PeerLost { peer_id });
                                } else {
                                    tracing::error!(
                                        "heartbeat timeout with no cached primary peer_id; \
                                         skipping PeerLost (should be unreachable)"
                                    );
                                }
                            }
                            missed_pings = 0;
                        }
                    } else {
                        missed_pings = 0;
                    }
                } else {
                    // DISCOVERY PROBE: If no session but we have a last known peer IP,
                    // try a direct handshake poke.
                    if let Some(_addr) = transport.cached_peer_addr().await {
                         // We don't initiate here because we lack the peer's static_pub,
                         // but we can log that we are waiting for that specific IP.
                         // In a future PR, we could cache the static_pub too.
                    }
                }

                // FluxMesh robustness slice 1: secondary peers run their own
                // heartbeat + ghost-timeout, independent of the primary (which
                // may even be down). A silent secondary drops ONLY its own
                // session — it must NOT drive the single FSM's `PeerLost`; it
                // just refreshes the mesh peer list via `MeshPeersChanged`.
                let secondaries = transport.secondary_liveness().await;
                let live: std::collections::HashSet<[u8; 32]> =
                    secondaries.iter().map(|(id, _)| *id).collect();
                secondary_missed.retain(|id, _| live.contains(id));
                for (peer_id, last_rx) in secondaries {
                    if let Some(bytes) = ping_bytes() {
                        let _ = transport.send_encrypted_to(peer_id, &bytes).await;
                    }
                    if now.saturating_sub(last_rx) > 3_000 {
                        let missed = secondary_missed.entry(peer_id).or_insert(0);
                        *missed += 1;
                        if *missed >= 3 {
                            tracing::warn!(
                                peer = %hex::encode(peer_id),
                                "Secondary peer timed out (~9s). Dropping its session."
                            );
                            // M6 residual fix: a secondary's ghost-timeout is a
                            // teardown exactly like the primary's heartbeat
                            // timeout above, so it gets the same stability-gated
                            // backoff reset — computed from THIS peer's own
                            // established time (not the primary's), captured
                            // before `drop_session_for` below clears its session.
                            if let Some(established) =
                                transport.session_established_at_for(peer_id).await
                            {
                                let uptime = Duration::from_millis(now.saturating_sub(established));
                                backoff
                                    .lock()
                                    .await
                                    .entry(peer_id)
                                    .or_insert_with(PeerBackoff::new)
                                    .on_session_ended(uptime);
                            }
                            transport.drop_session_for(peer_id).await;
                            secondary_missed.remove(&peer_id);
                            // FIX1 (P0 parked-payload leak): a silently
                            // timed-out secondary is gone just as surely as
                            // an explicitly revoked one — drop its parked
                            // `Ask` items too (see `Event::PeerRevoked`'s
                            // doc comment). This loop has no `app`, so it
                            // routes through `event_tx` like
                            // `MeshPeersChanged` below already does.
                            let _ = event_tx.try_send(Event::PeerRevoked { peer_id });
                            let _ = event_tx.try_send(Event::MeshPeersChanged);
                        }
                    } else {
                        secondary_missed.remove(&peer_id);
                    }
                }
            }
        }
    }
}

/// DIR-P2-03: how often the rekey watchdog re-checks the primary session's
/// age/bytes against the rekey thresholds. Cheap (atomic loads plus an
/// occasional lock read) and rekeys are rare, so a short interval costs
/// nothing while keeping test-injected (small) thresholds responsive.
pub(super) const REKEY_CHECK_INTERVAL: Duration = Duration::from_millis(500);

/// DIR-P2-03: automatic session rekey. Every [`REKEY_CHECK_INTERVAL`],
/// checks EVERY currently-linked session — the primary and every FluxMesh
/// `extra` secondary, via [`Transport::linked_peer_ids`] — for whether it
/// has crossed `max_age_ms` or `max_bytes` (see
/// [`crate::transport::rekey_due`]), each against its own established-at/
/// byte-count clock. For the first peer found due, checks whether this
/// daemon is the deterministic rekey initiator for that peer
/// ([`crate::transport::is_rekey_initiator`] — exactly one side of a pair
/// ever is). The other side does nothing: it just accepts the fresh
/// handshake the same way it already accepts any reconnect, via
/// `handshake::run_responder`'s generation-gated install (primary or
/// secondary — see the `secondary_generation` arm there).
///
/// FluxMesh fix: this used to read only the primary's clock and only ever
/// targeted `cached_peer_id()`, so a secondary session — however long-lived
/// — never rotated, violating the rekey policy for every mesh peer but the
/// primary. Iterating `linked_peer_ids()` and resolving each peer's own
/// clock via `session_established_at_for`/`session_bytes_for` (instead of
/// the primary-only `session_established_at`/`session_bytes`) extends the
/// same policy to all of them, uniformly.
///
/// Reuses the same `pending_initiator_tx` single-flight slot as ordinary
/// reconnects, now shared across every peer's rekey attempt too, so at most
/// one initiator handshake — for whichever due peer is checked first — runs
/// at a time; any other due peer simply retries on the next tick. A
/// rekey-triggered re-handshake is intentional, not a failure: on success it
/// feeds `PeerBackoff::on_session_ended` (gated on the old session's uptime,
/// M6) exactly like any other completed handshake; on failure it
/// deliberately does **not** call
/// `on_attempt_failed` — the peer did nothing wrong, so a transient rekey
/// hiccup must not penalize its future reconnect pacing. The next tick
/// simply retries (the age/bytes trigger stays true until a rekey
/// actually lands).
pub(super) async fn rekey_watchdog(sh: Arc<Shared>, max_age_ms: u64, max_bytes: u64) -> Result<()> {
    let Shared {
        identity,
        transport,
        trusted,
        pending_initiator_tx,
        event_tx,
        backoff,
        shutdown,
        ..
    } = &*sh;
    let keystore_dir = &sh.keystore_dir;
    let mut interval = tokio::time::interval(REKEY_CHECK_INTERVAL);
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            _ = interval.tick() => {
                // FluxMesh fix: check every currently-linked peer (primary +
                // every `extra` secondary), each against its OWN clock —
                // not just the primary. `pending_initiator_tx` stays a
                // single global slot, so at most one rekey handshake starts
                // per tick regardless of how many peers are due; the rest
                // are picked up on a later tick.
                for peer_id in transport.linked_peer_ids().await {
                    let Some(established_at) = transport.session_established_at_for(peer_id).await else {
                        continue;
                    };
                    let age_ms = now_ms().saturating_sub(established_at);
                    let bytes = transport.session_bytes_for(peer_id).await.unwrap_or(0);
                    if !rekey_due(age_ms, bytes, max_age_ms, max_bytes) {
                        continue;
                    }
                    if !is_rekey_initiator(identity.peer_id(), peer_id) {
                        // The peer is the deterministic initiator for this pair;
                        // we just wait to accept its handshake.
                        continue;
                    }

                    // Single-flight: never overlap with an organic reconnect
                    // or an earlier rekey attempt still finishing — shared
                    // across every peer, so once taken no other due peer can
                    // start either; stop scanning rather than looping
                    // through the rest for nothing.
                    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
                    {
                        let mut g = pending_initiator_tx.lock().await;
                        if g.is_some() {
                            break;
                        }
                        *g = Some(tx);
                    }

                    let Some(peer_addr) = transport.peer_addr_for(peer_id).await else {
                        *pending_initiator_tx.lock().await = None;
                        continue;
                    };
                    let static_pub = trusted.lock().await.get(&peer_id).map(|p| p.static_pub);
                    let Some(static_pub) = static_pub else {
                        *pending_initiator_tx.lock().await = None;
                        continue;
                    };
                    let Some(expected_generation) = transport.session_generation_for(peer_id).await else {
                        *pending_initiator_tx.lock().await = None;
                        continue;
                    };

                    tracing::info!(
                        peer = %hex::encode(&peer_id[..6]),
                        age_ms,
                        bytes,
                        "DIR-P2-03: starting planned session rekey"
                    );

                    let identity = identity.clone();
                    let transport = transport.clone();
                    let rekey_metrics = transport.metrics.clone();
                    let event_tx = event_tx.clone();
                    let backoff = backoff.clone();
                    let pending_initiator_tx = pending_initiator_tx.clone();
                    let trusted_for_rekey = trusted.clone();
                    let kd = keystore_dir.clone();
                    // M6 fix: gate the post-rekey backoff reset on the OLD
                    // session's uptime (already computed above as `age_ms`)
                    // instead of resetting unconditionally on every successful
                    // rekey — see `PeerBackoff::on_session_ended`.
                    let pre_rekey_uptime = Duration::from_millis(age_ms);
                    tokio::spawn(async move {
                        let result = handshake::run_rekey_initiator(
                            identity,
                            static_pub,
                            peer_addr,
                            transport,
                            rx,
                            event_tx,
                            peer_id,
                            expected_generation,
                            trusted_for_rekey,
                            kd,
                        )
                        .await;
                        match result {
                            Ok(()) => {
                                backoff
                                    .lock()
                                    .await
                                    .entry(peer_id)
                                    .or_insert_with(PeerBackoff::new)
                                    .on_session_ended(pre_rekey_uptime);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "DIR-P2-03: planned rekey attempt failed; will retry \
                                     (not counted against reconnect backoff)"
                                );
                                rekey_metrics.lock().await.on_handshake_fail();
                            }
                        }
                        *pending_initiator_tx.lock().await = None;
                    });
                    // Single-flight slot is now taken; stop scanning for
                    // more due peers this tick.
                    break;
                }
            }
        }
    }
}
