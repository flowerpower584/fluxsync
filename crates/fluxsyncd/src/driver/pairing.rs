//! mDNS discovery dispatch, initiator handshakes, PIN adverts and pair URIs.

use super::*;

pub(super) async fn discovery_dispatcher(
    mut rx: mpsc::Receiver<DiscoveryEvent>,
    sh: Arc<Shared>,
    // Item 4 (secondary redial): boot-time `peers.json` `last_addr` per
    // trusted peer id — the fallback candidate address for a SECONDARY
    // that has never held a session on `transport` this boot (so its
    // per-peer `roaming_history_snapshot_for` is still empty).
    persisted_peer_addrs: Arc<HashMap<[u8; 32], SocketAddr>>,
) -> Result<()> {
    let Shared {
        identity,
        trusted,
        transport,
        event_tx,
        disc_cache,
        backoff,
        shutdown,
        ..
    } = &*sh;
    // DIR-P1-02: polled at the initial-backoff granularity (see
    // `backoff::INITIAL_BASE`), not the redial cadence itself — actual
    // dial pacing is governed by `PeerBackoff::ready` below. Checking
    // this often is cheap (in-memory lock reads only, no I/O unless a
    // dial is actually due) and matches the clipboard watcher's own
    // 200ms poll elsewhere in this file.
    //
    // last_addr redial: the first tick is deliberately delayed (rather
    // than firing immediately, `tokio::time::interval`'s default) so a
    // fresh boot gives any imminent EXPLICIT reconnect command (PairAccept
    // / PairFromUri / PairFromPin — e.g. a CLI-driven manual redial issued
    // right after the IPC socket comes up) first claim on the single
    // in-flight initiator slot (`pending_initiator_tx`), rather than
    // racing it. Purely a fairness/ordering nicety: if nothing else claims
    // the slot, this blind proactive redial still engages a few seconds
    // later, which is negligible against the reconnect timescales already
    // in play (heartbeat timeout alone is ~9s). Does not affect the
    // separate, event-driven `DiscoveryEvent::Resolved` redial path below,
    // which reacts immediately regardless of this timer.
    let mut interval = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(2),
        Duration::from_millis(200),
    );
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            _ = interval.tick() => {
                // Sync switched off: no blind redials.
                if !sh.sync_on() {
                    continue;
                }
                // PROACTIVE PROBE: If no session, try the last known peer
                let has_session = transport.has_session().await;
                if !has_session {
                    let addr_opt = transport.cached_peer_addr().await;
                    let id_opt = transport.cached_peer_id().await;

                    if let (Some(_addr), Some(id)) = (addr_opt, id_opt) {
                        let peer_opt = {
                            let g = trusted.lock().await;
                            g.get(&id).cloned()
                        };

                        if let Some(peer) = peer_opt {
                            // DIR-P1-02: this is the blind cache-redial path —
                            // no fresh mDNS advert triggered it, we're just
                            // retrying the last known address. Gate it on the
                            // peer's backoff timer so a dead/flapping peer
                            // doesn't get redialed every tick forever (that
                            // was the pre-backoff handshake-storm bug). A
                            // fresh `DiscoveryEvent::Resolved` below
                            // deliberately bypasses this gate — see the
                            // comment there.
                            let ready = {
                                let mut g = backoff.lock().await;
                                g.entry(id).or_insert_with(PeerBackoff::new).ready(Instant::now())
                            };
                            if !ready {
                                continue;
                            }
                            // Redial candidate set (last_addr persistence +
                            // redial): the transport's roaming history —
                            // seeded at boot from the persisted `last_addr`
                            // (see `run()`'s seed loop) and updated on every
                            // confirmed handshake/roam — UNION any
                            // still-fresh mDNS discovery-cache hint for this
                            // peer, deduplicated by address. When mDNS is
                            // disabled `disc_cache` simply stays empty, so
                            // this reduces to the roaming-history-only set.
                            let mut candidates = transport.roaming_history_snapshot().await;
                            {
                                let cache = disc_cache.lock().await;
                                if let Some(hint) = cache.get(&id) {
                                    if Instant::now().duration_since(hint.last_seen) < DISCOVERY_CACHE_TTL
                                        && !candidates.contains(&hint.addr)
                                    {
                                        candidates.push(hint.addr);
                                    }
                                }
                            }
                            for h_addr in candidates {
                                let static_pub = peer.static_pub;
                                let peer_id_clone = id;
                                let peer_name = peer.name.clone();
                                let sh = sh.clone();

                                // [REMEDIATION] Proactive Probe Tie-break: only one side initiates.
                                if identity.public_key() >= static_pub {
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
                                        &sh,
                                        static_pub,
                                        vec![h_addr],
                                        peer_id_clone,
                                        peer_name,
                                        false,
                                    ).await;
                                });
                            }
                        }
                    }
                }

                // Item 4: also proactively redial known-trusted SECONDARIES
                // whose session is down. The probe above only ever retries
                // the PRIMARY (`cached_peer_id`) — a linked-but-since-dropped
                // secondary was otherwise stranded until mDNS happened to
                // rediscover it. Independent of the primary's own session
                // state (a secondary can need redialing whether or not the
                // primary is currently linked). Reuses the exact same
                // candidate-address union / backoff gate / tie-break /
                // `start_initiator` mechanics as the primary probe, just
                // per secondary id.
                let primary_id_now = transport.cached_peer_id().await;
                let secondary_candidates: Vec<(_, TrustedPeer)> = {
                    let g = trusted.lock().await;
                    g.iter()
                        .filter(|(id, _)| Some(**id) != primary_id_now)
                        .map(|(id, peer)| (*id, peer.clone()))
                        .collect()
                };
                for (id, peer) in secondary_candidates {
                    if transport.has_session_for(id).await {
                        continue;
                    }
                    let ready = {
                        let mut g = backoff.lock().await;
                        g.entry(id).or_insert_with(PeerBackoff::new).ready(Instant::now())
                    };
                    if !ready {
                        continue;
                    }
                    // Candidate set: this peer's own per-conn roaming
                    // history (populated once it has held ANY session on
                    // `transport` this boot, primary or `extra`) UNION the
                    // boot-time persisted `last_addr` (covers a secondary
                    // that has never connected yet this process) UNION a
                    // still-fresh mDNS discovery-cache hint.
                    let mut candidates = transport.roaming_history_snapshot_for(id).await;
                    if let Some(addr) = persisted_peer_addrs.get(&id) {
                        if !candidates.contains(addr) {
                            candidates.push(*addr);
                        }
                    }
                    {
                        let cache = disc_cache.lock().await;
                        if let Some(hint) = cache.get(&id) {
                            if Instant::now().duration_since(hint.last_seen) < DISCOVERY_CACHE_TTL
                                && !candidates.contains(&hint.addr)
                            {
                                candidates.push(hint.addr);
                            }
                        }
                    }
                    if candidates.is_empty() {
                        continue;
                    }
                    // Tie-break: only one side initiates (mirrors the
                    // primary probe above).
                    if identity.public_key() >= peer.static_pub {
                        tracing::debug!(peer = %hex::encode(&id[..4]), "proactive probe (secondary) tie-break: peer initiates");
                        continue;
                    }
                    for h_addr in candidates {
                        let static_pub = peer.static_pub;
                        let peer_id_clone = id;
                        let peer_name = peer.name.clone();
                        let sh = sh.clone();

                        tokio::spawn(async move {
                            tracing::debug!(
                                peer = %hex::encode(&peer_id_clone[..4]),
                                addr = %h_addr,
                                "proactive probe (secondary): trying known IP in parallel"
                            );
                            start_initiator(
                                &sh,
                                static_pub,
                                vec![h_addr],
                                peer_id_clone,
                                peer_name,
                                false,
                            ).await;
                        });
                    }
                }
            }
            Some(disc) = rx.recv() => {
                match disc {
                    DiscoveryEvent::Resolved { peer_id_hex, static_pub_hex, name, addrs, pair_pin } => {
                        let Ok(peer_id) = decode_hex32(&peer_id_hex) else { continue };
                        let Ok(static_pub) = decode_hex32(&static_pub_hex) else { continue };
                        if handshake::peer_id_for(&static_pub) != peer_id {
                            tracing::warn!("mDNS peer_id != BLAKE3(static_pub); ignoring");
                            continue;
                        }
                        // Best (highest-ranked) address for the reconnect
                        // cache; the initiator below gets the full ranked list.
                        let Some(best_addr) = addrs.first().copied() else { continue };
                        // PR2: feed the discovery cache before the trust
                        // gate so `PairFromPin` can resolve a not-yet-
                        // trusted peer. Cap to avoid unbounded growth from
                        // a hostile flood — old entries naturally age out
                        // via `DISCOVERY_CACHE_TTL`, but a burst could
                        // still wedge the map; 256 is far above the legit
                        // home-LAN peer count.
                        {
                            let mut cache = disc_cache.lock().await;
                            let now = Instant::now();
                            cache.retain(|_, e| now.duration_since(e.last_seen) < DISCOVERY_CACHE_TTL);
                            if cache.len() < 256 || cache.contains_key(&peer_id) {
                                cache.insert(peer_id, ResolvedPeer {
                                    static_pub,
                                    addr: best_addr,
                                    name: name.clone(),
                                    pair_pin: pair_pin.clone(),
                                    last_seen: now,
                                });
                            }
                        }
                        let trusted_match = {
                            let g = trusted.lock().await;
                            g.get(&peer_id).is_some_and(|t| t.static_pub == static_pub)
                        };
                        if !trusted_match {
                            // C-DAEMON-01: `peer_id == BLAKE3(static_pub)` is
                            // verified above, so a peer_id absent from the
                            // trust set is just an unknown device on the LAN —
                            // never a "cryptographic reset" of an existing
                            // pairing (impossible by construction: same id ⇒
                            // same key). Ignore it; do NOT touch trust. Firing
                            // UntrustedPeerSeen here let ANY stranger's mDNS
                            // advert remote-wipe the whole trust store.
                            tracing::debug!(peer = %peer_id_hex, "ignoring advertisement from untrusted/unknown peer");
                            continue;
                        }
                        // The discovery cache above stays fed (PairFromPin
                        // needs it), but with sync off nothing is dialed.
                        if !sh.sync_on() {
                            continue;
                        }
                        // Skip if a session is already up to THIS peer.
                        // FluxMesh 2C-b: per-peer, so a daemon already linked to
                        // one device still initiates to other discovered peers.
                        if transport.has_session_for(peer_id).await {
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
                        // DIR-P1-02: deliberately bypasses the backoff gate
                        // (contrast the "PROACTIVE PROBE" arm above). This
                        // fired because the peer *just* announced itself
                        // over mDNS, i.e. it is provably alive on the LAN
                        // right now — waiting out a stale backoff window
                        // here would only hurt reconnect latency for no
                        // storm-prevention benefit, since the trigger is a
                        // real signal, not a blind timer. The attempt still
                        // feeds `backoff` below so a failure here still
                        // paces the *next* blind redial correctly.
                        start_initiator(&sh, static_pub, addrs, peer_id, name, false).await;
                    }
                    DiscoveryEvent::Removed { .. } => {
                        // mDNS removal is unreliable — TTL expiry, transient
                        // multicast loss, or an unrelated FluxSync device
                        // leaving the LAN all fire it. It must NOT tear down a
                        // healthy link: while an encrypted session is live,
                        // heartbeat timeout (~9s) is the sole authority on peer
                        // liveness. Only surface PeerLost when there is no
                        // session to lose (already discovering / never linked).
                        // The removed mDNS `fullname` isn't resolved to a
                        // peer_id here, so this targets the last-known
                        // primary (`cached_peer_id`, the same "primary"
                        // concept the Bye/Revoke handlers gate on) — the
                        // only peer this no-session state could be about.
                        // Never linked at all ⇒ no cached id ⇒ nothing to
                        // reset, so skip rather than invent one.
                        if !transport.has_session().await {
                            if let Some(peer_id) = transport.cached_peer_id().await {
                                let _ = event_tx.try_send(Event::PeerLost { peer_id });
                            }
                        }
                    }
                }
            }
            else => return Ok(()),
        }
    }
}

pub(super) async fn start_initiator(
    sh: &Arc<Shared>,
    static_pub: [u8; 32],
    addrs: Vec<SocketAddr>,
    peer_id: [u8; 32],
    name: String,
    // `true` engages the SAS gate: a fresh pairing parks the peer in
    // `pending_pairs` until both sides confirm the 6 words. `false` is a
    // silent reconnect of an already-confirmed peer.
    sas_gate: bool,
) {
    if addrs.is_empty() {
        return;
    }
    // Single-flight: refuse to start a second initiator while one is
    // still waiting on its msg2. The pending slot doubles as the route
    // for HandshakeResp datagrams (transport_recv_loop), so two
    // overlapping initiators would steer the second peer's reply to
    // the first peer's session and corrupt both. Reserve the slot here
    // (under the lock, before spawning) with a placeholder; the loop
    // installs the real per-attempt channel before each handshake.
    {
        let mut g = sh.pending_initiator_tx.lock().await;
        if g.is_some() {
            tracing::debug!("initiator already pending; skipping");
            return;
        }
        let (placeholder, _) = mpsc::unbounded_channel::<Vec<u8>>();
        *g = Some(placeholder);
    }
    let sh = Arc::clone(sh);
    let pending = sas_gate.then(|| sh.pending_pairs.clone());
    tokio::spawn(async move {
        let Shared {
            identity,
            transport,
            pending_initiator_tx,
            event_tx,
            backoff,
            trusted,
            keystore_dir,
            ..
        } = &*sh;
        // Try each address hint in order (LAN first, then tailnet). A dead
        // hint fails fast via run_initiator's 5s msg2 timeout, then we
        // refresh the channel + pending slot and try the next. One QR with
        // `a=lan,tailnet` thus works on the LAN and across a tailnet.
        for (i, addr) in addrs.iter().enumerate() {
            let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
            *pending_initiator_tx.lock().await = Some(tx);
            // No address pinning here: `run_initiator` records `addr` via
            // `set_peer_info` on the slot the session actually lands in.
            // Writing it up front went to the *primary* slot, re-pointing a
            // live link at whichever device was being dialed.
            let result = handshake::run_initiator(
                identity.clone(),
                static_pub,
                *addr,
                transport.clone(),
                rx,
                event_tx.clone(),
                peer_id,
                name.clone(),
                pending.clone(),
                trusted.clone(),
                keystore_dir.clone(),
            )
            .await;
            match result {
                Ok(()) => {
                    // M6 fix: do NOT reset backoff on a mere completed
                    // handshake — that proves nothing about link stability
                    // and previously let a connect-then-immediately-drop
                    // flap bypass backoff on every cycle. The reset now
                    // happens at actual teardown (heartbeat timeout /
                    // `Msg::Bye`) gated on `PeerBackoff::MIN_STABLE` uptime
                    // — see `heartbeat_loop` and `dispatch_inbound_frame`.
                    // Linked. Leave the slot cleared and stop trying hints.
                    *pending_initiator_tx.lock().await = None;
                    return;
                }
                Err(e) => {
                    tracing::warn!(error = %e, addr = %addr, attempt = i, "initiator attempt failed");
                    // DIR-P1-09: one failed hint = one failed handshake
                    // attempt, same accounting as the responder/rekey paths.
                    transport.metrics.lock().await.on_handshake_fail();
                }
            }
        }
        // All hints exhausted; clear the slot so the next discovery resolve
        // / PairAccept can retry.
        *pending_initiator_tx.lock().await = None;
        // DIR-P1-02: this whole call (every hint tried) is one logical
        // reconnect attempt — schedule the next allowed blind redial.
        // `OsRng` here is the real jitter source (tests inject a seeded
        // RNG directly against `PeerBackoff`, see backoff.rs).
        backoff
            .lock()
            .await
            .entry(peer_id)
            .or_insert_with(PeerBackoff::new)
            .on_attempt_failed(Instant::now(), &mut rand_core::OsRng);
    });
}

/// PR2: rotation watchdog for the advertised pairing PIN.
///
/// While `pin_advert` is `Some(_)`, sleeps until its `expires_at`,
/// then either:
///   * pairing_window has elapsed → clear PIN + republish the mDNS
///     record without a `pair_pin` TXT and exit (user did not pair in
///     time; stale PIN must not linger on the LAN).
///   * otherwise → generate a fresh PIN, republish the TXT, and loop.
///
/// Note the trusted set deliberately does NOT stop the rotation: with
/// re-pairing allowed while already paired, a non-empty trusted set
/// says nothing about whether the user is done with the window. The
/// window deadline (refreshed by each `PairShow` the UI issues while
/// its pair screen stays open) is the single source of truth.
///
/// Exactly one watchdog runs per `PairShow`-opened session — callers
/// guard the spawn behind `was_active` (the previous `pin_advert`
/// being `Some`). On termination the task clears `pin_advert` to
/// `None` so the next `PairShow` re-spawns cleanly.
pub(super) fn spawn_pin_watchdog(
    pin_advert: PinAdvertisement,
    mdns_ctx: MdnsCtx,
    pairing_window: PairingWindow,
) {
    tokio::spawn(async move {
        loop {
            let sleep_until = match pin_advert.lock().await.as_ref() {
                Some(p) => p.expires_at,
                None => return,
            };
            let now = Instant::now();
            if sleep_until > now {
                tokio::time::sleep(sleep_until - now).await;
            }
            // After sleeping: decide whether to rotate or stop.
            let window_open = match *pairing_window.lock().await {
                Some(deadline) => deadline > Instant::now(),
                None => false,
            };
            if !window_open {
                // Window closed — strip the PIN from mDNS so a stale
                // code can't be used by a late scanner.
                *pin_advert.lock().await = None;
                if let Some(ctx) = mdns_ctx.lock().await.as_ref() {
                    if let Err(e) = discovery::republish_with_pin(
                        &ctx.daemon,
                        &ctx.instance_name,
                        &ctx.peer_id_hex,
                        &ctx.static_pub_hex,
                        ctx.bind_ip,
                        ctx.udp_port,
                        None,
                    ) {
                        tracing::warn!(error = %e, "mDNS republish (clear PIN) failed");
                    }
                }
                tracing::info!("pair PIN cleared");
                return;
            }
            // Rotate: fresh PIN, new expiry, re-publish TXT.
            let new_pin = gen_pair_pin();
            let new_expires = Instant::now() + handshake::PAIRING_WINDOW;
            *pin_advert.lock().await = Some(PinAd {
                pin: new_pin.clone(),
                expires_at: new_expires,
            });
            if let Some(ctx) = mdns_ctx.lock().await.as_ref() {
                if let Err(e) = discovery::republish_with_pin(
                    &ctx.daemon,
                    &ctx.instance_name,
                    &ctx.peer_id_hex,
                    &ctx.static_pub_hex,
                    ctx.bind_ip,
                    ctx.udp_port,
                    Some(&new_pin),
                ) {
                    tracing::warn!(error = %e, "mDNS republish (rotate PIN) failed");
                }
            }
            tracing::info!("pair PIN rotated");
        }
    });
}

pub(super) fn decode_hex32(s: &str) -> Result<[u8; 32]> {
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
pub(super) fn local_lan_addr(udp_bind: &str, udp_port: u16) -> String {
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

/// Best-effort tailnet (Tailscale) socket address for this host, if any.
///
/// Tailscale assigns each node an address in the CGNAT range
/// `100.64.0.0/10`. We discover ours the same dependency-free way as
/// `local_lan_addr`: open a UDP socket "connected" to a target inside that
/// range (Tailscale's MagicDNS resolver, `100.100.100.100`) and read back
/// the source address the kernel picks. With no tailnet route the source IP
/// won't land in the CGNAT range, so we reject it and return `None`. No
/// Tailscale SDK or dependency — purely a routing probe, so Tailscale stays
/// 100% optional. (False positive only if the host itself sits behind ISP
/// CGNAT in the same range; harmless — it's a hint the user can verify.)
pub(super) fn tailnet_local_addr(udp_port: u16) -> Option<String> {
    use std::net::{IpAddr, UdpSocket};
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("100.100.100.100:80").ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if is_cgnat(v4) => Some(format!("{v4}:{udp_port}")),
        _ => None,
    }
}

/// True if `ip` is in the `100.64.0.0/10` CGNAT range Tailscale assigns.
pub(super) fn is_cgnat(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

/// Render a `fluxsync://pair/<pubkey_b32>?a=<addr>&f=<w1.w2...>` URI.
pub(super) fn build_pair_uri(pubkey_b32: &str, addr_hint: &str, fp_words: &[String]) -> String {
    format!(
        "fluxsync://pair/{pubkey_b32}?a={addr_hint}&f={}",
        fp_words.join(".")
    )
}

pub(super) struct ParsedPairUri {
    pub(super) pubkey_b32: String,
    /// Address hints from `a=` (comma-separated), parsed + validated, in
    /// order. Lets one URI/QR carry LAN + tailnet so the initiator can try
    /// each until one handshake succeeds.
    pub(super) addrs: Vec<SocketAddr>,
    #[allow(dead_code)]
    pub(super) fp_words: Vec<String>,
}

/// Parse a `fluxsync://pair/...` URI. Tolerant of missing/extra params:
/// only the pubkey segment is required. The fingerprint words are
/// returned for display-side comparison but the daemon does not enforce
/// them — the user does that visually.
pub(super) fn parse_pair_uri(s: &str) -> Result<ParsedPairUri> {
    let rest = s
        .strip_prefix("fluxsync://pair/")
        .ok_or_else(|| anyhow!("scheme is not fluxsync://pair/"))?;
    let (pubkey_b32, query) = rest.split_once('?').unwrap_or((rest, ""));
    if pubkey_b32.is_empty() {
        return Err(anyhow!("missing pubkey segment"));
    }
    let mut addrs: Vec<SocketAddr> = Vec::new();
    let mut fp_words: Vec<String> = Vec::new();
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        match k {
            // `a` may carry several comma-separated hints (LAN,tailnet).
            // Keep only the ones that parse; order is preserved so the
            // initiator tries LAN before tailnet.
            "a" => {
                addrs = v
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .filter_map(|s| s.parse::<SocketAddr>().ok())
                    .collect();
            }
            "f" => fp_words = v.split('.').map(str::to_string).collect(),
            _ => {}
        }
    }
    Ok(ParsedPairUri {
        pubkey_b32: pubkey_b32.to_string(),
        addrs,
        fp_words,
    })
}

// ─────────────────────────────────────────────────────────────────
// IPC accept + per-client loop (unchanged from v0.1)
// ─────────────────────────────────────────────────────────────────
