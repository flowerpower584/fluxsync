//! Trusted-peer persistence (`peers.json`) and last-address bookkeeping.

use super::*;

/// Boot-time fallback trusted-peer choice, for the `Event::SetTrustedPeer`
/// UI hint `run()` sends right after reloading `peers.json`. `HashMap`
/// iteration order is randomized per process, so picking `.values().next()`
/// used to name a different trusted peer on every restart whenever more
/// than one is paired. Prefer the primary's own entry when its id is
/// already known at this point (e.g. the test harness's `test_pair` already
/// installed a session); otherwise fall back to the lowest peer id so the
/// choice is stable across restarts instead of iteration-order luck.
pub(super) fn choose_boot_trusted_peer(
    trusted: &HashMap<[u8; 32], TrustedPeer>,
    primary_id: Option<[u8; 32]>,
) -> Option<TrustedPeer> {
    primary_id
        .and_then(|id| trusted.get(&id))
        .or_else(|| trusted.iter().min_by_key(|(id, _)| **id).map(|(_, p)| p))
        .cloned()
}

/// Load the trusted-peer set from `peers.json` (FS-039); malformed entries
/// are skipped with a warning. Also returns each entry's persisted
/// last-known remote address (`last_addr` redial), best-effort parsed —
/// missing or unparseable yields `None` rather than failing the whole boot.
pub(super) fn load_trusted_peers(dir: &Path) -> Vec<([u8; 32], TrustedPeer, Option<SocketAddr>)> {
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
        // H1 (defense-in-depth): a peers.json copied from a vulnerable
        // pre-fix daemon may already contain degenerate pubkeys. Filter
        // them at boot rather than panicking later inside Noise IK.
        if let Err(e) = fluxsync_crypto::validate_peer_pubkey(&static_pub) {
            tracing::warn!(
                error = %e,
                peer = %p.peer_id_hex,
                "skipping peers.json entry: invalid pubkey (zero or low-order)"
            );
            continue;
        }
        let peer_id = handshake::peer_id_for(&static_pub);
        let last_addr = p.last_addr.as_deref().and_then(|s| match s.parse::<SocketAddr>() {
            Ok(a) => Some(a),
            Err(e) => {
                tracing::warn!(error = %e, peer = %p.peer_id_hex, addr = %s, "skipping unparseable last_addr");
                None
            }
        });
        out.push((
            peer_id,
            TrustedPeer {
                static_pub,
                name: p.name,
            },
            last_addr,
        ));
    }
    // H3: enforce the cap at load too. If a malicious or pre-fix
    // peers.json has more than `MAX_PERSISTED_PEERS` entries, keep the
    // first N (load order = file order = insertion order under the
    // disk lock). This is conservative: it never silently *replaces*
    // a peer the user might still recognize, but it stops boot-time
    // memory blow-up.
    if out.len() > MAX_PERSISTED_PEERS {
        tracing::warn!(
            total = out.len(),
            cap = MAX_PERSISTED_PEERS,
            "peers.json exceeds cap; truncating tail. Revoke unwanted entries via `fluxctl revoke <peer-id>`."
        );
        out.truncate(MAX_PERSISTED_PEERS);
    }
    out
}

/// Persist the current trusted-peer set to `peers.json` (FS-039). Used by
/// callers that rewrite the WHOLE set from the in-memory `TrustedSet`
/// (Unpair, Revoke, `PairConfirm --reject`) rather than upserting one entry
/// (contrast [`upsert_peer_persist`], used by the pair-insert paths, and
/// [`persist_last_addr`], used on every completed handshake).
///
/// last_addr persistence: `TrustedPeer` carries no address
/// field, so a naive rebuild would silently overwrite every surviving
/// peer's `last_addr` with `None` on each of these operations. Preserve it
/// by reading the existing on-disk record for each peer_id that survives
/// the rewrite and carrying its `last_addr` forward; only a genuinely new
/// entry (not found on disk) gets `None`.
pub(super) async fn save_current_peers(
    dir: &Path,
    trusted: &TrustedSet,
    _transport: &Transport,
) -> Result<()> {
    let existing_addrs: HashMap<String, Option<String>> = crate::keystore::load_peers(dir)
        .unwrap_or_default()
        .into_iter()
        .map(|p| (p.peer_id_hex, p.last_addr))
        .collect();
    let stored: Vec<crate::keystore::StoredPeer> = {
        let g = trusted.lock().await;
        g.iter()
            .map(|(peer_id, peer)| {
                let peer_id_hex = hex::encode(peer_id);
                let last_addr = existing_addrs.get(&peer_id_hex).cloned().flatten();
                crate::keystore::StoredPeer {
                    peer_id_hex,
                    static_pub_hex: hex::encode(peer.static_pub),
                    name: peer.name.clone(),
                    last_addr,
                }
            })
            .collect()
    };
    crate::keystore::save_peers(dir, &stored)
}

/// FS-052 / VULN-001 fix: persist `trusted` to `peers.json` with up to
/// `PEERS_PERSIST_ATTEMPTS` tries (exponential backoff 100/200/400 ms).
/// Used by paths whose security invariant depends on the on-disk state
/// matching the in-memory state — namely `PairConfirm --reject` and the
/// FS-052 strict pending-expiry revoke. Silently swallowing the write
/// would re-trust the attacker on next daemon restart.
pub(crate) async fn save_peers_with_retry(
    dir: &Path,
    trusted: &TrustedSet,
    transport: &Transport,
) -> Result<()> {
    // F-001 fix: serialize every peers.json write so a concurrent
    // pair-insert cannot read a stale snapshot and clobber this revoke.
    let _disk_guard = transport.peers_disk_lock.lock().await;
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..PEERS_PERSIST_ATTEMPTS {
        match save_current_peers(dir, trusted, transport).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                tracing::warn!(attempt, error = %e, "save_peers failed; retrying");
                last_err = Some(e);
                if attempt + 1 < PEERS_PERSIST_ATTEMPTS {
                    tokio::time::sleep(Duration::from_millis(100u64 << attempt)).await;
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("save_peers exhausted retries")))
}

/// Max attempts for [`save_peers_with_retry`]. Three is enough to ride
/// out a transient ENOSPC / EBUSY / fs-quota hiccup without making the
/// IPC reply hang forever on a broken disk.
pub(super) const PEERS_PERSIST_ATTEMPTS: u32 = 3;

/// Atomic upsert of a single [`crate::keystore::StoredPeer`] into
/// `peers.json`: takes the disk lock, reads the on-disk list, upserts
/// `entry` by `peer_id_hex`, and persists with retry. Used by the
/// pair-insert paths (PairFromUri / PairAccept / TOFU) where the new
/// entry carries data (e.g. `last_addr`) that the in-memory
/// `TrustedSet` does not retain.
///
/// Replaces the old `save_peers_with_retry_stored` + inline
/// `load_peers().unwrap_or_default()` pattern. Two fixes folded in:
///
/// * **F-001** — the load/modify/save sequence runs entirely under
///   `transport.peers_disk_lock`, so a concurrent reaper revoke cannot
///   race against the load and have its write overwritten.
/// * **F-002** — `load_peers` parse failure now propagates instead of
///   being swallowed by `unwrap_or_default()` (which would silently
///   nuke every other trusted peer from disk).
pub(crate) async fn upsert_peer_persist(
    dir: &Path,
    transport: &Transport,
    entry: crate::keystore::StoredPeer,
) -> Result<()> {
    let _disk_guard = transport.peers_disk_lock.lock().await;
    let mut stored = crate::keystore::load_peers(dir).with_context(|| {
        format!(
            "read {}/peers.json before upsert; refusing to overwrite a corrupt file",
            dir.display()
        )
    })?;
    crate::keystore::upsert_peer(&mut stored, entry);
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..PEERS_PERSIST_ATTEMPTS {
        match crate::keystore::save_peers(dir, &stored) {
            Ok(()) => return Ok(()),
            Err(e) => {
                tracing::warn!(attempt, error = %e, "upsert_peer_persist save failed; retrying");
                last_err = Some(e);
                if attempt + 1 < PEERS_PERSIST_ATTEMPTS {
                    tokio::time::sleep(Duration::from_millis(100u64 << attempt)).await;
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("upsert_peer_persist exhausted retries")))
}

/// Persist `peer_id`'s current remote address into its on-disk `StoredPeer`
/// record (last_addr persistence + redial). This is the
/// single chokepoint called from every path that completes a Noise
/// handshake — fresh pairing (TOFU), an ordinary reconnect, and a planned
/// rekey, both initiator and responder roles (see
/// `handshake::run_initiator`, `handshake::run_rekey_initiator`, and
/// `handshake::run_responder`) — so `peers.json`'s `last_addr` always
/// reflects the most recently confirmed address. That, combined with
/// `run()`'s boot-time seed of `Transport` from `load_trusted_peers`, is
/// what lets a rebooted daemon redial an already-paired peer with zero
/// mDNS involvement.
///
/// No-op when `keystore_dir` is `None` (in-process test harnesses with no
/// on-disk persistence) or when `peer_id` is not (yet) in `trusted` — the
/// latter should not happen for a handshake that just completed, but a
/// stale invariant here must degrade to "skip the write", never panic.
/// L4 fix: rejects the source-IP-spoofable address classes (unspecified /
/// multicast / link-local) so a `last_addr` we persist or seed a boot-time
/// redial from can never be one a LAN attacker plants via a forged source
/// IP during the pairing window. Loopback is deliberately NOT rejected: a
/// 127.0.0.0/8 source cannot be spoofed onto a real interface (the kernel
/// drops inbound packets claiming a loopback source), redialing localhost is
/// harmless, and the in-process test harness relies on it.
pub(super) fn is_redialable_addr(ip: std::net::IpAddr) -> bool {
    if ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        std::net::IpAddr::V4(v4) => !v4.is_link_local(),
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) != 0xfe80,
    }
}

pub(crate) async fn persist_last_addr(
    keystore_dir: Option<&Path>,
    transport: &Transport,
    trusted: &TrustedSet,
    peer_id: [u8; 32],
    addr: SocketAddr,
) {
    let Some(dir) = keystore_dir else { return };
    if !is_redialable_addr(addr.ip()) {
        tracing::warn!(
            peer = %hex::encode(&peer_id[..6]),
            addr = %addr,
            "L4: refusing to persist a link-local/multicast/unspecified last_addr"
        );
        return;
    }
    let entry = { trusted.lock().await.get(&peer_id).cloned() };
    let Some(entry) = entry else {
        tracing::debug!(
            peer = %hex::encode(&peer_id[..6]),
            "persist_last_addr: peer not in trusted set yet; skipping"
        );
        return;
    };
    let stored = crate::keystore::StoredPeer {
        peer_id_hex: hex::encode(peer_id),
        static_pub_hex: hex::encode(entry.static_pub),
        name: entry.name,
        last_addr: Some(addr.to_string()),
    };
    if let Err(e) = upsert_peer_persist(dir, transport, stored).await {
        tracing::warn!(
            error = %e,
            peer = %hex::encode(&peer_id[..6]),
            "failed to persist last_addr after handshake"
        );
    }
}
