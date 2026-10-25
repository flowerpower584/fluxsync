//! Resync-on-reconnect offer/pull helpers.

use super::*;

/// resync-1: build a `ResyncOffer` from our own outbox's held hashes
/// (already newest-first per `Outbox::hashes`), hex-encoding each for the
/// wire. Factored out of the `Msg::Hello` handler so it's unit-testable
/// without a live `Outbox`/transport.
pub(super) fn build_resync_offer(outbox_hashes: &[[u8; 32]]) -> ResyncOffer {
    ResyncOffer {
        hashes: outbox_hashes.iter().map(hex::encode).collect(),
    }
}

/// resync-1: which hashes a peer offered that we do not already hold,
/// preserving the offer's order and capped at `MAX_RESYNC_HASHES` (already
/// guaranteed by the codec on `offered`, but kept defensive here too since
/// this helper has no codec of its own to rely on). "Held" means present in
/// our clipboard history OR our own outbox. H2 fix: `cleared_hashes`
/// (hex-encoded, from `ClearedTombstone`) is a third exclusion — a hash we
/// deliberately cleared via `CmdOp::ClearHistory` must never be re-pulled
/// just because a peer's outbox still offers it.
pub(super) fn missing_resync_hashes(
    offered: &[String],
    history_hashes: &[String],
    outbox_hashes: &[String],
    cleared_hashes: &[String],
    pending_pull_hashes: &[String],
) -> Vec<String> {
    offered
        .iter()
        .filter(|h| {
            !history_hashes.iter().any(|x| x == *h)
                && !outbox_hashes.iter().any(|x| x == *h)
                && !cleared_hashes.iter().any(|x| x == *h)
                // Bug #7: a hash we already have an outstanding ResyncPull
                // in flight for (to ANY peer) must not start a second one —
                // see `in_flight_pull_hashes`.
                && !pending_pull_hashes.iter().any(|x| x == *h)
        })
        .take(MAX_RESYNC_HASHES)
        .cloned()
        .collect()
}

/// resync-1 defense in depth: the codec already validates a `ResyncOffer` /
/// `ResyncPull`'s shape and bounds, but a message must also come from a
/// currently linked peer that negotiated the `resync-1` capability with US
/// specifically — not just any peer that happens to claim it.
pub(super) async fn resync_authorized(
    transport: &Arc<Transport>,
    peer_meta: &PeerMetaMap,
    peer_id: [u8; 32],
) -> bool {
    if !transport.linked_peer_ids().await.contains(&peer_id) {
        return false;
    }
    peer_meta
        .lock()
        .await
        .get(&peer_id)
        .is_some_and(|m| m.caps.iter().any(|c| c == "resync-1"))
}
