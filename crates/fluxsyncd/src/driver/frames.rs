//! Building, forwarding and acking clipboard item frames.

use super::*;

/// Send an item Ack straight to the source peer. FluxMesh 2C-b: acks are a
/// transport concern routed to whoever sent the datagram (the only place the
/// source peer_id is known), not an FSM-emitted action.
pub(super) async fn ack_source(transport: &Arc<Transport>, peer_id: [u8; 32], hash: [u8; 32]) {
    let frame = Frame {
        version: PROTOCOL_VERSION,
        msg: Msg::Ack(fluxsync_proto::Ack { lamport: 0, hash }),
    };
    if let Ok(bytes) = fluxsync_proto::encode(&frame) {
        let _ = transport.send_encrypted_to(peer_id, &bytes).await;
    }
}

/// Relay a freshly-seen item to every linked peer except its `source` and
/// `origin`, tracking the relayed hash in `inflight` so retransmits cover a
/// dropped relay datagram (FluxMesh 2C-b mesh forwarding).
/// Encode a clipboard item into its wire frames: one `ClipboardItem` for a
/// small payload, or an empty-payload header followed by one `Chunk` per slice
/// for a large one. Shared by the outbound `SendItem` path and the chunked
/// relay (FluxMesh robustness slice 3), so a relayed image is re-chunked
/// identically and keeps the original `origin`/`event_seq`.
pub(super) fn build_item_frames(
    lamport: u64,
    hash: [u8; 32],
    kind: Kind,
    payload: &[u8],
    sensitive: bool,
    origin: [u8; 32],
    event_seq: u64,
) -> Vec<Vec<u8>> {
    let mut frames: Vec<Vec<u8>> = Vec::new();
    if payload.len() <= MAX_CHUNK_DATA {
        let item = ClipboardItem {
            lamport,
            hash,
            kind,
            payload: payload.to_vec(),
            sensitive,
            wall_time_ms: 0,
            origin,
            event_seq,
        };
        if let Ok(bytes) = fluxsync_proto::encode(&Frame {
            version: PROTOCOL_VERSION,
            msg: Msg::ClipboardItem(item),
        }) {
            frames.push(bytes);
        } else {
            tracing::error!("build_item_frames: CBOR encode failed");
        }
    } else {
        // Large payload: a header frame (empty payload), then one per chunk.
        let header = ClipboardItem {
            lamport,
            hash,
            kind,
            payload: Vec::new(),
            sensitive,
            wall_time_ms: 0,
            origin,
            event_seq,
        };
        if let Ok(bytes) = fluxsync_proto::encode(&Frame {
            version: PROTOCOL_VERSION,
            msg: Msg::ClipboardItem(header),
        }) {
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
            if let Ok(bytes) = fluxsync_proto::encode(&Frame {
                version: PROTOCOL_VERSION,
                msg: Msg::Chunk(chunk),
            }) {
                frames.push(bytes);
            }
        }
    }
    frames
}

/// Fan one item's frames out to every linked peer except `source` and `origin`
/// (mesh relay), with the same burst-16/pause-2ms pacing as the outbound path
/// for multi-frame items, and arm the retransmit timer until each target acks.
pub(super) async fn forward_frames(
    transport: &Arc<Transport>,
    inflight: &InflightMap,
    pending_pairs: &PendingSet,
    source: [u8; 32],
    origin: [u8; 32],
    hash: [u8; 32],
    frames: Vec<Vec<u8>>,
) {
    // FS-052 gate (mesh-relay hole fix): mirrors the per-target pending
    // filter `Action::SendItem` already applies. Without it, a confirmed
    // peer's plaintext clipboard was relayed to any linked-but-unconfirmed
    // TOFU secondary, bypassing the FS-052 confirmation gate entirely.
    let all_targets = transport.linked_peer_ids().await;
    let targets: Vec<[u8; 32]> = {
        let pending = pending_pairs.lock().await;
        all_targets
            .into_iter()
            .filter(|d| *d != source && *d != origin && !pending.contains_key(d))
            .collect()
    };
    if targets.is_empty() || frames.is_empty() {
        return;
    }
    let multi = frames.len() > 1;
    for peer in &targets {
        for (i, bytes) in frames.iter().enumerate() {
            let _ = transport.send_encrypted_to(*peer, bytes).await;
            if multi && (i + 1) % 16 == 0 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
    }
    // Inflight merge fix (sibling of the ResyncPull-serve merge below): a
    // blind `insert` here would REPLACE any entry a concurrent relay or
    // local `Action::SendItem` already created for this same hash, silently
    // dropping whichever peers that entry was still awaiting an ack from —
    // they'd never get a retransmit, and the entry would clear on the NEW
    // peers' acks as if the old ones had been delivered. Merge instead.
    match inflight.lock().await.entry(hash) {
        std::collections::hash_map::Entry::Occupied(mut e) => {
            let inf = e.get_mut();
            inf.pending_peers.extend(targets);
            inf.frames = frames;
            inf.last_sent = Instant::now();
        }
        std::collections::hash_map::Entry::Vacant(v) => {
            v.insert(Inflight {
                frames,
                attempts: 0,
                last_sent: Instant::now(),
                first_sent: Instant::now(),
                pending_peers: targets.into_iter().collect(),
            });
        }
    }
}

pub(super) async fn forward_item(
    transport: &Arc<Transport>,
    inflight: &InflightMap,
    pending_pairs: &PendingSet,
    source: [u8; 32],
    origin: [u8; 32],
    hash: [u8; 32],
    frame_bytes: Vec<u8>,
) {
    forward_frames(
        transport,
        inflight,
        pending_pairs,
        source,
        origin,
        hash,
        vec![frame_bytes],
    )
    .await;
}

/// Namespace the reassembly map by the immediate source peer so concurrent
/// transfers of the same `item_id` from different mesh peers cannot share a
/// `Reassembly` slot vector. Without this, a paired-but-misbehaving peer could
/// send `Chunk{item_id=H, ..}` to overwrite a slot another peer is filling for
/// the same H, delivering a corrupted payload under an authentic hash. Keyed by
/// BLAKE3(source ‖ item_id); the content hash itself is still carried unchanged
/// into `complete_reassembled_item`.
pub(super) fn reassembly_key(source: [u8; 32], item_id: [u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&source);
    buf[32..].copy_from_slice(&item_id);
    fluxsync_core::DedupRing::hash(&buf).into_bytes()
}

/// SE-14 defense in depth (daemon-side): confirm the wire `hash` a peer
/// claims for an item actually matches its payload before the frame is
/// trusted for outbox admission, mesh relay, or ack — otherwise a hostile
/// peer could squat a legitimate hash with different bytes, later served to
/// a third peer via resync. Mirrors each kind's real hashing convention:
/// text canonicalizes via `canon_text` before hashing for valid UTF-8 (same
/// as the sender's `clipboard_dedup_hash`, and the same rule core's own
/// SE-14 dedup recompute in `App::handle`'s `FrameReceivedClipboard` arm
/// uses), falling back to raw bytes for invalid UTF-8 exactly like it does.
/// Images hash the decoded RGBA pixels via `image_rgba_hash`, matching every
/// image sender path (`clipboard_watcher_loop`, `CmdOp::PushImage`) — this
/// is deliberately NOT core's internal dedup-ring hash for images, which
/// hashes the raw wire PNG bytes and was never meant to equal the sender's
/// claimed hash (see the SE-14 comment in `fluxsync-core/src/app.rs`: that
/// recompute exists so a hostile peer can't choose the dedup ring's slot,
/// not to validate what the sender claims). A payload that fails to decode
/// as PNG cannot be verified and is rejected fail-closed.
pub(super) fn verify_content_hash(kind: Kind, payload: &[u8], claimed: [u8; 32]) -> bool {
    let computed = match kind {
        Kind::Image => match decode_png_to_rgba(payload) {
            Some((w, h, rgba)) => image_rgba_hash(w, h, &rgba),
            None => return false,
        },
        _ => match std::str::from_utf8(payload) {
            Ok(text) => DedupRing::hash(fluxsync_core::canon_text(text).as_bytes()).into_bytes(),
            Err(_) => DedupRing::hash(payload).into_bytes(),
        },
    };
    computed == claimed
}
