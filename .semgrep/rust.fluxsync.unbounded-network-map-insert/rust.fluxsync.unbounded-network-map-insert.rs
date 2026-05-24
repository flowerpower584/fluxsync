// Test cases for rust.fluxsync.unbounded-network-map-insert.
// Network-handling async fns: run_responder, transport_recv_loop,
// dispatch_inbound_frame, handle_driver_cmd. Any HashMap insert /
// entry().or_insert_with reached from these without a nearby
// `if $MAP.len() ... { ... }` guard is the bug pattern.

use std::collections::HashMap;

struct Peer;
struct Reassembly;
struct Item { hash: [u8; 32] }
struct Chunk { item_id: [u8; 32], total: u32 }

async fn run_responder(
    trusted_guard: &mut HashMap<[u8; 32], Peer>,
    peer_id: [u8; 32],
    new_peer: Peer,
) {
    // ruleid: rust.fluxsync.unbounded-network-map-insert
    trusted_guard.insert(peer_id, new_peer);
}

async fn dispatch_inbound_frame(map: &mut HashMap<[u8; 32], Reassembly>, item: Item) {
    // ruleid: rust.fluxsync.unbounded-network-map-insert
    let _r = map.entry(item.hash).or_insert_with(|| Reassembly);
}

async fn transport_recv_loop(reassembly: &mut HashMap<[u8; 32], Reassembly>, hash: [u8; 32]) {
    // ruleid: rust.fluxsync.unbounded-network-map-insert
    reassembly.insert(hash, Reassembly);
}

async fn run_responder_safe(
    trusted_guard: &mut HashMap<[u8; 32], Peer>,
    peer_id: [u8; 32],
    new_peer: Peer,
) {
    if trusted_guard.len() >= 64 {
        return;
    }
    // ok: rust.fluxsync.unbounded-network-map-insert
    trusted_guard.insert(peer_id, new_peer);
}

async fn dispatch_inbound_frame_safe(map: &mut HashMap<[u8; 32], Reassembly>, c: Chunk) {
    if !map.contains_key(&c.item_id) && map.len() >= 5 {
        return;
    }
    // ok: rust.fluxsync.unbounded-network-map-insert
    let _r = map.entry(c.item_id).or_insert_with(|| Reassembly);
}

async fn handle_local_pair_accept(
    trusted: &mut HashMap<[u8; 32], Peer>,
    peer_id: [u8; 32],
    new_peer: Peer,
) {
    // ok: rust.fluxsync.unbounded-network-map-insert
    // Not in a network-handling fn — local IPC accept is user-driven.
    trusted.insert(peer_id, new_peer);
}

fn sync_helper(map: &mut HashMap<u32, u32>, k: u32, v: u32) {
    // ok: rust.fluxsync.unbounded-network-map-insert
    // Sync helper, not async, not network-fed.
    map.insert(k, v);
}
