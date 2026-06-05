# FluxSync — Variant Analysis (FS-052 hunting)

**Date:** 2026-05-23
**Reviewer:** Claude (variant-analysis skill, TOB)
**Seed:** `FluxSync_DIFFERENTIAL_REVIEW_2026-05-23.md` findings H1 + M2
**Scope:** Workspace `/Users/dethiekaire/fluxsync/crates/` (crypto, daemon, proto, core, ffi)

---

## Seed Patterns

**P1** — `fn(&[u8]) -> T` crypto-input function with `debug_assert!` length check followed by silent fallback return in release builds.
Seed location: `crates/fluxsync-crypto/src/fingerprint.rs:33-37` (H1 from diff review).

**P2** — `HashMap` fed from un-pre-authenticated network input, no insertion cap, cleanup only lazy/interval-based.
Seed location: `crates/fluxsyncd/src/handshake.rs:79-80` (`PendingSet`, M2 from diff review).

---

## P1 Hunt — Untyped Slice Crypto APIs with Silent Fallback

### Search

```bash
rg -n "pub fn.*: &\[u8\][,)].*->" crates/fluxsync-crypto/src/
rg -n "debug_assert" crates/ --type rust -A 3
```

### Matches (4 functions, all reviewed)

| File:Line | Function | Verdict |
|-----------|----------|---------|
| `crypto/session.rs:61` | `encrypt(&[u8])` | OK — plaintext is variable-length by contract |
| `crypto/session.rs:82` | `decrypt(&[u8])` | OK — ciphertext frame is variable-length by contract |
| `crypto/handshake.rs:53` | `Initiator::finish(&[u8])` | OK — Noise msg2 is variable-length (snow handles) |
| `crypto/fingerprint.rs:33` | `fingerprint_from_handshake_hash(&[u8])` | **SEED (H1)** — the only one with a fixed-size contract violated by `&[u8]` |

### `debug_assert!` survey

Only **two** matches workspace-wide:
- `crypto/fingerprint.rs:34` — seed itself
- `crypto/test_util.rs:25` — `debug_assert_eq!` in test setup, no security path

### P1 Verdict

**Zero new variants.** H1 is unique. Other crypto APIs use `&[u8]` because the input length is genuinely variable (Noise messages, AEAD plaintext, AEAD ciphertext). The fingerprint function is the only one with a fixed-size cryptographic primitive (`BLAKE2s-256` output = 32 bytes) that should have been typed as `&[u8; 32]`.

This is good news: the codebase has not yet developed a habit of this anti-pattern. Fixing H1 stops it before it spreads.

---

## P2 Hunt — Unbounded Network-Fed Maps

### Search

```bash
rg -n "HashMap::new\(\)|Mutex::new\(HashMap" crates/
rg -n "\.entry\(.*\)\.or_insert" crates/fluxsyncd/src/
rg -n "len\(\) >|len\(\) >=" crates/fluxsyncd/src/
```

### Map inventory and classification

| Map | File:Line | Insert source | Cap? | Cleanup | Verdict |
|-----|-----------|--------------|------|---------|---------|
| `trusted` | `driver.rs:95` | TOFU handshake (network) + IPC | **NONE** | manual revoke only | **VARIANT V1 — HIGH** |
| `pending_pairs` | `driver.rs:131` | TOFU handshake (network) | **NONE** | lazy on `PairPending` IPC | seed M2 |
| `inflight` | `driver.rs:143` | local outgoing sends | n/a | ack/timeout | OK (local-fed) |
| `reassembly` header arm | `driver.rs:2045` | Inbound `Msg::ClipboardItem` (network) | **NONE** | 60s/5s interval reaper | **VARIANT V2 — MEDIUM** |
| `reassembly` chunk arm | `driver.rs:2098-2100` | Inbound `Msg::Chunk` (network) | `>= 5` | 60s/5s interval reaper | OK |
| `last_written_hashes` | `driver.rs:138` | local clipboard writes | `> 10` pop_front | implicit | OK |
| `IMAGE_CACHE` | `driver.rs:1703` | local image decode | `IMAGE_CACHE_CAP` | implicit | OK |
| `ReplayWindow` | `crypto/session.rs:125` | per-frame nonces | fixed `REPLAY_WINDOW = 64` | sliding | OK |
| `transport peer_addrs` | `transport.rs:156, 281` | inbound packets | bounded transitively by `trusted` | n/a | only OK if V1 fixed |

---

### V1 (HIGH) — `trusted` map unbounded TOFU growth

**File:** `crates/fluxsyncd/src/handshake.rs:180-201`

**Description:**

```rust
trusted_guard.insert(peer_id, new_peer.clone());     // line 180 — no cap
newly_tofu = true;
if let Some(ref dir) = keystore_dir {                // line 186
    let mut stored = crate::keystore::load_peers(dir).unwrap_or_default();
    crate::keystore::upsert_peer(&mut stored, ...);  // PERSISTS to peers.json
    let _ = crate::keystore::save_peers(dir, &stored);
}
```

Strictly worse than the M2 pending-pairs map:

1. **No cap** — same as M2.
2. **Persists to disk** — every TOFU calls `save_peers` to `~/.fluxsync/peers.json`. M2 only ate RAM with a 90s TTL; V1 eats RAM + disk and entries are durable across daemon restarts.
3. **No expiry** — only manual `Revoke` / `PairConfirm --reject` removes an entry. M2 expires in 90s automatically.

**Attack scenario (M2 + V1 chained):**

1. Attacker spams 10 000 `HandshakeInit` during a 90s pairing window.
2. Each completes → 10 000 entries in `pending_pairs` (M2, ~2.5 MB).
3. Each ALSO triggers `trusted_guard.insert` + `save_peers` (V1).
4. `peers.json` grows to ~3 MB and gets rewritten 10 000 times during the burst → disk thrash + I/O storm.
5. After 90s the pending entries expire, but the trusted entries persist.
6. Next daemon start reads 10 000 trusted peers → memory footprint preserved across restarts → permanent damage.

**Recommendation:**

Same fix as M2 plus a hard cap on `trusted` itself:

- Cap `trusted.len()` at e.g. 64.
- When at cap during TOFU, reject the new handshake with `tracing::warn!` rather than evict an existing peer (security: never silently replace a peer the user has confirmed before).
- Batch `save_peers` writes: debounce by 1s or only persist once on shutdown / explicit confirm.
- Reject TOFU entirely if `pending_pairs.len() > N` (back-pressure).

Track as new ticket **FS-062** or fold into FS-058 (mDNS flood scope).

---

### V2 (MEDIUM) — `reassembly` map header arm unbounded

**File:** `crates/fluxsyncd/src/driver.rs:2042-2050`

**Description:**

```rust
Msg::ClipboardItem(item) => {
    if item.payload.is_empty() {
        // Header for a chunked transfer
        let mut map = reassembly.lock().await;
        let r = map.entry(item.hash).or_insert_with(|| Reassembly {     // <-- no cap
            metadata: Some((item.lamport, item.kind, item.sensitive)),
            chunks: Vec::new(),
            ...
        });
        ...
```

The chunk arm just below at `driver.rs:2098-2100` has explicit DoS protection:

```rust
if !map.contains_key(&c.item_id) && map.len() >= 5 {     // chunk arm OK
    // reject
}
```

The header arm has no equivalent guard. A paired attacker (or a TOFU'd attacker via H2 from the diff review) can spam empty-payload `ClipboardItem` frames with random `hash` values to inflate `reassembly` past the chunk-arm's intended cap of 5.

**Attack scenario:**

1. Attacker has a valid session (post-TOFU or post-pair).
2. Sends 10 000 `Msg::ClipboardItem { hash: random, payload: empty, lamport, kind, sensitive }` frames.
3. Each one runs `map.entry(item.hash).or_insert_with(...)` → 10 000 entries in `reassembly`.
4. Each entry is ~80 B + the `Reassembly` struct → low-MB RAM hit.
5. Cleanup tick runs every interval (need to find exact period) and expires entries after 60s total / 5s idle.
6. Sustained at 100 headers/sec, well under expiry rate → map size oscillates but can spike on bursts.

Severity is MEDIUM rather than HIGH because:
- Each entry is small (no payload yet).
- Cleanup is fairly aggressive (5s idle).
- Requires a valid session (post-handshake).

**Recommendation:**

Mirror the chunk-arm's check in the header arm:

```rust
if !map.contains_key(&item.hash) && map.len() >= 5 {
    tracing::warn!(hash = ?&item.hash[..6], "Rejecting header: reassembly map full (DoS protection)");
    return;
}
```

The constant `5` should ideally be lifted to a named const (e.g. `MAX_REASSEMBLY_INFLIGHT`) and reused. Sharp-edges follow-up: at a real DoS protection cap of 5 simultaneous transfers, legitimate users syncing several files in parallel might trip it. Consider 16 or 32.

---

## Audit-trail of "reviewed clean" sites

These are documented so a future audit doesn't re-walk them:

- `inflight` (`driver.rs:613, 1475, 2175, 2186, 2216`) — all `insert`/`remove` paths driven by local outgoing items or ack receipts keyed by an item the attacker can't forge without a session, and the map is drained by acks/timeouts. No unbounded growth surface.
- `last_written_hashes` (`driver.rs:138, 655, 706`) — bounded VecDeque with explicit `pop_front` after `len() > 10`.
- `IMAGE_CACHE` (`driver.rs:1703-1716`) — bounded by `IMAGE_CACHE_CAP` with explicit eviction.
- `ReplayWindow` (`crypto/session.rs:125`) — fixed 64-bit shift register; constant memory.
- `transport peer_addrs` (`transport.rs:156, 281`) — bounded transitively by `trusted` map. Becomes safe once V1 is bounded.
- IPC-driven `trusted` inserts (`driver.rs:1277, 1355`) — `PairAccept` / `PairTrust` from local IPC, user-driven; not network-fed.

---

## Summary

| ID | Severity | Same root cause as | Notes |
|----|----------|--------------------|-------|
| V1 | HIGH | M2 | `trusted` map + `peers.json` grow unbounded under TOFU spam; persists across restart |
| V2 | MEDIUM | M2 | `reassembly` header arm missing the cap that the chunk arm has |
| (P1) | n/a | H1 | No variants — fix H1 stops the anti-pattern before it spreads |

**Update to differential review:** elevate M2 scope to include V1 and V2 in the same FS-058 fix; the responder rate-limit + back-pressure should be a single shared concern across `pending_pairs`, `trusted`, and `reassembly`.

**Suggested next skill:** `semgrep-rule-creator` to codify two FluxSync-specific rules:

1. `rust.fluxsync.untyped-hash-slice` — flag any `pub fn ...(arg: &[u8]) -> [...; N]` in `crates/fluxsync-crypto/` whose body contains `debug_assert!(arg.len() >=`.
2. `rust.fluxsync.unbounded-network-map-insert` — flag `<map>.insert(...)` or `<map>.entry(...).or_insert` inside an `async fn` reachable from `transport_recv_loop` where the surrounding block does not contain `len()` / `capacity` / `retain` / `MAX_` within N lines.

These would catch future regressions on both seed patterns.
