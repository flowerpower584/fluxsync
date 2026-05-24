# Differential Security Review — 2026-05-24

**Scope:** commits `ec74d07`, `8842052`, `8c25818` on `main` (FluxSync).
**Goal:** regression check before S21+Mac device test.
**Strategy:** FOCUSED (codebase 59 .rs, 6 changed files, ~1400 LoC delta).

## Triage

| File | LoC Δ | Risk | Notes |
|---|---|---|---|
| `keystore.rs` | +328 | HIGH | FS-053 keychain migration + secure wipe. Already audited (ZA-0001 patched in `2abe56f`). |
| `driver.rs` | +207 | HIGH | VULN-001 V1/V2/V3/V4/V8 persist-or-rollback + FS-052 strict gate. |
| `handshake.rs` | +117 | HIGH | VULN-001 V6 TOFU rollback + V7 reaper rollback. |
| `discovery.rs` | +11 | MEDIUM | `mdns-sd` 0.19 API break, mechanical update. |
| `Cargo.toml` | +8 | LOW | Bump deps; cargo audit clean. |
| `Cargo.lock` | +836 | LOW | Auto. |

## Findings

### F-001 — peers.json write race: stale read-modify-write — HIGH

**Loc:** `handshake.rs:214`, `driver.rs:1385`, `driver.rs:1473`
**Pattern:**
```rust
let mut stored = crate::keystore::load_peers(dir).unwrap_or_default();
// dedup + push
save_peers_with_retry_stored(dir, &stored).await
```

Three call sites (TOFU branch, `PairFromUri`, `PairAccept`) read `peers.json` then write back a modified list. No global lock serializes peers.json access. Reaper (`save_peers_with_retry`) and `DropPeer`/`Unpair`/`Revoke` write from a snapshot of in-memory `TrustedSet` instead. The two write strategies can interleave and clobber each other.

**Attack scenario:**
1. Attacker peer A initiates TOFU. Daemon adds A to `pending` + `trusted`. peers.json = `[A]`.
2. User runs `fluxctl pair confirm --reject A`. `handle_driver_cmd::PairAccept` removes A from `trusted`/`pending`, starts `save_peers_with_retry` (snapshot empty).
3. **Race window** (between in-mem remove and disk write): attacker peer B initiates TOFU. `run_responder` at handshake.rs:214 calls `load_peers()` — disk still shows `[A]` because step 2 hasn't fsynced yet. Stored becomes `[A, B]`.
4. If B's save lands after step 2's save, disk = `[A, B]`. On daemon restart, **A is silently re-trusted** despite the explicit reject.

**Probability:** Low under normal load (sub-ms window) but elevated on (a) slow disk (Android SD, full APFS), (b) ENOSPC retry loop in `save_peers_with_retry` (up to ~700 ms window), (c) concurrent attacker probes.

**Severity:** HIGH because it undoes the exact guarantee VULN-001 was meant to establish (in-mem ↔ disk consistency after trust mutation).

**Fix:** serialize all `peers.json` access through one async mutex held across the load-modify-write transaction. Suggested helper:
```rust
pub(crate) struct PeersDiskLock(tokio::sync::Mutex<()>);
// All callers: let _g = peers_disk_lock.lock().await; load + modify + save.
```
Or convert read-modify-write sites to use `TrustedSet` snapshot (like reaper does) so only one write strategy exists.

### F-002 — `load_peers().unwrap_or_default()` silently nukes peers.json on parse error — MEDIUM

**Loc:** `handshake.rs:214`, `driver.rs:1385`, `driver.rs:1473`

If `peers.json` is corrupted (truncated by crash mid-write before FS-028 fsync landed, partial bit-rot, manual edit), `load_peers` returns `Err`. `unwrap_or_default()` treats the failure as an empty list. The TOFU/Pair handler then pushes its single peer and saves — **entire trust set vanishes from disk**, replaced by just the new peer. Next restart loses every previously paired device.

**Severity:** MEDIUM — requires corruption first, but the recovery path actively destroys data instead of refusing.

**Fix:** on parse error, refuse the TOFU/Pair operation:
```rust
let mut stored = crate::keystore::load_peers(dir)
    .map_err(|e| anyhow!("peers.json unreadable; refusing to overwrite ({e})"))?;
```
For TOFU branch, `anyhow::bail!` so the handshake is refused and the peer re-tries after the user manually inspects the file.

### F-003 — reaper rollback leaves session dropped while trust re-restored — INFO

**Loc:** `handshake.rs:333-356`

When `save_peers_with_retry` fails inside the reaper, the rollback re-inserts into `trusted` + `pending`, but the `transport.drop_session()` has already executed (line ~324). Net state: peer is trusted again, but the live session is gone. Peer must re-handshake.

The code comment explicitly documents this:
> "Session was already dropped (peer must re-handshake) but trust will be retried next reaper tick."

Intentional design tradeoff (session teardown is cheap; reordering would require holding `transport` lock longer). **No action.** Note in case future maintainer questions the asymmetry.

### F-004 — FS-052 strict gate uses non-atomic last_peer_id + pending_pairs read — LOW

**Loc:** `driver.rs:2236-2257` (`dispatch_inbound_frame`)
```rust
let cur_peer = *transport.last_peer_id.lock().await;
if let Some(id) = cur_peer {
    if pending_pairs.lock().await.contains_key(&id) {
        // drop frame
    }
}
```

Two separate lock acquisitions. Between them, user could `--accept` the peer (removing from pending). Result: one frame dropped that should have been allowed. **Not a security issue** (overly defensive direction). User-side sender retries naturally via Plan-C resend-until-ack (FS-018+).

**No action.** Documenting because security review must explain every race observed.

### F-005 — `mdns-sd` 0.19 non-deterministic IP selection on multi-homed hosts — LOW

**Loc:** `discovery.rs:149-156`

```rust
let Some(ip) = info.get_addresses().iter().next().map(|sip| sip.to_ip_addr())
else { continue };
```

`HashSet::iter().next()` returns an arbitrary IP. Same behavior pre-bump (was `HashSet<IpAddr>`). But mdns-sd 0.19.1 added `ScopedIpV4::interface_ids` and subnet-aware selection helpers — calling `.next()` ignores that data. On Mac wifi+ethernet or Android wifi+hotspot, discovery may pick the wrong scope and never reach the peer.

**Severity:** LOW (availability, not security). **Follow-up:** use the 0.19.1 source-IP-matching API once dual-stack hosts ship.

### F-006 — `keystore::save_peers` not atomic at the directory level — INFO

**Loc:** `keystore.rs:307-332`

`save_peers` is correctly atomic for `peers.json` itself (tmp + fsync + rename, FS-028). But the directory entry rename is not fsynced — on power-loss after `rename(2)` but before metadata flush, the new file may be lost on some filesystems (ext4 with `data=writeback`, ZFS without `sync=always`).

**Severity:** INFO. Affects durability under crash, not security. Mitigation costs an extra `fsync(dir_fd)`; deferred unless `FS-CRASH-*` test surfaces a regression.

## Blast Radius

| Change | Direct callers | Transitive impact |
|---|---|---|
| `save_peers_with_retry` (new) | 4 IPC handlers + reaper | All trust mutation paths post-v0.6.0 |
| `save_peers_with_retry_stored` (new) | PairFromUri, PairAccept, TOFU | All pair-insert flows |
| `dispatch_inbound_frame` signature +`pending_pairs` | 1 caller (transport_recv_loop) | All inbound encrypted traffic gated when pending |
| `run_pending_reaper` signature +3 args | 1 spawn site (driver `run`) | Every daemon boot |
| `load_or_create_identity` rewrite | 1 caller (daemon init) | Every boot. Migration is one-shot but runs on every install <v0.6.0. |
| `keystore` `Zeroizing<String>` (ZA-0001) | Internal | Eliminates heap residue of hex secret |

## Test Coverage

- Workspace: **25 suites green** (per commit messages, re-verified inline: `cargo test -p fluxsyncd --lib keystore` → 6/6 pass).
- **Gaps:**
  - F-001 race not testable without injection harness (loom/shuttle or manual fault injection).
  - F-002 corruption case has no test. Recommend: write a 2-byte garbage `peers.json` fixture, assert TOFU/Pair refuses.
  - ZA-0001 zeroization not assert-tested (zeroize is best-effort; testing requires unsafe heap probe).
  - FS-053 keychain integration only runs on Mac/Linux/Windows desktop test envs; CI Linux must have dbus + Secret Service available.

## Regression Check

- No security code removed in 3 commits (greenfield additions + helper extractions).
- `git blame` on touched lines: all new in this 3-commit range or pre-existing untouched.
- No `onlyOwner`/access-control modifiers in this Rust codebase.
- `cargo audit`: 0 CVE (2 unmaintained warnings pre-existing in `deny.toml` allowlist).

## Recommendations (priority order)

1. **Block device test** until F-001 is either fixed or explicitly accepted with a documented "known race, restart-revoke not yet atomic" note in `THREAT-MODEL.md`.
2. **Fix F-002 immediately** (5-line change, no design work needed). Replace `unwrap_or_default()` with explicit error refusal.
3. F-005 → file as follow-up issue, target v0.6.1.
4. F-006 → defer until crash-recovery audit.

## Confidence

- F-001: **confirmed** by code inspection of all 6 write paths. No PoC built; race is structural.
- F-002: **confirmed** — direct read of `unwrap_or_default()` semantics.
- F-003/F-004/F-005: **likely** based on code reading.
- F-006: **likely** based on `fs::rename` semantics; not POSIX-test-verified.

Coverage limitation: did not exhaustively map every `Arc<Mutex<TrustedSet>>` consumer. Possible additional racy reads exist but would only affect availability, not the integrity invariant F-001 targets.
