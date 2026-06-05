# FluxSync — Differential Security Review (FS-052 Phase 1)

**Date:** 2026-05-23
**Reviewer:** Claude (differential-review skill, TOB)
**Scope:** Uncommitted diff against `main @ b6f161e` — Phase 1 FS-052 session-binding SAS + threat model
**Strategy:** FOCUSED (111 .rs files, MEDIUM codebase)

---

## 1. Executive Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 3 |
| LOW | 4 |

**Overall Risk:** MEDIUM
**Recommendation:** CONDITIONAL — fix H1 (type-tighten new SAS API) before commit; H2 + M2 are acknowledged roadmap items.

**Key Metrics:**
- Files analyzed: 14/14 changed (100% HIGH RISK coverage)
- Test coverage gaps: 3 daemon-level integration tests missing
- High blast radius changes: 0 (Session::new = 2 callers, new SAS fn = 1 daemon site)
- Security regressions detected: 0

---

## 2. What Changed

**Base:** `b6f161e` (fix(daemon): Wayland image clipboard sync)
**Head:** Uncommitted working tree

| File | +/- | Risk | Blast |
|------|-----|------|-------|
| `crates/fluxsync-crypto/src/fingerprint.rs` | +71/-1 | HIGH | LOW |
| `crates/fluxsync-crypto/src/handshake.rs` | +14/-3 | HIGH | LOW |
| `crates/fluxsync-crypto/src/session.rs` | +20/-1 | HIGH | LOW |
| `crates/fluxsync-crypto/src/lib.rs` | +1/-1 | LOW | n/a |
| `crates/fluxsync-crypto/tests/handshake.rs` | +43/-1 | tests | n/a |
| `crates/fluxsyncd/src/handshake.rs` | +47/-3 | HIGH | LOW |
| `crates/fluxsyncd/src/driver.rs` | +85/-2 | HIGH | LOW |
| `crates/fluxsyncd/src/cmd.rs` | +35/-0 | MEDIUM | LOW |
| `crates/fluxctl/src/main.rs` | +95/-0 | LOW | n/a |
| `docs/SECURITY.md` | +35/-0 | doc | n/a |
| `docs/THREAT-MODEL.md` | new | doc | n/a |
| `apps/macos-tray/src-tauri/*` | +30/-7 | out-of-scope | n/a |
| `Cargo.lock` | +159/-2 | LOW | n/a |

**Total:** +643 / -23 across 15 files.

---

## 3. Critical Findings

### HIGH H1 — Silent empty-SAS fallback in release builds

**File:** `crates/fluxsync-crypto/src/fingerprint.rs:24-37`
**Commit:** uncommitted
**Blast Radius:** 1 caller today (daemon responder), but public API
**Test Coverage:** PARTIAL — `fs052_short_hash_returns_empty_in_release` exists but only `catch_unwind`s, never asserts the returned array

**Description:**

```rust
pub fn fingerprint_from_handshake_hash(hash: &[u8]) -> [&'static str; FINGERPRINT_WORDS] {
    debug_assert!(hash.len() >= 8, "...");
    if hash.len() < 8 {
        return [""; FINGERPRINT_WORDS];   // <-- silent fail
    }
    words_from_hash_bytes(hash)
}
```

Signature is `&[u8]` (untyped slice) instead of `&[u8; HANDSHAKE_HASH_LEN]` (the const you already export). In release builds, passing a slice shorter than 8 bytes returns six empty strings and the daemon will plumb those through `PendingPair::sas_words` into the IPC response.

**Attack Scenario:**

1. Future refactor introduces a path that derives SAS from a foreign byte source — e.g. a test fixture, a CLI subcommand exposing "preview your SAS", or a wire message that carries a truncated `h` for diagnostics.
2. Caller hands the function 4 bytes by mistake.
3. Release build returns `["", "", "", "", "", ""]`.
4. `fluxctl pair pending` prints `sas : ` (blank). User on the other device sees the real SAS, hits cancel, but the daemon side that produced blanks is still pending. If the SAME blank ever appears on both sides (e.g. both reach the broken path), user sees "empty=empty" and may accept assuming UI glitch.
5. MITM completes silently.

This is exactly the class of footgun the Rust type system is designed to eliminate at zero cost.

**Recommendation:**

```rust
pub fn fingerprint_from_handshake_hash(
    hash: &[u8; HANDSHAKE_HASH_LEN],
) -> [&'static str; FINGERPRINT_WORDS] {
    words_from_hash_bytes(hash)
}
```

Drop the `debug_assert!`, the `if`, and the empty-string fallback. Caller in `crates/fluxsyncd/src/handshake.rs:149` already passes `session.handshake_hash()` which returns `&[u8; 32]` — no migration needed at the call site. Tests that pass `&[1u8; 32]` etc. keep working. The `short` test at fingerprint.rs:96 should be deleted (the case it tests becomes a compile error).

---

### HIGH H2 — TOFU peer can transmit before user confirms (acknowledged)

**File:** `crates/fluxsyncd/src/handshake.rs:160-180`, `crates/fluxsyncd/src/driver.rs:1140+`
**Commit:** uncommitted
**Blast Radius:** entire FSM
**Test Coverage:** NONE

**Description:**

Phase 1 lands SAS visibility (`fluxctl pair pending`) but does NOT gate `Msg::Item` processing on user confirm. A TOFU peer is fully trusted from the moment IK completes; the pending entry is purely informational. `docs/SECURITY.md §7` and `docs/THREAT-MODEL.md §B` correctly mark this as v0.5.x partial mitigation with hard gate scheduled for v0.6.

**Attack Scenario:**

1. Attacker wins mDNS race during the 90s pairing window.
2. IK handshake succeeds; attacker now in `trusted` map.
3. Before user runs `fluxctl pair pending`, attacker sends `Msg::Pull` or waits for the next outbound clipboard event.
4. Daemon processes the message under full trust.
5. User runs `pair confirm --reject` — too late, clipboard already exfiltrated.

**Recommendation:**

Acknowledged on roadmap. To ship Phase 1 safely now, document this explicitly in the commit message and ensure `tracing::warn!` on the TOFU branch is loud enough that operators running with non-default log levels notice. The current warn at handshake.rs:171 already mentions `USER MUST CONFIRM` — good.

Track FS-052 v0.6 work as the path to close this.

---

## 4. Medium Findings

### MEDIUM M1 — API type weakness (sharp-edges)

**File:** `crates/fluxsync-crypto/src/fingerprint.rs:33`

Inconsistent with `pub fn fingerprint(public_key: &[u8; 32])` two functions above. Same library, two crypto-input functions, different type discipline. Future readers will copy the wrong pattern. Same fix as H1 — they're the same defect viewed two ways.

### MEDIUM M2 — Unbounded PendingSet — DoS via handshake spam

**File:** `crates/fluxsyncd/src/handshake.rs:206-218` (insert), `crates/fluxsyncd/src/driver.rs:1146-1150` (cleanup)
**Test Coverage:** NONE

**Description:**

`pending_pairs: HashMap<[u8; 32], PendingPair>` has no cap. Each entry holds `[u8;32] + String + [String;6] + SocketAddr + Instant` ≈ 250 B. Cleanup only runs lazily on `PairPending` IPC call (`g.retain(|_, p| p.expires_at > now)`). No background reaper, no per-source-IP rate limit on the responder spawn at `driver.rs:1613`.

**Attack Scenario:**

1. Attacker on LAN cheap-generates 10 000 Ed25519 keypairs.
2. Sends 10 000 `HandshakeInit` UDP packets to victim's port 41889 during the pairing window.
3. Each responder runs to completion, lands in `trusted` (TOFU) and `pending_pairs`.
4. Memory grows by ~2.5 MB per burst; entries don't reap until either IPC poll or natural 90s expiry.
5. Burst every 80s indefinitely → daemon memory keeps growing or pressure on small-memory devices (older Android, RPi-class hosts) triggers OOM.

Also indirectly inflates `trusted` map and `peers.json` via `save_current_peers` at handshake.rs:158 — disk-side growth on every TOFU.

**Recommendation:**

- Cap `pending_pairs` at e.g. 64 entries; new TOFU evicts oldest by `expires_at`.
- Background reaper task (5s tick) draining expired entries.
- Rate-limit handshake responder per source IP (token bucket, e.g. 5 init/min/IP).

Aligns with FS-058 already on roadmap; this finding adds the specific PendingSet growth vector to that ticket scope.

### MEDIUM M3 — No daemon-level integration tests for FS-052 paths

**File:** `crates/fluxsyncd/tests/` (missing)

Crypto-layer tests are solid (3 fingerprint tests + 2 handshake tests). But the new `PairPending` / `PairConfirm` dispatcher logic in `driver.rs:1140-1209` is untested:

- Accept path: pending entry dropped, trusted entry preserved
- Reject path: session torn down, trusted removed, `save_current_peers` persists removal, `Event::ManualUnpair` fires
- `was_pending` false path: returns error without side effects
- Hex-decode error paths

Phase 2 elevation rule (modified validation + unchanged tests → HIGH RISK) applies. Lowered to MEDIUM because crypto core is well-covered and dispatcher logic is straightforward.

**Recommendation:** add `crates/fluxsyncd/tests/pair_confirm.rs` that spins a daemon with mock transport and exercises the four paths.

---

## 5. Low Findings

### LOW L1 — Incomplete release-mode test

`crates/fluxsync-crypto/src/fingerprint.rs:95-98` — `catch_unwind` only proves "no panic", not the empty-array contract. Becomes moot once H1 is fixed (delete the test).

### LOW L2 — Lock acquisition order not documented

`PairConfirm` in `driver.rs:1183-1187` locks `pending_pairs` then `trusted` (sequentially, no overlap). Responder in `handshake.rs:160-180` locks `trusted` then `pending` (also sequential). No deadlock today because locks are never held simultaneously, but a future refactor could trip. Add a doc comment on `PendingSet` definition stating "if both must be held, lock `trusted` first".

### LOW L3 — IPC `PairConfirm` is not authenticated

Generic UNIX-socket / Named Pipe IPC trust — anyone able to talk to `~/.fluxsync/sock` can confirm/reject pairs. Acknowledged in `THREAT-MODEL.md §F`. Tracked as FS-059 / FS-060.

### LOW L4 — Pending entry stores stale name

`name: entry.name.clone()` at `handshake.rs:213` captures name at TOFU instant. If the peer's `Msg::Hello` lands a real device name before user runs `pair pending`, the listing shows the placeholder "New Peer". UX wart, not security.

---

## 6. What Looked Right

Verified clean:

- Snow `get_handshake_hash()` called post-handshake-complete and pre-`into_transport_mode()` on both initiator and responder (`crypto/handshake.rs:55-62, 106-112`).
- `try_into()` on snow's `Vec<u8>` correctly errors via `CryptoError::Handshake` if length ≠ 32.
- `Session::handshake_hash` field is `[u8; 32]` (type-safe at this layer; H1 is only the public API at the fingerprint module).
- `save_current_peers` (driver.rs:2013) snapshots the post-removal `trusted` map → reject path correctly persists removal to `peers.json`.
- `was_pending` check at `driver.rs:1183` prevents replaying `PairConfirm` against unknown peer ids.
- Test `fs052_handshake_sas_differs_across_sessions` proves fresh ephemerals mix into `h` per session — a captured SAS cannot silence a later pair.
- Test `fs052_both_peers_agree_on_handshake_sas` proves symmetry across peers.
- `fs056_handshake_sas_is_distinct_from_pubkey_fingerprint` proves the two derivations cannot be transposed by accident — addresses FS-056.

---

## 7. Test Coverage Analysis

**Coverage of new logic:**

| Surface | Tests | Verdict |
|---------|-------|---------|
| `fingerprint_from_handshake_hash` (happy path) | 2 unit + 1 integration | OK |
| `Session::handshake_hash` getter | 1 integration (symmetry + fresh-ephemeral) | OK |
| `snapshot_hash` size-mismatch path | NONE | acceptable (snow contract) |
| `PendingSet` insert on newly_tofu | NONE | gap |
| `PendingSet` expiry / cleanup | NONE | gap |
| `CmdOp::PairPending` dispatcher | NONE | gap |
| `CmdOp::PairConfirm` accept path | NONE | gap |
| `CmdOp::PairConfirm` reject path | NONE | gap (HIGHEST priority — touches keystore + dispatch) |

Recommend daemon-level integration test (M3).

---

## 8. Blast Radius Analysis

| Symbol | Callers | Notes |
|--------|---------|-------|
| `Session::new` | 2 (Initiator, Responder) | internal to crypto crate; signature change contained |
| `fingerprint_from_handshake_hash` | 1 (daemon responder) + tests | new public API, single consumer |
| `Session::handshake_hash` | 1 (daemon responder) + tests | leaf getter |
| `PendingSet` | 6 sites in driver + 1 in handshake | confined to daemon |
| `CmdOp::PairPending` / `PairConfirm` | 1 IPC dispatcher + 1 CLI | wire-format additions |

All LOW. No transitive footgun.

---

## 9. Historical Context

`git log -3 --oneline`:

```
b6f161e fix(daemon): Wayland image clipboard sync
bf92964 feat(tray): cross-platform Windows + Linux support + real launch-at-login
e94269f feat: image clipboard sync across proto, daemon, FFI, Android and tray
```

No security-related removals in this diff. All changes are additive (new types, new functions, new CmdOps). The only behavioral change to existing code is `Session::new` signature, which now requires the hash — caller-side update is mechanical.

`docs/SECURITY.md` change is honest: documents Phase 1 as partial mitigation rather than overclaiming.

---

## 10. Recommendations

### Immediate (Blocking — fix before commit)

- [ ] **H1/M1**: Tighten `fingerprint_from_handshake_hash` signature to `&[u8; HANDSHAKE_HASH_LEN]`. Delete `debug_assert`, `if hash.len() < 8` guard, and the `fs052_short_hash_returns_empty_in_release` test.

### Before next release (Tracking)

- [ ] **M3**: Add `crates/fluxsyncd/tests/pair_confirm.rs` covering accept / reject / unknown-peer / bad-hex paths.
- [ ] **M2**: Cap `PendingSet` (suggest 64), background reaper, rate-limit responder spawns per source IP. Roll into FS-058.
- [ ] **L2**: Doc comment on `PendingSet` documenting lock order if both must be held.

### Roadmap (Acknowledged)

- [ ] **H2 / FS-052 v0.6**: Hard-gate `Msg::Item` routing on confirmed-pair status.
- [ ] **L3 / FS-059 + FS-060**: IPC authentication (UNIX socket peer creds on Linux/macOS, Named Pipe ACL on Windows).

---

## 11. Analysis Methodology

**Strategy:** FOCUSED (MEDIUM codebase, 111 .rs files, 14-file diff).

**Scope:**
- HIGH RISK files: 100% read (crypto crate diffs + daemon handshake/driver diffs)
- MEDIUM RISK: 100% read (cmd.rs IPC schema, fluxctl CLI render)
- LOW / out-of-scope: skim only (macos-tray Windows fixes are pre-existing dirty from prior session)
- Reference docs: `docs/THREAT-MODEL.md` STRIDE table consulted for FS-052/056/057/058/059/060/061 cross-references

**Techniques:**
- Full diff read on HIGH RISK files
- Git blame skipped — no removals in this diff (additive change)
- Blast radius via `grep -rn` for new symbols
- Test coverage cross-check against new code paths
- Micro-adversarial scenarios on H1 and M2

**Limitations:**
- Did not run `cargo test --workspace --features fluxsync-crypto/test-util` myself; relied on memory note that prior session reported all 257 tests green
- Did not analyze snow crate source — assumed `get_handshake_hash()` contract per documented behavior
- Did not exercise actual mDNS flood / pairing race on hardware

**Confidence:** HIGH for the FS-052 changes in scope. MEDIUM for downstream impact (e.g., interaction with image-sync chunk reassembly inflight map under pending-pair concurrent load — out of diff scope).

---

## 12. Appendix — Related Memory & Tickets

- `[[fluxsync-security-audit-2026-05-23]]` — session that produced this diff
- `[[fluxsync-security-review-2026-05-22]]` — Discord reviewer feedback that motivated FS-052
- `[[claude-skills-security-stack]]` — installed skills catalogue
- `docs/THREAT-MODEL.md` — STRIDE table for surfaces A–H
- `docs/SECURITY.md §7` — honest doc-claim-vs-reality status table

**Next phase suggestion:** run `constant-time-analysis` skill on `crates/fluxsync-crypto/src/session.rs` ReplayWindow + ChaCha frame decrypt (FS-057), then `zeroize-audit` on `crates/fluxsync-crypto/src/identity.rs` (FS-053 prep).
