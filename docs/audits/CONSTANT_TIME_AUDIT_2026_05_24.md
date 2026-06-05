# Constant-Time Audit — 2026-05-24

**Scope:**
- `crates/fluxsync-crypto/src/session.rs` (Noise IK transport wrapper, 232 lines)
- `crates/fluxsyncd/src/transport.rs` (UDP transport + session lifecycle, 352 lines)

**Crypto stack (pinned):**
- `snow 0.9` (Noise IK Noise_IK_25519_ChaChaPoly_BLAKE2s)
- `chacha20poly1305 0.10.1` (RustCrypto; Poly1305 tag check via `subtle::ConstantTimeEq`)
- `subtle 2.6.1`

**Method:** manual audit (skill ships docs only, no installed binary analyzer). Asm-level verification deferred to future `cargo +nightly rustc --emit=asm` pass.

## Threat model in scope

Attacker = LAN/remote network. Capabilities:
- Send arbitrary UDP frames to daemon port.
- Replay/relay captured authentic ciphertext.
- Observe packet timing + sizes + ICMP responses.
- Cannot read host memory.

Out of scope: cache timing, microarch side-channels, host-local attackers.

## Headline

**No constant-time violation on secrets.** Tag verification + nonce-keyed AEAD live entirely inside `chacha20poly1305` (RustCrypto), which uses `subtle::ConstantTimeEq`. Both files contain zero secret-dependent branches, zero divisions, zero comparisons on key/plaintext material. All control flow is driven by public wire data (nonce, type byte, ciphertext length, addresses, timestamps).

Two non-CT findings worth fixing for hardening: one weak atomic ordering, one pre-AEAD replay-bitmap probe via error class.

## Findings

### F-CT1 — `last_roam_ms` uses `Ordering::Relaxed`; concurrent recv can bypass roam rate limit — LOW

**Loc:** `transport.rs:269-277`
```rust
let last_roam = self.last_roam_ms.load(Ordering::Relaxed);
if roam_allowed(now, last_roam) {
    ...
    self.last_roam_ms.store(now, Ordering::Relaxed);
}
```

The check is a load + branch + store, not atomic. Two concurrent `recv()` paths can both pass `roam_allowed` reading the same stale `last_roam`, then both update `peer_addr` — effectively two roams in one cooldown window.

Mitigated in practice by the surrounding `peer_addr` mutex (line 266) serializing each recv inside the lock, so concurrent execution requires multi-socket setups (not currently used). Severity stays LOW only as long as the daemon stays single-socket.

**Attack:** LAN attacker replays one authentic ciphertext from address X, then immediately one from address Y. If two recv tasks happen to race (e.g., post-FS-MULTI-SOCKET work), both pass `roam_allowed`, both call `peer_addr.lock()` in arbitrary order, and `last_roam_ms` only gets bumped once. FS-034 rate limit is effectively halved.

**Fix:**
```rust
let last = self.last_roam_ms.load(Ordering::Acquire);
if !roam_allowed(now, last) { /* reject */ }
if self.last_roam_ms
    .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
    .is_err()
{
    // another roam landed; reject ours
    tracing::warn!("roam lost CAS race; rejected");
    return;
}
```
Same `Acquire` upgrade recommended for `last_rx_ms` (line 294) since other tasks read it for liveness checks.

### F-CT2 — Pre-AEAD replay-window check leaks bitmap membership via error class — LOW (info-leak)

**Loc:** `session.rs:98-102` + `144-153`

`is_fresh()` runs *before* `read_message()` AEAD verification. Distinct error messages:

| Frame state | Error returned |
|---|---|
| Stale or replayed nonce | `"replayed or stale frame nonce N"` |
| Fresh nonce, bad tag | `"<snow error>"` (decryption error) |
| Fresh nonce, valid tag | Ok |

Attacker can probe the replay bitmap state without holding any key:
1. Capture a legitimate frame with nonce N.
2. Send a forged frame with the same nonce N but garbage ciphertext.
3. If response/log shows replay error → bitmap bit set, frame N already accepted.
4. If response/log shows AEAD failure → bitmap bit clear, frame N not yet seen (or evicted).

**Severity LOW:**
- Bitmap state is not secret per the FS-057 design comment (lines 125-132).
- No key material leaks.
- Frame nonces are public wire data anyway.
- Practical exploit value: confirming whether the peer received a specific frame, which a passive observer can already infer from acks / heartbeat cadence.

**Why call it out:** the error-message distinction is visible in `tracing` logs. If those logs ship to a shared sink (Sentry, journald, remote syslog), the bitmap-membership oracle becomes accessible to anyone with log access. The FS-057 comment claims "no timing channel leaks from this module" — true for keys, but the bitmap-state oracle is a weaker leak the comment doesn't address.

**Fix (defense-in-depth):** uniform error message at the public boundary.
```rust
fn decrypt(&mut self, framed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // … same parse …
    if !self.replay.is_fresh(nonce) {
        // Unified error so log readers can't distinguish replay from bad tag.
        return Err(CryptoError::Decrypt("decryption failed".into()));
    }
    self.transport.set_receiving_nonce(nonce);
    let mut buf = vec![0u8; ciphertext.len()];
    let n = self.transport
        .read_message(ciphertext, &mut buf)
        .map_err(|_| CryptoError::Decrypt("decryption failed".into()))?;
    // …
}
```
Retain the nonce + class in a `tracing::trace!` line scoped to a debug feature so prod logs stay uniform.

### F-CT3 — `snow::TransportState` post-tag-failure state — INFO

**Loc:** `session.rs:104-109`

`set_receiving_nonce(nonce)` followed by `read_message`. If `read_message` returns Err (bad tag), the next call must not be poisoned. Verified by inspection of snow 0.9 source: `read_message` on `TransportState` does not mutate cipher state on AEAD failure (it operates on a pinned counter, which we set explicitly each frame). Safe for the current snow version.

**Pin enforcement:** add a CI check or `deny.toml` lock that flags any future bump of `snow` past 0.9.x for a re-audit. Snow 1.0 will change `TransportState` API.

### F-CT4 — `handshake_hash` exposed by reference — INFO (intended)

**Loc:** `session.rs:51`

`pub fn handshake_hash(&self) -> &[u8; 32]` returns a borrow of the Noise transcript hash `h`. Per Noise spec, `h` is not secret (it is BLAKE2s of public handshake data). FS-052 uses it as SAS input. Confirmed safe to expose. No CT concern.

### F-CT5 — Nonce in cleartext, branches on it — DOCUMENTED (FS-057)

`session.rs:88` reads attacker-controllable `u64` nonce, then `is_fresh`/`accept` branch on it. Nonce is public per UDP transport design (8-byte prefix per frame). No CT concern. The FS-057 comment correctly states this.

### F-CT6 — Allocations in encrypt/decrypt hot path — INFO

`vec![0u8; …]` at lines 63, 70, 105. Allocation time depends on plaintext size, which is partly observable on the wire (length is leaked anyway). Not a CT issue per se but worth a future `BytesMut` pool for perf on Android.

## Negative checks (operations *not* present)

Verified absent from both files:
- ✗ No division or modulo on secret-derived values (KyberSlash class).
- ✗ No `memcmp` / `==` on secret arrays (only `SocketAddr` and public counters compared).
- ✗ No table lookups indexed by secret bytes (no S-box-style access).
- ✗ No `if secret { … }` branches.
- ✗ No early-exit loops over secret data.
- ✗ No printing of secret material in error messages or `tracing` output.
- ✗ No use of `rand` / `Math.random` style RNG (snow uses OS CSPRNG via `OsRng`).

## Verification gaps

1. **Asm-level confirmation deferred.** All findings come from source reading. A nightly `cargo rustc --release --emit=asm` pass on the two files at `-C opt-level=3` for both `x86_64` and `aarch64` would catch any rustc-introduced secret-dependent branch (Bug-class: LLVM speculative load hardening removed under `--release`). Recommend running this once the FS-053 / VULN-001 commits are tagged.

2. **`snow 0.9` Poly1305 tag-check path not re-audited here.** Trusted via RustCrypto's `subtle::ConstantTimeEq` usage. If snow ever inlines a fallback compare, this audit is invalidated.

3. **Cache-timing for AEAD key schedule** out of scope (handled by `chacha20poly1305`'s vectorized backend; intrinsic to ChaCha design — no S-box).

## Priorities

1. **F-CT1** — fix before any multi-socket work lands. ~10 lines, no design impact.
2. **F-CT2** — uniform error string in `decrypt`. ~5 lines. Low urgency but cheap.
3. **F-CT3** — add `deny.toml` rule to prevent silent `snow` bump.
4. **F-CT6** — perf hot-path optimization for v0.7.
5. **Asm-level pass** — schedule once v0.6.0 is tagged.

## Bottom line

**Crypto path is constant-time on secrets.** No key-leak vectors. Two minor info-leak/race hardening opportunities (F-CT1, F-CT2). Safe to proceed with S21+Mac device test from a side-channel perspective. The differential-review F-001 (peers.json race) remains the actual blocker.
