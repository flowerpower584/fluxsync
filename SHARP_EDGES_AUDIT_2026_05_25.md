# Sharp Edges Audit — FluxSync — 2026-05-25

Surfaces audited: `fluxsync-proto`, `fluxsync-crypto`, `fluxsync-core`, `fluxsync-mobile-ffi`.
Method: Trail of Bits `sharp-edges` workflow (Surface → Edge cases → 3-adversary threat model → validate). Each finding lists current signature, misuse scenario, recommended fix (typestate / newtype / consuming builder / etc).

Severity scale: Critical / High / Medium / Low — same definition as skill reference.

---

## Summary Table

| # | Severity | Location | Pattern | Fix type |
|---|----------|----------|---------|----------|
| SE-01 | High | crypto/session.rs:82 | Bare `&[u8]` for framed ciphertext (no nonce/key/cipher type distinction) | newtype wrappers |
| SE-02 | High | proto/types.rs:20-127 | Wire structs lack `#[serde(deny_unknown_fields)]` | per-struct serde attribute |
| SE-03 | High | crypto/identity.rs:39-43 | `from_secret_bytes(Zeroizing<[u8;32]>)` silently accepts an all-zero key | validating constructor + KeyMaterial newtype |
| SE-04 | High | crypto/handshake.rs:22-65, 67-115 | `Initiator` / `Responder` are non-consuming structs that *can* be reused / partially driven (no typestate guard on `finish`) | already consuming, but no `must_use` and no type-distinguished `Msg1`/`Msg2` |
| SE-05 | High | mobile-ffi/lib.rs:113-148 | `start(identity_secret_b64: String)` — empty string silently regenerates a fresh key (default = lose pairing) | enum `IdentitySource::{Generate, FromBytes(_), Keystore}` |
| SE-06 | Medium | crypto/identity.rs:18 | `#[derive(Clone)]` on `Identity` lets the raw long-term secret be duplicated unrestricted | `clone_for_keystore()` + drop blanket `Clone` |
| SE-07 | Medium | core/state.rs:118-128 | `Config::default()` returns a *usable but mis-labelled* daemon config (`peer_name_self = "this device"`, `build_id = "unknown"`) | drop `Default` impl, require explicit builder |
| SE-08 | Medium | core/clock.rs:35-49 | `LamportClock::observe` saturates silently at `u64::MAX` — replay-style desync if a peer sends `u64::MAX` | typed `LamportTick(NonZeroU64)` + `try_observe` |
| SE-09 | Medium | crypto/fingerprint.rs:44-55 | `words_from_hash_bytes(&[u8])` will panic on `bytes.len() < 8` (private but reachable refactor footgun) | already typed at call sites — make this function `&[u8; HANDSHAKE_HASH_LEN]` only |
| SE-10 | Medium | mobile-ffi/lib.rs:297-312 | `push_item(kind: String, …)` — stringly-typed kind; unknown variant returns error but `"Text"` (uppercase) silently mis-typed | UniFFI enum `FfiPushKind { Text, Image }` |
| SE-11 | Medium | proto/codec.rs:39-50 | `decode(bytes: &[u8]) -> Frame` — caller cannot tell from the type that the frame was validated | return `ValidatedFrame` newtype |
| SE-12 | Low | crypto/session.rs:61-74 | `Session::encrypt(&mut self, &[u8])` — caller can pass a plaintext that aliases another buffer; nonce comes from `sending_nonce()` (auto-increment) — fine, but no AAD parameter exposed | add `encrypt_with_aad` overload, document non-AAD path |
| SE-13 | Low | crypto/session.rs:105 | `transport.set_receiving_nonce(nonce)` is called with attacker-controlled u64 before AEAD check (intentional, but a future refactor could swap order and silently break replay protection) | wrap in `RecvNonce(u64)` newtype + `Session::decrypt_at(nonce: RecvNonce, …)` so call order is encoded in types |
| SE-14 | Low | core/dedup.rs:42-51 | `DedupRing::observe(hash)` — `hash` is `[u8; 32]` but accepted *as raw*; nothing forces it to be BLAKE3 of the payload | `ContentHash` newtype produced only by `DedupRing::hash` |
| SE-15 | Low | mobile-ffi/lib.rs:243-250 | `Drop for FluxsyncHandle` only cancels token, does NOT join daemon thread — silent thread-leak if Kotlin forgets `stop()` (doc says it but type doesn't enforce) | `#[must_use]` + ManuallyDrop pattern, or `stop()` consumes |

---

## Findings (detail)

### SE-01 — Untyped byte slices in crypto API
**File:** `crates/fluxsync-crypto/src/session.rs:61, 82`
**Signatures:**
```rust
pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>
pub fn decrypt(&mut self, framed: &[u8]) -> Result<Vec<u8>, CryptoError>
```
**Misuse:** the same `&[u8]` type is used for plaintext, framed ciphertext, and the Noise handshake messages produced by `Initiator::start` (`Vec<u8>`). A confused caller can wire the handshake `msg1` into `decrypt`, or pipe `encrypt` output back into `encrypt` (double-encrypted, but no type error). Also: `Vec<u8>` returned from `encrypt` does not flag "this contains the explicit nonce prefix; do not concatenate further".
**Fix (newtype):**
```rust
pub struct Plaintext<'a>(&'a [u8]);
pub struct Frame(Vec<u8>);  // nonce(8) || ct || tag(16)
pub struct HandshakeMsg(Vec<u8>);
fn encrypt(&mut self, pt: Plaintext<'_>) -> Result<Frame, CryptoError>;
fn decrypt(&mut self, fr: &Frame)         -> Result<Vec<u8>, CryptoError>;
```
Confused / Lazy developer adversary catches the swap at compile time.

---

### SE-02 — `deny_unknown_fields` missing on wire structs
**File:** `crates/fluxsync-proto/src/types.rs:19-127`
**Signatures:** every `Frame`, `Msg`, `ClipboardItem`, `HandshakeInit`, `HandshakeResp`, `Hello`, `Chunk`, `Nak`, `Ack`, `Heartbeat`, `BatteryStatus`, `PeerInfo` lacks `#[serde(deny_unknown_fields)]`.
**Misuse:** CBOR encoder for a v0.2 peer can sneak extra map keys past a v0.1 decoder without an error. Field-injection is a classic format-confusion vector (CVE-2017-2670 class). The user's own MEMORY.md notes this as required.
**Fix:**
```rust
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frame { … }
```
Apply to every wire struct + every enum variant payload. Add a regression test that decodes a frame with an extra field and asserts `ProtoError::Cbor(_)`.

---

### SE-03 — `Identity::from_secret_bytes` accepts all-zero key
**File:** `crates/fluxsync-crypto/src/identity.rs:38-43`
**Signature:**
```rust
pub fn from_secret_bytes(bytes: Zeroizing<[u8; 32]>) -> Self
```
**Misuse:** `StaticSecret::from([0u8; 32])` is a *valid* but degenerate X25519 secret; the corresponding public key is also predictable. A caller that mistakenly passes `Zeroizing::new([0u8; 32])` (e.g. on keystore-read-error fallback) ships a degenerate identity to the wire — and the peer's authenticator still verifies the handshake because Noise IK only cares about the static key being well-formed.
**Fix (validating ctor + newtype):**
```rust
pub struct SecretKey(Zeroizing<[u8; 32]>);
impl SecretKey {
    pub fn from_bytes(b: Zeroizing<[u8; 32]>) -> Result<Self, CryptoError> {
        if b.ct_eq(&[0u8; 32]).into() { return Err(CryptoError::DegenerateKey); }
        // (also reject the small-subgroup points if you want full RFC 7748 hygiene)
        Ok(Self(b))
    }
}
pub fn from_secret(sk: SecretKey) -> Identity { … }
```

---

### SE-04 — Noise handshake builders lack typestate distinction between msgs
**File:** `crates/fluxsync-crypto/src/handshake.rs:22-115`
**Current:** `Initiator::start -> (Self, Vec<u8>)` then `finish(self, msg2: &[u8])`. `Responder::step` takes the responder identity + `msg1: &[u8]` and returns three things in a tuple.
**Misuse:** `Initiator` is consumed by `finish` (good — typestate by move). But `msg1` and `msg2` are both `&[u8]` / `Vec<u8>`, so a caller can:
  - pass an `msg2` to a fresh `Initiator::start` peer's `finish` even though it was destined for a *different* initiator (no session-binding type),
  - swap the responder's `(buf, remote_static)` tuple positions silently (both are `Vec<u8>` / `[u8;32]`).
Also `Initiator` doesn't carry `#[must_use]`, so `let _ = Initiator::start(...)?;` compiles and silently throws the handshake state away.
**Fix:**
```rust
#[must_use] pub struct Initiator { … }
pub struct HandshakeMsg1(Vec<u8>);
pub struct HandshakeMsg2(Vec<u8>);
pub struct RemoteStatic([u8; 32]);
impl Initiator {
    pub fn start(id: &Identity, peer: &PeerPublic) -> Result<(Self, HandshakeMsg1), _>;
    pub fn finish(self, msg2: HandshakeMsg2) -> Result<Session, _>;
}
impl Responder {
    pub fn step(id: &Identity, msg1: HandshakeMsg1)
        -> Result<(Session, HandshakeMsg2, RemoteStatic), _>;
}
```

---

### SE-05 — Mobile FFI `start(...)` empty-string sentinel for identity
**File:** `crates/fluxsync-mobile-ffi/src/lib.rs:113-149`
**Signature:**
```rust
pub fn start(peer_name: String, ipc_path: String, keystore_dir: String,
             udp_port: u16, identity_secret_b64: String) -> Result<Arc<Self>, FluxError>
```
**Misuse:** all five args are `String` (or `u16`); the function uses three sentinel rules:
  - `identity_secret_b64 == ""` *and* `keystore_dir == ""` → generate fresh identity (silently destroys pairing if caller forgot to read keystore first);
  - `identity_secret_b64 == ""` *and* `keystore_dir != ""` → load-or-create from keystore;
  - `identity_secret_b64 != ""` → decode base64.
A Kotlin caller that mistakenly passes `""` for `identity_secret_b64` *and* `""` for `keystore_dir` (easy to do under the UniFFI 0.27 "no `Option<String>`" workaround you documented) silently re-pairs the device. This is the classic "Lazy Developer" footgun: empty string disables the safer path.
**Fix:** define a UniFFI sum type:
```rust
#[derive(uniffi::Enum)]
pub enum IdentitySource {
    Generate,
    Keystore { dir: String },
    SecretBase64 { secret: String },
}
```
Also `peer_name == ""` is currently accepted — reject it explicitly.

---

### SE-06 — `Identity: Clone` allows unrestricted secret duplication
**File:** `crates/fluxsync-crypto/src/identity.rs:18`
**Current:** `#[derive(Clone)]` over a `StaticSecret`.
**Misuse:** any caller (e.g. anyone holding `&Identity`) can `.clone()` the long-term secret implicitly — no audit trail, no marker for "I produced a second copy of the secret". Trail of Bits' guidance on key material favors *explicit copies for keystore storage only*.
**Fix:** drop `Clone`; expose `Identity::clone_for_keystore(&self) -> KeyMaterial` returning a `Zeroizing<[u8;32]>` newtype. Crypto code uses `&Identity` references only; keystore code is the only place that calls the explicit copy.

---

### SE-07 — `Config::default()` produces a usable but mis-stamped daemon
**File:** `crates/fluxsync-core/src/state.rs:118-128`
**Current:** `Default` impl returns `peer_name_self = "this device"`, `build_id = "unknown"`.
**Misuse:** A test using `Config::default()` that leaks into a `cargo run` path produces a daemon that reports `build_id = "unknown"` to peers — which the `State.build_id` field is precisely *designed to detect as stale*. Any caller forgetting to override these silently ships an unidentifiable build.
**Fix:** drop `Default`; require a `Config::new(peer_name_self: String, build_id: BuildId)` consuming builder, with `BuildId` a newtype that can only be produced from the workspace's `build.rs` (or explicitly via `BuildId::unknown_for_test()` in dev-deps).

---

### SE-08 — `LamportClock::observe` saturates silently
**File:** `crates/fluxsync-core/src/clock.rs:36-44`
**Current:**
```rust
fn observe(&mut self, seen: u64) -> u64 {
    self.counter = self.counter.max(seen).saturating_add(1);
    self.counter
}
```
**Misuse:** an attacker (or buggy peer) that sends a `ClipboardItem { lamport: u64::MAX, … }` permanently pins the local clock at `u64::MAX`. After that, every local `tick()` also saturates → every fresh item carries the same lamport → the ordering primitive collapses to "tie always". Test `lamport_saturates_at_u64_max` *asserts* this behavior, treating the footgun as design.
**Fix:** wrap the value:
```rust
fn observe(&mut self, seen: u64) -> Result<u64, ClockError> {
    let next = self.counter.max(seen).checked_add(1).ok_or(ClockError::Overflow)?;
    self.counter = next;
    Ok(next)
}
```
Or: enforce `seen < REASONABLE_BOUND` (e.g. `1 << 40`, ~35 years of nonstop syncing at 1k ops/s) and drop / log frames that exceed it.

---

### SE-09 — `words_from_hash_bytes(&[u8])` panic-on-misuse
**File:** `crates/fluxsync-crypto/src/fingerprint.rs:44-55`
**Current:** private fn takes `&[u8]`, indexes `bytes[..8]`, will panic if a future refactor calls it with shorter input.
**Misuse:** today the only callers pass a `&[u8;32]` so it's safe; but the *signature* admits any slice. A copy-paste into a new caller (e.g. some `fingerprint_from_short_tag(&[u8; 4])`) panics in production.
**Fix:** change signature to `fn words_from_hash_bytes(bytes: &[u8; HANDSHAKE_HASH_LEN])`. The two public wrappers already have typed array params, so this costs nothing.

---

### SE-10 — `push_item(kind: String, …)` stringly-typed enum over FFI
**File:** `crates/fluxsync-mobile-ffi/src/lib.rs:297-312`
**Current:**
```rust
pub fn push_item(&self, kind: String, bytes: Vec<u8>) -> Result<(), FluxError> {
    match kind.as_str() {
        "image" => …, "text" => …, other => Err(FluxError::Invalid(format!("unknown kind {other}")))
    }
}
```
**Misuse:** Kotlin caller writes `"Text"` / `"TEXT"` / `"img"` → silent runtime error. The wire `Kind` enum (`fluxsync_proto::Kind`) already exists with `rename_all = "lowercase"`; pushing that as a UniFFI enum is straightforward.
**Fix:** define a parallel `#[derive(uniffi::Enum)] pub enum FfiPushKind { Text, Image }` and convert internally. (UniFFI 0.27 supports flat enums.)

---

### SE-11 — `decode` returns the same `Frame` whether validated or not
**File:** `crates/fluxsync-proto/src/codec.rs:39-50`
**Current:** `pub fn decode(bytes: &[u8]) -> Result<Frame, ProtoError>` runs `validate(&frame)` internally but returns the *same `Frame` type* you could also build by hand.
**Misuse:** a future code path that re-enters validation logic (e.g. reassembly merging two `Chunk`s into a `ClipboardItem`) constructs a `Frame { version, msg }` directly without calling `validate`. Downstream code that received it as a `Frame` cannot distinguish "trusted because it came through `decode`" from "untrusted user input".
**Fix:** introduce a `ValidatedFrame(Frame)` newtype; `decode` returns `ValidatedFrame`; consumers that need the inner frame go through `.as_frame()`. Constructor for `ValidatedFrame` is private to this crate.

---

### SE-12 — `Session::encrypt` has no AAD path
**File:** `crates/fluxsync-crypto/src/session.rs:61-74`
**Current:** `encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, _>` — no AAD; the wire frame nonce is on the clear-text prefix but is *not* authenticated against the ciphertext context (Noise + ChaChaPoly does authenticate the nonce as part of its counter, so this is correct in practice — but the API doesn't say so).
**Misuse:** an unaware reviewer assumes they can splice the explicit 8-byte nonce prefix from one frame onto the ciphertext+tag of another. Today this would be caught by the tag, but the API design doesn't telegraph that.
**Fix:** add a doc comment that explains, and / or expose an `encrypt_with_aad(plaintext, aad: &[u8])` method whose absence-of-call clarifies the threat model.

---

### SE-13 — `set_receiving_nonce` ordering footgun
**File:** `crates/fluxsync-crypto/src/session.rs:105`
**Current:**
```rust
self.transport.set_receiving_nonce(nonce);
let n = self.transport.read_message(...)
```
**Misuse:** the current code path is correct (replay-window check, set nonce, AEAD verify, then `replay.accept`). However, the *type signature* of `decrypt` admits any ordering — a future refactor that splits `decrypt` into helper methods, or that loops over multiple candidate nonces, could call `set_receiving_nonce(attacker_value)` and then *forget* to call `is_fresh` first, silently disabling replay protection.
**Fix (typestate):** wrap the nonce in a `FreshNonce` token that can only be produced by `ReplayWindow::is_fresh`, and require `transport.set_receiving_nonce(FreshNonce(n))`.

---

### SE-14 — `DedupRing::observe([u8;32])` accepts arbitrary 32-byte input
**File:** `crates/fluxsync-core/src/dedup.rs:42-51`
**Current:** `pub fn observe(&mut self, hash: [u8; 32]) -> bool`
**Misuse:** the dedup invariant is "key is BLAKE3 of payload". Today this is enforced by convention because `DedupRing::hash(bytes)` is the only constructor; but the type lets a caller pass `[0u8;32]` or `peer.public_key()` or `item.hash` (which is a `ClipboardItem.hash` field — same shape!). If a refactor wires `item.hash` directly (it would compile), the dedup ring de-duplicates by sender-supplied hash, not by content hash — i.e. peer-controlled.
**Fix:** newtype `pub struct ContentHash(pub(crate) [u8; 32]);` produced only by `DedupRing::hash`. `observe(ContentHash)`. Compatible signature for `ClipboardItem.hash` is a *separate* `WireHash` newtype so the two can't be transposed.

---

### SE-15 — `FluxsyncHandle: Drop` does not join the daemon thread
**File:** `crates/fluxsync-mobile-ffi/src/lib.rs:246-250`
**Current:**
```rust
impl Drop for FluxsyncHandle {
    fn drop(&mut self) { self.shutdown.cancel(); }
}
```
**Misuse:** doc says "Kotlin must call `stop` explicitly so the daemon thread joins deterministically" — but Kotlin GC may collect the `Arc` without ever calling `stop`. Drop only fires `cancel()`, never `join()`, leaving the daemon OS thread to wind down on its own — and if `Drop` runs while the runtime is being torn down, the thread is orphaned.
**Fix:** make `stop(self)` consume, returning `()`. UniFFI's `Arc<Self>` flavor makes this awkward, so a softer fix is at minimum: `#[must_use = "Kotlin must call stop() before dropping"]` on the type, plus a `drop` that *also* attempts `try_join` and logs on failure.

---

## Defaults audit (quick)

- `LamportClock::default()` → 0 — safe.
- `DedupRing::default()` → 50-slot — safe.
- `ReplayWindow::default()` → empty + `started = false` — safe.
- `Config::default()` → see SE-07 — unsafe.
- `Identity` — no `Default` impl, must call `generate()` or `from_secret_bytes()` — safe.
- `Session` — no `Default`, builder-only via handshake — safe.

## Zero/empty/null audit

- `identity_secret_b64 == ""` → silently regenerates (SE-05).
- `keystore_dir == ""` → silently skips keystore (SE-05).
- `peer_name == ""` in `FluxsyncHandle::start` — accepted; daemon then advertises empty name.
- `udp_port == 0` — accepted by `start`; tokio binds to ephemeral port silently. Probably benign but worth a comment.
- `set_battery_threshold(0)` → rejected (✓).
- `set_self_battery(level=0)` → accepted (battery 0% is meaningful).
- `Chunk { total: 0 }` → rejected (✓).
- `Nak { missing: [] }` with `want_header: false` → accepted (no-op); consider rejecting as a malformed Nak.

## Adversary recap

| Adversary | Caught | Open |
|-----------|--------|------|
| The Scoundrel (controls peer wire bytes) | proto bound checks ✓, replay window ✓, validated decode ✓ | `Lamport: u64::MAX` saturation (SE-08); peer can pin dedup with crafted hash if a future caller trusts `ClipboardItem.hash` (SE-14) |
| The Lazy Developer (copy-paste, skip docs) | – | SE-05 empty-string defaults, SE-10 stringly kind, SE-07 Config::default |
| The Confused Developer (param swap) | most public APIs typed (`[u8; 32]` for pubkey, peer_id) | SE-01 plaintext vs frame, SE-04 msg1 vs msg2, SE-13 nonce ordering, SE-14 content-hash vs item-hash |

## Recommended priority order

1. **SE-02** (`deny_unknown_fields`) — one-line per struct, blocks format-confusion on v0.1→v0.2 transitions. Already in memory as Phase 2 todo.
2. **SE-05** (mobile FFI identity sentinels) — silently destroys pairing today.
3. **SE-08** (Lamport saturation) — wire-attacker DoS on ordering.
4. **SE-03** (degenerate key acceptance) — quick reject.
5. **SE-14 + SE-01** (newtype pass over crypto + dedup) — coordinated batch since they share `&[u8]` / `[u8;32]` plumbing.
6. **SE-07, SE-06, SE-15** (config + identity + handle ergonomics) — non-urgent.
7. **SE-04, SE-09, SE-11, SE-12, SE-13** (typestate hardening) — defensive against future refactors.
