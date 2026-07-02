# FluxSync — STRIDE Threat Model (v0.5.x)

Companion to [`SECURITY.md`](./SECURITY.md). `SECURITY.md` defines the design intent and current implementation status; this file applies STRIDE systematically per attack surface so each ticket (FS-052…FS-058) has an explicit threat it answers, and so a reviewer can see which threats the codebase does **not** yet mitigate.

| | |
|---|---|
| **Methodology**     | STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) |
| **Scope**           | FluxSync `main` @ `b6f161e` (v0.5.x) — `fluxsync-{crypto,core,proto}`, `fluxsyncd`, `fluxctl`, Android FFI, Tauri tray |
| **Assets in scope** | Clipboard payloads (text + PNG), long-term X25519 identity, peer registry (`peers.json`), pairing fingerprint material, Noise handshake hash `h` |
| **Trust boundaries**| `User ↔ daemon` (UNIX/Pipe), `daemon ↔ peer daemon` (Noise/UDP), `daemon ↔ OS keychain`, `daemon ↔ clipboard`, `daemon ↔ LAN` |
| **Adversary**       | Active LAN attacker (default), Same-user local malware (degraded), Lost-device holder |
| **Out of scope**    | Root-on-host, side-channels beyond `snow`, quantum-capable adversary (tracked separately in `SECURITY.md` §3) |

---

## 1. Attack surface inventory

| # | Surface                       | Code locations                                                                  | Primary asset   |
|---|-------------------------------|---------------------------------------------------------------------------------|------------------|
| A | mDNS discovery                | `fluxsyncd::discovery`                                                          | Peer reachability |
| B | Pair-time TOFU                | `fluxsyncd::handshake::run_responder`, `CmdOp::PairShow`/`PairAccept`           | Trusted set     |
| C | Noise IK handshake            | `fluxsync-crypto::handshake`, `fluxsyncd::handshake`                            | Session keys    |
| D | Transport (UDP + Noise)       | `fluxsync-crypto::session`, `fluxsyncd::transport`, `fluxsync-core::dedup`      | Clipboard items |
| E | Identity & peer storage       | `fluxsyncd::keystore` (`identity.bin`, `peers.json`)                            | Long-term keys  |
| F | IPC (UNIX/Pipe + JSON)        | `fluxsyncd::ipc`, `fluxsync-proto::ipc` cmd dispatcher                          | Daemon control  |
| G | Mobile FFI (Android)          | `fluxsync-mobile-ffi`, `apps/android/`                                          | Same as A–F     |
| H | Tauri tray (macOS/Win/Linux)  | `apps/macos-tray/src-tauri/`                                                    | Same as A–F     |

The rest of this document applies STRIDE to A–F. G/H inherit A–F through the FFI / IPC boundaries and are flagged only where they widen a category.

---

## 2. Surface A — mDNS discovery (`_fluxsync._udp.local.`)

| STRIDE | Threat | Severity | Status | Ticket / Note |
|---|---|---|---|---|
| **S**poofing            | Same-LAN attacker broadcasts the legitimate peer's `peer_id`/`static_pub` to advertise its own UDP address. Driver enqueues a Resolved event and the initiator may attempt IK against the attacker's address. | Medium | **Mitigated.** mDNS feeds discovery only; IK responder verifies `remote_static` against `peers.json` (`handshake.rs:131-135`). Attacker without responder's private key cannot complete IK. | — |
| **T**ampering            | Attacker tampers TXT record (`peer_id` / `static_pub`) en route. | Low | **Mitigated.** Discovery validates 32-byte hex (`discovery.rs:125`) before forwarding; malformed entries are dropped. A swapped `static_pub` would simply route IK to the wrong key and fail the trust check. | — |
| **R**epudiation          | Daemon cannot prove which peer initiated a discovery cycle (no signed audit log). | Low | Open. | **FS-055** (signed audit log) |
| **I**nfo disclosure      | mDNS TXT carries `static_pub_hex` (public) + `peer_id` (`BLAKE3(static_pub)`). Both are public by design. Hostname leak via SRV is OS-level (`<instance>.local.`). | Low | Accepted residual. Document explicitly in §2.5 of `SECURITY.md`. | — |
| **D**oS                  | Attacker spams `_fluxsync._udp.local.` with thousands of fake services to saturate the browse channel. | Low | Mitigated by structural validation (each fake costs validation cycles but discovery loop is async and bounded). Worth a regression test. | **FS-058** (mDNS flood test) |
| **E**levation            | None at this layer (no privileged action triggered by discovery alone — IK still gates everything). | — | — | — |

### Why mDNS isn't the trust boundary
The Discord review claim "you trust mDNS identity" applies to many P2P daemons (printer discovery, Chromecast, AirDrop's `_apple-mobdev_._tcp`). FluxSync's design treats mDNS as **best-effort routing**, not authentication — the trust boundary is the pinned `static_pub` enforced by `Responder::step` in `fluxsync-crypto`. Spoof attempts collapse at the Noise layer.

---

## 3. Surface B — Pair-time TOFU (`PairShow` window)

This is the **highest-severity surface** in v0.5.x — the only one where an attacker can land in the trusted set without the long-term key.

| STRIDE | Threat | Severity | Status | Ticket / Note |
|---|---|---|---|---|
| **S**poofing            | During the 90 s window opened by `CmdOp::PairShow`, attacker on LAN reads the responder's `static_pub` from mDNS, runs Noise IK as initiator with attacker's own static keypair, and lands in the responder's `trusted` set (`handshake.rs:148-152`). Attacker becomes a permanent peer until `fluxctl revoke` is run. | **High** | **Partial mitigation v0.5.x**: every TOFU acceptance is now recorded in a `PendingSet` (`handshake.rs`) with the session-binding SAS from the Noise handshake hash. `fluxctl pair pending` surfaces it, `fluxctl pair confirm --reject` revokes. Still pending: a hard gate that blocks `Msg::Item` processing until the user runs `--accept`. | **FS-052** |
| **T**ampering            | Attacker tampers the QR text en route (camera scan from a screen photo). Same effect as spoofing — wrong `static_pub` lands in the initiator's trusted set, IK then fails against the legitimate responder. | Low | Self-detecting (handshake just fails). User reruns `pair show`. | — |
| **R**epudiation          | Daemon records `TOFU: trusting new peer during pairing window` in tracing logs (`handshake.rs:149`) but does not sign or persist an audit trail. A user who later disputes "did I pair with this device?" has no cryptographic evidence. | Medium | Open. | **FS-055** (signed audit log) |
| **I**nfo disclosure      | The QR/URI exposes `pubkey_b32` + the 6-word fingerprint + LAN `IP:port`. All public by design. The `static_pub` of the host is also already on mDNS. No new leakage. | Low | Accepted residual. | — |
| **D**oS                  | Attacker races a flood of `HandshakeInit` packets at the responder during the pair window, hoping at least one wins the TOFU insert before the legitimate peer. | High (paired with the spoofing threat) | Partially answered by the short 90 s window (`PAIRING_WINDOW`) and by surfacing pending entries; full fix is the FS-052 gate. | **FS-052** |
| **E**levation            | A successful TOFU spoof gives the attacker the same privilege as the legitimate peer: read/write clipboard, push image items. There is no further escalation past peer-level. | High (conditional on the spoof above) | Closed once **FS-052** lands. | — |

### Test plan for FS-052
1. Pair two legitimate daemons with `pair show` → `pair from-uri`. ✅
2. Open the 90 s window on `bob` via `pair show`. Inject a hostile `HandshakeInit` from a third host before alice's IK. Confirm `pending` lists both, with **different SAS**.
3. User compares SAS verbally against alice's. Reject the imposter via `pair confirm <id> --reject`. Confirm session is dropped and `peers.json` no longer contains the attacker.
4. Repeat with `--accept` on the legitimate peer; confirm clipboard sync starts.

---

## 4. Surface C — Noise IK handshake (`Noise_IK_25519_ChaChaPoly_BLAKE2s`)

| STRIDE | Threat | Severity | Status | Ticket / Note |
|---|---|---|---|---|
| **S**poofing            | Attacker tries to impersonate a paired peer without its private key. IK requires the initiator to know the responder's `s` and the responder to verify the initiator's `s` against pinned trust; both directions are mutually authenticated by `snow`. | — | **Mitigated.** Verified by `fs052_both_peers_agree_on_handshake_sas` and `tampered_ciphertext_fails_decrypt`. | — |
| **T**ampering            | Attacker flips bits in `msg1` or `msg2` in flight. Noise's MAC over the handshake state detects this; `handshake.rs:84` surfaces it as `CryptoError::Handshake`. | — | Mitigated. | — |
| **R**epudiation          | Same as B: no signed log of which handshake completed. | Medium | Open. | **FS-055** |
| **I**nfo disclosure      | Handshake messages reveal the initiator's `static_pub` (IK property — encrypted to the responder, not the wire). `h` is mixed but never sent. No long-term key leakage on the wire. | — | Accepted property of IK. | — |
| **D**oS                  | Attacker fires malformed `msg1` packets continuously. `Responder::step` allocates ~1 KiB of state per attempt. Single-peer model (one in-flight handshake at a time, `handshake.rs:1510-1525`) limits damage. | Low | Mitigated by the early refusal logic at `handshake.rs:1510` ("session already active, ignoring"). Worth a regression test for >1 concurrent fake initiator. | **FS-058** |
| **E**levation            | Attacker that does complete the handshake (only possible via TOFU spoof, surface B) inherits peer-level privilege. Past the IK layer, IK provides no further mechanism to escalate. | — | Closed once **FS-052** lands. | — |
| **Side-channel**         | Timing leak in Noise primitives. `snow` ↔ `chacha20poly1305` are constant-time in their published audited paths; the `Session::decrypt` replay-window check (`session.rs:116-124`) is structurally constant-time. | Low | Validate with `constant-time-analysis` skill (installed Tier-S). | **FS-057** |

---

## 5. Surface D — Transport (UDP + Noise transport mode)

| STRIDE | Threat | Severity | Status | Ticket / Note |
|---|---|---|---|---|
| **S**poofing            | Attacker forges a UDP datagram claiming to be a Noise frame. `Session::decrypt` requires Poly1305 tag validity → forged frames fail (`session.rs:79-90`). | — | Mitigated. Verified by `tampered_ciphertext_fails_decrypt`. | — |
| **T**ampering            | Same as spoofing: any bit flip invalidates the tag. | — | Mitigated. | — |
| **R**epudiation          | Single Lamport counter + dedup ring (`fluxsync-core::dedup`) prevent silent re-acceptance but do not log to disk. | Low | Open. | **FS-055** |
| **I**nfo disclosure      | Traffic-shape metadata: timing, datagram length, source/destination port. Tracked in `SECURITY.md` §2.1 as residual; padding deferred to v0.2. | Low | Accepted residual. | **FS-061** (padding policy) |
| **D**oS                  | (i) Attacker floods UDP 41889 with random bytes → Poly1305 fails fast, but CPU is burned. (ii) Replay attack: pre-recorded ciphertext re-injection. Mitigated by `ReplayWindow` (`session.rs:106`) — 64-frame sliding bitmap rejects exact replays and stale nonces. | Low | Mitigated for replays. CPU exhaustion possible but bounded by single-peer model. | — |
| **E**levation            | None: every frame is bound to the established `Session`. No path to a different peer's session bytes. | — | — | — |
| **Forward secrecy**       | A future compromise of the long-term identity does **not** decrypt past sessions — Noise IK ephemerals are discarded. A compromise of the current `TransportState` lets the attacker decrypt all frames of the **live session** until rekey. **FluxSync does not currently rekey** mid-session. | Medium | Open. | **FS-054** |

---

## 6. Surface E — Identity & peer storage (`~/.fluxsync/`)

| STRIDE | Threat | Severity | Status | Ticket / Note |
|---|---|---|---|---|
| **S**poofing            | Same-user local malware reads `identity.bin`, exfiltrates the X25519 secret, and impersonates this device on the LAN against every peer that has paired with it. | **High** | **Narrowed on macOS (FS-062 / DIR-P2-01, opt-in):** the identity now lives in the OS keychain (not `identity.bin` — FS-053 landed since this row was last written). With `FLUXSYNC_STRICT_KEYCHAIN=1` a self-only ACL is attached and re-asserted every boot, wiping accumulated "Always Allow" grants. Default mode keeps the OS default ACL (other processes prompt on first read, but standing grants persist) because the strict trusted-app entry pins the exact binary and unsigned builds would re-prompt after every rebuild; strict becomes the default with Developer ID signing (DIR-P4-01). **Open on Windows/Linux**: no per-app ACL primitive exists on either backend to attach the same restriction to; documented as an accepted residual in `SECURITY.md` §2.4. | **FS-062** |
| **T**ampering            | Attacker overwrites `identity.bin` with a different valid X25519 secret → daemon now has a different `peer_id`, all paired peers refuse the next handshake. Effectively a DoS, not an impersonation. | Low | Mitigated structurally: a corrupted-length `identity.bin` refuses to start (`keystore.rs:73`). | — |
| **R**epudiation          | `peers.json` upserts have no signature. A tampered `peers.json` (added attacker pubkey) is indistinguishable from a legitimate pair, post-hoc. | Medium | Open. | **FS-055** |
| **I**nfo disclosure      | (i) Backup leakage: Time Machine, iCloud, Google Drive, `tar`-into-a-share will include `~/.fluxsync/identity.bin` verbatim. (ii) Forensic recovery from disk after delete: trivial. (iii) Android: `EncryptedSharedPreferences` is not yet used — secret rides as a raw file (`apps/android/.../sn/kaolack/fluxsync/`). | **High** | **Mitigated for (i)/(ii) since FS-053** landed (keychain, not a plaintext file, on desktop). (iii) Android still open, tracked separately. Same-UID keychain read: see FS-062 above (macOS narrowed via opt-in strict mode, Windows/Linux open). | **FS-053**, **FS-062** |
| **D**oS                  | Attacker deletes `~/.fluxsync/peers.json` → next daemon start has no trusted set, all peers re-pair (which fails because the window is closed). Equivalent to `fluxctl revoke` for all peers. | Low | Recoverable via re-pair. | — |
| **E**levation            | If an attacker has write to `~/.fluxsync/peers.json` they can insert their own `static_pub_hex` and immediately handshake-join the trusted set without going through TOFU. This is a same-UID attacker → already past the trust boundary documented in `SECURITY.md` §2.4. | High (but conditional on same-UID compromise) | Accepted within stated trust model. The FS-053 keychain move forces the attacker to also defeat the OS keychain ACL, raising the bar. | **FS-053** |

---

## 7. Surface F — IPC (UNIX socket / Named Pipe + NDJSON `CmdOp`)

| STRIDE | Threat | Severity | Status | Ticket / Note |
|---|---|---|---|---|
| **S**poofing            | Another process on the same machine connects to `~/.fluxsync/sock` and issues commands as the user. | Medium | **Mitigated.** Socket is mode `0600` (`SECURITY.md` §4). On Windows the Named Pipe ACL defaults to the creating user; verify on the v0.5.x branch. | **FS-060** (Windows pipe ACL audit) |
| **T**ampering            | A man-in-the-middle on the local socket would have to be the kernel — out of scope. | — | — | — |
| **R**epudiation          | The daemon does not record which IPC client issued which command. | Low | Open. | **FS-055** |
| **I**nfo disclosure      | `CmdOp::Pull` exposes the most recent clipboard item to any IPC client who can connect. The mode-0600 gate is the only defence. | Medium | Mitigated by socket permissions. | — |
| **D**oS                  | NDJSON parser is `serde_json` line-based — a malicious client could open many connections or send arbitrarily large lines. There is no per-line size cap visible at the dispatcher level (`driver.rs` IPC accept loop). | Low | Worth bounding. | **FS-059** (IPC line size cap) |
| **E**levation            | `CmdOp::Revoke` / `CmdOp::Unpair` / `CmdOp::PairAccept` are all available without further authentication — any client with socket access has full control. Same as the trust model: same-UID = trusted. | High (conditional on same-UID) | Accepted within stated trust model. Documented in `SECURITY.md` §4. | — |

---

## 8. New ticket inventory

The threats above introduce four tickets not yet tracked in `SECURITY.md` §7. Adding them here so the doc is the source of truth.

| ID      | Surface | Threat                                                                                          | Target |
|---------|---------|-------------------------------------------------------------------------------------------------|--------|
| FS-057  | C       | Run `constant-time-analysis` skill against `fluxsync-crypto::session` (replay window, AEAD calls). | v0.6   |
| FS-058  | A, C    | Add a fuzz / regression test for mDNS flood + concurrent fake `HandshakeInit` storms.            | v0.6   |
| FS-059  | F       | Enforce a per-line size cap on the IPC NDJSON parser; reject lines > 64 KiB.                    | v0.6   |
| FS-060  | F       | Audit Windows Named Pipe ACL; confirm it defaults to creator-only and document.                  | v0.6   |
| FS-061  | D       | Document padding / cover-traffic policy decision (defer to v0.2 or accept).                      | v0.7   |
| FS-062  | E       | Same-UID silent keychain read (§2.4 Spoofing/Info-disclosure above). **macOS: built, opt-in** (`FLUXSYNC_STRICT_KEYCHAIN=1`) — self-only ACL via `SecAccessCreate`, existing looser-ACL items tightened on next boot. Not default: unsigned builds re-prompt after every rebuild (prompt fatigue); flips to default with Developer ID signing (DIR-P4-01). **Windows/Linux: accepted residual**, documented in `SECURITY.md` §2.4 — neither backend exposes a per-app ACL to attach. | opt-in (macOS); default post-DIR-P4-01 |

---

## 9. How to use this document

- **Before merging a security-affecting PR**: cross-reference the touched surface against the table above. If the diff weakens any "Mitigated" cell, flag it.
- **When auditing**: run the matching Tier-S skill per surface — `constant-time-analysis` for C, `zeroize-audit` for E, `differential-review` against the PR, `variant-analysis` after any bug fix. `rust-dependency-audit` once per release.
- **When pairing**: the user-facing workflow this threat model designs around is `fluxctl pair show` → camera/QR → `fluxctl pair from-uri` → **verbal compare of 6 SAS words on both ends** → `fluxctl pair confirm --accept` on **both** ends (the latter step is the FS-052 gate).

---

## 10. Open questions for the next audit

1. **Do we need a relay (Surface I)** for NAT-traversed clipboard sync? If yes, what is its threat model? `SECURITY.md` §2.5 sketches one; this file needs a parallel section once the relay lands.
2. **Mobile-specific TOFU UX**: how does FS-052 surface on Android (Compose) when the IPC layer is FFI, not a CLI? Likely a system notification + confirmation sheet — not yet designed.
3. **iOS Secure Enclave**: when iOS support arrives, the identity should live in the Secure Enclave (signed, not exportable). Will affect FS-053's keychain abstraction.
