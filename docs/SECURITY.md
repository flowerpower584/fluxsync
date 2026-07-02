# FluxSync — Security & Threat Model (v0.1)

> One sentence: every byte that leaves the device is encrypted with ChaCha20-Poly1305 inside a Noise IK session keyed to a peer the user explicitly paired. There is no fallback to plaintext, ever.

---

## 1. Cryptographic stack

| Concern              | Algorithm                                      |
|----------------------|------------------------------------------------|
| Key agreement        | X25519 (inside Noise IK)                       |
| AEAD                 | ChaCha20-Poly1305 (RFC 8439)                   |
| Hash                 | BLAKE2s (inside Noise), BLAKE3 (content + fingerprint) |
| Handshake pattern    | `Noise_IK_25519_ChaChaPoly_BLAKE2s` (via `snow`) |
| Long-term identity   | X25519 static keypair, stored in OS keychain   |

`fluxsync-crypto` wraps `snow`. There is no in-house cryptography. The `snow` API call sites are concentrated in one file (`crypto/src/session.rs`) so a future audit has one surface to inspect.

---

## 2. Threat model

### 2.1 Passive LAN attacker (sniff Wi-Fi)

- **Goal**: read the user's clipboard.
- **What they see on the wire**: 12-byte Noise nonce + ChaCha20-Poly1305 ciphertext + 16-byte tag, plus mDNS service advertisements (`_fluxsync._udp.local`, peer name, IP).
- **Mitigation**: end-to-end encryption is mandatory. There is no plaintext fallback; if a frame arrives with a missing or invalid tag the Session is destroyed and the FSM returns to `Discovering`.
- **Residual leakage**: traffic-shape metadata (timing, datagram size, peer IP, peer hostname). Out of scope for v0.1; padding and cover traffic are tracked for v0.2.

### 2.2 Active LAN attacker (MITM, ARP spoof, rogue AP)

- **Goal**: convince A and B that the attacker is the other peer, then forward clipboard items in the clear.
- **Attack path**: respond to the mDNS query with the attacker's address; complete a Noise handshake using a freshly generated identity.
- **Mitigation**: Noise IK requires both sides to know the other's static public key **before** the handshake. During `fluxctl pair --qr` the user transports A's static pubkey out-of-band (camera-scanning a QR on B's phone, or pasting the QR's text payload into `fluxctl pair --accept` on a desktop). Both daemons then derive a 6-word fingerprint (BLAKE3 → BIP-39 wordlist subset, ~66 bits of entropy) and refuse to finalize the pairing unless the user types `y` on both sides. After pairing, the only key authorized to handshake is the one that was confirmed.
- **Why 6 words**: ~66 bits of entropy. Comfortably above the ~50-bit threshold an active LAN attacker would need to brute-force a fingerprint collision in real time, while keeping the verbal compare short enough that a user actually does it. Compared with the 4-word (~44 bit) variant some peers use, the extra two words cost the user ~3 seconds and remove ~22 bits of attacker margin.

### 2.3 Compromised device (lost or stolen phone)

- **Goal**: an attacker with the unlocked phone reads the desktop clipboard.
- **Mitigation**: from the desktop, run `fluxctl revoke <peer-id>`. This removes the peer's static pubkey from the local keyring. The next handshake from the lost phone is rejected at the Noise layer (the "I" in IK has no matching responder key on our side).
- **Limitation**: revocation is local. Each device that has paired with the lost phone must run `revoke` independently. No central revocation list in v0.1 (would defeat zero-knowledge).
- **Anti-replay**: handshakes use fresh ephemerals; a captured handshake cannot be replayed against a revoked entry because the responder's static key has been deleted.

### 2.4 Local malware (untrusted process on the same machine)

- **Goal**: extract the long-term identity private key, then impersonate this device on the LAN.
- **Mitigation**: the private key never appears in a file on disk. It lives in the OS keychain (`keyring` crate, service `fluxsyncd`, account `identity` — see `fluxsyncd::keystore`):
  - **macOS — default**: classic keychain (`kSecClassGenericPassword`) via `keyring` with the OS default ACL, exactly as before FS-062. The creating binary reads silently; any other process hits the system's keychain authorization prompt on first access, but "Always Allow" grants persist and accumulate on the item — a one-time human click gives that tool standing access.
  - **macOS — strict ACL, opt-in (FS-062 / DIR-P2-01, `FLUXSYNC_STRICT_KEYCHAIN=1`)**: the item is instead created with an explicit self-only access-control list (`SecAccessCreate` + `SecTrustedApplicationCreateFromPath`, called directly since neither `keyring` nor `security-framework`'s safe wrapper expose that call), and the ACL is re-asserted on every boot via a single atomic `SecItemUpdate` (no window where the item is missing or partially written) — so accumulated "Always Allow" grants are wiped and a pre-existing default-ACL item is tightened in place. **What this stops**: standing same-UID access ever accumulating — including the common exfiltration path of shelling out to `security find-generic-password -s fluxsyncd -w` after a past "Always Allow". **What this does not stop**: a local process with debugger privileges, or one that convinces the user to authorize it again. **Why opt-in and not the default**: the trusted-application entry pins the exact binary identity. fluxsyncd ships unsigned/self-built today, so every rebuild or update is a *different* binary and macOS re-prompts for the keychain password each time — recurring prompt fatigue, which violates the product's "it just works" requirement (and is exactly the failure mode observed in the field). Strict becomes the default once Developer ID signing (DIR-P4-01) lands, because a signature-anchored trusted-application entry survives app updates without re-prompting. **Why not the modern Data Protection Keychain ACL** (`kSecAttrAccessControl` / `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`): it requires the `keychain-access-groups` entitlement, which needs a Developer ID–signed, provisioned binary. Forcing the entitlement on an unsigned build gets the process killed by AMFI before it ever touches the keychain (verified empirically, not a guess). Post-DIR-P4-01, the DPK is the natural upgrade over what's here.
  - **macOS — switching strict off after using it**: the existing item's ACL stays pinned to the old binary, so the next default-mode boot may prompt once on read. Deny → the daemon exits with the standard actionable keychain error (no prompt loop); Allow → it boots normally. There is no prompt-free way to loosen such an item (modifying the ACL from an untrusted binary is itself an authorized operation), so no automatic loosening is attempted; deleting the `fluxsyncd`/`identity` item in Keychain Access and re-pairing is the manual reset.
  - **Windows — unchanged, documented residual**: Credential Manager (`CredWriteW`/`CredReadW`, Generic credential), encrypted at rest under the logged-in user's DPAPI master key. **What this stops**: disk/backup-level extraction (the blob is useless without the user's Windows login session). **What this does not stop**: Credential Manager has no per-app ACL layer analogous to macOS Keychain — any process running as the same Windows user can call `CredReadW` for this credential and get it back with no prompt. A second, app-specific DPAPI wrap on top would not meaningfully raise the bar (the entropy would have to live somewhere a same-user process can also reach), so none was added — this is an accepted gap, not an oversight.
  - **Linux — unchanged, documented residual**: Secret Service (`org.freedesktop.Secret`, via `keyring`'s `secret-service` backend), collection `default`. **What this stops**: disk-level extraction while the session keyring is locked. **What this does not stop**: the Secret Service model grants access per D-Bus session, not per requesting binary; any process with access to the user's session bus can query it, and the desktop keyring daemons FluxSync targets (GNOME Keyring, KWallet) do not offer a way to pin trust to one binary the way macOS does. Headless boxes (e.g. the Arch `systemd --user` bring-up) are expected to run with `FLUXSYNC_NO_KEYCHAIN=1` instead — this change does not touch that escape hatch.
  - **Android**: Keystore, key alias `fluxsync.identity`, hardware-backed when available.
- **Limitation**: on every platform, a local process running as the same user with debugger privileges, or one that fools the user into a standing "Always allow"/consent grant, can still read the key. macOS in strict mode narrows this (accumulated grants are wiped on every boot); the default mode and Windows/Linux do not, for the platform-specific reasons above. This is the same trust boundary as `ssh-agent` and `gpg-agent` — any tool that hands you cryptographic material on the same UID has this floor. We do not pretend to defend below this line.
- **Anti-tamper**: the IPC socket's permissions are `0600`; only the user's processes can connect.

### 2.5 Future relay (out of v0.1 scope, but designed for)

- **Goal**: a relay operator wants to know what users are syncing.
- **Mitigation when the relay arrives in v0.2**: the relay sees the same opaque ChaCha20 ciphertexts that a passive LAN sniffer would see. It additionally sees `peer_id` source/dest pairs (32-byte hashes that do not commit to the user's identity unless they leak it elsewhere). The relay never holds a key.
- **No telemetry, no logging of cleartext, no metadata sharing**. This is enforced by code: there is no TLS interceptor, no plaintext code path, no JSON metadata leaving the daemon.

---

## 3. Out of scope for v0.1

- **Root-on-host attacker**: if the OS is owned, every defense is moot. Detect, do not defend.
- **Side-channels**: timing, power-analysis, EM emissions. We do not have audited constant-time guarantees beyond what `snow` provides.
- **Quantum-capable adversaries**: X25519 / ChaCha20 are not post-quantum. v2 will rotate to a hybrid suite (X25519 + Kyber768) once `snow` or a successor exposes one.

---

## 4. Trust boundaries (one-line each)

| Boundary                           | Trust direction        | Mechanism                  |
|------------------------------------|------------------------|----------------------------|
| User ↔ daemon                      | mutual                 | UNIX socket / Named Pipe with `0600` permissions |
| Daemon ↔ peer daemon               | mutual, after pairing  | Noise IK with pre-shared static keys |
| Daemon ↔ OS keychain               | daemon trusts OS       | `keyring` crate            |
| Daemon ↔ local clipboard           | daemon trusts OS       | `arboard` crate            |
| Daemon ↔ network interface         | daemon trusts OS       | `mio` / `tokio` UDP        |

---

## 5. Reporting a vulnerability

Email Dethie at the address in `Cargo.toml`, PGP-encrypted if you have the key (fingerprint published in the README). Please give 90 days before public disclosure. There is no bug-bounty program; this is a side project and we will not pay you, but we will credit you in the changelog if you want.

---

## 6. Auditable surface

- All cryptographic calls live under `crates/fluxsync-crypto/src/`. Two files: `identity.rs` (key management) and `session.rs` (Noise + AEAD).
- All key material crosses the FFI boundary as opaque `[u8]`; the Kotlin side never sees plaintext clipboard either, because the daemon is the one that decrypts and writes to the system clipboard.
- `unsafe` is forbidden outside the FFI shim file in `fluxsync-mobile-ffi/src/lib.rs`. Every `unsafe` block carries a `// SAFETY:` comment explaining the invariant.
- `cargo deny` runs in CI to refuse known-vulnerable crates and incompatible licenses.

---

## 7. Implementation status (v0.5.x)

This document describes the **target** security posture. Some items above are not yet wired in the shipping code. Below is the honest delta between design intent (§1–§6) and what `main` actually does today. Each gap has a tracking ID and a planned milestone.

### Done

- Noise IK handshake on every session (`fluxsync-crypto::handshake`, daemon `handshake::run_{initiator,responder}`).
- ChaCha20-Poly1305 AEAD; no plaintext code path; FSM destroys session on tag failure.
- Pinned static-key auth: responder bails with `trusted peer key mismatch` if the remote `s` does not match the stored pubkey (`handshake.rs:131-135`).
- 6-word verbal fingerprint derivation (`fluxsync-crypto::fingerprint`, ~60 bits) — **displayed** in `fluxctl pair` output.
- Peer revocation via `fluxctl revoke <peer-id>` (`fluxctl/main.rs:157`), removes the static pubkey from the local registry.
- mDNS is discovery-only; daemon ignores broadcasts unless the advertised `peer_id` is already trusted.
- **FS-058 (v0.6.0)**: per-source-IP handshake rate-limiter (token bucket, capacity 5, refill ~1/6 s, bounded source table 1024). `PendingSet` capped at 64 with inline + background reaper; `TrustedSet` capped at 256 to bound `peers.json` disk growth; chunk-header reassembly map mirrors the chunk-arm cap=5. Together these close the M2/V1/V2 DoS surface flagged in `FluxSync_DIFFERENTIAL_REVIEW_2026-05-23.md` + `FluxSync_VARIANT_ANALYSIS_2026-05-23.md`.
- **FS-059 (v0.6.0)**: handshake source-IP filter — by default `lan_only_handshakes = true` refuses `HandshakeInit` datagrams from non-local sources (RFC 1918 / loopback / link-local / IPv6 ULA / link-local only).
- **FS-053 partial (v0.6.0)**: identity `secret_bytes()` / `from_secret_bytes()` now return / accept `Zeroizing<[u8; 32]>`; intermediate file-read buffers in `keystore::load_or_create_identity` and `mobile-ffi` decode path are also wrapped, so secret material on the stack/heap is scrubbed on drop. Keychain migration (replacing `~/.fluxsync/identity.bin`) still pending.
- **FS-057 (v0.6.0)**: constant-time review of `ReplayWindow` recorded inline in `session.rs`. All branches are driven by the wire nonce (public); tag check is delegated to `snow` → `chacha20poly1305` which uses `subtle::ConstantTimeEq`. No timing channel on key or plaintext.
- **H1 / M1 (v0.6.0)**: `fingerprint_from_handshake_hash` takes `&[u8; HANDSHAKE_HASH_LEN]` so the length is enforced at the type level; the release-mode silent-empty fallback is gone.
- **M3 (v0.6.0)**: daemon-level tests for `PairConfirm` accept / reject / unknown-peer / bad-hex (`crates/fluxsyncd/tests/pair_confirm.rs`).
- **Lock ordering** (FS-058 L2): the responder takes `trusted` first, then `pending`. Nothing in the codebase takes them in the reverse order. Holding `trusted` while touching `pending` is fine; holding `pending` while taking `trusted` would risk a deadlock — do not introduce that direction.
- **Supply chain** (v0.6.0): `cargo audit` reports 0 vulnerabilities; 2 unmaintained advisories (`bincode 1.3`, `paste 1.0`) come in via `uniffi 0.27` and are tracked for the uniffi 0.28+ bump. `cargo deny check` (advisories + bans + licenses + sources) is green.
- **FS-062 / DIR-P2-01 (macOS, opt-in)**: strict self-only keychain ACL via raw `SecAccessCreate`/`kSecAttrAccess` (`fluxsyncd::keystore::mac_acl`), enabled with `FLUXSYNC_STRICT_KEYCHAIN=1`. In strict mode, a pre-existing looser-ACL item is tightened in place on the next successful load via a single atomic `SecItemUpdate`, with a readback verification after. **Default OFF**: the trusted-app entry pins the exact binary, so unsigned builds re-prompt after every rebuild — strict becomes the default once Developer ID signing (DIR-P4-01) lands. The default boot path performs exactly the pre-FS-062 `keyring` calls. The legacy-file migration additionally gained an unconditional (prompt-neutral) readback-verify step before wiping `identity.bin`. Windows (Credential Manager) and Linux (Secret Service) have no per-app ACL primitive to attach to; documented as an accepted residual in §2.4 rather than given ceremony that wouldn't raise the real bar. See §2.4 for exactly what is and is not protected per platform and mode.

### Pending (security-relevant gaps)

| ID      | Gap                                                                                                                            | Doc claim that overstates reality                          | Target |
|---------|--------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------|--------|
| FS-052  | TOFU pairing window (90 s after `CmdOp::PairShow`) auto-accepts the **first** incoming Noise IK and inserts it into the trusted set. **Partial mitigation landed v0.5.x**: every TOFU acceptance is now recorded in a daemon-side `PendingSet` with a 6-word SAS derived from the Noise handshake hash `h` (not the long-term pubkey, FS-056), and surfaced via `fluxctl pair pending`. The user can compare the SAS verbally and run `fluxctl pair confirm <peer-id> --reject` to immediately revoke + tear down the session. **Still pending for v0.6**: a hard gate that blocks `Msg::Item` processing until the user runs `--accept`, so a drive-by attacker that races into the window cannot exfiltrate clipboard data before the user has a chance to compare the SAS. | §2.2 "refuse to finalize unless the user types `y` on both sides" | v0.6 |
| FS-053  | Long-term X25519 secret is stored in `~/.fluxsync/identity.bin` (mode `0600`), **not** in the OS keychain. No keychain code paths exist yet (`keyring` crate not in `Cargo.toml`). Backup leaks (Time Machine, iCloud, Google Drive), same-user malware, and disk forensics all extract the key trivially. | §1 "stored in OS keychain", §2.4 entire mitigation, §4 boundary table | v0.6 |
| FS-054  | No Noise rekey policy. A long-lived session reuses the same chaining key until process exit. PFS for past sessions still holds (ephemerals are discarded), but compromising a live session unlocks all of its traffic. | implicit in §1                                              | v0.7 |
| FS-055  | No signed audit log of pair / revoke / handshake decisions. Cannot detect "device paired without me knowing". | not yet claimed                                            | v0.7 |
| FS-056  | ✅ **Landed v0.5.x.** The pairing-time SAS exposed by `fluxctl pair pending` is now derived from the Noise handshake hash `h` (`fluxsync_crypto::fingerprint_from_handshake_hash`), not from the long-term pubkey. Each handshake mixes in fresh ephemerals, so a MITM that re-keys against a known pubkey gets different words and the verbal compare detects it. The pubkey-derived fingerprint shown by `fluxctl pair show` is unchanged — it still authenticates the long-term identity carried by the QR. | adjacent to §2.2                                            | done |

### Reading guide

If you are auditing FluxSync at `main` today, read §1–§6 as the **2026 roadmap**, and §7 as the **current state**. The drift is tracked; the doc will collapse back into a single source once FS-052 and FS-053 ship.

For the systematic STRIDE breakdown per attack surface (mDNS, pairing, Noise, transport, keystore, IPC), see [`THREAT-MODEL.md`](./THREAT-MODEL.md).

### Reporting a status mismatch

If you find another claim in §1–§6 that does not match the code on `main`, please file an issue with the heading `docs: status drift — <section>` and quote the line. We would rather under-promise in the doc than have a reviewer find the next gap on their own.
