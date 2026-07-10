# FluxSync — Security Policy & Threat Model (v1)

> One sentence: every byte that leaves the device is encrypted with ChaCha20-Poly1305 inside a Noise IK session keyed to a peer the user explicitly paired. There is no fallback to plaintext, ever.

---

## Reporting a vulnerability

**Preferred: GitHub Private Vulnerability Reporting.** Go to this repository's **Security** tab → **Report a vulnerability**. This opens a private advisory visible only to the maintainer, supports attachments, and lets us collaborate on a fix before anything becomes public.

**Fallback:** email **maxleboss261@gmail.com** with `[FluxSync security]` in the subject. There is no PGP key published yet — if you need encrypted email, say so in a first, detail-free message and we'll arrange it, or use the GitHub advisory route instead.

Please do not open a public GitHub issue for a security vulnerability.

Include, if you can: affected version or commit, the component (protocol / daemon / a specific client platform / crypto), reproduction steps or a PoC, and your assessment of impact.

There is no bug-bounty program — this is a solo-maintainer side project with no budget to pay out. You'll be credited in `CHANGELOG.md` if you want; say so if you'd rather stay anonymous.

**Disclosure norm:** please allow 90 days before public disclosure so a fix can ship. If that timeline doesn't fit a specific finding, say so — it's negotiable in good faith, not a hard rule.

---

## Supported versions

Only the latest GitHub release gets security fixes. There are no LTS branches and no backports to older tags.

| Version        | Supported |
|----------------|-----------|
| 0.6.2 (latest) | yes       |
| < 0.6.2        | no — upgrade |

With a small user base and a solo maintainer, "supported" means "the version we'll actually go fix something in," not a formal SLA.

---

## Response expectations

This is a solo-maintainer open-source project — no company, no on-call rotation. Best-effort targets:

- **Acknowledgment**: within 7 days of a report reaching either channel above.
- **Triage** (confirm or reject, rough severity): within 14 days of acknowledgment.
- **Fix timeline**: depends on severity and maintainer availability, no fixed SLA. A critical, actively-exploitable issue jumps the queue ahead of everything else.

If you hear nothing after 7 days, follow up — mail delivery and spam filters fail silently sometimes.

---

## Scope

**In scope:**
- The wire protocol (`fluxsync-proto`, see [`PROTOCOL.md`](./PROTOCOL.md)) — framing, encoding, message handling.
- The daemon (`fluxsyncd`) — discovery, pairing/TOFU, handshake, transport, IPC, keystore, clipboard capture/injection.
- The CLI (`fluxctl`).
- The client apps — macOS/Windows/Linux tray (`apps/macos-tray`), the native Linux ksni tray (`apps/linux-tray`), and Android (`apps/android`).
- The cryptography (`fluxsync-crypto`) — Noise IK usage, AEAD, identity-key handling, SAS/fingerprint derivation.
- The supply chain pulled in by the above (see `docs/audits/RUST_DEPENDENCY_AUDIT_*.md` for the last pass).

**Out of scope:**
- Compromise of the underlying OS keychain/credential store itself (macOS Keychain, Windows Credential Manager, Linux Secret Service). FluxSync trusts the OS to protect what it's handed — see **Known accepted risks** below for exactly what FluxSync does and doesn't add on top of that trust.
- Physical access to an unlocked, already-authenticated device.
- Local malware running as the same OS user as FluxSync, for the specific same-UID gaps already disclosed below — these are accepted trust-boundary floors, not bugs, unless you've found a way past a boundary this document claims to hold.
- Denial of service that requires the attacker to already be a trusted, paired peer — that's a reliability bug, file it as a normal issue instead.
- Social engineering of the user (e.g. talking someone into accepting a malicious pairing). The pairing UX's job is to make the SAS/QR comparison unambiguous — report it here if you find a way to make that comparison lie, not if a user could theoretically ignore it.
- The Android `AccessibilityService` doing exactly what it's documented to do — see [`WHY-ACCESSIBILITY.md`](./WHY-ACCESSIBILITY.md). If you find it doing *more* than documented, that's very much in scope.

If you're unsure whether something is in scope, report it anyway — triaging a false positive costs less than missing a real one.

---

## Known accepted risks (as of v0.6.2)

Deliberate trade-offs, not oversights — documented so a report doesn't spend time rediscovering them:

- **Unsigned desktop builds.** macOS builds are not notarized (no Apple Developer ID yet — $99/year, unfunded); Gatekeeper requires right-click → Open on first launch. Windows builds have no EV code-signing certificate, so SmartScreen shows a "Windows protected your PC" warning on first launch. Neither is an integrity failure — the binary is what CI built from this source — but an unsigned-binary warning is exactly what real malware looks like too. Get releases from this repository's GitHub Releases page, not a third-party mirror.
- **macOS keychain ACL is opt-in, not default.** By default the identity key sits in the macOS Keychain with the OS's normal ACL: any process running as the same user gets a one-time authorization prompt on first read, and if the user clicks "Always Allow," that process has standing access from then on. Setting `FLUXSYNC_STRICT_KEYCHAIN=1` attaches a self-only access-control list, re-asserted on every boot so accumulated "Always Allow" grants get wiped. It isn't the default because the strict ACL pins the exact binary identity — every rebuild of an unsigned/self-built FluxSync is a *different* binary, so strict mode would re-prompt for the keychain password after every update. It becomes the default once builds are Developer ID–signed.
- **`FLUXSYNC_NO_KEYCHAIN=1` stores the identity key unencrypted on disk.** This is an explicit escape hatch for headless boxes with no OS keychain / no D-Bus session (see [`HEADLESS-LINUX.md`](./HEADLESS-LINUX.md)). Anyone who can read that user's files — backup, forensic recovery, same-user malware — gets the long-term key. Don't set this on a machine you don't fully trust.
- **Windows Credential Manager and Linux Secret Service have no per-app ACL primitive.** Unlike the macOS strict-mode option above, neither backend lets FluxSync pin trust to its own binary — any process running as the same OS user can read the stored credential with no prompt at all. This is a platform limitation, not something FluxSync chose to skip.
- **Same-UID local malware is out of the defended threat model everywhere.** This is the same trust floor as `ssh-agent` or `gpg-agent`: any process with debugger privileges on your login session, or one that talks you into a standing permission grant, can extract key material FluxSync is handling. We do not defend below this line — see Scope above.
- **No post-quantum cryptography.** X25519 and ChaCha20-Poly1305 are not quantum-resistant; a future quantum-capable adversary that recorded today's traffic could decrypt it later ("harvest now, decrypt later"). No mitigation is planned until the underlying `snow` Noise library (or a successor) exposes an audited hybrid suite.
- **mDNS discovery leaks metadata, not content.** Anyone on the same LAN segment can see that a FluxSync peer exists, its advertised hostname, and its IP. mDNS is reachability only, never authentication — the Noise IK static-key check is the actual trust boundary. If that metadata itself is sensitive on your network, start the daemon with `--disable-mdns` and pair by IP (see [`TROUBLESHOOTING.md`](./TROUBLESHOOTING.md)).
- **No relay / NAT traversal.** FluxSync is LAN-only by design — a privacy property (no server ever sees your traffic), not a gap we're apologizing for. Cross-network sync today means putting both devices on an overlay network yourself (e.g. Tailscale, see the README Quickstart); there is no built-in relay to attack.

The rest of this document is the deeper technical threat model. For the full STRIDE analysis per attack surface, see [`THREAT-MODEL.md`](./THREAT-MODEL.md). **Note on freshness**: that document (and §7 below) were last fully revised against an earlier commit than `HEAD`; recent hardening work (mutual SAS confirmation, an outbox gate, session rekeying, resync-firewall changes — see `CHANGELOG.md`/`git log` for specifics) has landed since and may have closed items the tables below still list as open. Treat status tables as directionally accurate, not a live dashboard — if you find a claim that no longer matches `main`, see "Reporting a status mismatch" at the end of this document.

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
- **Residual leakage**: traffic-shape metadata (timing, datagram size, peer IP, peer hostname). Padding and cover traffic are tracked as a future item (see §3).

### 2.2 Active LAN attacker (MITM, ARP spoof, rogue AP)

- **Goal**: convince A and B that the attacker is the other peer, then forward clipboard items in the clear.
- **Attack path**: respond to the mDNS query with the attacker's address; complete a Noise handshake using a freshly generated identity.
- **Mitigation**: Noise IK requires both sides to know the other's static public key **before** the handshake. During `fluxctl pair --qr` the user transports A's static pubkey out-of-band (camera-scanning a QR on B's phone, or pasting the QR's text payload into `fluxctl pair --accept` on a desktop). Both daemons then derive a 6-word fingerprint (BLAKE3 → BIP-39 wordlist subset, ~66 bits of entropy) and the user compares words on both sides before trusting the pairing. After pairing, the only key authorized to handshake is the one that was confirmed.
- **Why 6 words**: ~66 bits of entropy, comfortably above the ~50-bit threshold an active LAN attacker would need to brute-force a fingerprint collision in real time, while keeping the verbal compare short enough that a user actually does it.

### 2.3 Compromised device (lost or stolen phone)

- **Goal**: an attacker with the unlocked phone reads the desktop clipboard.
- **Mitigation**: from the desktop, run `fluxctl revoke <peer-id>`. This removes the peer's static pubkey from the local keyring. The next handshake from the lost phone is rejected at the Noise layer.
- **Limitation**: revocation is local. Each device that has paired with the lost phone must run `revoke` independently — there is no central revocation list (would defeat the zero-server design).
- **Anti-replay**: handshakes use fresh ephemerals; a captured handshake cannot be replayed against a revoked entry because the responder's static key has been deleted.

### 2.4 Local malware (untrusted process on the same machine)

- **Goal**: extract the long-term identity private key, then impersonate this device on the LAN.
- **Mitigation**: the private key never appears in a plaintext file on disk by default. It lives in the OS keychain (`keyring` crate, service `fluxsyncd`, account `identity`):
  - **macOS — default**: classic keychain (`kSecClassGenericPassword`) with the OS default ACL. The creating binary reads silently; any other process hits the system's authorization prompt on first access, but "Always Allow" grants persist and accumulate on the item.
  - **macOS — strict ACL, opt-in** (`FLUXSYNC_STRICT_KEYCHAIN=1`): the item is created with an explicit self-only access-control list (`SecAccessCreate` + `SecTrustedApplicationCreateFromPath`), re-asserted on every boot via an atomic `SecItemUpdate`. **What this stops**: standing same-UID access accumulating over time. **What this does not stop**: a local process with debugger privileges, or one that convinces the user to authorize it again. **Why opt-in**: the trusted-application entry pins the exact binary; unsigned/self-built binaries change on every rebuild, so strict mode would re-prompt for the keychain password constantly. It becomes the default once Developer ID signing lands.
  - **Windows — unchanged, documented residual**: Credential Manager (`CredWriteW`/`CredReadW`), encrypted at rest under the logged-in user's DPAPI master key. Stops disk/backup-level extraction. Does not stop another process running as the same Windows user from reading it with no prompt — Credential Manager has no per-app ACL layer analogous to macOS Keychain.
  - **Linux — unchanged, documented residual**: Secret Service (`org.freedesktop.Secret`) via `keyring`'s `secret-service` backend. Stops disk-level extraction while the session keyring is locked. Does not stop another process on the same D-Bus session from reading it — the Secret Service model grants access per session, not per requesting binary. Headless boxes are expected to run with `FLUXSYNC_NO_KEYCHAIN=1` instead (see [`HEADLESS-LINUX.md`](./HEADLESS-LINUX.md)).
  - **Android**: Keystore, key alias `fluxsync.identity`, hardware-backed when available.
- **Limitation**: on every platform, a local process running as the same user with debugger privileges, or one that fools the user into a standing consent grant, can still read the key. This is the same trust boundary as `ssh-agent`/`gpg-agent` — we do not defend below this line.
- **Anti-tamper**: the IPC socket's permissions are `0600` (Windows Named Pipe defaults to creator-only); only the user's own processes can connect.

### 2.5 Future relay (out of current scope, but designed for)

- **Goal**: a relay operator wants to know what users are syncing.
- **If a relay ships later**: it would see the same opaque ChaCha20 ciphertexts a passive LAN sniffer sees, plus `peer_id` source/dest pairs (32-byte hashes that don't commit to user identity unless leaked elsewhere). The relay would never hold a key.
- **Today**: there is no relay. No telemetry, no logging of cleartext, no metadata leaving the daemon beyond LAN mDNS and the peer's own IP traffic.

---

## 3. Out of scope for the threat model

(Distinct from the vulnerability-reporting **Scope** section above — this is what the design deliberately does not defend against, not what a report should or shouldn't cover.)

- **Root-on-host attacker**: if the OS is owned, every defense is moot. Detect, do not defend.
- **Side-channels**: timing, power-analysis, EM emissions. There are no audited constant-time guarantees beyond what `snow` provides.
- **Quantum-capable adversaries**: X25519 / ChaCha20 are not post-quantum (see Known accepted risks above).

---

## 4. Trust boundaries (one-line each)

| Boundary                           | Trust direction        | Mechanism                  |
|------------------------------------|------------------------|----------------------------|
| User ↔ daemon                      | mutual                 | UNIX socket / Named Pipe with `0600`-equivalent permissions |
| Daemon ↔ peer daemon               | mutual, after pairing  | Noise IK with pre-shared static keys |
| Daemon ↔ OS keychain               | daemon trusts OS       | `keyring` crate            |
| Daemon ↔ local clipboard           | daemon trusts OS       | `arboard` crate            |
| Daemon ↔ network interface         | daemon trusts OS       | `mio` / `tokio` UDP        |

---

## 5. Auditable surface

- All cryptographic calls live under `crates/fluxsync-crypto/src/`. Two files: `identity.rs` (key management) and `session.rs` (Noise + AEAD).
- All key material crosses the FFI boundary as opaque `[u8]`; the Kotlin side never sees plaintext clipboard either, because the daemon is the one that decrypts and writes to the system clipboard.
- `unsafe` is forbidden outside the FFI shim file in `fluxsync-mobile-ffi/src/lib.rs`. Every `unsafe` block carries a `// SAFETY:` comment explaining the invariant.
- `cargo deny` runs in CI to refuse known-vulnerable crates and incompatible licenses.

---

## 6. Implementation status

This document describes the **target** security posture. Below is the delta between design intent (§1–§5) and what `main` did as of the last full revision of this section. Each gap has a tracking ID and a planned milestone. As flagged above, treat this as a snapshot, not a live dashboard.

### Done (as of last revision)

- Noise IK handshake on every session; ChaCha20-Poly1305 AEAD with no plaintext code path.
- Pinned static-key auth: responder rejects a remote static key that doesn't match the stored pubkey.
- 6-word verbal fingerprint derivation, displayed in `fluxctl pair` output.
- Peer revocation via `fluxctl revoke <peer-id>`.
- mDNS is discovery-only; the daemon ignores broadcasts unless the advertised `peer_id` is already trusted.
- Per-source-IP handshake rate-limiting and bounded pending/trusted-set sizes (DoS surface hardening).
- `lan_only_handshakes` default rejects `HandshakeInit` datagrams from non-local sources.
- Secret material (`Zeroizing<[u8; 32]>`) scrubbed on drop for the identity key and intermediate decode buffers.
- Constant-time review of the replay window and AEAD call sites.
- Long-term identity migrated from a plaintext `identity.bin` to the OS keychain by default (`FLUXSYNC_NO_KEYCHAIN=1` opts back out — see Known accepted risks).
- macOS strict keychain ACL, opt-in (`FLUXSYNC_STRICT_KEYCHAIN=1`) — see §2.4.
- `cargo audit` / `cargo deny` clean in CI.

### Pending / partially landed (security-relevant)

| ID      | Gap                                                                                                                            | Target |
|---------|--------------------------------------------------------------------------------------------------------------------------------|--------|
| FS-052  | TOFU pairing window: work has landed hardening the pending-pair gate and mutual SAS confirmation since this table was last revised (see `git log` for `PairConfirm`, `pending gate`, `outbox gate`) — re-verify against current `main` before relying on the exact mechanism described in §2.2. | tracking closed-out in a future doc pass |
| FS-054  | Noise session rekeying: a time/byte-based rekey policy exists in `fluxsyncd::transport` as of recent commits; the "no rekey" gap this row originally tracked appears addressed — re-verify before citing. | tracking closed-out in a future doc pass |
| FS-055  | No signed audit log of pair / revoke / handshake decisions. Cannot detect "device paired without me knowing." | open |
| FS-060  | Windows Named Pipe ACL: confirm it defaults to creator-only and document formally. | open |
| FS-061  | Padding / cover-traffic policy decision for traffic-shape metadata (§2.1 residual leakage) — not yet decided. | open |

### Reading guide

Read §1–§5 as the intended design. Read §6 as the last known implementation snapshot, already flagged above as potentially behind `HEAD`. For the systematic STRIDE breakdown per attack surface (mDNS, pairing, Noise, transport, keystore, IPC), see [`THREAT-MODEL.md`](./THREAT-MODEL.md) — same freshness caveat applies there.

### Reporting a status mismatch

If you find a claim in this document that doesn't match the code on `main`, file an issue with the heading `docs: status drift — <section>` and quote the line. We'd rather under-promise here than have someone find the next gap on their own.
