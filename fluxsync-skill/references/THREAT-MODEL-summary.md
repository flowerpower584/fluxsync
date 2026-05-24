# FluxSync STRIDE — quick-ref summary

Companion to `docs/THREAT-MODEL.md` (full, 150 lines) and `docs/SECURITY.md` (intent).
Scope: `main @ b6f161e` (v0.5.x). Adversary default = active LAN attacker.

## Attack surfaces

| # | Surface | Code | Trust boundary |
|---|---------|------|----------------|
| A | mDNS discovery | `fluxsyncd::discovery` | None — feeds routing only |
| B | Pair-time TOFU | `fluxsyncd::handshake::run_responder`, `CmdOp::PairShow/Accept` | **HIGH — only path into trusted set without long-term key** |
| C | Noise IK handshake | `fluxsync-crypto::handshake`, `fluxsyncd::handshake` | Pinned `static_pub` |
| D | UDP + Noise transport | `fluxsync-crypto::session`, `fluxsyncd::transport`, `fluxsync-core::dedup` | Per-session AEAD |
| E | Identity + peer storage | `fluxsyncd::keystore` (`identity.bin`, `peers.json`) | Same-UID = trusted (today) |
| F | IPC UNIX sock / Pipe | `fluxsyncd::ipc`, `fluxsync-proto::ipc` | mode 0600 / pipe ACL |
| G | Android FFI | `fluxsync-mobile-ffi`, `apps/android/` | Inherits A–F |
| H | Tauri tray | `apps/macos-tray/src-tauri/` | Inherits A–F |

## Threat heatmap per surface

### A — mDNS
- All Mitigated or Accepted residual.
- TXT carries public material only. Spoof collapses at Noise (B/C).
- Open: signed audit log (**FS-055**), mDNS flood regression (**FS-058**).

### B — Pair-time TOFU ⚠️ HIGHEST RISK
- **High**: 90s window, attacker IK with own static → lands in trusted set.
- **Partial mitigation** v0.5.x: `PendingSet` + SAS surfaced via `fluxctl pair pending`, reject via `pair confirm --reject`.
- **Still open**: hard gate blocking `Msg::Item` until `--accept`. → **FS-052** must land before v1.0.
- Signed audit log open → **FS-055**.

### C — Noise IK
- S/T: Mitigated. Verified by `fs052_both_peers_agree_on_handshake_sas` + `tampered_ciphertext_fails_decrypt`.
- Side-channel: validate via `constant-time-analysis` skill → **FS-057**.
- DoS via fake-init storms → **FS-058**.

### D — Transport
- S/T/Replay: Mitigated. 64-frame `ReplayWindow`, Poly1305 fast-fail.
- **Forward secrecy gap**: NO mid-session rekey. Past sessions safe (ephemerals dropped), but live session compromise = all live frames. → **FS-054**.
- Traffic-shape padding deferred → **FS-061**.

### E — Identity & storage ⚠️ HIGH
- **High S/I**: `identity.bin` mode 0600 blocks other UIDs, NOT same-UID malware / backups / forensics.
- Promised OS keychain migration NOT implemented. → **FS-053** (macOS Keychain / Win Credential Manager / Android EncryptedSharedPreferences).
- Android currently rides raw file — same risk amplified.

### F — IPC
- S: Mitigated via mode 0600 (UNIX). Windows pipe ACL audit pending → **FS-060**.
- DoS via huge NDJSON lines: no per-line cap → **FS-059** (cap 64 KiB).
- Same-UID = full control accepted within trust model.

## Open ticket inventory (priorities for v0.6)

| ID | Surface | Action | Target |
|----|---------|--------|--------|
| FS-052 | B | Hard gate `Msg::Item` until user `pair confirm --accept` | v0.6 (BLOCKER for v1.0) |
| FS-053 | E | OS keychain migration (mac/win/android) | v0.6 |
| FS-054 | D | Mid-session Noise rekey | v0.6 |
| FS-055 | All | Signed audit log | v0.6 |
| FS-057 | C | Run `constant-time-analysis` against session.rs | v0.6 |
| FS-058 | A, C | mDNS flood + concurrent fake-init fuzz | v0.6 |
| FS-059 | F | IPC NDJSON line size cap | v0.6 |
| FS-060 | F | Audit Windows Named Pipe ACL | v0.6 |
| FS-061 | D | Padding / cover-traffic policy decision | v0.7 |

## Skill mapping per surface

| Surface | Tier-S skill to run |
|---------|---------------------|
| B, all crypto | `differential-review`, `security-review` |
| C | `constant-time-analysis` |
| E | `zeroize-audit` |
| All | `variant-analysis` after any fix |
| Per release | `rust-dependency-audit`, `supply-chain-risk-auditor` |

## PR gate rule

Before merging any security-affecting PR:
1. Identify touched surface(s) (A–H).
2. Read matching rows above.
3. If diff weakens any "Mitigated" cell → block PR, document.
4. Run matching Tier-S skill from table above.
5. Update `docs/THREAT-MODEL.md` if a new threat surfaces.

## Pairing user flow (FS-052 designed around this)

```
A: fluxctl pair show          # opens 90s window, shows QR
B: scan QR / pair from-uri    # IK to A
both: read 6 SAS words aloud  # MUST match
both: fluxctl pair confirm --accept   # FS-052 gate, blocks Msg::Item until this
```

## Open questions next audit

1. NAT-traversal relay (Surface I) — does it land in v0.7? Needs own threat model.
2. Android TOFU UX — Compose system notification + confirmation sheet (not designed).
3. iOS Secure Enclave — when iOS lands, identity must be non-exportable.
