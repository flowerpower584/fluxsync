# FluxSync — Supply Chain Risk Report

- Scan Date: 2026-05-25
- Project: FluxSync (Rust workspace, 7 crates + Tauri 2 sub-workspace)
- Repositories scanned: workspace `Cargo.lock` (524 transitive crates) + `apps/macos-tray/src-tauri/Cargo.lock`
- Tooling: `cargo audit` (RustSec 1098 advisories), GitHub API for maintainer/recency, manual review of `Cargo.toml` build-scripts & proc-macros
- Threat focus: crypto / wire / FFI / clipboard parsing

---

## 1. Critical path dependencies (crypto + wire)

| Dep | Version | Role | Source |
|-----|---------|------|--------|
| `snow` | 0.9.6 | Noise IK handshake (transport setup) | crates.io |
| `chacha20poly1305` | 0.10.1 | AEAD via RustCrypto (dev-dep only — `snow` provides at runtime) | crates.io |
| `x25519-dalek` | 2.0.1 | DH static + ephemeral, identity keypair | crates.io |
| `curve25519-dalek` | (transitive) | scalar/field math under `x25519-dalek` | crates.io |
| `zeroize` | 1.8.2 | secret scrub on drop | crates.io |
| `subtle` | 2.6.1 | constant-time eq | crates.io |
| `blake3` | 1.8.5 | content hashing (dedup ring + pair SAS path) | crates.io |
| `ciborium` | 0.2.2 | CBOR wire codec (every packet over UDP + IPC) | crates.io |
| `serde` 1.0.228 / `serde_derive` | 1.x | derive scaffolding for wire types | crates.io |
| `mdns-sd` | 0.19.2 | service discovery over multicast UDP | crates.io |
| `arboard` | 3.6.1 | desktop clipboard read/write | crates.io |
| `image` | 0.25.10 / `png` 0.18.1 | image clipboard decode (Android + desktop) | crates.io |
| `tokio` | 1.52.3 | runtime; UDP + IPC sockets | crates.io |
| `keyring` | 3.6.3 | identity secret storage (macOS Keychain / Win CredMan / SecretService) | crates.io |
| `uniffi` | 0.27.3 | Kotlin/Android FFI bindings | crates.io |
| `jni` | 0.22.4 | (transitive via Android side) | crates.io |
| `tauri` | 2.x | tray UI runtime (separate Cargo workspace) | crates.io |
| `sentry` | 0.48.2 | crash telemetry (rustls TLS) | crates.io |

All sources are crates.io registry. **Zero `git = ` deps in either lockfile** — no commit-pin drift surface.

---

## 2. Risk matrix

| Dep | Risk | Reason |
|-----|------|--------|
| `x25519-dalek` 2.0.1 | **HIGH** | Last push to `dalek-cryptography/x25519-dalek` = **2023-09-01** (~32 months stale at scan date). Only 1 open issue but no releases tracking RUSTSEC ecosystem moves. Curve25519-dalek under same org is active (push 2026-05-24) so the maths layer is fine; the `x25519-dalek` wrapper itself is the stale link. Used for *every* identity key and Noise IK ephemeral. |
| `snow` 0.9.6 | **MEDIUM** | Bus-factor: 1 dominant author (`mcginty`) + small contributor set (10 unique). Repo active (push 2026-04-14). It is *the* Noise impl, but a single phished maintainer could push malicious 0.9.7. No security contact in README. **Wire-critical**. |
| `mdns-sd` 0.19.2 | **MEDIUM** | Single maintainer (`keepsimple1`), 202 stars only. Parses untrusted multicast DNS packets — classic high-blast-radius parser. Repo active (push 2026-05-25) but bus factor = 1. |
| `ciborium` 0.2.2 | **MEDIUM** | Owned by `enarx` org (Red Hat confidential-compute group). Repo active but FluxSync runs `ciborium::from_reader` against every untrusted UDP packet and every IPC frame — any deserializer CVE is catastrophic. No alternative is more battle-tested in Rust; risk = inherent feature surface, not maintainer. |
| `arboard` 3.6.1 | **MEDIUM** | 1Password org (good), 937 stars, active. Risk is *feature surface*: it parses image/HTML/RTF blobs out of every OS clipboard backend (Cocoa, Win32, X11, Wayland) — wide native-API attack surface and platform-specific `unsafe`. |
| `keyring` 3.6.3 | **MEDIUM** | Single maintainer (`hwchen`), 731 stars. Wraps OS secret stores (Keychain / CredMan / SecretService). One person can ship a malicious bump that exfils identity.bin on next install. |
| `tauri` 2.x | LOW–MED | tauri-apps org, 107k stars, very active. Standard supply-chain footprint for a desktop-shell framework; large transitive tree (webview, bundler scripts). |
| `uniffi` 0.27.3 | LOW–MED | Mozilla-owned, active. But pulls **`bincode` 1.3.3 (RUSTSEC-2025-0141 unmaintained)** and **`paste` 1.0.15 (RUSTSEC-2024-0436 unmaintained)** — both flagged by `cargo audit` today. Build/codegen path only, not runtime, so blast radius is limited to host machines that compile the mobile crate. |
| `sentry` 0.48.2 | LOW | getsentry org, active. Backtrace + panic features only; no transport over plaintext (`rustls`). |
| `image` 0.25.10 / `png` 0.18.1 | LOW | image-rs org, active, large user base. Decode surface is huge; mitigation = `default-features = false, features = ["png"]` already applied. |
| `chrono` 0.4.44 | LOW | known historical security-process pain but currently maintained. |
| `nix` 0.28/0.29/0.30 | LOW | three versions resolved transitively — cargo-tree noise, not a vuln, but worth pinning eventually. |
| `chacha20poly1305`, `subtle`, `zeroize`, `curve25519-dalek`, `blake3`, `serde`, `tokio` | LOW | RustCrypto / dalek / tokio-rs / serde-rs — large orgs, multi-maintainer, active. |

---

## 3. Build-script + proc-macro deps (compile-time code-exec surface)

Project-level `build.rs`:
- `crates/fluxsyncd/build.rs` — local, in-tree.
- `apps/macos-tray/src-tauri/build.rs` — local, in-tree (writes placeholder PNG icons + invokes `tauri-build`).

Notable third-party `build.rs` / proc-macros in tree:
- `aws-lc-sys` 0.40.0 (transitive via `rustls`/`aws-lc-rs` from `sentry` reqwest feature) — **C build script**, compiles AWS-LC native code at build time. Highest single compile-time-exec footprint in the tree.
- `cc` 1.2.61, `bindgen`-style toolchain — required by `aws-lc-sys`, `blake3` (non-Android), `ring` if pulled, etc.
- `serde_derive`, `thiserror`, `tracing-attributes`, `tokio-macros`, `async-trait`, `clap_derive`, `uniffi_macros`, `tauri-macros` — proc-macros, all from well-known orgs.
- `paste` 1.0.15 — proc-macro pulled by `uniffi_core` → **flagged unmaintained (RUSTSEC-2024-0436)**.
- `tauri-build` — runs at compile time, downloads/embeds front-end assets per `tauri.conf.json`.

Mitigation already in place: `unsafe_code = "forbid"` workspace-wide for FluxSync's own crates; `lto + codegen-units = 1`; `strip = "debuginfo"` only.

---

## 4. Yanked + git deps

- **No `git =` deps** in `Cargo.lock` (root) or `apps/macos-tray/src-tauri/Cargo.lock`. Everything resolves from crates.io registry.
- **No yanked versions** observed in current lockfile (cargo audit did not warn on yank).
- `cargo audit` results (2026-05-25, advisory DB 1098 entries):
  - `RUSTSEC-2025-0141` — `bincode` 1.3.3 unmaintained (under `uniffi_macros`).
  - `RUSTSEC-2024-0436` — `paste` 1.0.15 unmaintained (under `uniffi_core`).
  - 0 vulns, 0 yanked, 2 unmaintained warnings.

---

## 5. Recommendations

Top of the list:
1. **Swap `x25519-dalek` 2.0.1 → use `curve25519-dalek::MontgomeryPoint` directly OR adopt `dalek-cryptography/ed25519-dalek` ↔ `curve25519-dalek` directly for static keys.** The wrapper is stale; `curve25519-dalek` itself is active and audited. Alternatively, vendor `x25519-dalek` at the current commit and pin via `[patch.crates-io]` until upstream resumes releases, with `cargo deny` advisory monitoring.
2. **Pin `snow`, `mdns-sd`, `keyring`, `arboard` exactly** in `Cargo.toml` (use `=0.9.6`, `=0.19.2`, `=3.6.3`, `=3.6.1`) and turn on `cargo deny` `[bans]` `multiple-versions = "deny"` + watchlist alerts (GH watch → releases) so a surprise 0.9.7 / 0.20 doesn't auto-resolve on `cargo update`. These four have bus-factor = 1.
3. **Fuzz the wire path** with `cargo fuzz` targeting `ciborium::from_reader` over the `Frame`/`Packet` types and `mdns-sd` parse against random multicast bytes. Highest blast-radius parsers in the project; both feed pre-auth code paths.
4. **Bump `uniffi` to a version that drops `bincode` 1.3.3 + `paste`** (UniFFI 0.28+ removed `bincode`; check 0.29 for `paste`). Eliminates both `cargo audit` warnings. Build-time only, but eliminates a clean-bill metric.
5. **Adopt `cargo vet` + import Mozilla / Bytecode Alliance / ZF audits** — every dep in the workspace is in one of those import sets. Gives you reproducible verdicts on dep updates, low effort.
6. **Pin `aws-lc-sys` and reconsider whether `sentry` needs `reqwest`+`rustls`+`aws-lc-rs`** vs. the smaller `sentry-core` with a hand-rolled minimal transport. AWS-LC is by far the heaviest C build-script in the tree.
7. **Watchlist (no action yet, monitor only):** `tauri`, `image`/`png`, `nix` (consolidate to single version), `chrono`. All currently fine but high-surface.
8. **Typo-squat scan**: none of the focus dep names have visible collisions on crates.io right now, but add `cargo-supply-chain` to CI to surface name-similar new crates before they're accidentally pulled.

---

## Appendix — Counts

| Risk factor | Deps |
|---|---|
| HIGH | `x25519-dalek` |
| MEDIUM | `snow`, `mdns-sd`, `ciborium`, `arboard`, `keyring` |
| Unmaintained (RUSTSEC) | `bincode` 1.3.3, `paste` 1.0.15 (both via `uniffi`) |
| Git deps | 0 |
| Yanked in lock | 0 |
| Workspace `build.rs` files (in-repo) | 2 |
