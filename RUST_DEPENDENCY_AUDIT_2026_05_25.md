# FluxSync — Rust Dependency Audit

- **Date:** 2026-05-25
- **Auditor:** Claude Opus 4.7 + `rust-dependency-audit` skill
- **Scope:** Main workspace (`/Users/dethiekaire/fluxsync`) + Tauri sub-workspace (`apps/macos-tray/src-tauri`)
- **Tools:** `cargo-audit` 0.x (RUSTSEC DB rev 831c50f4, 2026-05-23), `cargo-deny`, `cargo-outdated`, `cargo-vet`, `cargo-geiger` (forbid-only)

---

## 1. Stats

| Metric | Main workspace | macos-tray sub-workspace |
|---|---:|---:|
| Cargo.lock crates | **524** | **565** |
| RUSTSEC vulnerabilities (CVE) | **0** | **0** |
| Unmaintained advisories | 2 | 17 |
| Unsound advisories | 0 | 2 |
| Outdated root deps (semver-incompatible) | 9 | 6 |
| `cargo deny check` status | bans ok, advisories ok (allow-listed), licenses ok, sources ok | **advisories FAILED**, bans ok, **licenses FAILED**, sources ok |
| `cargo vet` initialised? | **No** (`supply-chain/` missing) | No |
| `cargo geiger` unsafe scan | partial — `--forbid-only` on `fluxsync-crypto` shows all crypto-tree crates as `?` (don't `#![forbid(unsafe_code)]`). Expected for `sha2`, `chacha20`, `curve25519-dalek`, `x25519-dalek`, `digest`, etc. Full per-block geiger scan needs warm `target/` — deferred. |

The main workspace is in good shape: 0 CVEs, allow-list deny.toml is tight (12 explicit licenses), only 2 transitive unmaintained warnings (both via `uniffi 0.27.3` — patched in `uniffi 0.31.1`). The sub-workspace pulls Tauri's `wry`/`webkit2gtk` tree, which is the source of all but two of its warnings.

---

## 2. Findings

### P0 — fix before next release

None. **No active CVEs in either workspace.** The unmaintained/unsound advisories below are not exploitable today, but reduce review velocity and block clean CI.

### P1 — fix this sprint

| # | RUSTSEC ID | Crate @ version | Why P1 | Fix |
|---|---|---|---|---|
| P1-A | **RUSTSEC-2025-0141** | `bincode 1.3.3` (main) | Unmaintained; pulled in by `uniffi_macros 0.27.3`. Currently allow-listed in `deny.toml`. cargo-deny warns `advisory-not-detected` — the allow-list is stale because the dep is already on the way out via uniffi upgrade. | Bump `uniffi`/`uniffi-bindgen` 0.27.3 → 0.31.1 (latest, 2026-04-13). uniffi 0.31 drops both `bincode` **and** `paste` dependencies. Then drop the two `ignore` entries from `deny.toml`. |
| P1-B | **RUSTSEC-2024-0436** | `paste 1.0.15` (main) | Unmaintained; pulled via `uniffi_core 0.27.3`. Same allow-list staleness. | Same fix as P1-A — uniffi 0.31.1 removes `paste`. |
| P1-C | **RUSTSEC-2026-0097** | `rand 0.7.3` (tray, unsound) | Soundness hole reachable only with a custom logger calling `rand::rng()`. FluxSync doesn't, but it's transitively in `tauri-utils → kuchikiki → selectors → phf_codegen → phf_generator`. | Wait for Tauri to bump `kuchikiki`/`selectors`. Document accepted-risk in `deny.toml` `[advisories].ignore` with a TODO pointing at the upstream chain. Not user-fixable without forking Tauri. |
| P1-D | **RUSTSEC-2024-0429** | `glib 0.18.5` (tray, unsound) | Unsound trait impl. Linux-only path (gtk-rs GTK3). Mac builds do not exercise it; Linux builds do. | Same chain as RUSTSEC-2026-0097 — pinned by Tauri's webview. Add `ignore` entry until Tauri migrates off GTK3, or restrict Linux release to known-good distros. |
| P1-E | `fluxsync-macos-tray = 0.5.1` unlicensed | tray crate own manifest | `cargo deny check licenses` errors: `error[unlicensed]: fluxsync-macos-tray = 0.5.1 is unlicensed`. The tray `Cargo.toml` has no `license` field. | Add `license = "MIT OR Apache-2.0"` to `apps/macos-tray/src-tauri/Cargo.toml` `[package]`. One-line fix, removes a CI license-check failure. |
| P1-F | No `deny.toml` in tray | tray sub-workspace | The sub-workspace inherits **no policy**; running `cargo deny check` there fails because it falls back to defaults and hits the tray's own missing license + 17 unmaintained warnings as errors. | Copy `/Users/dethiekaire/fluxsync/deny.toml` to `apps/macos-tray/src-tauri/deny.toml`, then add ignores for the gtk-rs / unic-* / fxhash advisories the Tauri tree pulls. |

### P2 — backlog / nice-to-have

| # | RUSTSEC ID | Crate @ version | Notes |
|---|---|---|---|
| P2-A | RUSTSEC-2024-0411…0420 (10 advisories) | `atk`, `atk-sys`, `gdk*`, `gtk`, `gtk-sys`, `gtk3-macros` 0.18.2 (tray) | gtk-rs GTK3 bindings — entire family deprecated upstream. Solution is Tauri moving to GTK4 / WebKitGTK 6. Out of FluxSync's hands. Add bulk `ignore` in tray `deny.toml`. |
| P2-B | RUSTSEC-2025-0075, 0080, 0081, 0098, 0100 | `unic-char-property`, `unic-char-range`, `unic-common`, `unic-ucd-ident`, `unic-ucd-version` (tray) | `rust-unic` org abandoned. Pulled via `urlpattern → tauri-utils`. Same as gtk-rs — wait for Tauri to swap to `icu_properties`/`unicode-ident`. |
| P2-C | RUSTSEC-2025-0057 | `fxhash 0.2.1` (tray) | Pulled via `selectors`. Modern replacement = `rustc-hash`. Upstream `selectors` will need to migrate. Not user-fixable. |
| P2-D | RUSTSEC-2024-0370 | `proc-macro-error 1.0.4` (tray) | Build-time only. Replacement = `proc-macro-error2`. Pulled via a Tauri macro dep. Build-time, no runtime risk. |
| P2-E | Freshness (semver-incompatible) | `dirs 5→6`, `nix 0.28→0.31`, `snow 0.9→0.10`, `mdns-sd 0.19→0.20`, `keyring 3→4`, `rand_core 0.6→0.10`, `uniffi 0.27→0.31`, `android_logger 0.14→0.15`, `hex-literal 0.4→1.1` | None ship a CVE fix today; each upgrade is a small PR with a focused diff. **Caveat: `keyring 4.0.1` may have shifted scope to "CLI + sample lib"** — verify the library API is still complete before bumping (see WebFetch note in §5). |
| P2-F | Freshness (compat in-range) | `serde_json 1.0.149→1.0.150`, `tokio 1.52.1→1.52.3`, `png 0.17.16→0.18.1` (tray build), `tauri 2.10.3→2.11.2`, `tauri-build 2.5.6→2.6.2` | Run `cargo update` to pick up patch versions; `tauri 2.11` minor is a semver bump worth a separate PR. |

---

## 3. License Risks

| Source | Status |
|---|---|
| Main workspace `deny.toml` allow-list | **Tight.** Explicit allow of MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-2/3-Clause, BSL-1.0, Unicode-3.0, Zlib, MPL-2.0, CC0-1.0, ISC, CDLA-Permissive-2.0. No `GPL-*`, no `AGPL-*`, no `LGPL-*` reachable. `cargo deny check licenses` passes. |
| Tray sub-workspace | **Fails** because (a) it has no `deny.toml` and (b) the tray crate itself is missing a `license` field. **No** GPL/AGPL/LGPL infiltration was detected in the lockfile — Tauri ecosystem is uniformly permissive (MIT / Apache-2.0 / MPL-2.0). |
| Tray crate own license | Missing in `Cargo.toml` — `error[unlicensed]` (P1-E). Easy fix. |

**No copyleft contamination.** The dual-license MIT OR Apache-2.0 posture is intact across both workspaces.

---

## 4. Supply Chain Red Flags

- **`cargo vet` not initialised.** No `supply-chain/audits.toml`, no imports from Mozilla / Google / Bytecode Alliance / Embark. For a P2P + crypto app this is the single most cost-effective audit hygiene gap to close. Run `cargo vet init` then `cargo vet trust --all mozilla google bytecodealliance embark-studios` to pull thousands of free reviews and isolate the actually-unreviewed remainder.
- **Crypto path quality is high.** `snow`, `x25519-dalek`, `chacha20poly1305`, `blake3`, `subtle`, `zeroize`, `curve25519-dalek` — all from `dalek-cryptography` / `RustCrypto` / `mcginty`. Active maintainers, well-audited upstream. No typo-squat or fresh/single-maintainer red flags in the security-critical tree.
- **`uniffi 0.27.3` is 4 minor versions behind 0.31.1** — Mozilla project, healthy upstream. Lagging behind on a frequently-updated FFI binding generator is the largest single supply-chain hygiene gap (and the source of both P1 advisories).
- **`mdns-sd 0.19.2 → 0.20.0`** — single-maintainer crate by `keepsimple1`, but well-known in the Rust mDNS space; not a fresh-account or typo-squat. Routine bump.
- **No fresh / suspicious crates** in the dep graph. No `*-rs`, `*-real`, `*-fixed` typo-squat candidates. No deps published < 30 days. Lockfile checksums all from `index.crates.io-1949cf8c6b5b557f` (canonical registry).
- **No yanked versions** in either lockfile (cargo-audit would have flagged them; deny.toml has `yanked = "warn"`).

---

## 5. Recommendations — Actionable

Ordered by ROI. Each is a small, contained PR.

1. **Bump `uniffi` 0.27.3 → 0.31.1** in `crates/fluxsync-mobile-ffi/Cargo.toml` and `crates/uniffi-bindgen/Cargo.toml`. Removes **both** P1 unmaintained advisories (`bincode`, `paste`) at once. After the upgrade, drop both `RUSTSEC-2024-0436` and `RUSTSEC-2025-0141` from `deny.toml` `[advisories].ignore`. Verify Android JNI bindings re-generate correctly (UniFFI 0.28+ changed Kotlin binding shape slightly — re-run `gradlew :app:cargoBuild`).

2. **Add `license = "MIT OR Apache-2.0"` to `apps/macos-tray/src-tauri/Cargo.toml`** under `[package]`. Removes `error[unlicensed]` from `cargo deny check licenses`. 1-line fix.

3. **Create `apps/macos-tray/src-tauri/deny.toml`** mirroring the main one, with `[advisories].ignore` extended for the unfixable gtk-rs / unic-* / fxhash / proc-macro-error / glib / rand 0.7 chain. Gets the sub-workspace to `cargo deny check` clean and unblocks CI parity.

4. **Initialise `cargo vet`:**
   ```
   cargo vet init
   cargo vet trust --all mozilla
   cargo vet trust --all google
   cargo vet trust --all bytecodealliance
   cargo vet trust --all embark-studios
   cargo vet suggest
   ```
   Aim to certify the small crypto-critical surface (`fluxsync-crypto` direct deps: `snow`, `chacha20poly1305`, `x25519-dalek`, `blake3`, `zeroize`, `subtle`) yourself.

5. **`cargo update`** to pick up the in-range patches (`serde_json`, `tokio`, `tauri 2.10.x`). Zero-risk, run once.

6. **`tauri 2.10.3 → 2.11.2` + `tauri-build 2.5.6 → 2.6.2`** in tray. Minor bump; pulls in latest `tauri-utils` which may already drop some of the unmaintained transitives.

7. **Defer `keyring 3 → 4` upgrade.** WebFetch on `crates.io/api/v1/crates/keyring/4.0.1` indicates 4.x changed scope to "Sample code and CLI for the Rust Keyring." Verify the runtime library API surface is still complete (and matches the current `keyring::Entry::new` / `set_password` calls in `crates/fluxsyncd`) before bumping — could be a breaking restructure rather than a regular upgrade. Skip until confirmed.

8. **Defer `snow 0.9 → 0.10`, `nix 0.28 → 0.31`, `dirs 5 → 6`, `mdns-sd 0.19 → 0.20`** — bundle into one "transitive freshness" PR with `cargo test --workspace` verification. None ship a CVE fix; sequencing them avoids one bad bump bisect-blocking the others.

9. **CI-ify the audit.** Wire the four commands into `.github/workflows/audit.yml` on a weekly Monday cron + on PRs that touch `Cargo.toml` / `Cargo.lock`. Suggested matrix runs both workspaces independently.

10. **Optional: `cargo geiger` baseline.** Once `target/` is warm from a normal build, capture `cargo geiger --output-format Json -p fluxsyncd > geiger-baseline.json` and `-p fluxsync-crypto` to lock in current unsafe LoC counts. Re-run on each upgrade PR to catch new unsafe creeping in via deps.

---

## Appendix — Raw advisory inventory

### Main workspace (2 warnings, 0 vulns)
- `RUSTSEC-2025-0141` bincode 1.3.3 — unmaintained — via `uniffi_macros 0.27.3`
- `RUSTSEC-2024-0436` paste 1.0.15 — unmaintained — via `uniffi_core 0.27.3`, `uniffi_bindgen 0.27.3`

### macos-tray sub-workspace (19 warnings, 0 vulns)
- `RUSTSEC-2024-0411…0420` atk, atk-sys, gdk, gdk-sys, gdkwayland-sys, gdkx11, gdkx11-sys, gtk, gtk-sys, gtk3-macros 0.18.2 — unmaintained (gtk-rs GTK3)
- `RUSTSEC-2024-0370` proc-macro-error 1.0.4 — unmaintained
- `RUSTSEC-2024-0429` glib 0.18.5 — unsound
- `RUSTSEC-2025-0057` fxhash 0.2.1 — unmaintained
- `RUSTSEC-2025-0075` unic-char-range 0.9.0 — unmaintained
- `RUSTSEC-2025-0080` unic-common 0.9.0 — unmaintained
- `RUSTSEC-2025-0081` unic-char-property 0.9.0 — unmaintained
- `RUSTSEC-2025-0098` unic-ucd-version 0.9.0 — unmaintained
- `RUSTSEC-2025-0100` unic-ucd-ident 0.9.0 — unmaintained
- `RUSTSEC-2026-0097` rand 0.7.3 — unsound

All 19 are transitive through `tauri 2.10.3` / `wry 0.54.4`. None are reachable through FluxSync's own code paths; they live inside the WebView2 / GTK / urlpattern compilation tree.
