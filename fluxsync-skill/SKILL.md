---
name: fluxsync
description: Authoritative rules for working on the FluxSync repo (Rust workspace, Tauri 2 tray, Android Compose+JNI/UniFFI, mDNS+UDP P2P, Noise IK crypto). Load when user says "fluxsync", "lis ça", touches /Users/dethiekaire/fluxsync, edits any crates/fluxsync-*, apps/android, apps/macos-tray, or asks about clipboard sync, peers, pairing, named pipe, NAK, chunk reliability, image sync, brew formula, release pipeline.
license: MIT
---

# FluxSync skill

Battle-tested rules for FluxSync. ALWAYS read before editing. NEVER skip the completion gate.

## 0. Identity

- Repo root: `/Users/dethiekaire/fluxsync`
- License: dual MIT + Apache-2.0
- Stance: zero-server, zero-Pro-tier, donations only (GitHub Sponsors / Ko-fi / crypto)
- Target platforms: macOS (DMG universal), Windows (NSIS, x64 + ARM64), Linux (deb/AppImage), Android (NDK arm64-v8a only, namespace `sn.kaolack.fluxsync`)
- Repo URL canonical: `https://github.com/flowerpower584/fluxsync` (confirmed in CHANGELOG v0.5.1 fix). Brew tap: `flowerpower584/homebrew-fluxsync`. Older memory mentions `dethie/fluxsync` — stale, do NOT use.

## 1. Workspace map

```
crates/
  fluxsync-proto/        # CBOR Frame / Msg wire format
  fluxsync-crypto/       # Noise IK + ChaCha20-Poly1305, identity, SAS wordlist
  fluxsync-core/         # pure FSM, dedup, Lamport clock, classifier (NO IO)
  fluxsyncd/             # daemon: tokio + UDP + IPC + mDNS (mdns-sd)
                         # modules: cmd config discovery driver handshake ipc keystore logs transport wall
  fluxctl/               # CLI, IPC client (UNIX socket / Win Named Pipe)
  fluxsync-mobile-ffi/   # UniFFI bindings for Android, package sn.kaolack.fluxsync
  uniffi-bindgen/        # workspace-local uniffi_bindgen_main runner
apps/
  android/               # Compose v2, NDK arm64-v8a, UI under app/src/main/java/sn/kaolack/fluxsync/{ui,vm}/
  macos-tray/            # Tauri 2 menu-bar. src-tauri/ has its OWN [workspace] (empty), NOT in root workspace
packaging/
  homebrew/fluxsync.rb   # brew formula, source build + service do block
design/project/FluxSync-Mobile.html   # canonical Android UI spec (supersedes Desktop jsx)
```

ALWAYS verify file paths against the live tree — design/ on Desktop is out of sync vs design/ in repo.

## 2. Runtime defaults

- IPC socket: `~/.fluxsync/sock` (macOS/Linux UNIX), `\\.\pipe\fluxsync` (Windows)
- Keystore: `~/.fluxsync/identity.bin` (mode 0600), `~/.fluxsync/peers.json`
- UDP port: `41889`
- mDNS service type: `_fluxsync._udp.local.`
- Logs: `~/.fluxsync/logs/fluxsyncd.log` (rotated)

## 3. Senior Rust rules (NON-NEGOTIABLE)

- `fluxsync-core` MUST stay pure: NO `tokio`, NO `reqwest`, NO IO. Violation = revert.
- One-way dep graph: `core` ← `crypto` ← `proto` ← `fluxsyncd`/`fluxctl`/`mobile-ffi`. NEVER reverse.
- Workspace deps centralized in root `Cargo.toml [workspace.dependencies]`. Per-crate uses `{ workspace = true }`.
- Errors: `thiserror` typed in libs, `anyhow` only in binaries (`fluxsyncd`, `fluxctl`). NEVER leak `anyhow::Error` across crate boundary.
- NEVER `unwrap()` / `expect()` in library code. OK in tests + `main()` scaffolding only.
- Visibility: `pub(crate)` by default, curated re-export from `lib.rs`.
- Logging: `tracing` only. NEVER `println!`, `eprintln!`, `dbg!`. Use `info!("user {user_id}")` inline format (clippy::uninlined_format_args).
- MSRV pinned via `rust-toolchain.toml`. Don't bump casually.
- Features: additive only. NEVER feature-flag that flips semantics.

## 4. Async / tokio rules

- Keep async at the edges (daemon transport, IPC). Core stays sync.
- Cancellation: every long-lived task MUST honor `tokio::select!` on a shutdown signal. Document spawning site.
- Channels: `tokio::sync::mpsc` for backpressure, `broadcast` for fanout, `oneshot` for replies. NEVER unbounded mpsc.

### Named pipe gotcha (Windows tray) — REAL BUG, see fix 2026-05-20

NEVER call `tokio::net::windows::named_pipe::*` from a sync function or sync Tauri command context. It panics: "there is no reactor running".
Fix: use `std::fs::OpenOptions` + sync read/write for one-shot tray→daemon ping. Async only inside an explicit `tokio::runtime::Handle::current()` scope.

### Tokio + sync ctx checklist

1. Is caller `async fn` OR inside `tokio::spawn`? → tokio NP OK.
2. Sync Tauri command / sync FFI / sync test? → std::fs::OpenOptions + sync.
3. NEVER `block_on` inside an async runtime (deadlock on single-thread executors).

## 5. Wire protocol invariants (fluxsync-proto)

- Wire encoding: CBOR via `ciborium`. NEVER add JSON to wire (debug only).
- `Frame` = transport envelope (header + chunk). `Msg` = semantic payload.
- Header ordering: deterministic field order. Re-encoding MUST produce identical bytes.
- Chunk reliability: selective-NAK (landed 2026-05-19). Resend-until-ack (Plan C, 2026-05-18). NEVER drop chunks silently.
- Backward compat: bump `Msg` variant tag, never reorder existing tags.
- All wire types: `#[derive(Serialize, Deserialize)]` + `#[serde(deny_unknown_fields)]` for forward-compat checks.

## 6. Crypto baseline (fluxsync-crypto) — see THREAT-MODEL.md

- Handshake: Noise IK pattern (responder static known, initiator ephemeral + static).
- AEAD: ChaCha20-Poly1305. NEVER swap for AES-GCM without re-audit.
- SAS pairing: 5-word fingerprint from `wordlist.rs`. Compare out-of-band.
- Identity: `identity.bin` mode 0600. Migration target = OS keychain (macOS Keychain Services, Windows Credential Manager, Android Keystore).
- Zeroize: all secret material (`Key`, `StaticSecret`, `Noise*State`) MUST `impl Zeroize + Drop`. CI check via `zeroize-audit` skill.
- Constant-time: cmp via `subtle::ConstantTimeEq`. NEVER `==` on MAC/tag/fingerprint bytes.
- mDNS auth gap: NEVER trust mDNS-advertised peer identity. Always re-verify via Noise IK static key.

## 7. Daemon modules (fluxsyncd) — module ownership

| Module | Owns |
|--------|------|
| `cmd` | subcommand dispatch (`fluxsyncd run`, `pair`, `revoke`, ...) |
| `config` | TOML config + env override + defaults |
| `discovery` | mdns-sd register/browse, peer cache |
| `driver` | clipboard watcher: arboard (Mac/Linux/Win), Android via FFI |
| `handshake` | Noise IK orchestration, SAS UI events |
| `ipc` | UNIX sock / Named Pipe server, fluxctl protocol |
| `keystore` | identity.bin r/w, peers.json |
| `logs` | tracing-subscriber + file rotation |
| `transport` | UDP socket, chunk framing, NAK, retry, congestion |
| `wall` | event bus / dashboard hooks |

Cross-module rule: NEVER reach across modules — go through shared types in `fluxsync-proto` / `fluxsync-core`.

## 8. Tauri 2 tray (apps/macos-tray) — Impertio package idioms

- src-tauri/ owns its own `[workspace]`. NEVER add it to root workspace.
- IPC: `#[tauri::command] async fn …` Rust ↔ TS via `invoke()`. Mirror types both sides (D-008 dual coverage).
- Event API for daemon→tray push (peers update, pairing prompt, sync progress).
- Tray sidecar staleness gotcha: tray spawns CACHED `fluxsyncd` binary. After any daemon change, FORCE rebuild + relaunch tray. Document in PR.
- Frontend: vanilla HTML/CSS/JS under `src/`. NO React/Svelte unless explicit scope change.
- Code signing: macOS = Developer ID + notarize via `tauri build`. Windows = NSIS via `cargo-xwin` cross-build path validated 2026-05-20.

## 9. Android (apps/android) — Compose v2 + UniFFI

- Build: `JAVA_HOME=<Android Studio JBR>`, then `./gradlew` (auto-runs cargo-ndk).
- NDK: arm64-v8a ONLY. Skip x86/armv7.
- Package: `sn.kaolack.fluxsync`.
- Compose code: `app/src/main/java/sn/kaolack/fluxsync/{ui,vm}/`.
- UI canonical spec: `design/project/FluxSync-Mobile.html`. Match pixel/spacing intent, NOT 1:1 HTML.
- JNI bridge: UniFFI auto-gen from `fluxsync-mobile-ffi`. NEVER hand-write JNI.
- After Rust change: `./gradlew assembleDebug && adb install -r app/build/outputs/apk/debug/app-debug.apk`. Confirm clean `cargo-ndk` rerun (stale .so = real bug, 2026-05-18).
- Clipboard watcher: register on resume, unregister on pause. ClipboardManager listener fires on focus change.

### Known bug (2026-05-19, OPEN)

Image sync Android → Mac broken. Mac → Android works. Suspects:
1. Android clipboard watcher not calling `push_item` for images.
2. arboard write path on Mac for incoming PNG.
Verify both before claiming fix.

## 10. Test gate (MANDATORY before declaring done)

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
cargo audit
```

Android extra: `./gradlew lint test`.
Tauri extra: `cd apps/macos-tray && pnpm tsc --noEmit && pnpm build`.

If ANY step fails, fix before commit. NEVER `--no-verify`.

## 11. Release flow

- Version bump in root `Cargo.toml` + per-crate `Cargo.toml` (use workspace inheritance where possible).
- `CHANGELOG.md`: Keep a Changelog format. Group: Added / Changed / Fixed / Security.
- Tag: `git tag vX.Y.Z -m "..."`. Push tag after CI green.
- Assets per release: macOS DMG universal, Windows NSIS Setup.exe (x64 + ARM64), Linux deb + AppImage, Android APK arm64, fluxctl tarballs (mac+linux+win).
- Brew: bump `packaging/homebrew/fluxsync.rb` SHA256 + version.
- v0.5.2 baseline = 744c035 main. v0.6.0 plan @ b6f161e (NOT pushed at 2026-05-19 — verify state before tag).

## 12. Anti-patterns (REAL BUGS, never repeat)

| Bug | Lesson |
|-----|--------|
| Daemon 8d stale during device test (2026-05-17) | After Mac code change, ALWAYS `pkill fluxsyncd && cargo run -p fluxsyncd` before re-testing Android |
| Tray sidecar caches old daemon (recurring) | After daemon rebuild, FORCE tray refresh; tray ships its own copy |
| Header field reorder broke chunk decode (2026-05-18) | Wire-type field order is part of the ABI |
| Windows NP from sync Tauri ctx panicked (2026-05-20) | Sync ctx → std::fs::OpenOptions |
| Stale .so after cargo-ndk skipped rebuild (2026-05-18) | `./gradlew clean cargo-ndkBuild assembleDebug` when in doubt |
| WebView2 missing on installer first-run | NSIS = `embedBootstrapper` + `currentUser` install |
| identity.bin plain on disk | Keychain migration in flight, gate behind feature first |
| `qrcode` dep unresolved on Mac/Linux (2026-05-24) | `[target.'cfg(target_os = "windows")'.dependencies]` is a TOML section header — ALL keys below it inherit the gate until next header. ALWAYS place target-specific dep tables at END of Cargo.toml, or put cross-platform deps BEFORE any `[target.…]` block. Verify with `cargo check --lib` on Mac before push. |

## 13. Marketing / OSS

- Landing: Astro on Vercel (pending). Repo `fluxsync-site` (or `site/` subfolder, confirm).
- Demo: scrcpy → gifski → README hero.
- HN launch: Tuesday/Wednesday 8am PT. Title: "FluxSync — local-only clipboard sync between Mac, Windows, Linux, Android (Rust, no server)".
- NEVER add paid tier copy. ALWAYS link Sponsors / Ko-fi / crypto.

## 14. Trigger heuristics for THIS skill

Auto-engage when user message or task touches any of:
- "fluxsync", "fluxsyncd", "fluxctl", "kaolack", "sn.kaolack.fluxsync"
- Any path under `/Users/dethiekaire/fluxsync/`
- "clipboard sync", "peers", "pairing", "SAS", "Noise IK"
- "named pipe" + tray/Windows context
- "NAK", "chunk", "selective ack", "image sync"
- "brew formula" + clipboard
- "Tauri 2" + "tray" + "menu bar"
- "UniFFI", "cargo-ndk", "arm64-v8a"
- mention of `Frame` / `Msg` CBOR
- editing `Cargo.toml` at repo root

## 15. references/

Companion documents (read on demand, not auto-loaded):

**Skill-local (this dir / references/):**
- `references/THREAT-MODEL-summary.md` — STRIDE per surface (A–F), open tickets FS-052..FS-061
- `references/release-checklist.md` — version bump → tag → multi-OS artifacts → brew → announce

**Repo upstream sources of truth:**
- `docs/THREAT-MODEL.md` (full STRIDE, 150 lines)
- `docs/SECURITY.md` (design intent + implementation status)
- `docs/PROTOCOL.md` (wire spec)
- `docs/ARCHITECTURE.md`
- `docs/CONTRIBUTING.md`
- `CHANGELOG.md` (Keep-a-Changelog format)
- `CONSTANT_TIME_AUDIT_2026_05_24.md`
- `DIFFERENTIAL_REVIEW_2026_05_24.md`
- `FluxSync_VARIANT_ANALYSIS_2026-05-23.md`
- `.semgrep/` (custom Semgrep rules)
- `security-rules/`

Keep this SKILL.md under 500 lines. Push detail into references/ files.
