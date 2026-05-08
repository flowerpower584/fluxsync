# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [SemVer](https://semver.org/).

## [v0.5.1] — 2026-05-08

**Terminal polish + Linux headless support.**

### Added
- `fluxctl` styled terminal output: command-aware renderers for
  `status` (dashboard box), `peers` (table), `tail` (per-level colors),
  `pull` (highlighted card), `pair show` (structured view); `--json`
  path is preserved verbatim for scripts.
- Homebrew tap published at
  [`flowerpower584/homebrew-fluxsync`](https://github.com/flowerpower584/homebrew-fluxsync).
  Install with `brew tap flowerpower584/fluxsync && brew install fluxsync`.
- Linux build path documented (`cargo install --git ...` + sample
  `~/.config/systemd/user/fluxsync.service`). Cross-compile to
  `x86_64-unknown-linux-musl` is green; daemon + CLI run headless on
  Linux desktops with X11/Wayland.

### Changed
- README install section reorganized: per-platform paths
  (Android / macOS DMG / Homebrew / Linux / source). Explicit
  Gatekeeper warning callout for the unsigned `.dmg` plus a macOS
  Sequoia (15+) note since right-click "Open" no longer offers an
  unblock there.
- Platform-status callout now reflects what's actually shipped:
  macOS tray + Android app are first-class; Linux is headless CLI;
  Windows is untested.

### Fixed
- Repository URL across the workspace + brew formula corrected from
  `dethie/fluxsync` to `flowerpower584/fluxsync`.

## [v0.5.0] — 2026-05-06

**Beta Test Release. Stabilization & Universal Sync.**

### Added
- Complete stabilization of the cross-device P2P sync.
- Elimination of the 40s Lamport clock synchronization latency.
- Direct binary distribution via GitHub (APK & DMG).
- Full macOS Tray app and Android Compose UI integration.
- True universal clipboard (macOS, Windows, Android, Linux).
- Automated test cleanup and strict mock secret redaction for GitHub Push Protection.

## [v0.1.0] — 2026-04-29

**Backend foundation. No real cross-device sync yet.**

### Added
- Six-crate Rust workspace (MSRV 1.75): `fluxsync-proto`, `fluxsync-crypto`,
  `fluxsync-core`, `fluxsyncd`, `fluxctl`, `fluxsync-mobile-ffi`.
- Wire format: CBOR-encoded `Frame` envelope with hard caps
  (256 KiB payload, ≤ 256 chunks, 1024-byte data per chunk).
- Crypto: Noise IK pattern (`Noise_IK_25519_ChaChaPoly_BLAKE2s`) via `snow`,
  6-word verbal fingerprint from a curated 1024-entry BIP-39 subset
  (~60 bits), `pair_for_test` test helper behind `test-util` feature.
- Core: pure logic — battery policy + 6-state FSM + 50-entry BLAKE3 dedup
  ring + Lamport clock + clipboard classifier (text / url / code) +
  sensitive-secret detector (JWT, Stripe `sk_*`, OpenAI `sk-*`, GitHub
  `ghp_*`, AWS `AKIA*`, hex64). 99% line coverage; 100% on `policy.rs` and
  `fsm.rs`.
- Daemon: tokio runtime, AF_UNIX `SOCK_STREAM` IPC at `~/.fluxsync/sock`
  with `0600` perms set at create-time via `umask(0o077)`, NDJSON
  command/response/state/logs channels, in-memory log tail (200 entries).
- CLI: `fluxctl` with `status`, `peers`, `push`, `pull`, `tail`,
  `set-threshold`, `set-charge-override`, `revoke`, `debug-capture`. All
  commands support `--json`.
- Mobile FFI: UniFFI 0.27 cdylib + Android skeleton. Six entry points only:
  `start`, `stop`, `observe_state`, `push_text`, `set_battery_threshold`,
  `set_charge_override`. State is delivered as verbatim JSON for ABI
  stability.
- Docs: `ARCHITECTURE.md`, `PROTOCOL.md`, `SECURITY.md`, `CONTRIBUTING.md`.
- Tests: 101 across the workspace, including a two-daemon loopback
  integration test that asserts < 2 s sync, < 500 ms shutdown, and zero
  panics via a captured `std::panic::set_hook`. RFC 8439 §2.8.2
  ChaCha20-Poly1305 known-answer tests verbatim.

### Known limitations (v0.1)
- **No mDNS discovery driver.** The FSM transitions exist but the daemon
  never auto-finds a peer. Real cross-device sync requires v0.1.1.
- **No real `fluxctl pair --qr` / `--accept` flow.** v0.1 only supports
  pre-paired sessions injected via `DaemonConfig::test_pair` for the
  integration test. The CLI subcommand exits with "not implemented".
- **No clipboard / battery polling tasks** in the daemon. `arboard` and
  `starship-battery` are listed as v0.1.1 work; the FSM accepts the events
  via IPC today.
- **No identity persistence.** A fresh keypair is generated on every
  daemon boot. Keychain integration via `keyring` lands in v0.1.1.
- **Windows IPC is a stub** that returns `io::Error::Unsupported`. Named
  Pipes land in v0.1.1; the trait surface is shaped for the port.
- **Android `.so` requires Android NDK** to actually build. The crate
  type-checks for `aarch64-linux-android` without an NDK (we per-target
  gate `blake3` to its pure-Rust path), but linking the cdylib needs the
  NDK toolchain. `apps/android/README.md` has the recipe.
- **No Compose UI** in `apps/android/` — only a skeleton `MainActivity`
  that loads the `.so` and dumps state JSON to a `TextView`. Full UI in
  v0.1.1.
- **No chunk reassembly** for items > MTU (~1.4 KiB). The `Chunk` frame
  variant exists in `fluxsync-proto` but the daemon does not yet split
  large items.
- **No CI workflow** committed yet.

### Security notes
- Noise IK ChaCha20-Poly1305 sessions; no plaintext fallback.
- IPC socket created with `umask(0o077)` (no race window between bind and
  chmod). Parent directory forced to `0700` as defense in depth.
- 6-word fingerprint over BLAKE3 of the static public key.
- See [`docs/SECURITY.md`](docs/SECURITY.md) for the full threat model.

[v0.5.0]: https://github.com/flowerpower584/fluxsync/releases/tag/v0.5.0
[v0.1.0]: https://github.com/flowerpower584/fluxsync/releases/tag/v0.1.0
