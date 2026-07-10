# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [SemVer](https://semver.org/).

## [v0.7.0] — 2026-07-10

**FluxMesh multi-device topology, FluxVault encrypted history, and
FluxFirewall clipboard policy, plus a security-hardening pass across
rekey, resync, and pairing.**

### Added
- **FluxMesh:** star-topology multi-device sync — peer-keyed `Transport`
  map, per-secondary heartbeat/ghost-timeout, primary failover to a live
  secondary, relay of chunked items across a third hop, per-secondary
  unpair, mesh peer list in the clients, and a 3-node mesh integration
  test. Wire bumped to v2 with `EventId` (origin + event_seq) for
  fan-out anti-loop.
- **FluxVault:** AEAD-encrypted on-disk history store, persisted and
  rehydrated across restarts, and favorites (pin history items past TTL
  and cap) with UI on macOS and Android.
- **FluxFirewall:** per-class clipboard policy model gating apply and
  broadcast in core; `Ask` parks then resolves instead of fail-closed
  drop; policy persisted across restarts; `fluxctl firewall` command
  group; policy + pending-decision UI on macOS and Android.
- Resync-on-reconnect: `ResyncOffer`/`ResyncPull` wire messages, a
  persisted event-seq outbox, offer/pull of missed items on relink.
- Automatic session rekey (24h / 1 GiB, make-before-break) and mutual SAS
  confirmation over the wire (`Msg::PairConfirm`), plus a symmetric
  re-verify flow (`Msg::PairVerifyStarted`, capped verify-restart).
- Capability negotiation in `Hello`, multi-address pair URIs (LAN +
  Tailscale) with security caps, exponential backoff with jitter on
  reconnect, persisted `last_addr` for mDNS-free relink, `--disable-mdns`
  flag.
- Sensitive-image flag threaded from capture through every persistence
  gate (push, history cache, wipe).
- Device rename and reliability counters across daemon, CLI, tray and
  Android.
- `fluxctl doctor` — one-shot sync diagnostics; new `fluxctl favorite`,
  `unpair`, `shutdown`, and `pair --from-pin` subcommands.
- Android: background survival (battery exemption, OEM guidance, service
  self-check), identity encrypted at rest via the Android Keystore,
  release-keystore signing.
- Tray/UX: history search, image thumbnails with re-copy, 3-step device
  onboarding, a full ARIA pass, a daemon-offline banner, a ksni "Pair
  device…" tray entry, and ctrl+click to open the tray menu.
- Docs: `SECURITY.md` v1, `WHY-ACCESSIBILITY.md`, `TROUBLESHOOTING.md`,
  `FAQ.md`, `HEADLESS-LINUX.md`.
- Scripted chaos harness plus a weekly CI job.

### Fixed
- 12 multipeer bugs across relay, firewall gate, rekey and resync:
  scoped vault wipe via `other_linked_peers`, relay gated on a firewall
  Block decision, deterministic boot peer, secondary proactive redial
  off the persisted `last_addr`, and more.
- Resync no longer replays, clobbers, or leaks offline copies; fixed a
  Hello/session race on reconnect.
- Canonical CRLF dedup, unpair pending-item wipe, bounded hex regex.
- macOS tray: true pairing screen, clean unpair state, menu-bar-only
  window, and a notification-privacy leak on cold start.
- Android: SAS-verify race, battery-push retry, 16 KB native-lib page
  alignment.

### Security
- Phase 5 round-3 hardening: outbox gate, synchronous vault wipe,
  peer-scoped pending state, and egress/rekey/resync/SAS fixes.
- Clients now exit non-zero on daemon rejection; IPC reads are capped.
- Discovery cache purged on unpair/revoke/wipe.
- Opt-in strict keychain ACL (`FLUXSYNC_STRICT_KEYCHAIN=1`) plus a
  startup warning when running without keychain protection.
- `debug-capture` CLI command and the `SetLaunchAtLogin` IPC op removed.

### CI
- `release.yml` now publishes `SHA256SUMS` and ships non-draft releases.

## [v0.6.2] — 2026-06-14

**v6 "premium calm" interface, plus discovery and capture fixes.**

### Changed
- Full v6 UI redesign across the macOS tray and the Android app: a flat-fill
  design language (no tonal gradients or glossy insets), refreshed
  components, screens and theme.

### Fixed
- mDNS discovery: pin the LAN IP + interface kind so advertisements stop
  egressing on `awdl0` (macOS), which was breaking peer discovery.
- Android: session-seed guard on the accessibility clipboard capture stops a
  freshly linked peer from being sent stale clipboard contents.
- Proto/codec, FSM, state and driver follow-ups with matching test updates.

### CI
- Pin Windows runners to `windows-2025`; bump `setup-java` to v5.

## [v0.6.1] — 2026-06-04

**Pairing that actually works cross-device, plus a real Linux app.**

### Added
- Multi-screen pairing flow: QR scan **and** 6-digit PIN method, with a
  symmetric SAS verify-words gate (FS-052) that now fires on both the
  initiator and the responder.
- Linux desktop: the full Tauri GUI now builds and runs (deb + AppImage),
  alongside a native ksni `StatusNotifierItem` system-tray.
- Android: background clipboard capture via the system clip listener.
- Identity keychain escape hatch.

### Changed
- macOS tray reworked into a single-window Dock app (kills the white void;
  the close button hides instead of quitting).
- Daemon lifecycle: clean, deterministic shutdown.

### Fixed
- **mDNS discovery is pinned to the LAN interface.** It was advertising and
  browsing on every interface (`bind_ip = 0.0.0.0`); on macOS that included
  awdl0/utunN, so `_fluxsync` multicast egressed off-LAN and peers never saw
  each other — PIN pairing failed with "code not found" and trusted peers
  never auto-reconnected. Now resolved to the real egress IP and restricted
  to that interface.
- Tray: settings reachable while unpaired (header gear), real `NSApp` hide,
  version/label corrections.

### Security
- Audit + QA hardening: trust-store wipe on revoke/drop-peer, outbound
  TOFU/SAS gate, XSS fix in the webview, bounded mpsc channels.
- Phase 3 + Phase 4 adversarial-drill hardening (C1/C2, H1/H2/H3, M1/M2,
  SE-02/03/05/08/14).

## [v0.5.2] — 2026-05-17

**Clipboard reliability.**

### Fixed
- Clipboard no longer flaps. The Noise transport ran a stateful nonce
  counter over UDP; a single dropped or reordered datagram desynced
  decryption and silently starved the link until the 30s heartbeat
  timeout forced a re-handshake. Frames now carry an explicit per-frame
  nonce so they decrypt regardless of loss or reorder; a 64-bit sliding
  replay window keeps replay protection.
- `Revoke` and `Unpair` now rewrite `peers.json`. Previously a removed
  peer reappeared after a daemon restart and left `PairShow` stuck on
  `already_paired` with no way to re-pair from the UI.

### Changed
- Release binaries (APK, macOS Tauri sidecar) are no longer tracked in
  the repo — they ship via GitHub releases.

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

### Known Issues (v0.5.0)
- **Handshake Deadlock**: Rare race conditions during handshake can lead to a stuck state.
- **Clipboard Ping-Pong**: Trailing whitespace in text can trigger infinite synchronization loops.
- **Persistence**: Device pairing information is not saved; re-pairing is required after daemon restart.
- **Windows Support**: Native Named Pipes for IPC are pending; currently using Unix Socket emulation.

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
