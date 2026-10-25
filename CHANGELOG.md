# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [SemVer](https://semver.org/).

## [Unreleased]

**"Lien" — a from-scratch redesign of the desktop app (macOS, Windows,
Linux) around what FluxSync is: a direct link between your devices and
the clipboard items that flow across it. And a rework of the daemon from
the inside out: a new driver architecture, and a long list of link, sync
and security bugs fixed, each pinned by a test that fails without the
fix.**

### Changed
- New design system, derived from the FluxSync mark: coral (the two
  copies) for what flows — items in transit, primary actions, the packet
  that crosses the link; green (the sync dot) only for the live, verified
  link; night-ink surfaces; red only for destructive actions. IBM Plex
  Sans/Mono, bundled locally (the old Google Fonts import was blocked by
  the app CSP, so the UI had been rendering in fallback fonts).
- Tray popup rebuilt: state headline + the link between this device and
  the peer (end-to-end seal on the wire, coral packet on every sync),
  Clipboard / Firewall / Devices tabs, numbered history rows (01–09 double
  as ⌘/Ctrl+1–9), direction and origin device on every item, a
  Firewall rules matrix, and dedicated offline / unpaired screens.
- Settings and Pair windows rebuilt on the same system (numbered
  sections, hairline rows, crop-marked QR, numbered verification words,
  a "They match" step that reads as what it is).
- Dark, light or system appearance, shared live across all windows.
- In-app confirmation dialogs replace `window.confirm()`.
- Android palette tokens moved to the same night/green/coral values
  (names unchanged; layouts untouched).

### Added
- Devices lists every paired device, online or not (new `State.paired`):
  a device that is offline can still be seen and unpaired on its own.
  A paired device that is merely offline no longer reads "Not paired".
- A device rename reaches linked devices immediately, not on the next
  reconnect.
- History filters (pinned, text, links, code, images), instant search
  with Enter-to-copy, open-in-browser for links, keyboard navigation
  (↑/↓, `p` to pin, `o` to open, `/` or ⌘/Ctrl+F to search, Esc to hide).
- Pending firewall decisions are announced on every tab with a badge.

### Fixed — sync and links
- Copying A, then B, then A again never synced the second A (in either
  direction): echo suppression swallowed any content seen among the last
  50 items. A repeat now counts as an echo only when it is the current
  content or was seen in the last 5 seconds. History moves a re-copied
  item to the top instead of duplicating it.
- Switching sync off didn't: the other device re-linked to it right away,
  and switching back on then left it stuck "Searching" beside a live link.
  Off now means no link at all, and on relinks.
- Unpair and sync-off only ever reached the primary device; other linked
  devices stayed connected (and kept trusting this one).
- Dialing a second device re-pointed the live link at it: the linked
  device's traffic went to the wrong address.
- Devices that joined while this one was already linked (a mesh
  secondary, a peer restarting) never received its name and capabilities:
  no resync with it, and its pairing confirmation could wait forever.
- Revoking the only linked device left it on screen as "Searching for…",
  and ten minutes later the ghost timeout wiped the whole history.
- When the linked device has been away for ten minutes, the history wipe
  now keeps your favorites (in memory, on disk and their image bytes);
  the vault is rewritten atomically with what is kept. The wipes for an
  untrusted key or a different device pairing still take everything.
- Connection diagnostics: a second device joining, or a session rekey,
  no longer counts as a reconnect or resets the session uptime; rekeys
  have their own `rekeys` counter.
- Two items arriving back to back could land on the clipboard in the
  wrong order, leaving the older one.
- A 1 KiB text item, and every full image chunk, exceeded the datagram
  budget: byte fields went out as CBOR integer arrays. They are now byte
  strings (half the size, wire-compatible both ways) and every frame is
  checked to fit.
- A re-sent item inherited its predecessor's spent retry budget and was
  abandoned after one retry; whole-item retransmits no longer blast
  thousands of datagrams from the receive loop.
- Android: a daemon that missed its start-up deadline kept running with no
  handle, holding the UDP port so every retry failed.

### Security
- A captured handshake from a trusted device, replayed, replaced its live
  session and redirected its traffic — a link anyone on the LAN could cut
  repeatedly. Each handshake now answers once.
- A stray datagram could abort a pairing or reconnect in progress.
- A peer still pending confirmation (or kept from an item by the firewall)
  could pull the item's frames with a NAK.
- X25519 public keys with bit 255 set bypassed the low-order point check.
- Received images are decoded under explicit limits (16384 px a side,
  256 MiB) instead of inflating whatever a PNG header declares.
- `pending_pulls` is bounded under a flood of resync offers.
- Every on-disk save (peers, vault, firewall, device name, sequence
  horizon) now fsyncs its directory after the atomic rename.

### Fixed
- Desktop battery shown as "255%" on machines without a battery.
- Copying an image back from history always failed (CSP blocked the
  `fetch(data:)` path); bytes are now decoded locally.
- Onboarding promised an iPhone app that doesn't exist.
- The tray's `state-update` throttle dropped the newest update inside its
  100 ms window, leaving the UI on a stale state until the 5 s poll; it now
  coalesces and always delivers the latest snapshot.

### Architecture
- The daemon's 11k-line `driver.rs` is a `driver/` module tree, one
  concern per file, around a single `Arc<Shared>` context instead of
  twenty-argument functions (see docs/ARCHITECTURE.md §3b).
- Six hand-rolled atomic writes are one `fsutil::write_atomic`; three
  copies of the in-flight merge are one `track_inflight`; the state
  snapshot is built in one place for the watch and for `status`.
- Keystore I/O runs on the blocking pool, OS clipboard writes on one
  ordered writer thread, retransmits in their own paced task.

### Performance
- Popup renders are coalesced per frame, keyed and incremental: a
  heartbeat push with 50 history items went from ~150 ms of layout and
  ~400 new DOM nodes to well under a frame and zero new nodes.
- Image thumbnails are downscaled once and LRU-capped instead of keeping
  full PNG payloads in memory.
- Daemon: identical state snapshots no longer wake IPC subscribers, the
  state stream serializes straight from the watch borrow (no deep clone
  per client per change) and no longer sends a new subscriber its first
  snapshot twice; the vault persister and ghost-timeout watcher stop
  cloning the full history on every heartbeat.

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
