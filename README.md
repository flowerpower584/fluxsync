<!-- markdownlint-disable -->
```
   __  _              ____
  / _|| | _   _ __  __/ ___| _   _  _ __    ___
 | |_ | || | | |\ \/ /\___ \| | | || '_ \  / __|
 |  _|| || |_| | >  <  ___) | |_| || | | || (__
 |_|  |_| \__,_|/_/\_\|____/ \__, ||_| |_| \___|
                             |___/
```

[![CI](https://github.com/flowerpower584/fluxsync/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/flowerpower584/fluxsync/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)
[![Latest release](https://img.shields.io/github/v/release/flowerpower584/fluxsync?label=release)](https://github.com/flowerpower584/fluxsync/releases)
[![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Android%20%7C%20Linux-lightgrey)](#install)

**Universal clipboard. Local-first. Peer-to-peer. End-to-end encrypted.**
One Rust daemon, dedicated apps for macOS + Android, zero servers.

> **Platform status (v0.5.1):** Android app is the first-class GUI client. macOS ships via Homebrew (CLI + daemon — no tray app until Apple Dev ID is funded). The daemon + CLI also build cleanly on Linux (cross-compile to `x86_64-unknown-linux-musl` is green) so headless Linux use is supported. Windows daemon/CLI is not tested yet. No GUI on Linux/Windows — contributions welcome.

---

## ⚡ v0.5.1 Release: Terminal Polish + Linux Headless
Styled `fluxctl` terminal output. Linux headless cross-compile green. Daemon version now tied to `CARGO_PKG_VERSION` automatically.

> **No macOS DMG for now.** Apple Developer ID signing costs $99/year and isn't funded yet, so the unsigned DMG was pulled from releases to avoid the Gatekeeper detour. macOS users: install via **Homebrew** (below) — it builds locally, no signing required.

---

## Install

### 📱 Android
1. Download [**FluxSync-0.5.1.apk**](https://github.com/flowerpower584/fluxsync/releases/download/v0.5.1/FluxSync-0.5.1.apk) (~24 MB).
2. On the device, allow installs from the browser/Files app (Settings → Apps → Special access → Install unknown apps).
3. Open the APK to install. On first launch, grant the **camera** permission (used to scan the pairing QR) and **local network** access.

### 🍺 macOS — Homebrew (recommended)
The DMG is gone for now (no Apple Developer ID — $99/year, not in the budget yet), so Homebrew is the supported macOS path. Builds the daemon + CLI from source (~1–2 min on Apple Silicon, pulls Rust as a build dep). **No tray icon, no QR popup** — pair via `fluxctl pair show-qr` (renders the QR as Unicode in your terminal) and scan from the phone. Linuxbrew may work too — same formula — but isn't tested.

```sh
brew tap flowerpower584/fluxsync
brew install fluxsync
brew services start fluxsync   # auto-start daemon at login
fluxctl status                 # smoke-test
```

The tap lives at [`flowerpower584/homebrew-fluxsync`](https://github.com/flowerpower584/homebrew-fluxsync). Want a signed `.app` with a real tray + QR popup? Sponsor the Apple Dev ID and the DMG comes back.

### 🐧 Linux (terminal — headless)
The daemon and CLI cross-compile cleanly to Linux (`x86_64-unknown-linux-musl` checked from this machine). No tray app yet, so this is a CLI / systemd-unit setup — fine for servers and power-users. Two ways to install:

```sh
# Option A: cargo install (any distro with rustup)
cargo install --git https://github.com/flowerpower584/fluxsync \
              --tag v0.5.1 fluxsyncd fluxctl

# Option B: clone and build (lets you keep up with HEAD)
git clone https://github.com/flowerpower584/fluxsync.git
cd fluxsync
cargo build --release
# binaries: ./target/release/{fluxsyncd,fluxctl}
```

Auto-start on login via a per-user systemd unit at `~/.config/systemd/user/fluxsync.service`:
```ini
[Unit]
Description=FluxSync clipboard daemon
After=graphical-session.target

[Service]
ExecStart=%h/.cargo/bin/fluxsyncd
Restart=on-failure

[Install]
WantedBy=default.target
```
Then: `systemctl --user enable --now fluxsync.service`.

> **Linux clipboard caveat.** The daemon uses [`arboard`](https://crates.io/crates/arboard) which needs an X11 or Wayland session. On a fully headless box (no display at all) the clipboard watcher will fail to start — the daemon still runs and is reachable for `fluxctl push`, but you won't sync the system clipboard. Most desktop Linux setups are fine.

### 🛠️ Build from source (any platform)
Requires Rust ≥ 1.75 (`rustup` recommended).
```sh
git clone https://github.com/flowerpower584/fluxsync.git
cd fluxsync
cargo build --release
# binaries land at ./target/release/fluxsyncd  and  ./target/release/fluxctl
```

---

## Quickstart (v0.5.1)

### 1. Run the daemon
The Android app starts the daemon for itself — skip to step 2 if you're only using a phone.

For the Homebrew install: `brew services start fluxsync` (already covered above).

If you built from source, run it manually (defaults: `~/.fluxsync/sock` IPC, UDP `0.0.0.0:41889`, identity persisted to `~/.fluxsync/identity.bin`):
```sh
./target/release/fluxsyncd
```

### 2. Pair your devices
On macOS / Linux: `fluxctl pair show-qr` renders the QR in the terminal — scan it from the Android app. From the Android app, tap **Pair** and scan the QR shown by the other device. **Your data never leaves your local network.**

### 3. Use the CLI (optional)
The CLI talks to the daemon via the local IPC socket — useful for scripting headless setups. If you installed via Homebrew, drop the `./target/release/` prefix (binaries are on `$PATH`).
```sh
fluxctl status
fluxctl push "Hello from Kaolack! 🇸🇳"
fluxctl pair show-qr   # render this device's pair QR in the terminal
```

## Architecture
(See the Mermaid diagram below for technical details)

```mermaid
flowchart LR
    subgraph DeviceA[Device A · M1]
      A_clip[arboard] --> A_core[fluxsync-core App]
      A_core --> A_proto[fluxsync-proto CBOR]
      A_proto --> A_crypto[fluxsync-crypto Noise IK]
      A_crypto --> A_udp((UDP/41889))
      A_ipc[fluxctl / Compose] <-->|UNIX socket / Named Pipe| A_core
    end

    subgraph DeviceB[Device B · S21]
      B_udp((UDP/41889)) --> B_crypto[fluxsync-crypto]
      B_crypto --> B_proto[fluxsync-proto]
      B_proto --> B_core[fluxsync-core App]
      B_core --> B_clip[arboard]
      B_ipc[Compose UI] <-->|FFI| B_core
    end

    A_udp <-- "ChaCha20-Poly1305 ciphertext" --> B_udp
```

## Why FluxSync vs the alternatives

| Need                                     | KDE Connect | Apple Universal Clipboard | syncthing | **FluxSync** |
|------------------------------------------|:-----------:|:-------------------------:|:---------:|:------------:|
| Works across macOS + Android (apps shipped) |   partial (Linux+Android focus) |          macOS+iOS only  |   yes (file sync, not clipboard) |   **yes**    |
| End-to-end encrypted by default          |   yes       |          yes              |   yes     |   **yes**    |
| Zero servers / zero account              |   yes       |          no               |   yes     |   **yes**    |
| Designed for clipboard (not file sync)   |   yes       |          yes              |   no      |   **yes**    |
| Battery-aware auto-pause                 |   no        |          partial          |   no      |   **yes**    |
| One Rust daemon, no GUI dep              |   no        |          —                |   yes     |   **yes**    |
| Open source, permissive                  |   yes (GPL) |          no               |   yes (MPL) | **yes (MIT OR Apache-2.0)**     |

## License

FluxSync is dual-licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option. This is the standard Rust ecosystem dual-license — pick whichever fits your downstream project. Apache 2.0 adds an explicit patent grant; MIT keeps things short and GPL-compatible.

## 🔒 Security & Known Issues (v0.5.0)

- **End-to-End Encryption**: All traffic is encrypted using the **Noise IK** handshake (Curve25519, ChaCha20, Poly1305).
- **No Servers**: Peer discovery happens via mDNS (local network only). 
- **Known Bugs (v0.5.0)**:
    - **Handshake Deadlock**: If a handshake packet is lost, the sync can hang. Restart or manual toggle required.
    - **Clipboard Ping-Pong**: Trailing spaces in text can cause infinite sync loops.
    - **Persistence**: Peer pairing is NOT persistent across restarts in this version.
- **Roadmap (v0.6.0)**:
    - **Key Storage**: Secure OS Keychain integration (currently stored in plain text).
    - **Windows IPC**: Native Named Pipes (currently using Unix Socket emulation).

---
Crafted in Kaolack, Senegal 🇸🇳
