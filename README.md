<!-- markdownlint-disable -->
```
   __  _              ____
  / _|| | _   _ __  __/ ___| _   _  _ __    ___
 | |_ | || | | |\ \/ /\___ \| | | || '_ \  / __|
 |  _|| || |_| | >  <  ___) | |_| || | | || (__
 |_|  |_| \__,_|/_/\_\|____/ \__, ||_| |_| \___|
                             |___/
```

**Universal clipboard. Local-first. Peer-to-peer. End-to-end encrypted.**
One daemon, four operating systems, zero servers.

---

## ⚡ v0.5.0 Release: Stabilization & Universal Sync
Official stable release. No more 40s latency. Instant P2P pairing.

### 📥 Download Pre-built Binaries (Easiest)
Don't want to build from source? Download the latest stable binaries directly:
- 📱 **Android**: [**Download fluxsync.apk**](https://github.com/flowerpower584/fluxsync/raw/main/fluxsync.apk)
- 💻 **macOS**: [**Download fluxsync.dmg**](https://github.com/flowerpower584/fluxsync/raw/main/fluxsync.dmg)

---

## Quickstart (v0.5.0)

### 1. Start the Engine
Run the daemon. This handles the background sync and encryption.
```sh
# macOS / Linux
./fluxsyncd --udp-bind 0.0.0.0 --ipc-path /tmp/flux.sock

# Windows
# fluxsyncd.exe --udp-bind 0.0.0.0 --ipc-path \\.\pipe\flux
```

### 2. Connect your Devices
Open the Android app or the macOS Tray icon. Scan the QR code to pair. **Your data never leaves your local network.**

### 3. Use the CLI (Optional)
```sh
./fluxctl --ipc-path /tmp/flux.sock status
./fluxctl --ipc-path /tmp/flux.sock push "Hello from Kaolack! 🇸🇳"
```

---

## 🛠️ Build from Source
If you prefer to build it yourself (requires Rust):
```sh
git clone https://github.com/flowerpower584/fluxsync && cd fluxsync
cargo build --release
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
| Works across macOS / Win / Linux / Android |   yes       |          no (Apple-only)  |   yes     |   **yes**    |
| End-to-end encrypted by default          |   yes       |          yes              |   yes     |   **yes**    |
| Zero servers / zero account              |   yes       |          no               |   yes     |   **yes**    |
| Designed for clipboard (not file sync)   |   yes       |          yes              |   no      |   **yes**    |
| Battery-aware auto-pause                 |   no        |          partial          |   no      |   **yes**    |
| One Rust daemon, no GUI dep              |   no        |          —                |   yes     |   **yes**    |
| Open source, MIT                         |   yes (GPL) |          no               |   yes (MPL) | **yes**     |

---
Crafted in Kaolack, Senegal 🇸🇳
