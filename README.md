<!-- markdownlint-disable MD033 MD041 -->
# FluxSync

**Copy on one device, paste on another.** Your phone and your computers share one clipboard — over your own Wi-Fi, encrypted end to end. No account, no cloud, free and open source.

[![Latest release](https://img.shields.io/github/v/release/flowerpower584/fluxsync?include_prereleases&label=release)](https://github.com/flowerpower584/fluxsync/releases)
[![Platforms](https://img.shields.io/badge/platforms-Android%20%7C%20macOS%20%7C%20Windows%20%7C%20Linux-lightgrey)](#1-install-fluxsync-on-each-device)
[![CI](https://github.com/flowerpower584/fluxsync/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/flowerpower584/fluxsync/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

> 🧪 **The newest version, [v0.8.0-beta.1](https://github.com/flowerpower584/fluxsync/releases/tag/v0.8.0-beta.1), is a beta**: a redesigned desktop app and lots of fixes, still being tested on real devices. Want the proven version? Use [v0.7.0](https://github.com/flowerpower584/fluxsync/releases/tag/v0.7.0). [What changed](CHANGELOG.md)

## What it does

- You copy something on your phone, and it's ready to paste on your computer, and the other way round.
- It works with text, links, code and images, between any mix of Android, Mac, Windows and Linux.
- Everything goes **straight from one device to the other** on your network. Nothing passes through a server, and there's no account to create.

**What you need:** two devices **on the same Wi-Fi** (or the same network), and about five minutes.

---

## 1. Install FluxSync on each device

Open the [**release page**](https://github.com/flowerpower584/fluxsync/releases/tag/v0.8.0-beta.1), scroll down to **Assets**, and download the file for your device:

| Your device | File to download |
|---|---|
| **Android** phone or tablet | the `.apk` file |
| **Mac** with an Apple chip (M1, M2, M3…) | the `.zip` ending in `_aarch64.zip` |
| **Mac** with an Intel chip | the `.zip` ending in `_x64.zip` |
| **Windows** (most PCs) | the file ending in `_x64-setup.exe` |
| **Windows on ARM** (e.g. Surface Pro X) | the file ending in `_arm64-setup.exe` |
| **Linux** — Ubuntu, Debian, Mint… | the `.deb` file |
| **Linux** — any other distribution | the `.AppImage` file |

Not sure which Mac you have? Apple menu  → **About This Mac**: it says "Chip Apple M…" or "Processor … Intel".

> **About the warnings:** the apps aren't signed yet (that needs paid Apple and Microsoft certificates), so your system will warn you the first time. That's expected. The steps below show how to get past it.

<details open>
<summary><b>📱 Android</b></summary>

1. Open the downloaded `.apk`. If Android blocks it, allow installs from your browser or Files app when it asks (or in **Settings → Apps → Special app access → Install unknown apps**).
2. Open FluxSync. It asks for:
   - **Camera:** to scan the pairing QR code.
   - **Accessibility:** turn FluxSync on under **Settings → Accessibility**. Android doesn't let apps see your copies while they're in the background; this is the only way around it. [What it does and doesn't do](docs/WHY-ACCESSIBILITY.md).
3. Recommended: in your phone's battery settings, set FluxSync to **Unrestricted** so Android doesn't put it to sleep.

</details>

<details open>
<summary><b>🍎 Mac</b></summary>

1. Double-click the `.zip` to unzip it. You get a folder with `FluxSync.app`, `Install FluxSync.command` and `README-FIRST.txt`.
2. Open **Terminal** (press ⌘ + Space, type `Terminal`, press Return).
3. Type `bash` followed by a space, then **drag `Install FluxSync.command` into the Terminal window** and press Return.
4. That's it: FluxSync is installed in Applications and starts. Its icon (two overlapping squares) appears in the **menu bar** at the top of the screen, not in the Dock.

If macOS says the app "is damaged and can't be opened", click **Cancel** (not "Move to Trash") and use the steps above. Nothing is wrong with the app; this is what macOS does with apps that aren't notarized.

</details>

<details open>
<summary><b>🪟 Windows</b></summary>

1. Run the downloaded `…-setup.exe`.
2. If a blue "Windows protected your PC" screen appears, click **More info → Run anyway**.
3. FluxSync starts in the **system tray** (bottom right, near the clock; it may be hidden behind the **^** arrow).
4. If Windows asks whether FluxSync may use the network, click **Allow**. Without it, your devices can't find each other.

</details>

<details open>
<summary><b>🐧 Linux</b></summary>

- **`.deb` (Ubuntu, Debian, Mint…):** double-click it to install with your software center, or in a terminal:
  ```sh
  sudo apt install ./FluxSync_*_amd64.deb
  ```
- **`.AppImage` (any distribution):** make it executable, then run it:
  ```sh
  chmod +x FluxSync_*.AppImage
  ./FluxSync_*.AppImage
  ```

FluxSync shows up in your system tray. It needs a desktop session (X11 or Wayland) to reach the clipboard. For servers without a screen, see [Advanced](#advanced).

</details>

## 2. Pair your devices (once)

You only do this once per device; after that they reconnect on their own.

1. Open FluxSync on **both** devices.
2. On the **computer**, click **Pair a device → Show a QR code**. It shows a **QR code** and a **6-digit code**.
3. On the **phone**, tap **Pair a device** and scan the QR code.
   *Pairing two computers?* On the second one, click **Pair a device → Enter a 6-digit code** and type the code the first one shows (it changes every 90 seconds).
4. Both screens now show the **same 6 words**. Check that they really match, then tap **They match** on both devices.

The headline turns green and says **Linked**: you're done. The word check makes sure your devices are talking to each other directly, with nobody in between.

## 3. Use it

- **Copy as usual.** What you copy on one device is on the other device's clipboard a moment later. Just paste.
- **History:** click the FluxSync icon to see everything you've copied recently. Click an item to copy it again, or press **Ctrl/⌘ + 1–9** for the last nine. Type to search; press Enter to copy the best match.
- **Favorites:** pin an item with the ☆ star to keep it. Favorites aren't deleted with the rest of the history.
- **Pause:** the switch at the top turns syncing off and on.
- **Firewall tab:** choose, for each kind of content (text, links, code, images, passwords and keys), whether it syncs **Always**, **Ask** each time, or **Never**.
- **Devices tab:** see your paired devices, online or not, and unpair any of them.

## Something not working?

Most problems come down to the network. Check these first:

1. **Same network?** Both devices must be on the same Wi-Fi. Phones sometimes drop back to mobile data, and Macs to another Wi-Fi.
2. **Guest Wi-Fi or a public hotspot?** These often stop devices from seeing each other ("client isolation"). Use your home network instead.
3. **Firewall:** allow FluxSync on private networks. If you manage the firewall yourself, it uses **UDP port 41889**, plus mDNS (UDP 5353) to find your devices.
4. **Android:** check that FluxSync is still on in **Settings → Accessibility** and set to **Unrestricted** in battery settings.
5. **Still stuck?** Quit and reopen FluxSync on both devices. If that doesn't help, open **Settings → Devices → Reset all pairings** and pair again.

More fixes in the [troubleshooting guide](docs/TROUBLESHOOTING.md) and answers to common questions (iPhone? cloud? Play Store?) in the [FAQ](docs/FAQ.md). Found a bug? [Open an issue](https://github.com/flowerpower584/fluxsync/issues/new).

## Is it private?

- **No server, no account.** Your clipboard goes directly from one of your devices to the other over your own network. There's no FluxSync server for it to go through.
- **Encrypted end to end.** Everything is encrypted before it leaves your device (Noise protocol, ChaCha20-Poly1305), and only your paired devices can read it.
- **You approve every new device**, with the 6-word check.
- **Stored encrypted.** Your history is saved encrypted on your own device, and the keys are kept in your system's keychain.
- **Open source**, so anyone can check how it works. Details: [security policy](docs/SECURITY.md) and [threat model](docs/THREAT-MODEL.md).

---

## Advanced

<details>
<summary><b>Sync across different networks with Tailscale</b></summary>

FluxSync finds your devices on the same network automatically. To sync across networks (home ↔ office, phone on mobile data), put your devices on a [Tailscale](https://tailscale.com) network: FluxSync needs no setup for it. When Tailscale is running, the pairing QR code carries both addresses (local network and Tailscale), and the other device tries each one in turn. The same QR code works either way.

From the command line, `fluxctl pair show` prints the pairing link, including the Tailscale address, and `fluxctl pair from-uri --uri "<link>" --name laptop` pairs from it on the other device.

</details>

<details>
<summary><b>Command line (<code>fluxctl</code>)</b></summary>

The apps run a background service, `fluxsyncd`. `fluxctl` talks to it, for scripts or computers without a screen:

```sh
fluxctl status            # what's linked, battery, history
fluxctl push "Hello from Kaolack! 🇸🇳"
fluxctl pair show-qr      # show this device's pairing QR in the terminal
fluxctl doctor            # one-shot diagnosis: why isn't sync working?
```

</details>

<details>
<summary><b>Headless Linux (no screen) and starting on login</b></summary>

Install the service and the command line with Rust (`rustup`):

```sh
cargo install --git https://github.com/flowerpower584/fluxsync \
              --tag v0.8.0-beta.1 fluxsyncd fluxctl    # or --tag v0.7.0 for the stable one
```

Start it on login with a systemd user service at `~/.config/systemd/user/fluxsync.service`:

```ini
[Unit]
Description=FluxSync clipboard service
After=graphical-session.target

[Service]
ExecStart=%h/.cargo/bin/fluxsyncd
Restart=on-failure

[Install]
WantedBy=default.target
```

Then run `systemctl --user enable --now fluxsync.service`. Without any display, the service can't reach a clipboard, but `fluxctl push` still works. More in [docs/HEADLESS-LINUX.md](docs/HEADLESS-LINUX.md).

</details>

<details>
<summary><b>Build from source</b></summary>

You need Rust 1.88 or newer (`rustup`). For the desktop app, you also need Node.js and pnpm.

```sh
git clone https://github.com/flowerpower584/fluxsync.git
cd fluxsync
cargo build --release              # service + CLI: ./target/release/{fluxsyncd,fluxctl}

cd apps/macos-tray                 # the desktop app (macOS, Windows and Linux)
pnpm install
pnpm tauri dev                     # run it, or: pnpm tauri build
```

The Android app is in `apps/android` (Gradle; it builds the Rust core with `cargo-ndk`).

</details>

<details>
<summary><b>How it works</b></summary>

A small Rust service (`fluxsyncd`) runs on each device. It finds your other devices on the local network (mDNS), opens an encrypted channel to each one (Noise IK handshake, ChaCha20-Poly1305), and sends each clipboard item over UDP, port 41889. The desktop app (Tauri) and the Android app (Kotlin) are front ends to that service.

- [Architecture](docs/ARCHITECTURE.md)
- [Wire protocol](docs/PROTOCOL.md)
- [Contributing](docs/CONTRIBUTING.md)

</details>

## Support

FluxSync is free and open source, and will stay that way: no paid tier, no account, no cloud. If it saves you time, you can [sponsor the project](https://github.com/sponsors/flowerpower584). Donations go toward costs like the Apple Developer ID ($99/year), which would let macOS open FluxSync without any warning.

## License

Dual-licensed under the [MIT License](LICENSE-MIT) or the [Apache License 2.0](LICENSE-APACHE), at your option.

---
Crafted in Kaolack, Senegal 🇸🇳
