# Headless Linux (server, no display)

FluxSync's daemon and CLI are plain Rust binaries with no GUI dependency, so they run fine on a headless box — a home server, a NAS, a VM, a single-board computer. This doc covers the parts that differ from a normal desktop install: no OS keychain/D-Bus session to store the identity key in, no display for clipboard capture, and no GUI for pairing.

If you *do* have a desktop session (X11/Wayland) and just want auto-start, the systemd unit in the README's Linux install section is enough on its own — this document is for the fully headless case, plus the optional native tray.

## 1. Identity storage without a keychain

FluxSync normally stores its long-term identity key in the OS keychain via D-Bus Secret Service (GNOME Keyring, KWallet). A headless box typically has neither a login session nor a D-Bus session bus running, so that backend isn't available.

Set:

```sh
export FLUXSYNC_NO_KEYCHAIN=1
```

before starting `fluxsyncd` (or in the systemd unit's `Environment=` line below). This stores the identity key in a `0600` file instead of the keychain.

**Security tradeoff, stated plainly**: with this set, the identity key sits unencrypted on disk. Anyone who can read that user's files — a backup system, a restored disk image, or malware running as the same user — gets the long-term key. This is a deliberate, documented escape hatch (see [`SECURITY.md`](./SECURITY.md) "Known accepted risks"), not a hidden default; don't set it on a box you don't otherwise trust with root-equivalent access to that user's files.

## 2. systemd `--user` unit for the daemon

```ini
# ~/.config/systemd/user/fluxsync.service
[Unit]
Description=FluxSync clipboard daemon
After=graphical-session.target

[Service]
Environment=FLUXSYNC_NO_KEYCHAIN=1
ExecStart=%h/.cargo/bin/fluxsyncd
Restart=on-failure

[Install]
WantedBy=default.target
```

```sh
systemctl --user enable --now fluxsync.service
```

Drop the `Environment=FLUXSYNC_NO_KEYCHAIN=1` line if this box does have a working D-Bus Secret Service you'd rather use instead.

If you want the daemon to keep running across logout (no active session at all — e.g. a server you only SSH into), also enable lingering for the user once, as root:

```sh
loginctl enable-linger <username>
```

Without lingering, systemd tears down the user's service manager (and everything in it) shortly after the last session for that user ends.

## 3. Optional: native tray on a headless box with a lightweight desktop

If the box does run a minimal desktop (e.g. a status-bar-only window manager, or a lightweight DE like a tiling WM with a systray widget), `apps/linux-tray` ships a small native tray icon (binary `fluxsync-tray`, package `fluxsync-linux-tray`) using the ksni `StatusNotifierItem` protocol — no Tauri/WebView dependency, much lighter than the full GUI app. It's an IPC client only; it doesn't run the daemon itself, so it still needs `fluxsync.service` above (or an equivalent) running.

```ini
# ~/.config/systemd/user/fluxsync-tray.service
[Unit]
Description=FluxSync tray icon
After=fluxsync.service graphical-session.target
Requires=fluxsync.service

[Service]
ExecStart=%h/.cargo/bin/fluxsync-tray
Restart=on-failure

[Install]
WantedBy=default.target
```

```sh
systemctl --user enable --now fluxsync-tray.service
```

If there's no systray host at all (fully headless, no desktop), skip this — `fluxctl` covers everything the tray does for headless use, see below.

## 4. Pairing without a GUI

Everything the tray/Compose UI does for pairing is available through `fluxctl`:

```sh
# On the headless box: render this device's pairing QR/URI as text
fluxctl pair show-qr        # QR rendered in the terminal
fluxctl pair show           # same pairing info as a plain URI + 6-word fingerprint, no QR art

# On the other device (phone camera scan, or another fluxctl):
fluxctl pair from-uri --uri "fluxsync://pair/<pubkey>?a=<addr>&f=<words>" --name myserver

# If mDNS can't reach the headless box (common on servers/VMs — see below),
# pair by address directly instead:
fluxctl pair accept --pubkey <b32> --name myserver --addr 192.168.1.50:41889
```

Compare the 6-word fingerprint verbally (or visually, if you can see both terminals) exactly as you would with two GUI apps — the security property doesn't change just because one side has no display.

## 5. `--disable-mdns` for manual-IP-only setups

Servers and VMs are frequently on networks where multicast (which mDNS depends on) doesn't work the way it does on a home LAN — routed subnets, cloud VPC networking, or firewalls that drop multicast entirely. If mDNS isn't going to work on this box, turn it off explicitly rather than letting the daemon spend cycles browsing for peers that will never resolve:

```sh
fluxsyncd --disable-mdns
```

(or add `--disable-mdns` to the `ExecStart=` line in the systemd unit above). This stops both advertising and browsing for peers — pairing and reconnection then rely entirely on the manual-IP flow in §4, plus the address hint (`addr`) FluxSync persists per peer so a reconnect after a restart doesn't need mDNS either.

## 6. Clipboard caveat on a truly display-less box

The daemon uses [`arboard`](https://crates.io/crates/arboard) for the local clipboard, which needs an X11 or Wayland session to talk to. On a box with no display server at all, the clipboard watcher itself won't start — everything else (identity, pairing, receiving pushes via `fluxctl pull`, `fluxctl push` from that box's own shell) still works, you just won't get automatic OS-clipboard-in/out on that particular machine. This matches the same caveat noted in the README for desktop Linux without a session.

---

See [`TROUBLESHOOTING.md`](./TROUBLESHOOTING.md) for `fluxctl doctor` and general connectivity diagnostics, and [`SECURITY.md`](./SECURITY.md) for the full rationale behind `FLUXSYNC_NO_KEYCHAIN`.
