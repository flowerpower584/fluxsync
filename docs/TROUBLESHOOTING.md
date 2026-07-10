# Troubleshooting

Start here whenever sync isn't working. Most issues fall into one of the categories below.

## First step: `fluxctl doctor`

Before anything else, run:

```sh
fluxctl doctor
```

This is a one-shot diagnostic that checks the daemon's local health (IPC reachable, identity loaded, keychain backend, listening socket, known peers) and exits non-zero if something's wrong, so it's scriptable. Run it on the device that isn't behaving as expected first — most "why won't it sync" reports turn out to be a local problem on one side, not a network problem.

If `fluxctl doctor` can't even reach the daemon, see "Daemon appears offline" below before looking at network issues.

---

## mDNS discovery isn't finding the other device

Symptom: both devices are on and paired, but `fluxctl pair show-qr` / the Android scan never resolves the other side, or the tray app shows no peers.

**Interface pinning (already fixed, but relevant if you're on an old build).** Older FluxSync releases bound mDNS to `0.0.0.0`, which on macOS can make announcements go out over `awdl0`/`utunN` instead of the real LAN interface — they never reach the other device even though both are on the same Wi-Fi. Current releases pin mDNS to the actual LAN-bound interface (`crates/fluxsyncd/src/discovery.rs`), so this specific failure mode should not occur on an up-to-date build. If you still see it, update both devices first.

**AP / client isolation.** Many consumer and most guest/hotel/office Wi-Fi networks enable "client isolation" (also called AP isolation or wireless isolation) on the router — it explicitly blocks device-to-device traffic on the same access point, including multicast/mDNS, even though both devices show as connected to the same network. This is a router-level security feature, not something FluxSync can detect or work around. Symptoms: devices see each other on other apps (AirDrop, file shares) failing too, or work fine on your home network but not on a coffee-shop/hotel network. There's no software fix — either disable client isolation in the router admin panel (if it's your network), or use the manual-IP fallback below.

**Manual IP pairing fallback.** If mDNS can't reach the peer for any reason (client isolation, VLANs, firewalled multicast, or a genuinely different subnet like a Tailscale tailnet), pair by address directly:

```sh
fluxctl pair accept --pubkey <b32> --name laptop --addr 192.168.1.42:41889
```

The pairing URI/QR itself already carries an address hint — look for the `a=` parameter in a `fluxsync://pair/<pubkey>?a=<addr>&f=<words>` URI. When multiple addresses are relevant (e.g. LAN and a Tailscale tailnet), `a=` can carry a comma-separated list and the receiving device tries each in order. See the README's Quickstart section for the Tailscale example — the same mechanism applies to any manual-IP scenario, not just Tailscale.

---

## Android: sync stops working after a while / only works with the screen on

This is almost always the OS killing FluxSync's background process, not a FluxSync bug — Android OEMs (Samsung, Xiaomi, OnePlus, Huawei and others) apply aggressive background-process and battery-optimization policies well beyond stock Android, and they routinely kill apps that hold a background service for clipboard sync.

- Check **[dontkillmyapp.com](https://dontkillmyapp.com)** for your specific device/OEM — it documents the exact settings screen and steps per manufacturer to stop this.
- FluxSync's Android app prompts for a battery-optimization exemption during setup; if you dismissed it, go to **Settings → Apps → FluxSync → Battery → Unrestricted** (wording varies by OEM).
- If sync still stops after long idle periods, it's worth re-checking that exemption — some OEMs silently re-restrict it after a system update.

## Android ↔ desktop via `scrcpy`: clipboard "ping-pongs" or duplicates

If you use `scrcpy` to mirror/control your Android device from a desktop, its own clipboard auto-sync feature will race with FluxSync's — each one sees the other's write as a new clipboard change and re-broadcasts it, producing a ping-pong loop or duplicate entries.

Fix: launch `scrcpy` with its clipboard autosync disabled and let FluxSync be the only thing syncing the clipboard:

```sh
scrcpy --no-clipboard-autosync
```

## Daemon appears offline / `fluxctl` can't connect

Symptoms: `fluxctl status` or `fluxctl doctor` reports it can't reach the daemon; the tray icon shows a disconnected state.

- Confirm the daemon process is actually running: on macOS/Linux, `pgrep -f fluxsyncd`; on Windows, check Task Manager.
- On desktop, the tray app manages the daemon lifecycle for you — if you're running the tray app but the daemon isn't up, quit and relaunch the tray app rather than starting `fluxsyncd` by hand alongside it (running two copies will fight over the IPC socket and the UDP port).
- If you're running the daemon manually (headless / server use), check its stdout/stderr for a bind error — a stale IPC socket file from an unclean shutdown (`~/.fluxsync/sock` on Unix) or the UDP port (`41889`) already in use by a previous instance are the two common causes. Removing the stale socket file (with the daemon confirmed not running) and restarting resolves it.
- On Linux, if you're running headless under `systemd --user`, see [`HEADLESS-LINUX.md`](./HEADLESS-LINUX.md) for the service-unit setup and its own diagnostic steps.

---

If none of the above matches what you're seeing, check [`FAQ.md`](./FAQ.md) for a "why does it do X" question, or open an issue with the output of `fluxctl doctor` attached.
