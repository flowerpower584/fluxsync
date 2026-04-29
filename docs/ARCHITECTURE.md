# FluxSync — Architecture (v0.1)

> Local-first, peer-to-peer clipboard sync for 2 devices on the same LAN.
> One Rust workspace. Daemon + CLI on desktop. Same daemon as a library on Android via UniFFI.

---

## 1. Workspace layout

```
fluxsync/
├── Cargo.toml                workspace manifest
├── crates/
│   ├── fluxsync-proto/       wire types, CBOR codec
│   ├── fluxsync-crypto/      Noise IK + ChaCha20-Poly1305 wrapper
│   ├── fluxsync-core/        pure logic: FSM, policy, dedup, clocks, classifier
│   ├── fluxsyncd/            tokio daemon: net, mDNS, IPC, clipboard, battery
│   ├── fluxctl/              CLI talking to fluxsyncd over IPC
│   └── fluxsync-mobile-ffi/  UniFFI bindings exposing the daemon as a Kotlin library
├── apps/android/             Kotlin/Compose skeleton that loads the .so
├── docs/                     this directory
├── design/                   read-only frontend bundle (do not edit)
└── .github/workflows/        CI matrix
```

### Dependency graph

```
                        ┌────────────────────┐
                        │ fluxsync-proto     │ (CBOR types, no deps on others)
                        └────────────────────┘
                                  ▲
                                  │
            ┌─────────────────────┼─────────────────────┐
            │                     │                     │
┌────────────────────┐   ┌────────────────────┐   ┌────────────────────┐
│ fluxsync-crypto    │   │ fluxsync-core      │   │                    │
│ Noise + cipher     │   │ FSM + policy +     │   │                    │
│ + key fingerprint  │   │ dedup + classify   │   │                    │
└────────────────────┘   └────────────────────┘   │                    │
            ▲                     ▲               │                    │
            └──────────┬──────────┘               │                    │
                       │                          │                    │
            ┌────────────────────┐                │                    │
            │ fluxsyncd          │                │                    │
            │ tokio runtime      │                │                    │
            │ mDNS, UDP, IPC,    │                │                    │
            │ clipboard, battery │                │                    │
            └────────────────────┘                │                    │
                       ▲                          │                    │
            ┌──────────┴──────────┐               │                    │
            │                     │               │                    │
┌────────────────────┐  ┌──────────────────────────┐                   │
│ fluxctl (CLI)      │  │ fluxsync-mobile-ffi      │                   │
│ binary, calls IPC  │  │ UniFFI exposes daemon    │                   │
└────────────────────┘  │ as Kotlin-friendly API   │                   │
                        └──────────────────────────┘                   │
                                                                       │
        crates above never depend on the ones below. Only one direction. │
```

The strict downward arrow rule keeps `fluxsync-core` testable in isolation: no tokio, no I/O, no clocks of its own.

---

## 2. Dataflow — clipboard outbound

```
[user copies "github.com" on M1]
            │
            ▼
┌────────────────────────────┐
│ fluxsyncd::clipboard       │  arboard polls every 500 ms
│  emits raw text            │
└────────────────────────────┘
            │  (text, timestamp)
            ▼
┌────────────────────────────┐
│ fluxsync-core::classify    │  kind = url, sensitive = false
│  + dedup (BLAKE3 hash)     │  drop if hash in 50-item ring
└────────────────────────────┘
            │  ClipboardItem
            ▼
┌────────────────────────────┐
│ fluxsync-proto::Frame      │  CBOR encode
└────────────────────────────┘
            │  bytes
            ▼
┌────────────────────────────┐
│ fluxsync-crypto::Session   │  ChaCha20-Poly1305 encrypt
└────────────────────────────┘
            │  ciphertext
            ▼
┌────────────────────────────┐
│ fluxsyncd::transport (UDP) │  port 41889
└────────────────────────────┘
            │
            ▼
                          [LAN]
            │
            ▼
┌────────────────────────────┐
│ peer fluxsyncd::transport  │
└────────────────────────────┘
            │
            ▼  (decrypt, decode, dedup)
┌────────────────────────────┐
│ peer fluxsyncd::clipboard  │  arboard write
│  → emits StateChanged      │  → IPC fanout to UI subscribers
└────────────────────────────┘
```

Inbound clipboard (peer → us) follows the same path in reverse, ending at `fluxsyncd::clipboard::write` and a state event published to all IPC subscribers.

---

## 3. Tokio task model (inside `fluxsyncd`)

Each long-lived concern is its own task. Tasks talk through tokio `mpsc` channels carrying `fluxsync_core::Event`. `fluxsync_core::App` is the only place that holds mutable state — every other task is a producer or consumer.

| Task            | Loop period / trigger        | Produces / consumes                                  |
|-----------------|------------------------------|-------------------------------------------------------|
| `clipboard_in`  | 500 ms poll (`arboard`)      | → `Event::LocalClipboardChange`                       |
| `battery`       | 30 s poll (`starship-battery`) | → `Event::BatteryChanged`                           |
| `discovery`     | mDNS rescan every 30 s       | → `Event::PeerSeen` / `PeerLost`                      |
| `transport_rx`  | UDP recv loop                | decrypt + decode → `Event::FrameReceived`             |
| `heartbeat`     | 5 s tick                     | → `Event::Tick` (transport sends Heartbeat)           |
| `net_change`    | `if-watch` event             | → `Event::NetworkChanged` (flush + re-discover)       |
| `ipc_listener`  | accept loop (UNIX/NamedPipe) | spawns per-client `ipc_session` tasks                 |
| `ipc_session`   | per CLI connection           | reads `Cmd`, asks `App` for response, optional sub    |
| `app`           | merges all `Event` streams   | mutates state, emits `Action` (Send / EmitState / …)  |
| `transport_tx`  | drains outbound `Action::Send` | encrypt + encode → UDP send                         |

Shutdown: a single `tokio::sync::Notify` is fired on SIGINT / SIGTERM (Unix) or Ctrl-C (Win). Every loop selects on `notify.notified()` and exits cleanly. No `unwrap()` in any task body.

---

## 4. State surface (matches the frontend)

`fluxsync-core::State` is serialised to JSON over the IPC `state` channel and consumed verbatim by every UI:

```json
{
  "on": true,
  "batteryLevel": 87,
  "batteryThreshold": 15,
  "charging": false,
  "peerName": "Galaxy S21 Ultra",
  "peerBattery": 64,
  "peerCharging": false,
  "history": [
    { "kind": "url|text|code", "preview": "...", "time": "HH:MM" }
  ],
  "status": "inactive|syncing|paused|critical",
  "version": "0.4.2",
  "linkLatencyMs": 12,
  "cipher": "chacha20-poly1305"
}
```

`status` is **derived** in `fluxsync-core::policy::status_for(state)` and never set directly. Rule:

```
if !on                                                       → "inactive"
if peerBattery <= 5                                          → "critical"
if on && peerBattery <= threshold && !peerCharging           → "paused"
otherwise                                                    → "syncing"
```

`history` is a 50-item ring buffer in RAM. The IPC layer slices `[..5]` before serialising (the UIs never need more).

A second IPC channel (`logs`) carries `{time, level, msg}` events one per line (NDJSON). The same daemon emits both raw `tracing` JSON to stderr **and** plain-English versions to the `logs` channel via a `friendly!()` macro.

---

## 5. IPC abstraction

Daemon ↔ CLI uses one transport per platform. Same wire format on both: NDJSON, one JSON object per line.

| Platform        | Implementation                                  | Path / name                          |
|-----------------|--------------------------------------------------|--------------------------------------|
| Linux / macOS   | AF_UNIX SOCK_STREAM (`tokio::net::UnixListener`) | `~/.fluxsync/sock`                   |
| Windows         | Named Pipe (`tokio::net::windows::named_pipe`)   | `\\.\pipe\fluxsync`                  |

A trait `IpcListener / IpcStream` lives in `fluxsyncd::ipc`. Higher layers depend only on the trait.

**Channels per connection.** A client opens one connection and sends an opening line `{ "subscribe": "state" | "logs" | "cmd" }`. After that:

- `cmd`: request/response. Each request is one JSON line; the daemon answers with one JSON line.
- `state`: server-push. The daemon writes one full `State` JSON object on every change (no diffs).
- `logs`: server-push. NDJSON `{time, level, msg}` on every emitted log entry.

No HTTP, no port. Permissions on the socket are `0600`.

---

## 6. Storage

- **In RAM**: history ring (50), peers, last battery samples, Lamport clock, current FSM phase.
- **On disk**: nothing of substance.
- **In OS keychain** (`keyring` crate): the long-term identity private key and the peer revocation set. Mapping: macOS Keychain, Windows DPAPI/Credential Manager, Linux Secret Service, Android Keystore via the FFI host.

No SQLite. No config file is needed for v0.1; defaults are baked in and CLI commands persist threshold / overrides via `fluxctl set-*` which calls into the daemon.

---

## 7. Concurrency / safety rules

- `unsafe` is forbidden anywhere outside FFI boundaries; if it appears, it carries a `// SAFETY:` line explaining the invariant.
- No `.unwrap()` / `panic!()` outside `#[cfg(test)]`.
- All tokio tasks are joinable; the daemon shutdowns in one path that drives `Notify::notify_waiters()` once, then awaits each task handle.
- `fluxsync-core` has no `std::sync::Mutex` — it is single-threaded by design, owned only by the `app` task.

---

## 8. What this architecture deliberately does not do

- No mesh > 2 devices (v0.2).
- No HTTP / REST endpoint (v0.2 maybe, only if a real outside-LAN consumer appears).
- No QUIC (UDP custom is enough for one peer).
- No SQLite (RAM ring is enough for 50 items).
- No GUI Linux (CLI is the UI; tray icon comes later via a generic Tauri/Qt shell).
- No telemetry, no auto-update, no central account.

These are not "missing features"; they are deliberate boundaries documented in the v0.1 prompt and re-stated here.
