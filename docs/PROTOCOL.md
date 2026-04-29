# FluxSync — Wire Protocol (v0.1)

> Two protocols live here:
> 1. **Net protocol** — daemon ↔ daemon over LAN. CBOR frames inside ChaCha20-Poly1305 ciphertexts inside UDP datagrams.
> 2. **IPC protocol** — daemon ↔ CLI / UI on the same host. NDJSON over a UNIX socket or a Windows named pipe.

Both are versioned with a single byte field; v0.1 = `0x01`.

---

## 1. Net protocol

### 1.1 Transport

- UDP, port `41889` (`_fluxsync._udp.local` advertised over mDNS).
- Each datagram carries one ciphertext.
- Maximum datagram size is `1232` bytes payload (IPv6 minimum MTU 1280 minus headers minus Noise overhead). Larger items are split into `Chunk` frames (see §1.4).
- No TCP, no QUIC in v0.1. Reliability for clipboard items is provided by application-level `Ack` + retry with exponential backoff (1s, 2s, 4s, … capped at 60s).

### 1.2 Ciphertext envelope (every datagram)

```
| nonce: 12 bytes | ciphertext + tag: N bytes |
```

Where `nonce` is the 96-bit ChaCha20 nonce supplied by the sender's Noise IK transport state and `ciphertext + tag` is the AEAD output of `ChaCha20-Poly1305(key = session_send_key, ad = peer_id_local || peer_id_remote)`.

### 1.3 Plaintext = one CBOR `Frame`

```rust
struct Frame {
    version: u8,    // 0x01 for v0.1
    msg: Msg,       // tagged enum below
}

enum Msg {
    HandshakeInit(HandshakeInit),     // Noise message 1, plaintext-but-authenticated
    HandshakeResp(HandshakeResp),     // Noise message 2
    ClipboardItem(ClipboardItem),
    BatteryStatus(BatteryStatus),
    Heartbeat(Heartbeat),
    Chunk(Chunk),
    Ack(Ack),
    Bye,
}
```

CBOR is encoded with **definite-length** maps and arrays (no streaming indefinite forms). The enum discriminator is the variant name as a CBOR text string in a single-key map: `{"HandshakeInit": {...}}`. Decoders that see an unknown key MUST drop the frame.

### 1.4 Frame payloads

```rust
struct ClipboardItem {
    lamport:        u64,        // sender's Lamport clock at emit time
    hash:           [u8; 32],   // BLAKE3 of payload (for dedup + ack)
    kind:           Kind,       // "text" | "url" | "code"
    payload:        Vec<u8>,    // UTF-8 text bytes; max 256 KiB total once reassembled
    sensitive:      bool,       // sender marked it as secret-like (never persisted in receiver ring)
    wall_time_ms:   u64,        // sender's UNIX millis (display only, NOT used for ordering)
}

struct BatteryStatus {
    lamport:  u64,
    level:    u8,    // 0..=100
    charging: bool,
}

struct Heartbeat {
    lamport:  u64,
    rtt_hint: Option<u32>,   // last measured RTT in ms; helps the peer fill its own state
}

struct Chunk {
    item_id: [u8; 32],   // == ClipboardItem.hash; chunks reassemble into one item
    idx:     u16,        // 0-based, must be < total
    total:   u16,        // total chunk count, must be the same for every chunk of an item;
                         // hard cap: total <= 256 (decoder rejects anything higher to bound
                         // reassembly buffer at 256 KiB and refuse trivial DoS allocations)
    data:    Vec<u8>,    // up to 1024 bytes
}

struct Ack {
    lamport: u64,
    hash:    [u8; 32],   // hash of the item being ack'd
}

struct HandshakeInit {
    peer_id:       [u8; 32],   // BLAKE3(static_pubkey)
    ephemeral_pub: [u8; 32],
    static_pub:    [u8; 32],
    lamport:       u64,
}

struct HandshakeResp {
    peer_id:       [u8; 32],
    ephemeral_pub: [u8; 32],
    static_pub:    [u8; 32],
    lamport:       u64,
}
```

`Kind` is encoded as a lower-case text string. Adding a new variant in v0.2 is a breaking change to be flagged via the `version` byte.

### 1.5 Lamport ordering

- Each side maintains a `u64` clock starting at `0`.
- Outbound: `clock += 1`; the new value is the frame's `lamport` field.
- Inbound: `clock = max(clock, frame.lamport) + 1`.
- **Conflict resolution**: when the same content `hash` arrives from both sides within the dedup window, the one with the **higher `lamport`** wins; ties are broken by lexicographic comparison of the sender's `peer_id` (deterministic, no extra round trip).
- `wall_time_ms` is for the UI's `time: "HH:MM"` display only and is never used for ordering — clocks across devices drift and we do not assume NTP.

### 1.6 Dedup

- Receiver keeps the last 50 `ClipboardItem.hash` values (BLAKE3-256) in a ring buffer.
- An incoming item whose `hash` is already in the ring is acked but not surfaced.
- The sender suppresses re-sending an item that just arrived from the peer by checking the same ring before emitting an outbound `LocalClipboardChange`.

### 1.7 Reliability

- Every `ClipboardItem` is retried until an `Ack` with the matching `hash` arrives, or until 5 attempts have failed. Backoff: `1s · 2^attempts`, capped at `60s`.
- `Heartbeat` is fire-and-forget every 5 s.
- A peer is considered offline after **3 missed heartbeats** (i.e. ~15 s).

---

## 2. State machine (the daemon's view of one peer)

```
                                 ┌──────────┐
              boot, on=false ──▶ │  Idle    │
                                 └────┬─────┘
                              ToggleOn │
                                 ┌─────▼────────┐
              no peer cached ──▶ │ Discovering  │ ◀── PeerLost
                                 └─────┬────────┘
                            PeerSeen   │
                                 ┌─────▼────────┐
                                 │ Handshaking  │
                                 └─────┬────────┘
                          HandshakeOk  │
                                 ┌─────▼────────┐                 ┌──────────────┐
                                 │   Linked     │ ── battery ──▶ │   Paused     │
                                 └─────┬────────┘   policy        └──────┬───────┘
                                       │ ◀────────────────────────────────┘
                            critical batt (≤5%)         charge_override or recovered
                                       │
                                 ┌─────▼────────┐
                                 │   Halted     │ ── ToggleOff ──▶ Idle
                                 └──────────────┘
```

Transition table (events → next phase, side effect):

| From          | Event                          | To            | Action                          |
|---------------|--------------------------------|---------------|---------------------------------|
| Idle          | ToggleOn                       | Discovering   | start mDNS                      |
| Discovering   | PeerSeen                       | Handshaking   | send HandshakeInit              |
| Discovering   | NetworkChanged                 | Discovering   | flush peers, restart mDNS       |
| Handshaking   | FrameReceived(HandshakeResp)   | Linked        | open Session, EmitState         |
| Handshaking   | timeout (5 s)                  | Discovering   | EmitLog WARN                    |
| Linked        | BatteryChanged(self/peer)      | Linked/Paused | apply policy (§3)               |
| Linked        | LocalClipboardChange           | Linked        | classify, dedup, Send ClipboardItem |
| Linked        | FrameReceived(ClipboardItem)   | Linked        | dedup, write clipboard, Ack     |
| Linked        | PeerLost                       | Discovering   | EmitState (status=inactive)     |
| Linked        | self battery ≤ 5%              | Halted        | EmitState (status=critical)     |
| Paused        | BatteryChanged → above thresh. | Linked        | EmitState (status=syncing)      |
| Paused        | Reconnect after offline        | Linked        | **burst mode**: send last 5 items only |
| Halted        | BatteryChanged → above 5%      | Linked        | EmitState                       |
| any           | ToggleOff                      | Idle          | close Session, EmitState        |

Unknown event in current phase = no-op + DEBUG log.

---

## 3. Battery policy

`status_for(state)` lives in `fluxsync-core::policy` and is the single source of truth for the `status` field exposed to UIs.

```text
inactive  if !on
critical  if peerBattery <= 5
paused    if on && peerBattery <= threshold && !peerCharging
syncing   otherwise
```

`charge_override` (default true) overrides `paused` whenever the *low* device is plugged in: a peer below threshold but `peerCharging == true` keeps the link `syncing`.

Self-side mirrors the same rule for our device (`batteryLevel`/`charging`); the result is the **worse** of the two — if either side wants to pause, both pause. UIs distinguish with copy ("paused — peer below 15%" vs "paused — local low battery").

Metered network (Android only in v0.1, exposed via the FFI host) forces `paused` regardless of battery.

---

## 4. Pairing (LAN, QR-driven)

v0.1 supports exactly one pairing mode: `fluxctl pair --qr` on the same Wi-Fi.

1. Initiator (device A) runs `fluxctl pair --qr`.
   - Daemon generates a fresh ephemeral static keypair just for the pairing session (separate from the long-term identity, which is created on first run if absent).
   - Outputs an ASCII QR encoding `peer_id_a || ephemeral_pub_a || transient_token`.
   - Prints the 6 safe-words derived from `peer_id_a` (BLAKE3 → BIP-39 wordlist subset, ~66 bits of entropy).
2. Responder (device B) runs `fluxctl pair --accept` and pastes the QR's textual payload on stdin (one line, base32). Webcam-driven scanning is **Android-only** (handled in the Kotlin host via the FFI) and out of scope for the desktop CLI. Daemon:
   - Parses the pasted line.
   - Initiates Noise IK to A using A's `static_pub` as the responder's known key.
   - On success, derives the same 6 safe-words and prints them. The user compares with the words shown on A.
3. The user types `y` on both sides to confirm. Both daemons persist the peer's static public key in the keyring's "peers" set.

**No relay, no STUN in v0.1.** The `--code <6digits>` fallback was deliberately dropped from v0.1 (planned for v0.2 with a proper relay).

Revocation: `fluxctl revoke <peer-id>` removes the peer's static key from the keyring; subsequent handshakes from that key are refused at the Noise layer.

---

## 5. IPC protocol (daemon ↔ CLI/UI)

### 5.1 Connection

A client opens the platform IPC and sends one opening JSON line:

```json
{ "subscribe": "cmd" }
```

Allowed values: `cmd`, `state`, `logs`. After this opening line the channel role is fixed for the lifetime of the connection.

### 5.2 Command channel (`cmd`)

Request:

```json
{ "id": 7,  "op": "status" }
{ "id": 8,  "op": "peers" }
{ "id": 9,  "op": "push", "text": "https://github.com" }
{ "id": 10, "op": "pull" }
{ "id": 11, "op": "tail", "n": 20 }
{ "id": 12, "op": "set_threshold", "value": 30 }
{ "id": 13, "op": "set_charge_override", "value": true }
{ "id": 14, "op": "pair_start" }
{ "id": 15, "op": "pair_confirm", "peer_id": "..." }
{ "id": 16, "op": "revoke", "peer_id": "..." }
{ "id": 17, "op": "debug_capture" }
```

Examples for the two boolean/number setters (the CLI sends one of these every time the user adjusts a slider or toggle in the UI):

```json
{ "id": 12, "op": "set_threshold",       "value": 30 }    // 5..=50
{ "id": 13, "op": "set_charge_override", "value": true }  // bool
```

`tail` returns the last `n` log entries as a one-shot array (no streaming); for a live feed, open a separate `{"subscribe":"logs"}` connection.

Response (always one JSON line, `id` echoes the request):

```json
{ "id": 7, "ok": true,  "data": { /* full State, see ARCHITECTURE §4 */ } }
{ "id": 9, "ok": true }
{ "id": 9, "ok": false, "err": "daemon paused; toggle on first" }
```

### 5.3 State channel

After `{"subscribe":"state"}`, the server pushes one JSON line per change. The first line is always the current snapshot. Lines never contain newlines inside (NDJSON).

### 5.4 Logs channel

After `{"subscribe":"logs"}`, the server streams:

```json
{ "time": "14:32:07", "level": "OK",   "msg": "Clipboard updated — 38 chars from S21 Ultra." }
{ "time": "14:32:01", "level": "INFO", "msg": "Galaxy S21 Ultra came back online." }
```

Levels are exactly `OK | INFO | SYNC | WARN | ERR` to match the frontend's filter buttons.

### 5.5 Errors

Daemon refuses an unknown `op` with `{ "ok": false, "err": "unknown_op" }` and keeps the connection open. Malformed JSON closes the connection.

---

## 6. Versioning

- The byte `Frame.version` covers net frames.
- The IPC layer carries no explicit version; CLI and daemon are released together. A version mismatch (build hashes baked in) returns `{"ok": false, "err": "version_mismatch", "expected": "0.4.2", "got": "0.4.1"}` on the very first command and the connection is closed.
