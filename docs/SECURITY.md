# FluxSync — Security & Threat Model (v0.1)

> One sentence: every byte that leaves the device is encrypted with ChaCha20-Poly1305 inside a Noise IK session keyed to a peer the user explicitly paired. There is no fallback to plaintext, ever.

---

## 1. Cryptographic stack

| Concern              | Algorithm                                      |
|----------------------|------------------------------------------------|
| Key agreement        | X25519 (inside Noise IK)                       |
| AEAD                 | ChaCha20-Poly1305 (RFC 8439)                   |
| Hash                 | BLAKE2s (inside Noise), BLAKE3 (content + fingerprint) |
| Handshake pattern    | `Noise_IK_25519_ChaChaPoly_BLAKE2s` (via `snow`) |
| Long-term identity   | X25519 static keypair, stored in OS keychain   |

`fluxsync-crypto` wraps `snow`. There is no in-house cryptography. The `snow` API call sites are concentrated in one file (`crypto/src/session.rs`) so a future audit has one surface to inspect.

---

## 2. Threat model

### 2.1 Passive LAN attacker (sniff Wi-Fi)

- **Goal**: read the user's clipboard.
- **What they see on the wire**: 12-byte Noise nonce + ChaCha20-Poly1305 ciphertext + 16-byte tag, plus mDNS service advertisements (`_fluxsync._udp.local`, peer name, IP).
- **Mitigation**: end-to-end encryption is mandatory. There is no plaintext fallback; if a frame arrives with a missing or invalid tag the Session is destroyed and the FSM returns to `Discovering`.
- **Residual leakage**: traffic-shape metadata (timing, datagram size, peer IP, peer hostname). Out of scope for v0.1; padding and cover traffic are tracked for v0.2.

### 2.2 Active LAN attacker (MITM, ARP spoof, rogue AP)

- **Goal**: convince A and B that the attacker is the other peer, then forward clipboard items in the clear.
- **Attack path**: respond to the mDNS query with the attacker's address; complete a Noise handshake using a freshly generated identity.
- **Mitigation**: Noise IK requires both sides to know the other's static public key **before** the handshake. During `fluxctl pair --qr` the user transports A's static pubkey out-of-band (camera-scanning a QR on B's phone, or pasting the QR's text payload into `fluxctl pair --accept` on a desktop). Both daemons then derive a 6-word fingerprint (BLAKE3 → BIP-39 wordlist subset, ~66 bits of entropy) and refuse to finalize the pairing unless the user types `y` on both sides. After pairing, the only key authorized to handshake is the one that was confirmed.
- **Why 6 words**: ~66 bits of entropy. Comfortably above the ~50-bit threshold an active LAN attacker would need to brute-force a fingerprint collision in real time, while keeping the verbal compare short enough that a user actually does it. Compared with the 4-word (~44 bit) variant some peers use, the extra two words cost the user ~3 seconds and remove ~22 bits of attacker margin.

### 2.3 Compromised device (lost or stolen phone)

- **Goal**: an attacker with the unlocked phone reads the desktop clipboard.
- **Mitigation**: from the desktop, run `fluxctl revoke <peer-id>`. This removes the peer's static pubkey from the local keyring. The next handshake from the lost phone is rejected at the Noise layer (the "I" in IK has no matching responder key on our side).
- **Limitation**: revocation is local. Each device that has paired with the lost phone must run `revoke` independently. No central revocation list in v0.1 (would defeat zero-knowledge).
- **Anti-replay**: handshakes use fresh ephemerals; a captured handshake cannot be replayed against a revoked entry because the responder's static key has been deleted.

### 2.4 Local malware (untrusted process on the same machine)

- **Goal**: extract the long-term identity private key, then impersonate this device on the LAN.
- **Mitigation**: the private key never appears in a file on disk. It lives in the OS keychain:
  - **macOS**: `security` framework, item class `kSecClassGenericPassword`, service `app.fluxsync.identity`, access scoped to the running user.
  - **Windows**: DPAPI via Credential Manager, `LegacyGeneric:target=app.fluxsync.identity`.
  - **Linux**: Secret Service (libsecret), collection `Default`, attribute `application=fluxsync`.
  - **Android**: Keystore, key alias `fluxsync.identity`, hardware-backed when available.
- **Limitation**: a local process running as the same user with debugger privileges (or with the user's keychain unlocked and explicit "Always allow") can still read the key. This is the same trust boundary as `ssh-agent` and `gpg-agent` — any tool that hands you cryptographic material on the same UID has this floor. We do not pretend to defend below this line.
- **Anti-tamper**: the IPC socket's permissions are `0600`; only the user's processes can connect.

### 2.5 Future relay (out of v0.1 scope, but designed for)

- **Goal**: a relay operator wants to know what users are syncing.
- **Mitigation when the relay arrives in v0.2**: the relay sees the same opaque ChaCha20 ciphertexts that a passive LAN sniffer would see. It additionally sees `peer_id` source/dest pairs (32-byte hashes that do not commit to the user's identity unless they leak it elsewhere). The relay never holds a key.
- **No telemetry, no logging of cleartext, no metadata sharing**. This is enforced by code: there is no TLS interceptor, no plaintext code path, no JSON metadata leaving the daemon.

---

## 3. Out of scope for v0.1

- **Root-on-host attacker**: if the OS is owned, every defense is moot. Detect, do not defend.
- **Side-channels**: timing, power-analysis, EM emissions. We do not have audited constant-time guarantees beyond what `snow` provides.
- **Quantum-capable adversaries**: X25519 / ChaCha20 are not post-quantum. v2 will rotate to a hybrid suite (X25519 + Kyber768) once `snow` or a successor exposes one.

---

## 4. Trust boundaries (one-line each)

| Boundary                           | Trust direction        | Mechanism                  |
|------------------------------------|------------------------|----------------------------|
| User ↔ daemon                      | mutual                 | UNIX socket / Named Pipe with `0600` permissions |
| Daemon ↔ peer daemon               | mutual, after pairing  | Noise IK with pre-shared static keys |
| Daemon ↔ OS keychain               | daemon trusts OS       | `keyring` crate            |
| Daemon ↔ local clipboard           | daemon trusts OS       | `arboard` crate            |
| Daemon ↔ network interface         | daemon trusts OS       | `mio` / `tokio` UDP        |

---

## 5. Reporting a vulnerability

Email Dethie at the address in `Cargo.toml`, PGP-encrypted if you have the key (fingerprint published in the README). Please give 90 days before public disclosure. There is no bug-bounty program; this is a side project and we will not pay you, but we will credit you in the changelog if you want.

---

## 6. Auditable surface

- All cryptographic calls live under `crates/fluxsync-crypto/src/`. Two files: `identity.rs` (key management) and `session.rs` (Noise + AEAD).
- All key material crosses the FFI boundary as opaque `[u8]`; the Kotlin side never sees plaintext clipboard either, because the daemon is the one that decrypts and writes to the system clipboard.
- `unsafe` is forbidden outside the FFI shim file in `fluxsync-mobile-ffi/src/lib.rs`. Every `unsafe` block carries a `// SAFETY:` comment explaining the invariant.
- `cargo deny` runs in CI to refuse known-vulnerable crates and incompatible licenses.
