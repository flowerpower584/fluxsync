# FluxSync Insecure Defaults Audit — 2026-05-25

Scope: fail-open patterns that let the daemon and Tauri tray run insecurely with default config. Surfaces: `crates/fluxsyncd/src/{config,cmd,keystore,discovery,handshake,ipc,transport,main}.rs`, `apps/macos-tray/src-tauri/`, env-var handling, hardcoded secrets, Windows ACL.

Tally: **3 High / 4 Medium / 4 Low**.

---

## H1 — Hardcoded Sentry DSN + `send_default_pii = true` shipped to all users

**File:** `crates/fluxsyncd/src/main.rs:46-50`

```rust
let _guard = sentry::init(("https://9c9d519251cf44cc9149f318b383f4f5@o4511345219600384.ingest.de.sentry.io/4511345258659920", sentry::ClientOptions {
    release: sentry::release_name!(),
    send_default_pii: true,
    ..Default::default()
}));
```

**Risk:** Every `fluxsyncd` boot ships telemetry — including PII (`send_default_pii: true` enables IP, username, request bodies in events) — to a hardcoded Sentry org owned by you. There is no opt-out, no `if env::var("FLUXSYNC_TELEMETRY").is_ok()` gate, no privacy notice. README/longDescription advertise "No servers, no accounts" — this contradicts the product promise and is a GDPR/CCPA exposure (personal data exfil from a user's LAN-only clipboard tool). Anyone who breaches the Sentry org gets crash dumps from every install, which can include clipboard fragments inside panic messages or stack-frame variables.

**Fix:** gate behind explicit opt-in env var, default OFF. `send_default_pii: false` always. Pull the DSN from a build-time env so OSS forks don't ship your DSN.

---

## H2 — Default UDP bind `0.0.0.0` exposes daemon on every interface

**File:** `crates/fluxsyncd/src/main.rs:27` + `crates/fluxsyncd/src/config.rs:65`

```rust
#[arg(long, default_value = "0.0.0.0")]
udp_bind: String,
// ...
udp_bind: String::from("0.0.0.0"),
```

**Risk:** Daemon listens on **every** local interface by default — VPN tunnels, public Wi-Fi (hotel/airport/coffee shop), tethered USB, virtual adapters. `lan_only_handshakes=true` (config.rs:77) gates *handshake initiators* by source IP being RFC1918/loopback/link-local, but the UDP socket itself still receives traffic from any reachable network. That gives free DoS surface (rate-limiter then absorbs it, see `rate_limit.rs`) and exposes Noise-IK parsing + handshake state-machine to public-internet attackers — bug-class amplifier even with the LAN-only filter. macOS bonjour over 0.0.0.0 also broadcasts `peer_id` + `static_pub` to every connected network.

**Fix:** default to `127.0.0.1` for IPC-only mode, or enumerate non-public interfaces and bind each. At minimum drop public IPs at socket layer, not just handshake layer.

---

## H3 — Windows Named Pipe has no ACL / security descriptor

**File:** `crates/fluxsyncd/src/ipc.rs:98-130`

```rust
impl IpcServer {
    pub async fn bind(path: &Path) -> io::Result<Self> {
        let first = ServerOptions::new()
            .first_pipe_instance(true)
            .create(path)?;
```

**Risk:** On Unix, `ipc.rs:38-89` does the right thing — umask 0o077, 0600 socket, 0700 parent, flock. On Windows the Named Pipe is created with the default DACL, which on most systems grants **Everyone / Authenticated Users** generic read/write. Any local user (including low-priv RDP sessions, guest accounts, low-IL processes) can connect to `\\.\pipe\fluxsync`, send `{"subscribe":"cmd"}` and issue `Push`, `Pull`, `Unpair`, `Revoke`, `Shutdown`, `PairAccept` — i.e. inject clipboard content into another user's session and tear down their trust set. No auth on the IPC at all; security model assumes filesystem-level isolation that Windows does not provide by default.

**Fix:** set a SDDL on `ServerOptions` restricting to current user SID (e.g. `D:(A;;GA;;;<currentUserSid>)`). Match the Unix 0600 invariant.

---

## M1 — Keystore fallback to `./fluxsync-keystore` when `$HOME` missing

**File:** `crates/fluxsyncd/src/main.rs:59-62`

```rust
let keystore_dir = args
    .keystore_dir
    .or_else(default_keystore_dir)
    .unwrap_or_else(|| PathBuf::from("./fluxsync-keystore"));
```

**Risk:** If `HOME` unset (cron, systemd unit without `User=`, some container layouts), the daemon writes `peers.json` + Android `identity.bin` fallback into **CWD**. CWD is unpredictable — could be `/`, `/tmp`, a world-readable working dir of whatever launched the daemon. `ensure_dir` chmods 0700 *after* creation, leaving a small race window, and any pre-existing `./fluxsync-keystore` is reused without ownership check.

**Fix:** hard fail on missing `$HOME` instead of CWD fallback. Same pattern for `ipc_path` fallback to `./fluxsync.sock` (main.rs:57) — fail-secure beats fail-open.

---

## M2 — `FLUXSYNC_DAEMON_BIN` env var = arbitrary binary execution at tray boot

**File:** `apps/macos-tray/src-tauri/src/ipc.rs:263-269`

```rust
if let Some(p) = std::env::var_os("FLUXSYNC_DAEMON_BIN") {
    let p = PathBuf::from(p);
    if p.is_file() {
        return Ok(p);
    }
}
```

**Risk:** Anything that can set the tray's environment (LaunchAgent plist swap, `.zshenv`, malicious shortcut on Windows) makes the tray spawn an attacker-chosen binary detached + setsid'd at every login. No path validation, no signature check, no notarization check. This is a persistence + privilege-laundering vector — the malicious "daemon" runs under the user's UID with the tray's notification + autostart entitlements.

**Fix:** restrict to debug builds (`#[cfg(debug_assertions)]`), or require the env var to point inside the app bundle / a signed-binary allow-list. At minimum, log the override loudly.

---

## M3 — `FLUXSYNC_IPC_PATH` env var lets unsigned process redirect tray IPC

**File:** `apps/macos-tray/src-tauri/src/ipc.rs:19-29`

```rust
fn ipc_path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("FLUXSYNC_IPC_PATH") {
        return Ok(PathBuf::from(p));
    }
```

**Risk:** Same env-var injection class as M2. An attacker who can set tray env can point the tray at an attacker-controlled UNIX socket, MITM every `pair_accept` / `push` / `status` call, harvest `pubkey_b32` + SAS, and steer the user into pairing with the attacker's daemon. The comment says "so contributors can point the tray at a non-default daemon during development" — should be debug-only.

**Fix:** `#[cfg(debug_assertions)]` gate, or refuse if path is outside `$HOME/.fluxsync/`.

---

## M4 — `EnvFilter` `RUST_LOG` lets any caller upgrade daemon to debug logging in prod

**File:** `crates/fluxsyncd/src/main.rs:130-138`

```rust
fn init_tracing(verbose: bool) {
    let default_filter = if verbose { "debug" } else { "info" };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
```

**Risk:** Anyone with env access can set `RUST_LOG=trace` to force the daemon into verbose mode, which (combined with H1 Sentry pipeline) increases the surface for sensitive data leakage to crash reports + on-disk logs (`~/.fluxsync/daemon.log` from `ipc.rs:234-245`, append-only, never rotated). Multiple places log peer_id prefixes, SAS words, source addresses — fine at INFO, noisier under DEBUG/TRACE.

**Fix:** in release builds cap the filter at `info` regardless of `RUST_LOG`, or strip secrets from log macros independently.

---

## L1 — `withGlobalTauri: true` exposes invoke() to any frame

**File:** `apps/macos-tray/src-tauri/tauri.conf.json:13`

```json
"withGlobalTauri": true,
```

**Risk:** Injects `window.__TAURI__` into every WebView frame. The CSP (`default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:`) blocks remote script, but `unsafe-inline` for styles + any XSS in `pair.html` / `settings.html` / `index.html` (which render the SAS words, peer name, history items) becomes pivot → invoke `fluxsync_push`, `fluxsync_pair_from_uri`, etc. No script-src `'unsafe-inline'` is good; but global Tauri removes the explicit allow-list boundary.

**Fix:** flip to `false`, import the invoke API per-window. Tighten CSP to drop `'unsafe-inline'` (rare to need styled inline on this surface).

---

## L2 — Tauri `core:default` permission bundle is permissive

**File:** `apps/macos-tray/src-tauri/capabilities/default.json:7-18`

`core:default` grants the union of window/event/path/etc allow-lists; combined with `shell:allow-open` and `dialog:default` the capability surface is broader than the 14 commands actually used. `shell:allow-open` + `fluxsync_open_url(url: String)` (lib.rs:104-108) lets the JS side pass any string to `open <url>` — which on macOS will happily open `file:///`, `x-apple-...`, JXA scripts, etc.

**Risk:** XSS / compromised remote string → arbitrary `open` invocation. Today the only caller is internal, but the surface is unrestricted.

**Fix:** scope `shell:allow-open` to https-only URLs, or validate scheme in `fluxsync_open_url` before spawning `open`.

---

## L3 — `lan_only_handshakes` opt-out is binary, no per-peer trust

**File:** `crates/fluxsyncd/src/config.rs:48-52, 77`

```rust
pub lan_only_handshakes: bool,
// default true
lan_only_handshakes: true,
```

Default is secure (true). But there's no CLI flag exposed (main.rs has no `--allow-wan-pair`), and no documented way to flip it — so the OFF code-path can only be hit by callers that build `DaemonConfig` directly. That's good *unless* a future tray setting adds it without UX explaining the implication: a user flipping a "Allow internet pairing" toggle has no protection against handshake-flood from WAN scanners.

**Risk:** future regression. Document the invariant + add a guard rail (rate-limiter must be active when this is false).

**Fix:** add a `#[deprecated]`-style warning log on boot if it's flipped off, plus a clippy::missing_docs reminder.

---

## L4 — `peers.json` on Android lives in app-private dir but no keystore

**File:** `crates/fluxsyncd/src/keystore.rs:175-188`

```rust
#[cfg(target_os = "android")]
{
    let path = dir.join(IDENTITY_FILE);
    // ...
    write_secret_atomic(&path, &secret)?;
```

Documented as v0.6.0+ TODO ("future migration to Android Keystore via JNI tracked separately"). Today, root or `adb backup`-enabled devices, or any app sharing UID (rare), can lift the long-term X25519 secret. Mode 0600 is enforced (line 283), and the app sandbox does most of the work, but this is the only secret in the codebase not stored in a hardware-backed credential store.

**Risk:** rooted Android device compromise = identity theft + clipboard impersonation.

**Fix:** Android Keystore via UniFFI/JNI (already in roadmap). Until then, document threat model in `THREAT-MODEL.md`.

---

## Notes — patterns that LOOK fail-open but ARE fail-secure

- `keystore.rs:165-172`: keychain backend error → **refuses** to fall back to plaintext `identity.bin`. Correct fail-secure.
- `handshake.rs:175-185`: unknown peer + pairing window closed → bails with `"untrusted peer"`. Correct fail-secure.
- `handshake.rs:179`: `unwrap_or(false)` on `window_open` — fail-closed (no window = no TOFU).
- `ipc.rs:38-89` Unix: umask 0o077 + flock + 0600 chmod is solid.
- `transport.rs:208-228` send_encrypted: aborts on generation mismatch — fail-secure against nonce reuse.

---

## Top 3 fail-open to fix immediately

1. **H1 Sentry DSN + PII** — privacy/GDPR critical, contradicts marketing, exfiltrates from every install. Fix: gate behind opt-in env, default OFF.
2. **H3 Windows Named Pipe ACL** — every local user can drive the IPC. Fix: set SDDL restricting to current user SID.
3. **H2 UDP bind 0.0.0.0 default** — daemon listens on every public interface. Fix: bind to enumerated private interfaces or `127.0.0.1`; force WAN gate at socket layer.
