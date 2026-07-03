# Chaos harness (DIR-P1-03, gate G2)

A local, reproducible harness that tortures a loopback pair of real
`fluxsyncd` processes — process kills, freezes, port contention, and
boot-order races — and asserts they recover. Lives at
`crates/fluxsyncd/tests/chaos_harness.rs`, driven by `scripts/chaos.sh`.

## Running it

```sh
scripts/chaos.sh                  # all 5 scenarios (several minutes)
scripts/chaos.sh kill9_restart    # one scenario (substring match)
CHAOS_SEED=1234 scripts/chaos.sh sigstop_wake   # reproduce a specific run
```

Every scenario draws its own timing randomness from a seed it logs on
stderr (`[chaos:<name>] seed=... (reproduce with CHAOS_SEED=...)`), so a
failure is replayable. `scripts/chaos.sh` prints a scenario-by-scenario
PASS/FAIL summary at the end and exits non-zero if any scenario failed.

The scenarios are `#[ignore]`d (`cargo test -p fluxsyncd` stays fast and
green without them) and run real wall-clock waits — backoff timers,
simulated sleeps, a 60s idle window — so this is not something to run on
every push. See `.github/workflows/chaos.yml` for the scheduled subset.

## How daemons are driven

Each scenario spawns the actual `fluxsyncd` binary (not the in-process
`DaemonConfig`/`run()` shortcut the other integration tests use) as a
real OS subprocess, because `kill -9`, `SIGSTOP`/`SIGCONT`, and UDP port
contention only mean something against a real process. `FLUXSYNC_NO_KEYCHAIN=1`
plus an isolated `--keystore-dir`/`--ipc-path` per daemon keeps this
hermetic — no macOS keychain prompts, no touching `~/.fluxsync`.

Pairing goes through the real IPC verbs a user would drive
(`PairShow` → `PairAccept { addr: Some(..) }` on loopback → `PairConfirm`
on both sides, since FS-052 gates the initiator too), because
`DaemonConfig::test_pair` isn't reachable from the CLI binary. Every
assertion reads the daemon's own IPC status surface
(`CmdOp::Status` → `State.phase`, `State.history`, `State.metrics`) —
never log scraping.

## Scenarios

| Scenario | Proves toward G2 |
|---|---|
| `KILL9_RESTART` | A hard process kill (simulates a crash/OOM-kill) mid-traffic, then an immediate restart: identity + trust + vault history all persist (rehydration is asserted on its own, before any re-link), an explicit reconnect-by-address re-links, and the already-delivered item is never duplicated. Automatic post-crash *rediscovery* is deliberately not asserted — see "no unicast redial hint" below. |
| `SIGSTOP_WAKE` | A frozen process (simulates laptop sleep, 15-60s) resumes to a healthy, re-linked session within the backoff envelope. See "Known gap" below for what it does *not* yet prove. |
| `FLAP` | 10 rapid freeze/thaw cycles don't trigger a handshake storm (`ConnectionMetrics.handshakes_total` stays bounded) and the pair settles back to `Linked`. |
| `PORT_SQUAT` | If a daemon's UDP port is taken by something else, it fails to boot cleanly (non-zero exit, no hang) instead of degrading silently, and recovers once the port frees up (reconnect driven by the same explicit `PairAccept { addr }` as `KILL9_RESTART` — see "no unicast redial hint" below). |
| `SLOW_START` | A daemon that's been idle and unpaired for a long time (60s) is still fully healthy and pairs normally once a peer shows up — no timer/resource wedge from sitting alone. |

## Known gaps this harness surfaces, not papers over

### 1. No unicast redial hint after a restart

Every production `StoredPeer` write in `driver.rs` persists
`last_addr: None` — even though `main.rs` *reads* `last_addr` at boot and
would seed the transport's roaming history from it. Net effect: a daemon
that crashes and restarts has no address to redial its trusted peer at,
and re-linking depends entirely on mDNS rediscovery. On macOS loopback,
mDNS is unreliable enough that the harness observed both outcomes across
two otherwise-identical runs (re-linked in ~10s in one, no link after 30s
in the next).

`KILL9_RESTART` and `PORT_SQUAT` therefore drive the reconnect
explicitly over IPC (a repeat `PairAccept { addr }` on the
already-confirmed peer — the manual-reconnect path, no pending gate) and
assert everything else (persistence, rehydration, session recovery,
dedup) deterministically. The surviving peer's reconnect dispatcher only
dials discovery-cache hints, so with mDNS silent it has nothing to dial
either — both directions of automatic re-link are blocked on the same
gap.
The fix that would let the harness assert *automatic* crash recovery:
persist the peer's last-seen socket address on link (the read side in
`main.rs` already exists and is currently dead code). Flagged under
"requested hooks" below.

### 2. No resync-on-reconnect (items lost past the retransmit budget)

`driver.rs`'s outbound delivery retries an unacked item every 2s
(`RETRANSMIT_INTERVAL`) for 6 attempts (`MAX_RETRANSMIT`) — about 14s —
then drops it for good. There is no resync-on-reconnect: a fresh
handshake does not replay anything the retry loop already gave up on.

DIR-P1-03 asks `SIGSTOP_WAKE` to prove zero item loss across a 15-60s
simulated sleep. That range is almost entirely *longer* than the ~14s
retransmit budget, so most runs cannot honestly claim zero loss today.
`sigstop_wake_recovers_within_backoff_envelope` reflects this precisely
instead of narrowing the scenario to a duration that always passes:

- it always hard-asserts session **recovery** (reconnect within 30s of
  `SIGCONT`) and that the link is healthy again (a *post-wake* item
  always delivers) — both are real, currently-true guarantees;
- for the item copied *during* the sleep, it only hard-asserts delivery
  when the drawn stop duration is within the retransmit budget; outside
  that window it logs a `KNOWN GAP` line instead of failing the run.

**This is the single most important finding from building this
harness.** Closing it needs a resync-on-reconnect mechanism in
`driver.rs` (e.g. replay outstanding/recent items keyed by the peer's
last-seen Lamport clock once a fresh session links) — out of scope here
per this task's constraint not to touch `driver.rs`/`backoff.rs`, but a
concrete, harness-verified candidate for the next DIR-P1 item.

### 3. Write-behind vault persistence window

`State.history` reaching a peer's in-memory state is not proof it is on
disk: the vault persister writes `history.enc` asynchronously after each
state publish. A hard kill inside that sub-second window loses the item
from the restarted daemon's history (observed live in the first harness
run). `KILL9_RESTART` waits for `history.enc` to exist before killing, so
the scenario asserts what the vault actually guarantees. The residual
window is real product behavior — acceptable for clipboard history, but
worth knowing it exists.

## What G2 still does not cover

This harness only injects faults the OS and this process can produce
without privileges: process death, process freeze, and local UDP port
contention, all on loopback. It does **not** exercise:

- a real Wi-Fi flap or AP roam (actual radio/driver behavior, not just
  "the process didn't get scheduled for a while");
- a real IP address change (DHCP renewal to a different subnet, moving
  between networks) — `is_local_ip`/roaming logic is exercised in unit
  tests, but never against a live interface change;
- a VPN connecting/disconnecting mid-session;
- multi-hop or lossy-but-not-dead LAN conditions (packet loss %, added
  latency) — everything here runs over instantaneous loopback.

Those need real hands and real hardware (or, short of that, actual
network-namespace/veth or `tc netem`-style link shaping, which needs
root and was explicitly out of scope for this harness). Until one of
those lands, gate G2 should be considered "process-fault-tolerant,
network-fault-unverified."

## Requested hooks (would make chaos assertions strictly stronger)

Not added here — noted for whoever picks up DIR-P1-09 or the next pass
on `driver.rs`:

- **Resync-on-reconnect** (known gap 2 above) — the biggest one.
- **Persist `last_addr` on link** (known gap 1 above): the `main.rs` read
  side already exists; populating it in driver.rs's `StoredPeer` writes
  would make crash-restart re-link deterministic without mDNS, and would
  let `KILL9_RESTART` assert fully automatic recovery instead of driving
  the reconnect over IPC.
- A `--disable-mdns` flag (or env var) on the real binary, mirroring
  `DaemonConfig::disable_mdns`: would make subprocess-level tests fully
  hermetic (today every harness daemon registers + browses real mDNS on
  the host network).
- `ConnectionMetrics` already exposes `handshakes_total`, `reconnects`,
  `dedup_drops`, `decrypt_failures`, `last_disconnect_reason` over IPC —
  this harness leans on it heavily and it was sufficient for every
  scenario as specified. No new counter was needed.
- A CLI/env override for `disable_clipboard` on the real binary (today
  only `DaemonConfig` in-process construction can set it). Harmless here
  because `State.history`/`AckItem` don't depend on the actual OS
  clipboard write succeeding, but it's the reason `chaos.yml` has to run
  under `xvfb` on Linux at all — a real flag would remove that
  dependency for headless environments entirely.
