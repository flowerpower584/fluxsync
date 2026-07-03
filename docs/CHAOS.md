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
| `SIGSTOP_WAKE` | A frozen process (simulates laptop sleep, 15-60s) resumes to a healthy, re-linked session within the backoff envelope. See "Closed (v0.6.x): resync-on-reconnect" below for why the mid-sleep item is logged rather than hard-asserted. |
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

### 2. Closed (v0.6.x): resync-on-reconnect

`driver.rs`'s outbound delivery retries an unacked item every 2s
(`RETRANSMIT_INTERVAL`) for 6 attempts (`MAX_RETRANSMIT`) — about 14s —
then drops it from `inflight`. That retry loop alone could never replay
anything it already gave up on. As of the resync-1 slice, it doesn't
have to: on session link, peers that negotiated the `resync-1`
capability (advertised in `Msg::Hello.caps`) exchange
`ResyncOffer`/`ResyncPull` over content hashes held in a small
in-memory outbox — 16 items / 8 MiB / 24h, non-sensitive items only
(the same classifier the at-rest vault uses), full payload bytes so a
re-offer is byte-identical to the original send. Whatever the peer is
missing gets re-served through the normal inflight machinery, so a
relink after any outage — a laptop sleep, a Wi-Fi drop, a killed and
restarted daemon on the *receiving* end — recovers items the direct
retransmit budget alone would have lost.

DIR-P1-03 asks `SIGSTOP_WAKE` to prove zero item loss across a 15-60s
simulated sleep, which is longer than the ~14s retransmit budget for
nearly the whole range — exactly the case resync-1 now covers.
`sigstop_wake_recovers_within_backoff_envelope` still logs (rather than
hard-asserts) the outcome for the mid-sleep item past that budget,
since that scenario's job is proving session **recovery**, not resync-1
itself. The dedicated end-to-end proof — a real peer restart, a missed
item recovered out of the sender's outbox, `items_resynced` advancing
on the sender — lives in `crates/fluxsyncd/tests/resync_on_reconnect.rs`.

One case stays narrow and out of scope for resync-1 by design: the
outbox is purely in-memory. If the *sender* itself restarts before the
peer relinks, whatever it alone was holding for that peer is lost with
it — a **receiver** restart is fine (the sender is still up and still
holds the outbox to re-offer from), but a **sender** restart is not.
Closing that would mean persisting the outbox to disk, which reopens
exactly the kind of at-rest exposure the "non-sensitive only, in-memory"
design was built to avoid — not pursued here.

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

- **Resync-on-reconnect** — shipped, see "Closed (v0.6.x)" (known gap 2
  above); no longer a requested hook.
- **Persist `last_addr` on link** (known gap 1 above) — the biggest
  remaining one. The `main.rs` read
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
