#!/usr/bin/env bash
# DIR-P1-03: runs the chaos harness (crates/fluxsyncd/tests/chaos_harness.rs)
# and prints a scenario-by-scenario PASS/FAIL summary.
#
# Wall-clock heavy: backoff waits, simulated sleeps, and one 60s idle
# window are real time, not mocked. A full run (all 5 scenarios) takes
# several minutes.
#
# Usage:
#   scripts/chaos.sh                      # run all 5 scenarios
#   scripts/chaos.sh kill9_restart         # run scenarios whose name
#                                          # contains this substring
#   scripts/chaos.sh port_squat slow_start # OR of multiple filters
#
# CHAOS_SEED=<n> re-runs the scenarios that draw randomized timing
# (sigstop_wake, flap) with a fixed seed, to reproduce a specific failure.
# Every run logs its own seed regardless (look for "seed=" in the output).

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

LOG="$(mktemp "${TMPDIR:-/tmp}/fluxsync-chaos.XXXXXX")"
echo "chaos harness log: $LOG"
echo

# --nocapture: the per-scenario seed lines ([chaos:<name>] seed=...) and
# the sigstop_wake KNOWN GAP diagnostics go to stderr; without this,
# libtest swallows them for PASSING tests and a green run is not
# reproducible after the fact. --test-threads=1 because scenarios freeze
# and kill whole processes — parallel scheduling noise would blur every
# timing assertion.
set +e
cargo test -p fluxsyncd --test chaos_harness -- --ignored --test-threads=1 --nocapture "$@" 2>&1 | tee "$LOG"
STATUS=$?
set -e

# With --nocapture the per-test verdict is interleaved with test output,
# so parse scenario names from the "test <name> ..." start markers and
# failures from libtest's final "failures:" list instead of relying on
# "test <name> ... ok" staying on one line.
failed_names="$(sed -n '/^failures:$/,/^test result:/p' "$LOG" | grep -E '^    [a-z0-9_]+$' | tr -d ' ' | sort -u)"

echo
echo "==================== chaos summary ===================="
while IFS= read -r name; do
    [ -z "$name" ] && continue
    if printf '%s\n' "$failed_names" | grep -qx "$name"; then
        printf '  FAIL  %s\n' "$name"
    else
        printf '  PASS  %s\n' "$name"
    fi
done < <(grep -oE '^test [a-zA-Z0-9_]+ \.\.\.' "$LOG" | awk '{print $2}' | sort -u)
echo "=========================================================="
echo "full log: $LOG"

exit "$STATUS"
