#!/usr/bin/env bash
# CONTRACT: connectivity-e6-harness
# Evidence-mode workload driver for the E6 paired-run harness
# (scripts/run-connectivity-e6-harness.mjs, "--workload-driver-cmd"). The
# .mjs owns all behavior — the driver event contract (env in, NDJSON events
# out, content-free stdout, exact attempt accounting), the honesty guards
# (never self-reported role PIDs, proxy-only routing, loopback routes refused
# against evidence-grade schedules, basis-carrying saturation declarations),
# the embedded self-test, and the machinery contract-validation mode (see its
# header comment). This wrapper only pins the repository root and execs node
# so arguments pass through verbatim:
#   bash scripts/e6-workload-driver.sh --self-test
#   bash scripts/e6-workload-driver.sh --validate-contract
#   bash scripts/e6-workload-driver.sh --help
# Contract mode is invoked BY the harness as --workload-driver-cmd; running it
# bare without the E6_* environment fails closed with a diagnostic.
# Exit codes: 0 ok, 1 machinery/usage failure (usage exits 1, never 2).
# shellcheck disable=SC1091
source "$(dirname "$0")/_base.sh"
set -euo pipefail

DRIVER="$ROOT/scripts/e6-workload-driver.mjs"

if [[ ! -f "$DRIVER" ]]; then
  echo "e6-workload-driver: driver missing: scripts/e6-workload-driver.mjs" >&2
  exit 1
fi

exec node "$DRIVER" "$@"
