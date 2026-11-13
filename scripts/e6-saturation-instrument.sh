#!/usr/bin/env bash
# CONTRACT: connectivity-e6-harness / E6 rerun scheme v4 (comparator window)
# Comparator saturation instrument for the E6 paired-run harness — the
# run-scoped program scheme v4 §2.1.1 names, spawned BY the harness (never
# the launcher), ONE instance per comparator window. The .mjs owns all
# behavior — the frozen optional-job workload shape through the window's
# fault proxy, the production admission/backoff rules (mirrored from
# mailserver/webmail/src/lib/offline/ with provenance), the §2.4-as-amended
# declared-level saturation proof (engaged at-limit OR held-by-production-
# rule with reason codes; outage alone never refutes), the per-poll samples
# and summary receipt fragment, the §2.3.1 ordered drain, and the embedded
# offline self-test (see its header comment). This wrapper only pins the
# repository root and execs node so arguments pass through verbatim:
#   bash scripts/e6-saturation-instrument.sh --self-test
#   bash scripts/e6-saturation-instrument.sh --gateway-origin ... (contract mode)
#   bash scripts/e6-saturation-instrument.sh --help
# Contract mode is invoked BY the harness with the §2.1.1 interface flags;
# running it bare without them fails closed with a diagnostic.
# Exit codes (the .mjs's): 0 ok, 1 machinery/usage failure (usage exits 1,
# never 2), 3 proof refuted, 130/143 on SIGINT/SIGTERM after ordered drain.
# shellcheck disable=SC1091
source "$(dirname "$0")/_base.sh"
set -euo pipefail

INSTRUMENT="$ROOT/scripts/e6-saturation-instrument.mjs"

if [[ ! -f "$INSTRUMENT" ]]; then
  echo "e6-saturation-instrument: instrument missing: scripts/e6-saturation-instrument.mjs" >&2
  exit 1
fi

exec node "$INSTRUMENT" "$@"
