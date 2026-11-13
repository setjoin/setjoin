#!/usr/bin/env bash
# CONTRACT: connectivity-e6-harness
# Paired-run driver for the frozen E6 comparison profile
# (docs/verification/connectivity-e6-profile.json; producer for the CAS-E6-*
# core-lane evidence: CRITICAL-SAMPLE-FLOOR, PAIRED-REGRESSION,
# FAILED-REQUEST-ACCOUNTING, CROSSPROCESS-CRITICAL-SATURATION).
# The .mjs owns all behavior — protocol execution, embedded results-doc
# schema validation, sealing, resource ledger/cleanup, and the ops runbook
# (see its header comment). This wrapper only pins the repository root and
# execs node so arguments pass through verbatim:
#   bash scripts/run-connectivity-e6-harness.sh --self-test
#   bash scripts/run-connectivity-e6-harness.sh --smoke
#   bash scripts/run-connectivity-e6-harness.sh --dry-run --pairs 20
# Exit codes: 0 ok, 1 machinery/validation/usage failure (usage exits 1,
# never 2), 3 evidence run completed with overall verdict FAIL,
# 127 driver spawn failure, 130 interrupted.
# shellcheck disable=SC1091
source "$(dirname "$0")/_base.sh"
set -euo pipefail

HARNESS="$ROOT/scripts/run-connectivity-e6-harness.mjs"

if [[ ! -f "$HARNESS" ]]; then
  echo "run-connectivity-e6-harness: harness missing: scripts/run-connectivity-e6-harness.mjs" >&2
  exit 1
fi

exec node "$HARNESS" "$@"
