#!/usr/bin/env bash
# CONTRACT: connectivity-e6-harness
# CQ E6 desktop-lane client-pair launcher (readiness item "Client-pair launch
# wiring" in retired-docs:verification/2026-09-19-connectivity-e6-harness.md). The
# .mjs owns all behavior — the once-off client build, the two-instance launch
# with distinct user-data dirs and the SETJOIN_E6_* flag-delta seams, the
# readiness wait, the harness-expected PID/saturation export blocks, the
# driver-wrapper per-member attribution mode, the embedded self-test, and the
# verified teardown-on-exit trap (see its header comment). This wrapper only
# pins the repository root and execs node so arguments pass through verbatim:
#   bash scripts/e6-client-pair-launch.sh --self-test
#   bash scripts/e6-client-pair-launch.sh --smoke
#   bash scripts/e6-client-pair-launch.sh            (launch + hold)
# Exit codes: 0 ok, 1 machinery/readiness failure, 130/143 on SIGINT/SIGTERM
# after verified teardown. Wrapper (--driver-wrapper) exits with the real
# driver's exit code.
# shellcheck disable=SC1091
source "$(dirname "$0")/_base.sh"
set -euo pipefail

LAUNCHER="$ROOT/scripts/e6-client-pair-launch.mjs"

if [[ ! -f "$LAUNCHER" ]]; then
  echo "e6-client-pair-launch: launcher missing: scripts/e6-client-pair-launch.mjs" >&2
  exit 1
fi

exec node "$LAUNCHER" "$@"
