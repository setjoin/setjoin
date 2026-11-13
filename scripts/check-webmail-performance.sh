#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEBMAIL="$ROOT/mailserver/webmail"
MODE="${1:---require}"

case "$MODE" in
  --self-test)
    (cd "$WEBMAIL" && npm run test:performance)
    ;;
  --require)
    [ -f "$WEBMAIL/build/index.html" ] || {
      echo "E_WEBMAIL_PERF_INPUTS_ABSENT problem=production_build_missing cause=build/index.html_absent value=build/index.html artifact=build/ fix='run npm run build' rerun='bash scripts/check-webmail-performance.sh --require'" >&2
      exit 1
    }
    (cd "$WEBMAIL" && node scripts/performance-report.mjs)
    ;;
  *)
    echo "usage: bash scripts/check-webmail-performance.sh [--require|--self-test]" >&2
    exit 2
    ;;
esac
