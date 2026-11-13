#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${1:-}" == "--self-test" ]]; then
  shift
  if (($# != 0)); then
    echo '{"code":"E_SECURITY_PROGRAM_USAGE","message":"--self-test accepts no arguments","networkStarts":0,"scanLaunch":"HOLD","scannerStarts":0,"schema":"setjoin.security-program.control/v1","status":"FAIL"}' >&2
    exit 2
  fi
  exec "$script_dir/verify-security-program.test.sh"
fi
exec node "$script_dir/security-program.mjs" "$@"
