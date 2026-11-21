#!/usr/bin/env bash
# Run every pgTAP suite for the server-rust lane. Suites listed in the known-red file (reviewed, each with an
# issue reference) still RUN and only warn; every other suite must pass through run-pgtap-evidence.sh, and a
# listed suite that now passes fails the lane (ratchet: delete its line). Mirrors run-guards.sh --known-red.
#
# Usage: run-pgtap-lane.sh KNOWN_RED_FILE PG_PROVE_CONNECTION_ARGS...   (e.g. -h 127.0.0.1 -p 5432 -U postgres -d db)
source "$(dirname "$0")/_base.sh"
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: run-pgtap-lane.sh KNOWN_RED_FILE PG_PROVE_ARGS..." >&2
  exit 2
fi
known_red_file="$1"
shift

red=()
while IFS= read -r line; do
  line="${line%%#*}"
  line="${line//[[:space:]]/}"
  [[ -z "$line" ]] && continue
  [[ -f "$ROOT/$line" ]] || { echo "pgtap-known-red: unknown suite $line (not a file; delete the stale entry)" >&2; exit 2; }
  red+=("$line")
done <"$ROOT/$known_red_file"

is_red() {
  local s
  for s in "${red[@]+"${red[@]}"}"; do [[ "$s" == "$1" ]] && return 0; done
  return 1
}

required_for() { # required_for DIR → suites under DIR/sql/tests not on the known-red list
  local f
  for f in "$ROOT/$1"/sql/tests/*.pg; do
    f="${f#"$ROOT"/}"
    is_red "$f" || printf '%s\n' "$f"
  done
}

cd "$ROOT"
mapfile -t mail_suites < <(required_for mailserver)
mapfile -t auth_suites < <(required_for authserver)
bash scripts/run-pgtap-evidence.sh test-results/pgtap/mailserver.tap --ext .pg "$@" "${mail_suites[@]}"
bash scripts/run-pgtap-evidence.sh test-results/pgtap/authserver.tap --ext .pg "$@" "${auth_suites[@]}"

stale=()
warned=()
for suite in "${red[@]+"${red[@]}"}"; do
  echo "──[ known-red pgTAP suite: $suite ]──"
  if pg_prove --ext .pg "$@" "$suite"; then
    stale+=("$suite")
  else
    warned+=("$suite")
  fi
done

if [[ ${#warned[@]} -gt 0 ]]; then
  echo "  KNOWN RED pgTAP (tolerated via $known_red_file): ${warned[*]}"
  echo "::warning::known-red pgTAP suites: ${warned[*]} (see $known_red_file)"
fi
if [[ ${#stale[@]} -gt 0 ]]; then
  echo "  STALE known-red pgTAP (now PASS): ${stale[*]} — remove from $known_red_file" >&2
  exit 1
fi
