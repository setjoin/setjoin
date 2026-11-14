#!/usr/bin/env bash
# run-guards-selftest.sh — proves run-guards.sh --known-red: tolerates a red listed guard,
# fails an unlisted red guard, fails a listed guard that now passes (ratchet), rejects unknown names.
source "$(dirname "$0")/_base.sh"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/scripts"
cp "$ROOT/scripts/_base.sh" "$ROOT/scripts/run-guards.sh" "$tmp/scripts/"
printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/scripts/check-green.sh"
printf '#!/usr/bin/env bash\nexit 1\n' > "$tmp/scripts/check-red.sh"
rg() { bash "$tmp/scripts/run-guards.sh" "$@" >/dev/null 2>&1; }
fail=0
expect() { # want label args...
  local want="$1" label="$2"; shift 2
  local rc=0; rg "$@" || rc=$?
  if { [ "$want" = 0 ] && [ $rc -ne 0 ]; } || { [ "$want" != 0 ] && [ $rc -eq 0 ]; }; then
    echo "run-guards self-test FAILED: $label (rc=$rc)" >&2; fail=1
  else echo "  ✓ $label"; fi
}
printf 'check-red # #1\n' > "$tmp/red.txt"
printf 'check-red # #1\ncheck-green # #1\n' > "$tmp/stale.txt"
printf 'check-nope # #1\n' > "$tmp/unknown.txt"
expect nonzero "unlisted red guard fails" 
expect 0 "listed red guard is tolerated" --known-red "$tmp/red.txt"
expect nonzero "listed guard that passes fails the run (ratchet)" --known-red "$tmp/stale.txt"
expect nonzero "unknown known-red name is rejected" --known-red "$tmp/unknown.txt"
exit "$fail"
