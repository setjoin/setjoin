#!/usr/bin/env bash
# Resolved relative to this script at runtime.
# shellcheck disable=SC1091
source "$(dirname "$0")/_base.sh"
set -euo pipefail

script="$ROOT/scripts/verify-architecture-r4.sh"
help="$(bash "$script" --help)"
grep -q '13 stable lanes' <<<"$help"
grep -q 'LANE \[--self-test\] \[--verbose\]' <<<"$help"
[ "$(bash "$script" list | wc -l | tr -d ' ')" = 13 ]
bash "$script" --doctor >/dev/null

for lane in $(bash "$script" list | cut -f1); do
  bash "$script" "$lane" --self-test >/dev/null
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
if ARCH_R4_RESULTS_ROOT="$tmp/missing" bash "$script" evidence >/dev/null 2>&1; then
  echo "E_ARCH_R4_TEST missing evidence was accepted" >&2
  exit 1
fi

set +e
bash "$script" not-a-lane >"$tmp/unknown" 2>&1
unknown_rc=$?
bash "$script" ldap --not-a-flag >"$tmp/flag" 2>&1
flag_rc=$?
ARCH_R4_RESULTS_ROOT="$tmp/missing" bash "$script" evidence --run-id absent >"$tmp/run" 2>&1
run_rc=$?
set -e
[[ "$unknown_rc" -eq 2 ]] && grep -q E_ARCH_R4_CLI_UNKNOWN "$tmp/unknown"
[[ "$flag_rc" -eq 2 ]] && grep -q E_ARCH_R4_CLI_USAGE "$tmp/flag"
[[ "$run_rc" -eq 1 ]] && grep -q E_ARCH_R4_EVIDENCE_MISSING "$tmp/run"
for output in "$tmp/unknown" "$tmp/flag" "$tmp/run"; do
  grep -q '^problem:' "$output"
  grep -q '^cause:' "$output"
  grep -q '^fix:' "$output"
  grep -q '^rerun:' "$output"
done

mkdir -p "$tmp/stale/run"
printf 'artifact\n' >"$tmp/stale/run/output.log"
artifact_sha="$(shasum -a 256 "$tmp/stale/run/output.log" | cut -d' ' -f1)"
cat >"$tmp/stale/run/manifest.json" <<EOF
{"schemaVersion":1,"lane":"ldap","caseId":"R4-LDAP-BOUND-VISIBILITY","verdict":"passed","sourceFingerprint":"stale","artifacts":[{"path":"output.log","sha256":"$artifact_sha"}]}
EOF
set +e
ARCH_R4_RESULTS_ROOT="$tmp/stale" bash "$script" evidence --run-id run >"$tmp/stale-output" 2>&1
stale_rc=$?
set -e
[[ "$stale_rc" -eq 1 ]] && grep -q E_ARCH_R4_EVIDENCE_STALE "$tmp/stale-output"

echo "architecture-r4 script contract: PASS"
