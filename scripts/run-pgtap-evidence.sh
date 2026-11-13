#!/usr/bin/env bash
# Run pg_prove verbosely so every assertion is machine-matchable, retain the TAP
# stream, and preserve pg_prove's exit status through tee.
source "$(dirname "$0")/_base.sh"
set -euo pipefail
source "$ROOT/scripts/architecture-r2-test-db.sh"

if [[ $# -lt 2 ]]; then
  echo "usage: run-pgtap-evidence.sh REPORT PG_PROVE_ARGS..." >&2
  exit 2
fi

report="$1"
shift
case "$report" in
  test-results/pgtap/*.tap)
    if [[ "$report" == *"/../"* || "$report" == *"/./"* || "$report" == *"//"* ]]; then
      echo "pgtap-evidence: report path is not normalized: $report" >&2
      exit 2
    fi
    report_path="$ROOT/$report"
    ;;
  *) echo "pgtap-evidence: report must be under test-results/pgtap/: $report" >&2; exit 2 ;;
esac

architecture_r2_validate_test_db || exit $?

mkdir -p "$(dirname "$report_path")"
report_dir="$(dirname "$report_path")"
report_base="$(basename "$report_path")"
partial="$(mktemp "$report_dir/.${report_base}.partial.XXXXXX")"
failed_path="$report_path.failed"
published=0

preserve_partial() {
  if [[ "$published" -eq 0 && -f "$partial" ]]; then
    mv -f "$partial" "$report_path.partial"
  fi
}
trap preserve_partial EXIT INT TERM

set +e
"${PG_PROVE_BIN:-pg_prove}" -v "$@" | tee "$partial"
statuses=("${PIPESTATUS[@]}")
prove_status=${statuses[0]}
tee_status=${statuses[1]}
set -e

if [[ "$prove_status" -ne 0 || "$tee_status" -ne 0 ]]; then
  mv -f "$partial" "$failed_path"
  published=1
  echo "pgtap-evidence: failed report retained at $failed_path (pg_prove=$prove_status tee=$tee_status)" >&2
  [[ "$prove_status" -ne 0 ]] && exit "$prove_status"
  exit "$tee_status"
fi

mv -f "$partial" "$report_path"
published=1
rm -f "$failed_path" "$report_path.partial"
