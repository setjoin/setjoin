#!/usr/bin/env bash
# CONTRACT: architecture-r2-dx-metrics
source "$(dirname "$0")/_base.sh"

METRICS="$ROOT/scripts/architecture-r2-metrics.mjs"
LATEST="$ROOT/test-results/architecture-r2/dx/latest.json"

usage() {
  cat <<'EOF'
Usage: bash scripts/check-architecture-r2-dx-metrics.sh [--require|--self-test|--help]

Without --require, validates the latest Architecture R2 timing population when
present and otherwise performs the structural guard only. CI uses --require
after generating its five-sample warm surrogate.
EOF
}

validate_latest() {
  local required="$1" aggregate
  if [[ ! -f "$LATEST" ]]; then
    if [[ "$required" == "1" ]]; then
      echo "E_ARCH_R2_METRICS problem=missing_evidence cause=latest_pointer_absent value=$LATEST fix='run the benchmark on this checkout' rerun='bash scripts/verify-architecture-r2.sh benchmark --class warm --samples 5 --warmup 1'" >&2
      return 1
    fi
    echo "architecture-r2 metrics: no local benchmark evidence (structural contract ready)"
    return 0
  fi
  aggregate="$(node -e '
    const fs = require("fs");
    const path = require("path");
    const pointer = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    if (pointer.schemaVersion !== 1 || typeof pointer.aggregate !== "string" || path.isAbsolute(pointer.aggregate) || pointer.aggregate.includes("..")) process.exit(2);
    process.stdout.write(path.resolve(process.argv[2], pointer.aggregate));
  ' "$LATEST" "$ROOT")" || {
    echo "E_ARCH_R2_METRICS problem=invalid_pointer cause=latest_pointer_contract value=$LATEST fix='regenerate benchmark evidence' rerun='bash scripts/verify-architecture-r2.sh benchmark --class warm --samples 5 --warmup 1'" >&2
    return 1
  }
  node "$METRICS" validate "$aggregate"
}

case "${1:-}" in
  --help) usage ;;
  --require) [[ $# -eq 1 ]] || { usage >&2; exit 2; }; validate_latest 1 ;;
  --self-test)
    [[ $# -eq 1 ]] || { usage >&2; exit 2; }
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    started="$(node -e 'process.stdout.write(String(Date.now()))')"
    set +e
    node "$METRICS" diagnostic >"$tmp/out" 2>"$tmp/diagnostic"
    status=$?
    set -e
    ended="$(node -e 'process.stdout.write(String(Date.now()))')"
    [[ "$status" -eq 1 ]] || { echo "architecture-r2 metrics self-test: diagnostic probe did not fail" >&2; exit 1; }
    grep -q '^E_ARCH_R2_METRICS problem=planted_failure' "$tmp/diagnostic" || { echo "architecture-r2 metrics self-test: stable E_* diagnostic missing" >&2; exit 1; }
    (( ended - started <= 30000 )) || { echo "architecture-r2 metrics self-test: diagnostic exceeded 30000ms" >&2; exit 1; }

    mkdir -p "$tmp/samples"
    node "$METRICS" fingerprint "$ROOT" "$tmp/fingerprint.json"
    population_key="$(node -e 'const p=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")); process.stdout.write(p.populationKey)' "$tmp/fingerprint.json")"
    commit="$(git -C "$ROOT" rev-parse HEAD)"
    for sample in 1 2 3 4 5; do
      ordinal="$(printf '%03d' "$sample")"
      printf 'fixture sample %s\n' "$sample" > "$tmp/samples/$ordinal.log"
      node "$METRICS" record-sample "$tmp/samples/$ordinal.json" "$tmp/samples/$ordinal.log" \
        "$commit" warm "$population_key" "$sample" 2026-01-01T00:00:00Z 10 10 pass
    done
    node "$METRICS" aggregate "$tmp" 5 1 warm >/dev/null
    node "$METRICS" validate "$tmp/aggregate.json" >/dev/null
    node -e '
      const fs = require("fs");
      const source = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      source.metrics.p95DurationMs = 1;
      fs.writeFileSync(process.argv[2], JSON.stringify(source));
    ' "$tmp/aggregate.json" "$tmp/tampered.json"
    if node "$METRICS" validate "$tmp/tampered.json" >/dev/null 2>&1; then
      echo "architecture-r2 metrics self-test: tampered aggregate was accepted" >&2
      exit 1
    fi
    echo "architecture-r2 metrics self-test: PASS"
    ;;
  "") [[ $# -eq 0 ]] || { usage >&2; exit 2; }; validate_latest 0 ;;
  *) usage >&2; exit 2 ;;
esac
