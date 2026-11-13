#!/usr/bin/env bash
# CONTRACT: future-code-test-gates
# Pins the minimum required requirement/evidence IDs so deleting a registry row
# cannot silently make the allowlist and its verifier agree on a smaller scope.
source "$(dirname "$0")/_base.sh"
set -euo pipefail

CHECKER="$ROOT/scripts/check-required-test-evidence.mjs"
MANIFEST="${REQUIRED_EVIDENCE_MANIFEST:-$ROOT/docs/verification/feature-test-contracts.json}"
BASELINE="${REQUIRED_EVIDENCE_BASELINE:-$ROOT/docs/verification/required-test-evidence.json}"

run_check() {
  node "$CHECKER" "$MANIFEST" "$BASELINE"
}

if [[ "${1:-}" == "--self-test" ]]; then
  run_check >/dev/null
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  cat > "$tmp/manifest.json" <<'JSON'
{"contracts":[{"requirements":[{"id":"kept","evidence":[{"id":"proof"}]}]}]}
JSON
  cat > "$tmp/baseline.json" <<'JSON'
{"schemaVersion":1,"requirements":["kept","deleted"],"evidence":["proof"]}
JSON
  if node "$CHECKER" "$tmp/manifest.json" "$tmp/baseline.json" >/dev/null 2>&1; then
    echo "required-test-evidence self-test: deleted requirement was accepted" >&2
    exit 1
  fi
  cat > "$tmp/duplicate.json" <<'JSON'
{"contracts":[{"requirements":[{"id":"kept","evidence":[{"id":"proof"}]},{"id":"kept","evidence":[]}]}]}
JSON
  if node "$CHECKER" "$tmp/duplicate.json" "$tmp/baseline.json" >/dev/null 2>&1; then
    echo "required-test-evidence self-test: duplicate requirement was accepted" >&2
    exit 1
  fi
  echo "required-test-evidence self-test: PASS"
  exit 0
fi

if [[ $# -ne 0 ]]; then
  echo "usage: check-required-test-evidence.sh [--self-test]" >&2
  exit 2
fi

run_check
