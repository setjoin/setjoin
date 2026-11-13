#!/usr/bin/env bash
# CONTRACT: future-code-test-gates
# Validates the machine-readable feature/test registry. In pilot mode, an
# enforced claim can reference only a self-tested scripts/check-*.sh guard;
# ordinary test-file pointers stay planned until result adapters can prove the
# named case ran and was not skipped.
source "$(dirname "$0")/_base.sh"
set -euo pipefail

MANIFEST="${FEATURE_TEST_MANIFEST:-$ROOT/docs/verification/feature-test-contracts.json}"
VALIDATOR="$ROOT/scripts/check-feature-test-contracts.go"

run_check() {
  local root="$1" manifest="$2"
  command -v go >/dev/null 2>&1 || {
    echo "feature-test-contracts: go is required to validate the registry" >&2
    return 1
  }
  go run "$VALIDATOR" "$root" "$manifest"
}

if [[ "${1:-}" == "--self-test" ]]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/docs/standards" "$tmp/scripts"
  printf '# authority\n' > "$tmp/docs/standards/TESTING.md"
  printf '#!/usr/bin/env bash\n# CONTRACT: fixture-contract\nif [[ "${1:-}" == "--self-test" ]]; then exit 0; fi\n' > "$tmp/scripts/check-fixture.sh"

  valid="$tmp/valid.json"
  cat > "$valid" <<'JSON'
{"schemaVersion":1,"rollout":"pilot","contracts":[{"id":"fixture-contract","authority":"docs/standards/TESTING.md","status":"enforced","requirements":[{"id":"fixture-requirement","risk":"high","obligations":["fail_closed"],"evidence":[{"id":"fixture-evidence","kind":"guard","path":"scripts/check-fixture.sh","selector":"CONTRACT: fixture-contract","gate":"scripts/check-fixture.sh","skipPolicy":"forbid","covers":["fail_closed"]}]}]}]}
JSON
  run_check "$tmp" "$valid" >/dev/null

  missing_selector="$tmp/missing-selector.json"
  sed 's/CONTRACT: fixture-contract/CONTRACT: absent-contract/' "$valid" > "$missing_selector"
  if run_check "$tmp" "$missing_selector" >/dev/null 2>&1; then
    echo "feature-test-contracts self-test: missing selector was accepted" >&2
    exit 1
  fi

  printf '#!/usr/bin/env bash\n# CONTRACT: fixture-contract\n' > "$tmp/scripts/check-fixture.sh"
  if run_check "$tmp" "$valid" >/dev/null 2>&1; then
    echo "feature-test-contracts self-test: guard without a self-test was accepted" >&2
    exit 1
  fi
  printf '#!/usr/bin/env bash\n# CONTRACT: fixture-contract\nif [[ "${1:-}" == "--self-test" ]]; then exit 0; fi\n' > "$tmp/scripts/check-fixture.sh"

  uncovered="$tmp/uncovered.json"
  sed 's/"covers":\["fail_closed"\]/"covers":[]/' "$valid" > "$uncovered"
  if run_check "$tmp" "$uncovered" >/dev/null 2>&1; then
    echo "feature-test-contracts self-test: uncovered obligation was accepted" >&2
    exit 1
  fi

  expired="$tmp/expired.json"
  cat > "$expired" <<'JSON'
{"schemaVersion":1,"rollout":"pilot","contracts":[{"id":"fixture-contract","authority":"docs/standards/TESTING.md","status":"enforced","requirements":[{"id":"fixture-requirement","risk":"high","obligations":["fail_closed"],"exception":{"owner":"owner","approvedBy":"reviewer","reason":"temporary","tracking":"TEST-1","expires":"2000-01-01"}}]}]}
JSON
  if run_check "$tmp" "$expired" >/dev/null 2>&1; then
    echo "feature-test-contracts self-test: expired exception was accepted" >&2
    exit 1
  fi

  echo "feature-test-contracts self-test: PASS"
  exit 0
fi

if [[ $# -ne 0 ]]; then
  echo "usage: check-feature-test-contracts.sh [--self-test]" >&2
  exit 2
fi

run_check "$ROOT" "$MANIFEST"
