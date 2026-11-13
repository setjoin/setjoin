#!/usr/bin/env bash
# CONTRACT: architecture-r2-evidence
# Proves the Architecture R2 database refusal and pgTAP atomic-publication
# contracts with local, dependency-free fixtures.
source "$(dirname "$0")/_base.sh"

RUNNER="${ARCH_R2_EVIDENCE_RUNNER:-$ROOT/scripts/run-pgtap-evidence.sh}"
VALIDATOR="${ARCH_R2_DB_VALIDATOR:-$ROOT/scripts/architecture-r2-test-db.sh}"

usage() {
  echo "usage: check-architecture-r2-evidence.sh [--self-test|--help]"
}

check_contract() {
  local failed=0
  for literal in 'architecture_r2_validate_test_db' 'mktemp ' 'PIPESTATUS' 'mv -f "$partial" "$report_path"' '"$report_path.failed"'; do
    if ! grep -Fq -- "$literal" "$RUNNER"; then
      echo "architecture-r2-evidence: runner missing contract: $literal" >&2
      failed=1
    fi
  done
  for literal in 'mailserver_test_arch_r2_[0-9a-f]{12}' 'remote_database_host' 'dsn_mismatch'; do
    if ! grep -Fq -- "$literal" "$VALIDATOR"; then
      echo "architecture-r2-evidence: validator missing contract: $literal" >&2
      failed=1
    fi
  done
  [[ "$failed" -eq 0 ]]
}

run_runtime_fixtures() {
  local tmp fake hash db report_rel report_path
  tmp="$(mktemp -d)"
  hash="$(printf '%s' "$ROOT" | shasum -a 256 | cut -c1-12)"
  db="mailserver_test_arch_r2_$hash"
  # The validator accepts an ambient DSN only when it points at the DERIVED
  # Architecture R2 database. A CI job legitimately exports DB_DSN/TEST_DB_DSN
  # for the shared test database (e.g. a Postgres service container), which
  # would otherwise fail the derived-name match mid-run — rebind both to the
  # derived database for this guard's own scope (same contract, same host).
  DB_DSN="postgres://${DB_USER:-mail}@${DB_HOST:-127.0.0.1}:${DB_PORT:-5432}/${db}?sslmode=disable"
  TEST_DB_DSN="$DB_DSN"
  export DB_DSN TEST_DB_DSN
  report_rel="test-results/pgtap/architecture-r2-evidence-$$.tap"
  report_path="$ROOT/$report_rel"
  trap 'rm -rf "'"$tmp"'"; rm -f "'"$report_path"'" "'"$report_path"'.failed" "'"$report_path"'.partial"' EXIT

  # shellcheck source=architecture-r2-test-db.sh
  source "$VALIDATOR"
  ARCH_R2_TEST_MODE=1 DB_NAME="$db" DB_HOST=127.0.0.1 architecture_r2_validate_test_db >/dev/null
  if ARCH_R2_TEST_MODE=1 DB_NAME=mailserver_test DB_HOST=127.0.0.1 architecture_r2_validate_test_db >/dev/null 2>&1; then
    echo "architecture-r2-evidence: shared database was accepted" >&2
    return 1
  fi
  if ARCH_R2_TEST_MODE=1 DB_NAME="$db" DB_HOST=db.example.test architecture_r2_validate_test_db >/dev/null 2>&1; then
    echo "architecture-r2-evidence: remote database host was accepted" >&2
    return 1
  fi
  if ARCH_R2_TEST_MODE=1 DB_NAME="$db" DB_HOST=127.0.0.1 DB_DSN=postgres://mail@127.0.0.1/other_test architecture_r2_validate_test_db >/dev/null 2>&1; then
    echo "architecture-r2-evidence: mismatched DSN was accepted" >&2
    return 1
  fi

  fake="$tmp/pg_prove"
  printf '%s\n' '#!/usr/bin/env bash' 'printf "1..1\\nok 1 - fixture\\n"' 'exit "${FAKE_PG_PROVE_STATUS:-0}"' > "$fake"
  chmod +x "$fake"

  PG_PROVE_BIN="$fake" FAKE_PG_PROVE_STATUS=0 bash "$RUNNER" "$report_rel" fixture.pg >/dev/null
  [[ -f "$report_path" && ! -e "$report_path.failed" && ! -e "$report_path.partial" ]] || {
    echo "architecture-r2-evidence: successful evidence was not published atomically" >&2
    return 1
  }

  rm -f "$report_path"
  set +e
  PG_PROVE_BIN="$fake" FAKE_PG_PROVE_STATUS=7 bash "$RUNNER" "$report_rel" fixture.pg >/dev/null 2>&1
  local status=$?
  set -e
  [[ "$status" -eq 7 && ! -e "$report_path" && -f "$report_path.failed" ]] || {
    echo "architecture-r2-evidence: failed evidence occupied the canonical path" >&2
    return 1
  }
}

run_check() {
  check_contract
  run_runtime_fixtures
}

case "${1:-}" in
  --help) usage; exit 0 ;;
  --self-test)
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    sed '/failed_path=/d' "$RUNNER" > "$tmp/broken-runner.sh"
    original="$RUNNER"
    RUNNER="$tmp/broken-runner.sh"
    if check_contract >/dev/null 2>&1; then
      echo "architecture-r2-evidence self-test: broken runner was accepted" >&2
      exit 1
    fi
    RUNNER="$original"
    echo "architecture-r2-evidence self-test: PASS"
    exit 0
    ;;
  "") run_check; echo "architecture-r2-evidence: PASS" ;;
  *) usage >&2; exit 2 ;;
esac
