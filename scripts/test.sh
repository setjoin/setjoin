#!/usr/bin/env bash
source "$(dirname "$0")/_base.sh"

# Preflight: verify the toolchain + a reachable, baseline-loaded test DB BEFORE
# the suites run. A hard prerequisite (no cargo/psql/pg_prove, Postgres down, or an
# unloaded mailserver_test) is fatal HERE with a named fix, instead of surfacing
# 200 lines into pg_prove as a raw "connection refused". Set PREFLIGHT_SKIP=1 to
# bypass (e.g. a CI image that provisions services in a separate step).
if [ "${PREFLIGHT_SKIP:-0}" != "1" ]; then
  bash "$(dirname "$0")/deploy/preflight.sh" || {
    echo "==> Preflight failed (see above). Set PREFLIGHT_SKIP=1 to bypass." >&2
    exit 1
  }
fi

# Structural invariant guards — via the manifest. run-guards.sh globs every
# scripts/check-*.sh (self-test first, then verdict; per-guard rationale lives
# in each guard's own header), so this gate always runs the FULL guard set with
# no hand-maintained list to drift. Adding a guard = dropping a file into
# scripts/. Includes check-schema-determinism.sh (the slow double-DB-rebuild
# guard; its two scratch DBs don't touch mailserver_test).
bash "$(dirname "$0")/run-guards.sh"

export DB_DSN="${DB_DSN:-postgres://mail@127.0.0.1:5432/mailserver_test?sslmode=disable}"
export TEST_DB_DSN="${TEST_DB_DSN:-$DB_DSN}"
export REQUIRE_DB=1

echo "==> Verifying U2.5 backup/restore integrity evidence"
bash "$ROOT/scripts/deploy/audit-backup-integrity.sh"

echo "==> Testing webmail (Vitest + coverage ratchet)"
cd "$ROOT/webmail" && npm run test:coverage
echo "==> Verifying named Webmail test evidence"
cd "$ROOT" && TEST_EVIDENCE_OUTPUT="webmail/test-results/test-evidence.json" \
  bash "$ROOT/scripts/guards/check-test-evidence-results.sh" --verify vitest-json
echo "==> Enforcing changed Webmail coverage"
node "$ROOT/scripts/ci/report-changed-coverage.mjs" --mode enforce

echo "==> Reloading clean schema before pgTAP"
bash "$ROOT/scripts/load-test-schema.sh"

echo "==> Testing PL/pgSQL reducers — mailserver (pgTAP)"
bash "$ROOT/scripts/ci/run-pgtap-evidence.sh" test-results/pgtap/mailserver.tap \
  -d mailserver_test "$ROOT/sql/tests/"*.pg

echo "==> Testing PL/pgSQL reducers — authserver (pgTAP)"
bash "$ROOT/scripts/ci/run-pgtap-evidence.sh" test-results/pgtap/authserver.tap \
  -d mailserver_test "$ROOT/sql/auth/tests/"*.pg

echo "==> Verifying named pgTAP evidence"
TEST_EVIDENCE_OUTPUT="test-results/pgtap/test-evidence.json" \
  bash "$ROOT/scripts/guards/check-test-evidence-results.sh" --verify tap
