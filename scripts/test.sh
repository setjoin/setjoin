#!/usr/bin/env bash
source "$(dirname "$0")/_base.sh"

# Every DB-backed package shares mailserver_test. Package-level concurrency can
# mutate organization-wide state between assertions (for example the GAL sync
# token's visible-user count), so serialize package processes. Test functions
# inside each package keep their normal behavior. RACE=1 adds the race detector
# to this deterministic lane.
GO_TEST_FLAGS=(-p 1)
if [ "${RACE:-0}" = "1" ]; then GO_TEST_FLAGS+=(-race); fi

# Preflight: verify the toolchain + a reachable, baseline-loaded test DB BEFORE
# the suites run. A hard prerequisite (no go/psql/pg_prove, Postgres down, or an
# unloaded mailserver_test) is fatal HERE with a named fix, instead of surfacing
# 200 lines into pg_prove as a raw "connection refused". Set PREFLIGHT_SKIP=1 to
# bypass (e.g. a CI image that provisions services in a separate step).
if [ "${PREFLIGHT_SKIP:-0}" != "1" ]; then
  bash "$(dirname "$0")/preflight.sh" || {
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

# DB-gated Go guards (scope/issuance/expiry/case-fold regressions) call t.Skip()
# when DB_DSN is unset — a SKIP reads green but means the guard never ran
# ("skipped guard = fail-open", same theme as the P1 harness wave). Export the
# loaded mailserver_test DSN so those guards RUN. Both names are read across the
# tree: DB_DSN (config/runtime) and TEST_DB_DSN (test-only direct connections).
# The shared/config koanf default-DSN tests isolate themselves via t.Setenv.
export DB_DSN="${DB_DSN:-postgres://mail@127.0.0.1:5432/mailserver_test?sslmode=disable}"
export TEST_DB_DSN="${TEST_DB_DSN:-$DB_DSN}"
# Fail-closed: testsupport.OpenTestPool t.Skip's a DB-backed test when DB_DSN is
# empty, which reads green. That is the hole that hid 8 failing internal/admin
# tests on main (the admin-protection-guard merge). With REQUIRE_DB set, a missing
# DSN is a FATAL t.Fatal instead of a silent skip, so the gate actually RUNS the
# DB tests it just loaded mailserver_test for. (preflight above already verified
# the DB is reachable + baseline-loaded.)
export REQUIRE_DB=1

# Start the Go lane from a deterministic database. An interrupted previous run
# can leave organization-wide fixtures (for example an enabled Super Admin)
# behind even when every normally completed test has cleanup. Several security
# tests intentionally assert process-global invariants, so accepting arbitrary
# residue here makes the canonical suite order-dependent. The separate reload
# before pgTAP below is still required because the Go lane itself mutates the DB.
echo "==> Reloading clean schema before Go tests (isolate from prior-run residue)"
bash "$ROOT/scripts/load-test-schema.sh"
# Several auth integration fixtures intentionally attach users to the first
# local domain. The production baseline contains no deployment-specific domain,
# so seed one explicitly for this lane instead of letting those tests skip on a
# pristine database or depend on residue from an earlier test.
psql "$TEST_DB_DSN" -X -v ON_ERROR_STOP=1 -q -c \
  "INSERT INTO domains (name, is_local) VALUES ('go-tests.local', TRUE) ON CONFLICT (name) DO UPDATE SET is_local = EXCLUDED.is_local"

cd "$ROOT" || exit
while IFS=$'\t' read -r module_id _module_path module_workspace _kind _tags _gowork; do
  [[ "$module_workspace" == "workspace" ]] || continue
  bash "$ROOT/scripts/run-go-test-evidence.sh" "$module_id" "test-results/go/$module_id.json" "${GO_TEST_FLAGS[@]}" ./...
done < <(node "$ROOT/scripts/go-module-catalog.mjs" list test)

echo "==> Verifying U2.5 backup/restore integrity evidence"
bash "$ROOT/scripts/audit-backup-integrity.sh"

# asrbot (B3 Task 12): NOT in go.work (eng E1) — see scripts/build.sh's
# comment for the full rationale (GOWORK=off + -tags nolibopusfile). A
# LOUD named skip when libopus isn't installed, never a silent one. Not
# part of the -race lane above: asrbot has no shared-state DB dependency
# on mailserver_test to race-cover alongside shared/mailctl.
if pkg-config --exists opus 2>/dev/null; then
  GOWORK=off bash "$ROOT/scripts/run-go-test-evidence.sh" asrbot test-results/go/asrbot.json -tags nolibopusfile ./...
  ASRBOT_COVERAGE_SUFFIX=",asrbot"
else
  echo "==> SKIP asrbot tests (libopus not installed — brew install opus / apt install libopus-dev)"
  ASRBOT_COVERAGE_SUFFIX=""
fi

echo "==> Verifying named Go test evidence"
cd "$ROOT" && TEST_EVIDENCE_OUTPUT="test-results/go/test-evidence.json" \
  bash "$ROOT/scripts/check-test-evidence-results.sh" --verify go-json

echo "==> Enforcing Go coverage ratchets"
GO_COVERAGE_MODULES="authserver,mailserver,shared,mailctl,setjoin-release${ASRBOT_COVERAGE_SUFFIX:-}" \
  node "$ROOT/scripts/report-go-coverage.mjs" --mode enforce

echo "==> Running bounded Go fuzz smoke"
bash "$ROOT/scripts/run-go-fuzz-smoke.sh"

echo "==> Testing webmail (Vitest + coverage ratchet)"
cd "$ROOT/mailserver/webmail" && npm run test:coverage
echo "==> Verifying named Webmail test evidence"
cd "$ROOT" && TEST_EVIDENCE_OUTPUT="mailserver/webmail/test-results/test-evidence.json" \
  bash "$ROOT/scripts/check-test-evidence-results.sh" --verify vitest-json
echo "==> Enforcing changed Webmail coverage"
node "$ROOT/scripts/report-changed-coverage.mjs" --mode enforce

# The Go suite above mutates mailserver_test (seeded users/mailboxes/messages/
# blobs/jobs); many tests t.Cleanup but not all, and pgTAP asserts against a
# pristine fixture set. Reload the baseline so pgTAP runs on a CLEAN DB regardless
# of Go-test residue — both suites pass individually on a fresh DB, but the old
# Go→pgTAP order (no reload) let one Go test's leftover row fail an unrelated
# pgTAP file.
echo "==> Reloading clean schema before pgTAP (isolate from Go-suite residue)"
# Absolute path: the webmail/Go test steps above cd around, so a $0-relative path
# would resolve against the wrong CWD (exit 127).
bash "$ROOT/scripts/load-test-schema.sh"

echo "==> Testing PL/pgSQL reducers — mailserver (pgTAP)"
bash "$ROOT/scripts/run-pgtap-evidence.sh" test-results/pgtap/mailserver.tap \
  -d mailserver_test "$ROOT/mailserver/sql/tests/"*.pg

echo "==> Testing PL/pgSQL reducers — authserver (pgTAP)"
bash "$ROOT/scripts/run-pgtap-evidence.sh" test-results/pgtap/authserver.tap \
  -d mailserver_test "$ROOT/authserver/sql/tests/"*.pg

echo "==> Verifying named pgTAP evidence"
TEST_EVIDENCE_OUTPUT="test-results/pgtap/test-evidence.json" \
  bash "$ROOT/scripts/check-test-evidence-results.sh" --verify tap

# ── Vulnerability scanning ──────────────────────

echo ""
echo "=== govulncheck ==="
GOVULNCHECK="$(command -v govulncheck 2>/dev/null || true)"
if [ -z "$GOVULNCHECK" ]; then
    GOVULNCHECK="$(go env GOPATH)/bin/govulncheck"
fi
if [ ! -x "$GOVULNCHECK" ]; then
    echo "  FAIL: govulncheck is required. Install with:" >&2
    echo "        go install golang.org/x/vuln/cmd/govulncheck@latest" >&2
    exit 1
fi
while IFS=$'\t' read -r module_id module_path _workspace _kind module_tags module_gowork; do
  echo "  $module_id..."
  vuln_args=()
  [[ -n "$module_tags" ]] && vuln_args=(-tags "$module_tags")
  if [[ "$module_gowork" == "off" ]]; then
    (cd "$ROOT/$module_path" && GOWORK=off "$GOVULNCHECK" "${vuln_args[@]}" ./...)
  else
    (cd "$ROOT/$module_path" && "$GOVULNCHECK" "${vuln_args[@]}" ./...)
  fi
done < <(node "$ROOT/scripts/go-module-catalog.mjs" list vulnerability)
