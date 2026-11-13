#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-guc-afterconnect-selftest.sh — negative-case self-test for
# check-guc-afterconnect.sh.
#
# A guard that never fires is theater. This copies shared/ into a scratch dir
# (the REAL repo tree is never touched), neuters the AfterConnect assignment
# in the copy's shared/pgxutil/pool.go, and asserts:
#   1. the neutered copy's TestOpenPool_AfterConnect_SetsEncryptionKeyGUC FAILS
#      (the guard would catch the hook being removed/bypassed).
#   2. the real check-guc-afterconnect.sh (against the untouched tree) PASSES.
#
# Usage: scripts/check-guc-afterconnect-selftest.sh  (exit 0 = both cases pass).
# Wired into run-guards.sh ahead of the real guard run (same convention as
# check-migration-allocation-selftest.sh).
# ──────────────────────────────────────────────────────────────────────────
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

export DB_DSN="${DB_DSN:-postgres://mail@127.0.0.1:5432/mailserver_test?sslmode=disable}"
export REQUIRE_DB=1

fail=0
pass() { echo "    ok   $1"; }
bad()  { echo "    FAIL $1"; fail=1; }

echo "==> AfterConnect-guard self-test (must fire when the hook is neutered)"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cp -r "$ROOT/shared" "$TMP/shared"

# Neuter the AfterConnect wiring in the COPY only: force the guarding
# condition false so the GUC is never set, regardless of encryptionKey.
POOL_GO="$TMP/shared/pgxutil/pool.go"
if ! grep -q 'if encryptionKey != "" || auditHMACKey != "" {' "$POOL_GO"; then
  bad "expected AfterConnect guard condition not found in pool.go — check-guc-afterconnect.sh's assumption about the source shape may be stale"
else
  sed -i.bak 's/if encryptionKey != "" || auditHMACKey != "" {/if false \&\& (encryptionKey != "" || auditHMACKey != "") {/' "$POOL_GO"
  rm -f "$POOL_GO.bak"

  if (cd "$TMP/shared" && DB_DSN="$DB_DSN" REQUIRE_DB=1 go test ./pgxutil/... -run '^TestOpenPool_AfterConnect_SetsEncryptionKeyGUC$' -count=1 >"$TMP/out" 2>&1); then
    bad "neutered AfterConnect hook — guard test did NOT fail"
    sed 's/^/        /' "$TMP/out"
  else
    pass "neutered AfterConnect hook — guard test correctly failed"
  fi
fi

echo "==> clean tree (real repo, untouched) must still pass"
if bash "$ROOT/scripts/check-guc-afterconnect.sh" >"$TMP/clean_out" 2>&1; then
  pass "real check-guc-afterconnect.sh passes against the untouched tree"
else
  bad "real check-guc-afterconnect.sh should pass against the untouched tree"
  sed 's/^/        /' "$TMP/clean_out"
fi

if [ "$fail" -ne 0 ]; then
  echo "==> AfterConnect-guard self-test FAILED — the guard stopped catching a removed/bypassed hook."
  exit 1
fi
echo "    AfterConnect-guard self-test: fires on a neutered hook, passes the clean tree."
