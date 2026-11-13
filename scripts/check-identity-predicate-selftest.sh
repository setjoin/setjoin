#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-identity-predicate-selftest.sh — negative+positive self-test for the
# identity-predicate definition guard (scripts/check-identity-predicate.sh).
#
# A guard that never fires is theater; a guard that ALWAYS fires (a blind string
# compare) is noise. This proves BOTH ends:
#   · REAL tree (the two identical twins)         → guard PASSES.
#   · injected REAL divergence (a 4th OR branch;  → guard FIRES (exit 1).
#     a changed case-fold)
#   · COSMETIC-only difference (rename the        → guard still PASSES
#     mailboxes alias; the reducer-only null-       (proves the normalization is
#     guard present/absent)                         real, not a string compare).
#
# It drives the guard against TEMP copies of the twins via the guard's
# REDUCER_FILE / CONNECTOR_FILE overrides, so the real repo files are untouched.
#
# Usage: scripts/check-identity-predicate-selftest.sh   (exit 0 = all cases pass).
# Wired into scripts/test.sh ahead of the real guard run.
# ──────────────────────────────────────────────────────────────────────────
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUARD="$ROOT/scripts/check-identity-predicate.sh"
REAL_REDUCER="$ROOT/mailserver/sql/reducers/resolve_identity.sql"
REAL_CONNECTOR="$ROOT/authserver/internal/connector/connector.go"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail=0
pass() { echo "    ok   $1"; }
bad()  { echo "    FAIL $1"; fail=1; }

# run_guard <reducer> <connector> → writes $TMP/out, returns guard exit code.
run_guard() {
  REDUCER_FILE="$1" CONNECTOR_FILE="$2" bash "$GUARD" > "$TMP/out" 2>&1
  return $?
}

echo "==> identity-predicate guard self-test"

# ── Positive: the real, identical twins must PASS. ──────────────────────────
if run_guard "$REAL_REDUCER" "$REAL_CONNECTOR"; then
  pass "real (identical) twins pass"
else
  bad "real twins should pass"; sed 's/^/        /' "$TMP/out"
fi

# ── Negative 1: a 4th OR branch in the reducer twin → DRIFT. ─────────────────
cp "$REAL_REDUCER" "$TMP/reducer_4or.sql"
# Add an extra OR branch to the predicate (a plausible "resolve by phone too").
perl -0pi -e 's/(OR lower\(u\.ad_upn\) = lower\(p_address\)\n)/$1      OR lower(u.phone) = lower(p_address)\n/' "$TMP/reducer_4or.sql"
if run_guard "$TMP/reducer_4or.sql" "$REAL_CONNECTOR"; then
  bad "N1: 4th OR branch — guard did NOT fire"; sed 's/^/        /' "$TMP/out"
elif grep -q "DRIFT" "$TMP/out"; then
  pass "N1: 4th OR branch (reducer) — caught (DRIFT)"
else
  bad "N1: failed but without a DRIFT message"; sed 's/^/        /' "$TMP/out"
fi

# ── Negative 2: a changed case-fold in the connector twin → DRIFT. ──────────
# Swap lower(u.email) → upper(u.email): a real normalization-rule change.
cp "$REAL_CONNECTOR" "$TMP/connector_fold.go"
perl -0pi -e 's/lower\(u\.email\) = lower\(\$1\)/upper(u.email) = upper(\$1)/' "$TMP/connector_fold.go"
if run_guard "$REAL_REDUCER" "$TMP/connector_fold.go"; then
  bad "N2: changed case-fold — guard did NOT fire"; sed 's/^/        /' "$TMP/out"
elif grep -q "DRIFT" "$TMP/out"; then
  pass "N2: lower()→upper() case-fold (connector) — caught (DRIFT)"
else
  bad "N2: failed but without a DRIFT message"; sed 's/^/        /' "$TMP/out"
fi

# ── Negative 3: a changed join target → DRIFT. ──────────────────────────────
# Change the alias join from a.mailbox_id to a different column: rule divergence.
cp "$REAL_REDUCER" "$TMP/reducer_join.sql"
perl -0pi -e 's/JOIN mailboxes m ON m\.id = a\.mailbox_id/JOIN mailboxes m ON m.id = a.owner_mailbox_id/' "$TMP/reducer_join.sql"
if run_guard "$TMP/reducer_join.sql" "$REAL_CONNECTOR"; then
  bad "N3: changed join column — guard did NOT fire"; sed 's/^/        /' "$TMP/out"
elif grep -q "DRIFT" "$TMP/out"; then
  pass "N3: changed alias-join column (reducer) — caught (DRIFT)"
else
  bad "N3: failed but without a DRIFT message"; sed 's/^/        /' "$TMP/out"
fi

# ── Positive (cosmetic only): rename the mailboxes alias in the connector. ──
# mb → xb everywhere in the EXISTS subquery. Normalization canonicalizes the
# mailboxes alias, so this is a no-op to the rule → must STILL PASS.
cp "$REAL_CONNECTOR" "$TMP/connector_alias.go"
perl -0pi -e 's/JOIN mailboxes mb ON mb\.id = a\.mailbox_id\n(\s*)WHERE mb\.user_id = u\.id/JOIN mailboxes xb ON xb.id = a.mailbox_id\n${1}WHERE xb.user_id = u.id/' "$TMP/connector_alias.go"
if run_guard "$REAL_REDUCER" "$TMP/connector_alias.go"; then
  pass "P1: cosmetic mailboxes-alias rename (mb→xb) — still passes (normalized away)"
else
  bad "P1: cosmetic alias rename should pass (normalization failed to absorb it)"; sed 's/^/        /' "$TMP/out"
fi

# ── Positive (cosmetic only): the reducer keeps its IS NOT NULL null-guard, ──
# the connector does not. The real twins already differ this way and pass; to
# prove the null-guard normalization is load-bearing, ADD a redundant second
# null-guard to the reducer (still semantically the reducer-only guard) — the
# normalization drops it, so the twins still agree → PASS.
cp "$REAL_REDUCER" "$TMP/reducer_nullguard.sql"
perl -0pi -e 's/(AND p_address IS NOT NULL\n)/$1    AND p_address IS NOT NULL\n/' "$TMP/reducer_nullguard.sql"
if run_guard "$TMP/reducer_nullguard.sql" "$REAL_CONNECTOR"; then
  pass "P2: extra reducer-only IS NOT NULL guard — still passes (normalized away)"
else
  bad "P2: extra null-guard should pass (normalization failed to absorb it)"; sed 's/^/        /' "$TMP/out"
fi

if [ "$fail" -ne 0 ]; then
  echo "==> identity-predicate guard self-test FAILED — the guard mis-classified a case."
  exit 1
fi
echo "    identity-predicate guard self-test: all cases (positive + negative) behave."
