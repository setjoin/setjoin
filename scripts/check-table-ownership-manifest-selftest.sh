#!/usr/bin/env bash
# Self-test for scripts/check-table-ownership-manifest.sh (Issue #539).
# Auto-discovered by scripts/run-guards.sh (runs before check-table-ownership-manifest.sh).
# Verifies pristine repo passes and all 8 required negative mutants fail with named codes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="$SCRIPT_DIR/check-table-ownership-manifest.sh"

echo "==> check-table-ownership-manifest selftest"

# 1. Run full Python mutant & invariant suite (pristine repo + all 8 named mutants + edge cases).
python3 "$SCRIPT_DIR/test-table-ownership-manifest.py"

# 2. Shell-level grep -qF verification on synthetic fixtures for all 8 named error codes.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/dbschema" "$WORK/domains/calendar/src" "$WORK/domains/chat/src" "$WORK/domains/user-settings/src" "$WORK/domains/jmap/src"
cat >"$WORK/dbschema/V001__base.sql" <<'SQL'
CREATE TABLE public.messages (id bigint PRIMARY KEY, mailbox_id bigint NOT NULL);
ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messages FORCE ROW LEVEL SECURITY;
CREATE TABLE public.drive_nodes (id bigint PRIMARY KEY, space_id bigint NOT NULL, name text);
ALTER TABLE public.drive_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.drive_nodes FORCE ROW LEVEL SECURITY;
CREATE TABLE public.user_signatures (id bigint PRIMARY KEY, user_id bigint NOT NULL, body text);
ALTER TABLE public.user_signatures ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_signatures FORCE ROW LEVEL SECURITY;
SQL

cat >"$WORK/manifest.json" <<'JSON'
{
  "schema_version": 1,
  "legacy_rls_pending_ceiling": 0,
  "legacy_rls_pending_tables": [],
  "legacy_write_migration_ceiling": 0,
  "r1_r3_allowlist": [],
  "tables": {
    "messages": {
      "owner": "jmap",
      "security_class": "mailbox_scoped",
      "rls_posture": "enforced",
      "rls_scope_column": "mailbox_id",
      "read_contracts": []
    },
    "drive_nodes": {
      "owner": "drive",
      "security_class": "user_scoped",
      "rls_posture": "enforced",
      "rls_scope_column": "space_id -> drive_spaces.owner_user_id",
      "read_contracts": []
    },
    "user_signatures": {
      "owner": "user-settings",
      "security_class": "user_scoped",
      "rls_posture": "enforced",
      "rls_scope_column": "user_id",
      "read_contracts": []
    }
  }
}
JSON

# Inject all 8 failure modes into one combined smoke fixture and verify each named tag with grep -qF.
cat >"$WORK/dbschema/V002__mutants.sql" <<'SQL'
CREATE TABLE public.unclassified_smoke (id bigint PRIMARY KEY);
CREATE TABLE public.new_pending_smoke (id bigint PRIMARY KEY, user_id bigint NOT NULL);
ALTER TABLE public.drive_nodes NO FORCE ROW LEVEL SECURITY;
SQL

cat >"$WORK/manifest-mutants.json" <<'JSON'
{
  "schema_version": 1,
  "legacy_rls_pending_ceiling": 0,
  "legacy_rls_pending_tables": [],
  "legacy_write_migration_ceiling": 0,
  "r1_r3_allowlist": [],
  "tables": {
    "messages": {
      "owner": "jmap",
      "security_class": "mailbox_scoped",
      "rls_posture": "enforced",
      "rls_scope_column": "mailbox_id",
      "read_contracts": []
    },
    "drive_nodes": {
      "owner": "drive",
      "security_class": "user_scoped",
      "rls_posture": "enforced",
      "rls_scope_column": "space_id -> drive_spaces.owner_user_id",
      "read_contracts": []
    },
    "user_signatures": {
      "owner": "user-settings",
      "security_class": "user_scoped",
      "rls_posture": "enforced",
      "rls_scope_column": "user_id",
      "read_contracts": []
    },
    "new_pending_smoke": {
      "owner": "identity",
      "security_class": "user_scoped",
      "rls_posture": "pending_wave1_cutover",
      "rls_tracking_issue": "#546",
      "rls_scope_column": "user_id",
      "read_contracts": []
    },
    "stale_smoke_table": {
      "owner": "platform",
      "security_class": "system_only",
      "rls_posture": "not_applicable",
      "read_contracts": []
    }
  }
}
JSON

cat >"$WORK/domains/calendar/src/lib.rs" <<'RS'
pub const Q: &str = "SELECT id FROM messages WHERE mailbox_id = $1";
RS
cat >"$WORK/domains/chat/src/lib.rs" <<'RS'
pub const Q: &str = "UPDATE drive_nodes SET name = $2 WHERE id = $1 AND space_id = $3";
RS
cat >"$WORK/domains/user-settings/src/lib.rs" <<'RS'
pub const Q1: &str = "SELECT user_id FROM user_signatures WHERE id = $1";
pub const Q2: &str = "DELETE FROM user_signatures WHERE id = $1";
RS

rc=0
OUT="$(TABLE_MANIFEST="$WORK/manifest-mutants.json" TABLE_SCHEMA_DIR="$WORK/dbschema" TABLE_RUST_DOMAINS_DIR="$WORK/domains" bash "$GUARD" 2>&1)" || rc=$?
if [ "$rc" -eq 0 ]; then
  echo "FAIL: combined mutant fixture unexpectedly passed" >&2
  exit 1
fi

for tag in \
  "UNCLASSIFIED:" \
  "STALE:" \
  "UNCONTRACTED_CROSS_DOMAIN_READ:" \
  "UNCONTRACTED_CROSS_DOMAIN_WRITE:" \
  "MISSING_FORCE_RLS:" \
  "R1_MISSING_PREDICATE" \
  "R3_MISSING_PREDICATE" \
  "RLS_PENDING_RATCHET"; do
  if ! printf '%s\n' "$OUT" | grep -qF "$tag"; then
    echo "FAIL: expected named failure tag '$tag' not found in guard output:" >&2
    printf '%s\n' "$OUT" >&2
    exit 1
  fi
done

echo "check-table-ownership-manifest-selftest: PASS (pristine repo + all 8 named mutant tags verified)."
