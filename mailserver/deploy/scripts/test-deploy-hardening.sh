#!/usr/bin/env bash
set -euo pipefail

# Render/posture and behavior check for the deploy-file ER5 closures:
#
#   - mailserver/deploy/config.env.sample (occ_05d647b,
#     insecure-configuration.superuser-application-dsn): the sample a fresh
#     operator copies MUST render the constrained native-RLS three-role shape —
#     tenant-facing services on the setjoin_app role (NOSUPERUSER, NOBYPASSRLS),
#     the privileged worker/owner tiers only in the 0600 root-owned credential
#     file, and no superuser/owner DSN spelled as a default. It must also carry
#     no real credential (the 0600-credential-file discipline of
#     secret-zero-read-redaction: nothing secret in the shared sample).
#
#   - mailserver/deploy/scripts/backup.sh (occ_46ce8465,
#     insecure-permissions.database-backup): a raw pg_dump is a complete copy
#     of every mailbox and secret column, so the script must write it
#     mode-0600 (umask 077), publish it atomically (a failed run leaves no
#     truncated file that looks restorable), deliver the password via the
#     PGPASSWORD environment only (never argv, never echoed), and keep prior
#     backups safe when a run fails.
#
# The backup.sh legs are LIVE: the assertions run the real script against a
# stub pg_dump, so the mode/atomicity/retention behavior is executed, not
# merely grepped.

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SAMPLE="$ROOT/mailserver/deploy/config.env.sample"
BACKUP_SH="$ROOT/mailserver/deploy/scripts/backup.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

require() {
  local desc="$1" pattern="$2" file="$3"
  if ! grep -Fq -- "$pattern" "$file"; then
    echo "deploy hardening: missing required pattern ($desc): $pattern" >&2
    exit 1
  fi
}

refuse() {
  local desc="$1" pattern="$2" file="$3"
  if grep -Fq -- "$pattern" "$file"; then
    echo "deploy hardening: forbidden pattern present ($desc): $pattern" >&2
    exit 1
  fi
}

mode_of() {
  # Portable file-mode octal (BSD stat first, then GNU).
  stat -f %Lp "$1" 2>/dev/null || stat -c %a "$1"
}

# ── 1. config.env.sample: constrained three-role DSN posture ─────────────────
bash -n "$BACKUP_SH"

require "sample: runtime DSN uses the constrained app role" \
  'DB_DSN=postgres://setjoin_app:' "$SAMPLE"
require "sample: direct DSN uses the constrained app role" \
  'DB_DIRECT_DSN=postgres://setjoin_app:' "$SAMPLE"
require "sample: names the FORCE'd RLS constraint" \
  'constrained by FORCE' "$SAMPLE"
require "sample: worker tier lives in the 0600 credential file" \
  'DB_WORKER_DSN' "$SAMPLE"
require "sample: owner tier lives in the 0600 credential file" \
  'DB_OWNER_DSN' "$SAMPLE"
require "sample: points at the root-owned credential file" \
  '/etc/setjoin/db-credentials.d/db-credentials.env' "$SAMPLE"
require "sample: cites the native-RLS runbook" \
  'docs/guides/NATIVE_RLS_FLIP_RUNBOOK.md' "$SAMPLE"
require "sample: marks permissive single-DSN as an explicit downgrade" \
  '--permissive-dsn' "$SAMPLE"
require "sample: warns against owner/superuser runtime credentials" \
  'Tenant-facing services must never run as the database owner' "$SAMPLE"
refuse "sample: no owner-role DSN default" \
  'postgres://mail:' "$SAMPLE"
refuse "sample: no throwaway shared password" \
  'changeme' "$SAMPLE"
refuse "sample: no superuser role spelling" \
  'postgres://postgres:' "$SAMPLE"

# ── 2. backup.sh: static posture ─────────────────────────────────────────────
require "backup.sh: restrictive umask" 'umask 077' "$BACKUP_SH"
require "backup.sh: password via PGPASSWORD environment" 'PGPASSWORD=' "$BACKUP_SH"
# shellcheck disable=SC2016  # the pattern must match the literal script text
require "backup.sh: atomic publication via mv" 'mv "$tmp"' "$BACKUP_SH"
require "backup.sh: partial dump cleaned on failure" "trap 'rm -f" "$BACKUP_SH"
refuse "backup.sh: no password prompt flag" ' -W' "$BACKUP_SH"
if grep -Eq 'pg_dump [^|]*2>/dev/null' "$BACKUP_SH"; then
  echo "deploy hardening: backup.sh must not discard pg_dump stderr" >&2
  exit 1
fi

# ── 3. backup.sh: live behavior against a stub pg_dump ───────────────────────
stub_bin="$tmp/bin"
data_dir="$tmp/data"
args_file="$tmp/args"
mkdir -p "$stub_bin" "$data_dir"

cat >"$stub_bin/pg_dump" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >"$STUB_ARGS_FILE"
if [ -n "${STUB_FAIL:-}" ]; then
  echo "stub pg_dump: simulated failure" >&2
  exit 1
fi
echo "SET statement_timeout = 0;"
echo "CREATE dummy;"
STUB
chmod +x "$stub_bin/pg_dump"

run_backup() {
  STUB_ARGS_FILE="$args_file" DATA_DIR="$data_dir" \
    DB_PASSWORD="s3cr3t-test-password" PATH="$stub_bin:$PATH" bash "$BACKUP_SH"
}

# 3a. Happy path: dump lands 0600, complete content, password never on argv,
#     no partial left behind.
before_count="$(find "$data_dir" -name 'pg-*.sql.gz' | wc -l | tr -d ' ')"
run_backup >/dev/null
after_count="$(find "$data_dir" -name 'pg-*.sql.gz' | wc -l | tr -d ' ')"
if [ "$after_count" != "$((before_count + 1))" ]; then
  echo "deploy hardening: successful run did not publish exactly one dump" >&2
  exit 1
fi
final="$(find "$data_dir" -name 'pg-*.sql.gz' | head -1)"
mode="$(mode_of "$final")"
if [ "$mode" != "600" ]; then
  echo "deploy hardening: published dump mode is $mode, want 600 (world/group unreadable)" >&2
  exit 1
fi
gzip -t "$final"
if ! gzip -cd "$final" | grep -Fq 'CREATE dummy;'; then
  echo "deploy hardening: published dump does not hold the pg_dump stream" >&2
  exit 1
fi
if [ -n "$(find "$data_dir" -name '*.partial')" ]; then
  echo "deploy hardening: partial dump left behind after success" >&2
  exit 1
fi

# 3b. Password never reaches pg_dump argv; the stub saw the documented target.
if grep -Fq 's3cr3t-test-password' "$args_file"; then
  echo "deploy hardening: password leaked into pg_dump argv" >&2
  exit 1
fi
require "backup.sh: stub saw the target database" '-d mailserver' "$args_file"

# 3c. Failure path: pg_dump failing must exit nonzero, publish nothing,
#     clean the partial file, and leave the previous backup untouched.
seed="$data_dir/pg-20260101-000000.sql.gz"
echo "previous" | gzip >"$seed"
chmod 600 "$seed" # the seeded prior backup starts 0600, like every real one
seeded_count="$(find "$data_dir" -name 'pg-*.sql.gz' | wc -l | tr -d ' ')"
if STUB_ARGS_FILE="$args_file" DATA_DIR="$data_dir" DB_PASSWORD="s3cr3t-test-password" \
  STUB_FAIL=1 PATH="$stub_bin:$PATH" bash "$BACKUP_SH" >/dev/null 2>&1; then
  echo "deploy hardening: backup.sh exited 0 despite pg_dump failure" >&2
  exit 1
fi
after_fail_count="$(find "$data_dir" -name 'pg-*.sql.gz' | wc -l | tr -d ' ')"
if [ "$after_fail_count" != "$seeded_count" ]; then
  echo "deploy hardening: failed run changed the published backup set" >&2
  exit 1
fi
if [ -n "$(find "$data_dir" -name '*.partial')" ]; then
  echo "deploy hardening: partial dump left behind after failure" >&2
  exit 1
fi
if [ "$(mode_of "$seed")" != "600" ]; then
  echo "deploy hardening: pre-existing backup lost its 0600 mode" >&2
  exit 1
fi

echo "deploy hardening: PASS (sample three-role posture; backup.sh 0600 atomic PGPASSWORD-only behavior)"
