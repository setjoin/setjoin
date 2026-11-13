#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-queue-contract.sh — queue failure-contract ratchet (F4).
#
# For every CREATE TABLE matching *_queue|*_jobs across the dbschema corpus
# (baseline + forward migrations), assert the failure contract (mailserver/sql/
# AGENTS.md → Queue failure contract): attempt_count, next_attempt_at, last_error,
# and a status column. A table NOT on the waiver ALLOWLIST that is missing any
# contract column FAILS the build. Also asserts the shared retry reducer
# (settle_job.sql) exists — converged queues route their failure branches through
# it. Greppy + fast, in the genre of scripts/check-no-duplicate-version.sh.
#
# Note: a table's columns may be SPREAD across the baseline def + a later
# ALTER TABLE ... ADD COLUMN migration (journal_queue gains next_attempt_at/
# last_error in V033), so the check scans the WHOLE corpus for each table's
# columns, not just its CREATE TABLE block.
#
# DBSCHEMA_DIR / REDUCERS_DIR may be overridden (absolute dirs) by the self-test.
# Usage: scripts/check-queue-contract.sh  (0=clean, 1=violation).
# Wired into scripts/test.sh; self-tested by scripts/check-queue-contract-selftest.sh.
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

DBSCHEMA_DIR="${DBSCHEMA_DIR:-$ROOT/mailserver/sql/dbschema}"
REDUCERS_DIR="${REDUCERS_DIR:-$ROOT/mailserver/sql/reducers}"

# ── Waiver ALLOWLIST (one bare table name per line; see AGENTS.md for the why) ──
#   outbound_queue     — read-contract only; Go-side backoff, terminal 'bounced'.
#   blob_cleanup_queue — GC delay-list; no status lifecycle by design.
#   migration_jobs     — bespoke multi-phase import FSM; own recovery.
#   restore_jobs       — admin-triggered DR restore FSM; own error_log/status, not a retry queue.
#   eap_apply_jobs     — single-pass email-address-policy apply job (own error/status);
#                        Phase 2 convergence target, not yet routed through settle_job.
#   bulk_role_jobs     — batch-resume job (tracks processed count; resumes on restart);
#                        own error/status; Phase 2 convergence target, same posture as eap_apply_jobs.
#   identity_jobs      — bounded operator-job FSM with state, leased claims,
#                        hard 20-attempt ceiling, progress.lastErrorCode, and
#                        dedicated claim/fail/batch-settle reducers.
#   drive_chunk_gc_queue — zero-ref chunk GC delay-list (spec §3.5, V114); same
#                          shape as blob_cleanup_queue — the worker DELETEs the
#                          row on every outcome (removed or re-referenced), no
#                          retry/backoff bookkeeping by design.
ALLOWLIST="outbound_queue blob_cleanup_queue migration_jobs migration_thread_reconcile_jobs restore_jobs eap_apply_jobs bulk_role_jobs drive_chunk_gc_queue identity_jobs"

is_waived() { local t="$1" a; for a in $ALLOWLIST; do [ "$t" = "$a" ] && return 0; done; return 1; }

echo "==> queue failure-contract guard (*_queue / *_jobs must carry the contract)"

# All SQL text in the corpus, concatenated (CREATE TABLE + later ALTERs).
CORPUS="$(cat "$DBSCHEMA_DIR"/V*.sql 2>/dev/null)"

# Retry reducer must exist.
if ! grep -q 'FUNCTION settle_job(' "$REDUCERS_DIR"/settle_job.sql 2>/dev/null; then
  echo "  MISSING retry reducer: reducers/settle_job.sql (FUNCTION settle_job)"
  echo "==> queue-contract guard FAILED"
  exit 1
fi

# Enumerate every CREATE TABLE [public.]<name>(_queue|_jobs).
tables="$(
  printf '%s\n' "$CORPUS" \
    | grep -oiE 'CREATE TABLE (IF NOT EXISTS )?(public\.)?[a-z_]+' \
    | sed -E 's/.*[[:space:]](public\.)?//' \
    | grep -E '_(queue|jobs)$' \
    | sort -u
)"

fail=0
for t in $tables; do
  if is_waived "$t"; then
    echo "    waived: $t"
    continue
  fi
  missing=""
  # Collect every SQL statement (CREATE TABLE / ALTER TABLE) that names this table,
  # then check each contract column appears within that table's statements. A
  # table's columns may be SPREAD across the baseline CREATE plus later ALTER ...
  # ADD COLUMN migrations (journal_queue gains next_attempt_at/last_error in V033),
  # so we gather all of them. awk splits the corpus into ;-terminated statements
  # (portable; avoids GNU-grep-only -z multiline matching).
  # Each ;-terminated statement is one awk record. Keep (whole, multiline) records
  # that are a CREATE/ALTER TABLE naming this table; concatenate their text so a
  # later grep sees every column the table declares across all its statements.
  stmts="$(
    printf '%s\n' "$CORPUS" \
      | awk -v t="$t" 'BEGIN{RS=";"} {
          s=tolower($0)
          if (s ~ /(create|alter)[ \t\r\n]+table/ && s ~ ("[^a-z0-9_]" t "[^a-z0-9_]")) {
            gsub(/\n/," ",$0); print $0
          }
        }'
  )"
  for col in attempt_count next_attempt_at last_error status; do
    if ! printf '%s\n' "$stmts" | grep -iqE "[^a-z0-9_]${col}[^a-z0-9_]"; then
      missing="$missing $col"
    fi
  done
  if [ -n "$missing" ]; then
    fail=1
    echo ""
    echo "  CONTRACT VIOLATION: table '$t' is missing:$missing"
    echo "  → add the column(s) (see mailserver/sql/AGENTS.md → Queue failure"
    echo "    contract) or, if genuinely exempt, add '$t' to ALLOWLIST in"
    echo "    scripts/check-queue-contract.sh with a one-line reason."
  fi
done

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "==> queue-contract guard FAILED — a non-waived queue table lacks the contract."
  exit 1
fi
echo "    all *_queue/*_jobs tables carry the contract (waivers listed above)."
