#!/usr/bin/env bash
# check-audit-coverage-selftest.sh — mutation-proof the WP3 guard.
#
# Plants each failure class against a sandbox reducers tree + inventory and
# proves the guard fires with the right diagnosis; then proves a clean fixture
# passes. Without this, a guard that silently stopped matching would pass CI
# while nothing was enforced.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUARD="$ROOT/scripts/check-audit-coverage.sh"
SBX="$(mktemp -d /tmp/audit-coverage-selftest.XXXXXX)"
trap 'rm -rf "$SBX"' EXIT
mkdir -p "$SBX/reducers"

fail() {
  echo "SELFTEST FAIL: $1" >&2
  exit 1
}
expect_fire() { # <label> <expected-substring>
  local label="$1" want="$2"
  local out rc
  out=$(AUDIT_REDUCERS_ROOT="$SBX/reducers" AUDIT_COVERAGE_TSV="$SBX/audit-coverage.tsv" bash "$GUARD" 2>&1)
  rc=$?
  if [ $rc -eq 0 ]; then fail "$label — guard passed, expected it to fire"; fi
  if ! grep -q "$want" <<<"$out"; then
    fail "$label — fired but did not name the planted defect ($want):" $'\n'"$out"
  fi
  echo "  ✓ $label"
}
expect_clean() {
  local label="$1"
  local out rc
  out=$(AUDIT_REDUCERS_ROOT="$SBX/reducers" AUDIT_COVERAGE_TSV="$SBX/audit-coverage.tsv" bash "$GUARD" 2>&1)
  rc=$?
  if [ $rc -ne 0 ]; then fail "$label — guard failed on the clean fixture:" $'\n'"$out"; fi
  echo "  ✓ $label"
}

reset() {
  rm -f "$SBX/reducers"/*.sql "$SBX/audit-coverage.tsv"
}
sink_row() { printf 'audit_write.sql\taudit_write\tAUDIT_SINK\t-\tthe single INSERT path into admin_audit_log\n'; }

# (0) clean baseline: one sink, one MUST with a real call, one exempt, one read-only.
reset
cat >"$SBX/reducers/audit_write.sql" <<'SQL'
CREATE OR REPLACE FUNCTION audit_write(p_actor bigint, p_action text) RETURNS void AS $$
BEGIN
  INSERT INTO admin_audit_log (user_id, action) VALUES (p_actor, p_action);
END;
$$ LANGUAGE plpgsql;
SQL
cat >"$SBX/reducers/thing_create.sql" <<'SQL'
CREATE OR REPLACE FUNCTION thing_create(p_actor bigint) RETURNS void AS $$
BEGIN
  INSERT INTO things (id) VALUES (1);
  PERFORM audit_write(p_actor, 'thing.create', 'thing', 1, NULL, NULL, NULL, NULL, 'core');
END;
$$ LANGUAGE plpgsql;
SQL
cat >"$SBX/reducers/thing_touch.sql" <<'SQL'
CREATE OR REPLACE FUNCTION thing_touch(p_id bigint) RETURNS void AS $$
BEGIN
  UPDATE things SET touched = now() WHERE id = p_id;
END;
$$ LANGUAGE plpgsql;
SQL
cat >"$SBX/reducers/thing_get.sql" <<'SQL'
CREATE OR REPLACE FUNCTION thing_get(p_id bigint) RETURNS jsonb AS $$
  SELECT row_to_json(t) FROM things t WHERE id = p_id;
$$ LANGUAGE sql;
SQL
{
  sink_row
  printf 'thing_create.sql\tthing_create\tMUST\tcore\taccount-style lifecycle creation\n'
  printf 'thing_touch.sql\tthing_touch\tEXEMPT\t-\thigh-frequency user-content mutation, ownership-scoped\n'
  printf 'thing_get.sql\tthing_get\tREAD_ONLY\t-\tpure read path (guard re-derives no DML)\n'
} >"$SBX/audit-coverage.tsv"
expect_clean "clean fixture passes"

# (1) unclassified NEW function.
reset
cat >"$SBX/reducers/audit_write.sql" <<'SQL'
CREATE OR REPLACE FUNCTION audit_write(p_actor bigint, p_action text) RETURNS void AS $$
BEGIN
  INSERT INTO admin_audit_log (user_id, action) VALUES (p_actor, p_action);
END;
$$ LANGUAGE plpgsql;
SQL
cat >"$SBX/reducers/new_mutator.sql" <<'SQL'
CREATE OR REPLACE FUNCTION new_mutator(p_id bigint) RETURNS void AS $$
BEGIN
  UPDATE things SET touched = now() WHERE id = p_id;
END;
$$ LANGUAGE plpgsql;
SQL
{ sink_row; } >"$SBX/audit-coverage.tsv"
expect_fire "unclassified function is named" "UNCLASSIFIED.*new_mutator"

# (2) stale row for a function that no longer exists.
reset
cat >"$SBX/reducers/audit_write.sql" <<'SQL'
CREATE OR REPLACE FUNCTION audit_write(p_actor bigint, p_action text) RETURNS void AS $$
BEGIN
  INSERT INTO admin_audit_log (user_id, action) VALUES (p_actor, p_action);
END;
$$ LANGUAGE plpgsql;
SQL
{
  sink_row
  printf 'gone.sql\tgone_mutator\tEXEMPT\t-\treason\n'
} >"$SBX/audit-coverage.tsv"
expect_fire "stale row is named" "STALE.*gone_mutator"

# (3) MUST without a call in its own body — the sibling's call does not count
# (the exact bundled-file trap the plan calls out).
reset
cat >"$SBX/reducers/audit_write.sql" <<'SQL'
CREATE OR REPLACE FUNCTION audit_write(p_actor bigint, p_action text) RETURNS void AS $$
BEGIN
  INSERT INTO admin_audit_log (user_id, action) VALUES (p_actor, p_action);
END;
$$ LANGUAGE plpgsql;
SQL
cat >"$SBX/reducers/bundle.sql" <<'SQL'
CREATE OR REPLACE FUNCTION bundle_writer(p_actor bigint) RETURNS void AS $$
BEGIN
  INSERT INTO things (id) VALUES (1);
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION bundle_audited(p_actor bigint) RETURNS void AS $$
BEGIN
  PERFORM audit_write(p_actor, 'x', 'y', 1, NULL, NULL, NULL, NULL, 'core');
END;
$$ LANGUAGE plpgsql;
SQL
{
  sink_row
  printf 'bundle.sql\tbundle_writer\tMUST\tcore\tlifecycle write\n'
  printf 'bundle.sql\tbundle_audited\tMUST\tcore\tlifecycle write\n'
} >"$SBX/audit-coverage.tsv"
expect_fire "bundled MUST without its own call fires" "MUST-NO-CALL.*bundle_writer"

# (4) comment-only audit_write does not satisfy a MUST row.
reset
cat >"$SBX/reducers/audit_write.sql" <<'SQL'
CREATE OR REPLACE FUNCTION audit_write(p_actor bigint, p_action text) RETURNS void AS $$
BEGIN
  INSERT INTO admin_audit_log (user_id, action) VALUES (p_actor, p_action);
END;
$$ LANGUAGE plpgsql;
SQL
cat >"$SBX/reducers/comment_only.sql" <<'SQL'
CREATE OR REPLACE FUNCTION comment_only(p_actor bigint) RETURNS void AS $$
BEGIN
  -- audit_write(p_actor, 'looks.audited', ...) — TODO wire this up
  INSERT INTO things (id) VALUES (1);
END;
$$ LANGUAGE plpgsql;
SQL
{
  sink_row
  printf 'comment_only.sql\tcomment_only\tMUST\tcore\tlifecycle write\n'
} >"$SBX/audit-coverage.tsv"
expect_fire "comment-only call fails the MUST row" "MUST-NO-CALL.*comment_only"

# (5) blank exemption reason.
reset
cat >"$SBX/reducers/audit_write.sql" <<'SQL'
CREATE OR REPLACE FUNCTION audit_write(p_actor bigint, p_action text) RETURNS void AS $$
BEGIN
  INSERT INTO admin_audit_log (user_id, action) VALUES (p_actor, p_action);
END;
$$ LANGUAGE plpgsql;
SQL
cat >"$SBX/reducers/exempt_no_reason.sql" <<'SQL'
CREATE OR REPLACE FUNCTION exempt_no_reason(p_id bigint) RETURNS void AS $$
BEGIN
  UPDATE things SET touched = now() WHERE id = p_id;
END;
$$ LANGUAGE plpgsql;
SQL
{
  sink_row
  printf 'exempt_no_reason.sql\texempt_no_reason\tEXEMPT\t-\t\n'
} >"$SBX/audit-coverage.tsv"
expect_fire "blank exemption reason fires" "REASON.*exempt_no_reason"

# (6) READ_ONLY row whose body now mutates (re-derivation).
reset
cat >"$SBX/reducers/audit_write.sql" <<'SQL'
CREATE OR REPLACE FUNCTION audit_write(p_actor bigint, p_action text) RETURNS void AS $$
BEGIN
  INSERT INTO admin_audit_log (user_id, action) VALUES (p_actor, p_action);
END;
$$ LANGUAGE plpgsql;
SQL
cat >"$SBX/reducers/was_read_only.sql" <<'SQL'
CREATE OR REPLACE FUNCTION was_read_only(p_id bigint) RETURNS void AS $$
BEGIN
  DELETE FROM things WHERE id = p_id;
END;
$$ LANGUAGE plpgsql;
SQL
{
  sink_row
  printf 'was_read_only.sql\twas_read_only\tREAD_ONLY\t-\tpure read path (guard re-derives no DML)\n'
} >"$SBX/audit-coverage.tsv"
expect_fire "READ_ONLY that mutates fires" "READ_ONLY-MUTATES.*was_read_only"

# (7) wildcard row.
reset
cat >"$SBX/reducers/audit_write.sql" <<'SQL'
CREATE OR REPLACE FUNCTION audit_write(p_actor bigint, p_action text) RETURNS void AS $$
BEGIN
  INSERT INTO admin_audit_log (user_id, action) VALUES (p_actor, p_action);
END;
$$ LANGUAGE plpgsql;
SQL
{
  sink_row
  printf 'audit_write.sql\t*\tEXEMPT\t-\teverything\n'
} >"$SBX/audit-coverage.tsv"
expect_fire "wildcard row is rejected" "WILDCARD"

# (8) duplicate rows.
reset
cat >"$SBX/reducers/audit_write.sql" <<'SQL'
CREATE OR REPLACE FUNCTION audit_write(p_actor bigint, p_action text) RETURNS void AS $$
BEGIN
  INSERT INTO admin_audit_log (user_id, action) VALUES (p_actor, p_action);
END;
$$ LANGUAGE plpgsql;
SQL
{
  sink_row
  sink_row
} >"$SBX/audit-coverage.tsv"
expect_fire "duplicate rows fire" "DUPLICATE.*audit_write"

# (9) second AUDIT_SINK.
reset
cat >"$SBX/reducers/audit_write.sql" <<'SQL'
CREATE OR REPLACE FUNCTION audit_write(p_actor bigint, p_action text) RETURNS void AS $$
BEGIN
  INSERT INTO admin_audit_log (user_id, action) VALUES (p_actor, p_action);
END;
$$ LANGUAGE plpgsql;
SQL
cat >"$SBX/reducers/audit_write_shadow.sql" <<'SQL'
CREATE OR REPLACE FUNCTION audit_write_shadow(p_actor bigint, p_action text) RETURNS void AS $$
BEGIN
  INSERT INTO admin_audit_log (user_id, action) VALUES (p_actor, p_action);
END;
$$ LANGUAGE plpgsql;
SQL
{
  sink_row
  printf 'audit_write_shadow.sql\taudit_write_shadow\tAUDIT_SINK\t-\tshadow path\n'
} >"$SBX/audit-coverage.tsv"
expect_fire "second sink fires" "audit_write.sql is the only sink"

# (10) UPDATE-only mutator misclassified READ_ONLY — the dead-regex class the
# GLM screen caught (UPDATE arm previously matched single-char table names only).
reset
cat >"$SBX/reducers/audit_write.sql" <<'SQL'
CREATE OR REPLACE FUNCTION audit_write(p_actor bigint, p_action text) RETURNS void AS $$
BEGIN
  INSERT INTO admin_audit_log (user_id, action) VALUES (p_actor, p_action);
END;
$$ LANGUAGE plpgsql;
SQL
cat >"$SBX/reducers/was_read_only_update.sql" <<'SQL'
CREATE OR REPLACE FUNCTION was_read_only_update(p_id bigint) RETURNS void AS $$
BEGIN
  UPDATE some_real_table SET state = 'stopped' WHERE id = p_id;
END;
$$ LANGUAGE plpgsql;
SQL
{
  sink_row
  printf 'was_read_only_update.sql\twas_read_only_update\tREAD_ONLY\t-\tpure read path (guard re-derives no DML)\n'
} >"$SBX/audit-coverage.tsv"
expect_fire "UPDATE-only mutator under READ_ONLY fires" "READ_ONLY-MUTATES.*was_read_only_update"

# (11) tier mismatch: row says core, body passes routine.
reset
cat >"$SBX/reducers/audit_write.sql" <<'SQL'
CREATE OR REPLACE FUNCTION audit_write(p_actor bigint, p_action text) RETURNS void AS $$
BEGIN
  INSERT INTO admin_audit_log (user_id, action) VALUES (p_actor, p_action);
END;
$$ LANGUAGE plpgsql;
SQL
cat >"$SBX/reducers/tier_lie.sql" <<'SQL'
CREATE OR REPLACE FUNCTION tier_lie(p_actor bigint) RETURNS void AS $$
BEGIN
  PERFORM audit_write(p_actor, 'x', 'y', 1, NULL, NULL, NULL, NULL, 'routine');
END;
$$ LANGUAGE plpgsql;
SQL
{
  sink_row
  printf 'tier_lie.sql\ttier_lie\tMUST\tcore\tlifecycle write\n'
} >"$SBX/audit-coverage.tsv"
expect_fire "tier mismatch between row and audit_write call fires" "TIER-MISMATCH.*tier_lie"

# (12) reverse tier mismatch: row says routine, body passes core.
reset
cat >"$SBX/reducers/audit_write.sql" <<'SQL'
CREATE OR REPLACE FUNCTION audit_write(p_actor bigint, p_action text) RETURNS void AS $$
BEGIN
  INSERT INTO admin_audit_log (user_id, action) VALUES (p_actor, p_action);
END;
$$ LANGUAGE plpgsql;
SQL
cat >"$SBX/reducers/tier_lie_reverse.sql" <<'SQL'
CREATE OR REPLACE FUNCTION tier_lie_reverse(p_actor bigint) RETURNS void AS $$
BEGIN
  PERFORM audit_write(p_actor, 'x', 'y', 1, NULL, NULL, NULL, NULL, 'core');
END;
$$ LANGUAGE plpgsql;
SQL
{
  sink_row
  printf 'tier_lie_reverse.sql\ttier_lie_reverse\tMUST\troutine\tpreference write\n'
} >"$SBX/audit-coverage.tsv"
expect_fire "reverse tier mismatch (row routine over core body) fires" "TIER-MISMATCH.*tier_lie_reverse"

# (13) astra probe 1: an unaudited FIRST overload hides behind an audited
# last one under the old last-wins parser.
reset
cat >"$SBX/reducers/audit_write.sql" <<'SQL'
CREATE OR REPLACE FUNCTION audit_write(p_actor bigint, p_action text) RETURNS void AS $$
BEGIN
  INSERT INTO admin_audit_log (user_id, action) VALUES (p_actor, p_action);
END;
$$ LANGUAGE plpgsql;
SQL
cat >"$SBX/reducers/overload_pair.sql" <<'SQL'
CREATE OR REPLACE FUNCTION overload_pair(p_actor bigint) RETURNS void AS $$
BEGIN
  UPDATE things SET x = 1 WHERE id = p_actor;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION overload_pair(p_actor bigint, p_n int) RETURNS void AS $$
BEGIN
  PERFORM audit_write(p_actor, 'x', 'y', 1, NULL, NULL, NULL, NULL, 'core');
END;
$$ LANGUAGE plpgsql;
SQL
{
  sink_row
  printf 'overload_pair.sql\toverload_pair\tMUST\tcore\tlifecycle write\n'
} >"$SBX/audit-coverage.tsv"
expect_fire "unaudited first overload fires" "MUST-NO-CALL.*overload_pair"

# (14) astra probe 2: a quoted function name must not evade classification.
reset
cat >"$SBX/reducers/audit_write.sql" <<'SQL'
CREATE OR REPLACE FUNCTION audit_write(p_actor bigint, p_action text) RETURNS void AS $$
BEGIN
  INSERT INTO admin_audit_log (user_id, action) VALUES (p_actor, p_action);
END;
$$ LANGUAGE plpgsql;
SQL
cat >"$SBX/reducers/quoted.sql" <<'SQL'
CREATE OR REPLACE FUNCTION "quoted_mutator"(p_id bigint) RETURNS void AS $$
BEGIN
  UPDATE things SET x = 1 WHERE id = p_id;
END;
$$ LANGUAGE plpgsql;
SQL
{ sink_row; } >"$SBX/audit-coverage.tsv"
expect_fire "quoted function name is named" "UNCLASSIFIED.*quoted_mutator"

# (15) astra probe 3: a tagged $tag$ body carrying UPDATE under READ_ONLY.
reset
cat >"$SBX/reducers/audit_write.sql" <<'SQL'
CREATE OR REPLACE FUNCTION audit_write(p_actor bigint, p_action text) RETURNS void AS $$
BEGIN
  INSERT INTO admin_audit_log (user_id, action) VALUES (p_actor, p_action);
END;
$$ LANGUAGE plpgsql;
SQL
cat >"$SBX/reducers/tagged.sql" <<'SQL'
CREATE OR REPLACE FUNCTION tagged_mutator(p_id bigint) RETURNS void AS $body$
BEGIN
  UPDATE things SET x = 1 WHERE id = p_id;
END;
$body$ LANGUAGE plpgsql;
SQL
{
  sink_row
  printf 'tagged.sql\ttagged_mutator\tREAD_ONLY\t-\tpure read path (guard re-derives no DML)\n'
} >"$SBX/audit-coverage.tsv"
expect_fire "tagged-body UPDATE under READ_ONLY fires" "READ_ONLY-MUTATES.*tagged_mutator"

# (16) astra probe 4: GRANT is a mutation — READ_ONLY cannot hold it.
reset
cat >"$SBX/reducers/audit_write.sql" <<'SQL'
CREATE OR REPLACE FUNCTION audit_write(p_actor bigint, p_action text) RETURNS void AS $$
BEGIN
  INSERT INTO admin_audit_log (user_id, action) VALUES (p_actor, p_action);
END;
$$ LANGUAGE plpgsql;
SQL
cat >"$SBX/reducers/granter.sql" <<'SQL'
CREATE OR REPLACE FUNCTION granter() RETURNS void AS $$
BEGIN
  GRANT SELECT ON things TO somebody;
END;
$$ LANGUAGE plpgsql;
SQL
{
  sink_row
  printf 'granter.sql\tgranter\tREAD_ONLY\t-\tpure read path (guard re-derives no DML)\n'
} >"$SBX/audit-coverage.tsv"
expect_fire "GRANT under READ_ONLY fires" "READ_ONLY-MUTATES.*granter"

# (17) astra probe 5: the substring 'audit_write(' inside a string literal is
# not a call.
reset
cat >"$SBX/reducers/audit_write.sql" <<'SQL'
CREATE OR REPLACE FUNCTION audit_write(p_actor bigint, p_action text) RETURNS void AS $$
BEGIN
  INSERT INTO admin_audit_log (user_id, action) VALUES (p_actor, p_action);
END;
$$ LANGUAGE plpgsql;
SQL
cat >"$SBX/reducers/literal_liar.sql" <<'SQL'
CREATE OR REPLACE FUNCTION literal_liar(p_actor bigint) RETURNS void AS $$
BEGIN
  RAISE NOTICE 'call audit_write() here eventually';
  UPDATE things SET x = 1 WHERE id = p_actor;
END;
$$ LANGUAGE plpgsql;
SQL
{
  sink_row
  printf 'literal_liar.sql\tliteral_liar\tMUST\tcore\tlifecycle write\n'
} >"$SBX/audit-coverage.tsv"
expect_fire "string-literal audit_write does not satisfy MUST" "MUST-NO-CALL.*literal_liar"

# (18) fail-closed: unsupported body syntax refuses to classify.
reset
cat >"$SBX/reducers/audit_write.sql" <<'SQL'
CREATE OR REPLACE FUNCTION audit_write(p_actor bigint, p_action text) RETURNS void AS $$
BEGIN
  INSERT INTO admin_audit_log (user_id, action) VALUES (p_actor, p_action);
END;
$$ LANGUAGE plpgsql;
SQL
cat >"$SBX/reducers/stringbody.sql" <<'SQL'
CREATE OR REPLACE FUNCTION stringbody(p_id bigint) RETURNS void
  LANGUAGE sql AS 'UPDATE things SET x = 1 WHERE id = p_id';
SQL
{ sink_row; } >"$SBX/audit-coverage.tsv"
expect_fire "unparseable body fails closed" "UNPARSEABLE.*stringbody"

echo "check-audit-coverage self-test: all cases green."
