#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-rls-coverage-selftest.sh — proves check-rls-coverage.sh actually FIRES
# and that its migration-derived FORCE'd-table set is the one we expect
# (D-1, plan 2026-09-18-debt-consolidation.md + Astra r1 amendments).
# A guard that never fails is theater; a guard that derives its table set from
# the migrations must ALSO have its extractor pinned to independently expected
# fixtures — comparing the extractor with itself proves nothing. So this builds
# a synthetic gateway tree AND a synthetic dbschema, and asserts:
#   (A) an UNCLASSIFIED site against a FORCE'd table FAILS the guard (exit 1,
#       names the site).
#   (B) the SAME site, once classified in the allowlist, PASSES (exit 0).
#   (C) a site on a non-FORCE'd user-data table (mailboxes) is IGNORED (no
#       entry needed) — the guard is scoped to the FORCE'd set.
#   (D) look-alikes (message_trace / message_id column) are IGNORED
#       (word-boundary — no false-positive on look-alike tables/columns).
#   (E) a double-quoted dynamic literal (fmt.Sprintf) is CAUGHT.
#   (F) a table FORCE'd ONLY through the FOREACH-ARRAY + EXECUTE format form
#       (theta, V002 fixture) is CAUGHT — the dynamic extraction feeds the scan.
#   (G) an INSERT into a FORCE'd table (iota) is CAUGHT.
#   (H) the message_tags FORCE arm is CAUGHT while message_trace is not (D).
#   (I) the derived set from the synthetic schema EQUALS the independently
#       hand-written expected list (extractor pinned to fixtures — NOT
#       extractor-compared-with-itself): alpha, beta, eta_multitest, iota,
#       message_tags, theta. Proves: direct single-space + schema-qualified,
#       direct double-space (V004 form), array+EXECUTE format (single and
#       multi-line array), comments skipped, ENABLE-only excluded, bare
#       NO FORCE excluded, FORCE-then-NO-FORCE excluded (epsilon), and a later
#       migration's NO FORCE REMOVING an earlier FORCE (zeta, V002).
#   (J) a query against zeta — FORCE'd in V001 then NO FORCE'd in V002 — is
#       IGNORED (the removed table left the guard's set).
#   (K) the REAL tree's derived set contains ALL EIGHT V254 tables
#       (device_events, device_policy, device_policy_groups, device_registry,
#       device_telemetry, managed_devices, mdm_device_state, mdm_policies —
#       hardcoded from V254__mdm_rls_backstop.sql, the amendment's
#       independent expectation) plus the original W6/W7 set.
#   (L) an UNSUPPORTED dynamic form (%s table name) FAILS LOUDLY (non-zero
#       exit + "UNSUPPORTED" on stderr) instead of silently shrinking the set.
#   (M) an EMPTY extraction (migrations with zero FORCE statements) FAILS
#       LOUDLY.
#   (N) a QUOTED-identifier statement preceding a recognized one (Astra r2
#       D-1a: `public."omega"` FORCE before a recognized FORCE) FAILS LOUDLY
#       via the consumed-prefix net instead of silently returning only the
#       recognized table.
#   (O) ENABLE PRESERVES FORCE (Astra r2 D-1b): FORCE then ENABLE keeps the
#       table in the set (ENABLE never unsets relforcerowsecurity); an
#       ENABLE-only table stays out.
#   (P) dynamic replay is ORDERED (Astra r2 D-1b): a block that runs
#       NO FORCE → FORCE ends FORCE'd; FORCE → NO FORCE ends unforced.
#   (Q) BLOCK comments never contribute (Astra r2 D-1c): a block-commented
#       NO FORCE cannot remove a table, a block-commented FORCE cannot add
#       one, single-line and multi-line and nested forms all inert.
#   (R) comments INSIDE inline `DO $$ … $$` bodies never contribute (Astra r3
#       finding 1): the dollar-quote branch used to copy body text verbatim,
#       so a block-commented NO FORCE un-forced a table. Single-line,
#       multi-line, nested and `--` forms inside a body must all be inert.
#   (S) an UNCONSUMED loop-body statement FAILS LOUDLY (Astra r3 D-1): the
#       FOREACH branch discarded its body after consuming only EXECUTE format
#       calls, and the direct-form check excludes quoted identifiers — so
#       `ALTER TABLE public."omega" FORCE ROW LEVEL SECURITY;` inside the loop
#       exited 0 without omega. With and without a recognized format call in
#       the same body, both must die; a block with ONLY recognized calls still
#       extracts (positive control, arms F/I/P).
# Runs FIRST in test.sh so a broken guard is caught before we trust its verdict.
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

GUARD="$(dirname "$0")/check-rls-coverage.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/pkg" "$WORK/dbschema"

# ── Synthetic migration fixture (the extractor's independent expectation).
# Every supported statement form appears exactly once; the expected derived set
# is hand-written in arm (I) BELOW, from this file's contents — not from the
# extractor's output.
cat > "$WORK/dbschema/V001__fixture_rls_forms.sql" <<'SQL'
-- A comment mentioning ALTER TABLE public.ghost_table FORCE ROW LEVEL SECURITY
-- must NEVER contribute ghost_table to the set (comment skipping).
ALTER TABLE public.alpha FORCE ROW LEVEL SECURITY;
ALTER TABLE public.beta FORCE  ROW LEVEL SECURITY;
ALTER TABLE public.gamma ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.delta NO FORCE ROW LEVEL SECURITY;
ALTER TABLE public.epsilon FORCE ROW LEVEL SECURITY;
ALTER TABLE public.epsilon NO FORCE ROW LEVEL SECURITY;
ALTER TABLE public.message_tags FORCE ROW LEVEL SECURITY;
DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['eta_multitest',
  'zeta'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t); END LOOP; END $$;
SQL
# NOTE: zeta is added here through the ARRAY form so arm (J) proves a later
# migration's NO FORCE removes an array-FORCE'd table (final state wins).

cat > "$WORK/dbschema/V002__fixture_rls_removal.sql" <<'SQL'
DO $$ DECLARE v_table text; BEGIN
  FOREACH v_table IN ARRAY ARRAY[
    'theta',
    'iota'
  ] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', v_table);
    EXECUTE format('ALTER TABLE public.%I FORCE  ROW LEVEL SECURITY', v_table);
  END LOOP;
END $$;
-- A later migration's NO FORCE must REMOVE an earlier FORCE (final state wins).
ALTER TABLE public.zeta NO FORCE ROW LEVEL SECURITY;
SQL

# ── Synthetic gateway file: representative sites against the fixture tables.
cat > "$WORK/pkg/sample.go" <<'GO'
package pkg

import "fmt"

func tenantRead(h *H) {
	// (A/B) a raw read of a FORCE'd table — must be classified.
	h.pool.QueryRow(ctx,
		`SELECT secret FROM alpha WHERE id = $1 AND mailbox_id = $2`,
		id, mb)
	// (C) a non-FORCE'd user-data table — out of THIS guard's scope.
	h.pool.QueryRow(ctx, `SELECT email FROM mailboxes WHERE id = $1`, id)
	// (D) look-alikes that must NOT trip the guard.
	h.pool.QueryRow(ctx, `SELECT details FROM message_trace WHERE id = $1`, id)
	h.pool.QueryRow(ctx, `SELECT blob_sha256 FROM message_attachments WHERE message_id = $1`, id)
	// (E) a dynamic, double-quoted literal — the class the manual sweep missed.
	q := fmt.Sprintf("SELECT COUNT(*) FROM beta m WHERE %s", where)
	_ = q
	// (F) a table FORCE'd ONLY via the FOREACH-ARRAY + EXECUTE format form.
	h.pool.QueryRow(ctx,
		`SELECT permission FROM theta WHERE mailbox_id = $1 AND user_id = $2`,
		mb, uid)
	// (G) an INSERT into an array-FORCE'd table.
	h.pool.Exec(ctx, `INSERT INTO iota (message_pk, outcome) VALUES ($1, $2)`, pk, oc)
	// (H) the message_tags FORCE arm.
	h.pool.QueryRow(ctx, `SELECT consumer_type FROM message_tags WHERE id = $1`, id)
	// (J) zeta was FORCE'd in V001 and NO FORCE'd in V002 — must be IGNORED.
	h.pool.QueryRow(ctx, `SELECT gone FROM zeta WHERE id = $1`, id)
}
GO

ALLOW_EMPTY="$WORK/allow-empty.txt"
: > "$ALLOW_EMPTY"

ALLOW_FULL="$WORK/allow-full.txt"
cat > "$ALLOW_FULL" <<'ALLOW'
sample.go	WRAPPED	select secret from alpha where	id and mailbox_id in one scoped tx (selftest)
sample.go	AUDITED-XTENANT	select count(*) from beta m where	selftest: dynamic xtenant count
sample.go	BYPASS	select permission from theta where	selftest: array-FORCE'd table on workerPool
sample.go	BYPASS	insert into iota	selftest: worker-pool insert
sample.go	WRAPPED	select consumer_type from message_tags where	selftest: message_tags lookup
ALLOW

pass=0; fail=0
ok()  { echo "  ok: $1"; pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }

# ── (I) FIRST: the extractor's derived set must EQUAL the hand-written
# expectation. This is the independent-fixture arm — the expected list was
# written by reading V001/V002 above, never by running the extractor.
# Sorted expected set:
EXPECTED_SET='alpha
beta
eta_multitest
iota
message_tags
theta'
rc_set=0
GOT_SET="$(GATEWAY_DIR="$WORK" RLS_ALLOWLIST_FILE="$ALLOW_EMPTY" RLS_SCHEMA_DIR="$WORK/dbschema" RLS_PRINT_TABLE_SET=1 bash "$GUARD" 2>&1)" || rc_set=$?
if [ "$rc_set" -ne 0 ]; then
  bad "(I) table-set extraction FAILED (exit $rc_set):"$'\n'"$GOT_SET"
else
  if [ "$GOT_SET" = "$EXPECTED_SET" ]; then
    ok "(I) derived set equals the independent fixture expectation (6 tables; ghost/gamma/delta/epsilon excluded, zeta removed by V002)"
  else
    bad "(I) derived set MISMATCH. expected:"$'\n'"$EXPECTED_SET"$'\n'"got:"$'\n'"$GOT_SET"
  fi
fi

# ── (J) pre-check inside the set print: zeta must NOT be in the derived set.
if printf '%s' "$GOT_SET" | grep -qx 'zeta'; then
  bad "(J) zeta still in the derived set (later NO FORCE did not remove it)"
else
  ok "(J) later-migration NO FORCE removed zeta from the derived set"
fi

# ── (A) empty allowlist → guard FAILS and names the alpha site. `set -e` is
# active (from _base.sh): the guard's non-zero exit inside $(...) on the RHS of
# an assignment WOULD abort, so guard against it with `|| rc=$?` form.
rc_empty=0
out_empty="$(GATEWAY_DIR="$WORK" RLS_ALLOWLIST_FILE="$ALLOW_EMPTY" RLS_SCHEMA_DIR="$WORK/dbschema" bash "$GUARD" 2>&1)" || rc_empty=$?
if [ "$rc_empty" -ne 0 ]; then ok "(A) unclassified FORCE'd-table site fails the guard"; else bad "(A) guard PASSED with an unclassified alpha site (false-negative!)"; fi
if printf '%s' "$out_empty" | grep -qi 'select secret from alpha where'; then ok "(A) names the raw alpha site"; else bad "(A) did not name the raw alpha site"; fi

# (E) the dynamic double-quoted literal is among the flagged sites.
if printf '%s' "$out_empty" | grep -qi 'from beta m where'; then ok "(E) catches the dynamic double-quoted FROM beta literal"; else bad "(E) MISSED the dynamic double-quoted FROM beta literal"; fi

# (F) the array+format-FORCE'd table (theta) is flagged — dynamic extraction
# drives the SCAN, not just the set print.
if printf '%s' "$out_empty" | grep -qi 'from theta where'; then ok "(F) catches a site against the array+format-FORCE'd table (theta)"; else bad "(F) MISSED theta (FOREACH-ARRAY + EXECUTE format extraction broken)"; fi

# (G) the iota INSERT is flagged.
if printf '%s' "$out_empty" | grep -qi 'into iota'; then ok "(G) catches an unclassified INSERT into iota"; else bad "(G) MISSED the iota INSERT (array-form table-set extension broken)"; fi

# (H) the message_tags site is flagged (word-boundary twin of D).
if printf '%s' "$out_empty" | grep -qi 'from message_tags where'; then ok "(H) catches an unclassified message_tags site"; else bad "(H) MISSED message_tags (direct-FORCE arm broken)"; fi

# (C) the mailboxes-only site is NOT flagged by THIS guard.
if printf '%s' "$out_empty" | grep -qiE 'from mailboxes[^_]'; then bad "(C) flagged a non-FORCE'd (mailboxes) site"; else ok "(C) ignores non-FORCE'd user-data tables (mailboxes != message_tags)"; fi

# (D) message_trace / message_attachments / message_id look-alikes NOT flagged.
if printf '%s' "$out_empty" | grep -qiE 'message_trace|message_attachments'; then bad "(D) flagged a look-alike table (false-positive)"; else ok "(D) word-boundary: ignores message_trace / message_attachments / message_id"; fi

# (J) the zeta query is NOT flagged (NO FORCE removed it from the set).
if printf '%s' "$out_empty" | grep -qi 'from zeta where'; then bad "(J) flagged a NO-FORCE'd table (zeta) — removal semantics broken"; else ok "(J) ignores the NO-FORCE'd table (zeta)"; fi

# (B) full allowlist → guard PASSES.
rc_full=0
out_full="$(GATEWAY_DIR="$WORK" RLS_ALLOWLIST_FILE="$ALLOW_FULL" RLS_SCHEMA_DIR="$WORK/dbschema" bash "$GUARD" 2>&1)" || rc_full=$?
if [ "$rc_full" -eq 0 ]; then ok "(B) classified sites pass the guard"; else bad "(B) guard FAILED with all sites classified:"$'\n'"$out_full"; fi

# ── (K) the REAL tree's derived set contains all eight V254 tables (hardcoded
# from V254__mdm_rls_backstop.sql — the Astra r1 independent expectation) plus
# the original W6 FORCE'd set.
rc_real=0
REAL_SET="$(RLS_PRINT_TABLE_SET=1 bash "$GUARD" 2>&1)" || rc_real=$?
if [ "$rc_real" -ne 0 ]; then
  bad "(K) real-tree extraction FAILED (exit $rc_real):"$'\n'"$REAL_SET"
else
  v254_missing=""
  for t in device_events device_policy device_policy_groups device_registry device_telemetry managed_devices mdm_device_state mdm_policies; do
    printf '%s\n' "$REAL_SET" | grep -qx "$t" || v254_missing="$v254_missing $t"
  done
  if [ -z "$v254_missing" ]; then
    ok "(K) real tree: all eight V254 tables are in the derived FORCE'd set"
  else
    bad "(K) real tree: V254 tables MISSING from the derived set:$v254_missing"
  fi
  w6_missing=""
  for t in messages message_tags mailbox_delegates delivery_attempts approval_requests approval_policies held_inbound_messages; do
    printf '%s\n' "$REAL_SET" | grep -qx "$t" || w6_missing="$w6_missing $t"
  done
  if [ -z "$w6_missing" ]; then
    ok "(K) real tree: the original W6 FORCE'd set is still present"
  else
    bad "(K) real tree: W6 tables MISSING from the derived set:$w6_missing"
  fi
fi

# ── (L) an UNSUPPORTED dynamic form (%s table placeholder) must FAIL LOUDLY.
mkdir -p "$WORK/badfmt"
cat > "$WORK/badfmt/V001__broken_dynamic.sql" <<'SQL'
DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['omega'] LOOP
  EXECUTE format('ALTER TABLE public.%s FORCE ROW LEVEL SECURITY', t); END LOOP; END $$;
SQL
rc_bad=0
out_bad="$(GATEWAY_DIR="$WORK" RLS_ALLOWLIST_FILE="$ALLOW_EMPTY" RLS_SCHEMA_DIR="$WORK/badfmt" bash "$GUARD" 2>&1)" || rc_bad=$?
if [ "$rc_bad" -ne 0 ] && printf '%s' "$out_bad" | grep -q 'UNSUPPORTED'; then
  ok "(L) unsupported dynamic form (%s placeholder) fails LOUDLY (exit $rc_bad)"
else
  bad "(L) unsupported dynamic form did NOT fail loudly (exit $rc_bad)"
fi

# ── (M) EMPTY extraction (no FORCE statements at all) must FAIL LOUDLY.
mkdir -p "$WORK/emptyschema"
cat > "$WORK/emptyschema/V001__nothing.sql" <<'SQL'
CREATE TABLE public.not_forced (id bigint);
SQL
rc_emptyset=0
out_emptyset="$(GATEWAY_DIR="$WORK" RLS_ALLOWLIST_FILE="$ALLOW_EMPTY" RLS_SCHEMA_DIR="$WORK/emptyschema" bash "$GUARD" 2>&1)" || rc_emptyset=$?
if [ "$rc_emptyset" -ne 0 ] && printf '%s' "$out_emptyset" | grep -q 'ZERO FORCE'; then
  ok "(M) empty extraction fails LOUDLY (exit $rc_emptyset)"
else
  bad "(M) empty extraction did NOT fail loudly (exit $rc_emptyset)"
fi

# ── (N) QUOTED identifier before a recognized statement must FAIL LOUDLY
# (Astra r2 D-1a): the consumed-prefix net. The pre-r2 extractor discarded the
# text before each recognized statement and only netted the FINAL suffix, so
# `public."omega"` FORCE followed by a recognized FORCE returned success with
# only the recognized table — the quoted statement silently vanished.
mkdir -p "$WORK/quotedschema"
cat > "$WORK/quotedschema/V001__quoted_prefix.sql" <<'SQL'
ALTER TABLE public."omega" FORCE ROW LEVEL SECURITY;
ALTER TABLE public.alpha_plain FORCE ROW LEVEL SECURITY;
SQL
rc_quoted=0
out_quoted="$(GATEWAY_DIR="$WORK" RLS_ALLOWLIST_FILE="$ALLOW_EMPTY" RLS_SCHEMA_DIR="$WORK/quotedschema" RLS_PRINT_TABLE_SET=1 bash "$GUARD" 2>&1)" || rc_quoted=$?
if [ "$rc_quoted" -ne 0 ] && printf '%s' "$out_quoted" | grep -q 'consumed prefix'; then
  ok "(N) quoted-identifier statement before a recognized one fails LOUDLY via the consumed-prefix net (exit $rc_quoted)"
else
  bad "(N) quoted-prefix statement did NOT fail loudly (exit $rc_quoted) — an unsupported form silently shrank the set:"$'\n'"$out_quoted"
fi

# ── (O) ENABLE PRESERVES FORCE (Astra r2 D-1b): the pre-r2 extractor REMOVED
# a table on ENABLE, but ENABLE never unsets relforcerowsecurity. FORCE then
# ENABLE must stay in the set; an ENABLE-only table must stay out.
mkdir -p "$WORK/enableschema"
cat > "$WORK/enableschema/V001__enable_after_force.sql" <<'SQL'
ALTER TABLE public.rho FORCE ROW LEVEL SECURITY;
ALTER TABLE public.rho ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sigma ENABLE ROW LEVEL SECURITY;
SQL
rc_enable=0
GOT_ENABLE="$(GATEWAY_DIR="$WORK" RLS_ALLOWLIST_FILE="$ALLOW_EMPTY" RLS_SCHEMA_DIR="$WORK/enableschema" RLS_PRINT_TABLE_SET=1 bash "$GUARD" 2>&1)" || rc_enable=$?
if [ "$rc_enable" -ne 0 ]; then
  bad "(O) enable-after-force extraction FAILED (exit $rc_enable):"$'\n'"$GOT_ENABLE"
else
  if printf '%s\n' "$GOT_ENABLE" | grep -qx 'rho'; then
    ok "(O) ENABLE after FORCE keeps rho in the derived set"
  else
    bad "(O) ENABLE removed the FORCE'd table rho from the derived set (FORCE not preserved):"$'\n'"$GOT_ENABLE"
  fi
  if printf '%s\n' "$GOT_ENABLE" | grep -qx 'sigma'; then
    bad "(O) ENABLE-only table sigma wrongly added to the derived set"
  else
    ok "(O) ENABLE-only table (sigma) stays out of the derived set"
  fi
fi

# ── (P) dynamic replay is ORDERED (Astra r2 D-1b): the pre-r2 replay applied
# the flags so NO FORCE always won, even when FORCE FOLLOWED it in the block.
mkdir -p "$WORK/orderedschema"
cat > "$WORK/orderedschema/V001__ordered_dynamic.sql" <<'SQL'
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['sig_a'] LOOP
    EXECUTE format('ALTER TABLE public.%I NO FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);
  END LOOP;
  FOREACH t IN ARRAY ARRAY['sig_b'] LOOP
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE public.%I NO FORCE ROW LEVEL SECURITY', t);
  END LOOP;
END $$;
SQL
rc_ordered=0
GOT_ORDERED="$(GATEWAY_DIR="$WORK" RLS_ALLOWLIST_FILE="$ALLOW_EMPTY" RLS_SCHEMA_DIR="$WORK/orderedschema" RLS_PRINT_TABLE_SET=1 bash "$GUARD" 2>&1)" || rc_ordered=$?
if [ "$rc_ordered" -ne 0 ]; then
  bad "(P) ordered dynamic replay extraction FAILED (exit $rc_ordered):"$'\n'"$GOT_ORDERED"
else
  if printf '%s\n' "$GOT_ORDERED" | grep -qx 'sig_a'; then
    ok "(P) dynamic NO FORCE → FORCE ends FORCE'd (sig_a in the set)"
  else
    bad "(P) dynamic NO FORCE → FORCE did NOT end FORCE'd (sig_a missing):"$'\n'"$GOT_ORDERED"
  fi
  if printf '%s\n' "$GOT_ORDERED" | grep -qx 'sig_b'; then
    bad "(P) dynamic FORCE → NO FORCE wrongly leaves sig_b in the set"
  else
    ok "(P) dynamic FORCE → NO FORCE ends unforced (sig_b out of the set)"
  fi
fi

# ── (Q) BLOCK comments never contribute (Astra r2 D-1c): the pre-r2 extractor
# stripped only `--` line comments, so a block-commented NO FORCE removed a
# FORCE'd table and a block-commented FORCE added one. Single-line, multi-line
# and nested forms must all be inert; content inside them (including `--` and
# quotes) must never reach the extractor.
mkdir -p "$WORK/blockschema"
cat > "$WORK/blockschema/V001__block_comments.sql" <<'SQL'
ALTER TABLE public.kappa FORCE ROW LEVEL SECURITY;
/* ALTER TABLE public.kappa NO FORCE ROW LEVEL SECURITY; */
/*
ALTER TABLE public.kappa NO FORCE ROW LEVEL SECURITY;
*/
/* ALTER TABLE public.lam_ghost FORCE ROW LEVEL SECURITY; */
/* a comment with -- double dash and 'quotes' then
   ALTER TABLE public.ghost_two FORCE ROW LEVEL SECURITY; */
/* nested /* deeper ALTER TABLE public.ghost_three NO FORCE ROW LEVEL SECURITY; */ still comment: ALTER TABLE public.kappa NO FORCE ROW LEVEL SECURITY; */
ALTER TABLE public.mu_table FORCE  ROW LEVEL SECURITY; -- trailing line comment ignored
SQL
rc_block=0
GOT_BLOCK="$(GATEWAY_DIR="$WORK" RLS_ALLOWLIST_FILE="$ALLOW_EMPTY" RLS_SCHEMA_DIR="$WORK/blockschema" RLS_PRINT_TABLE_SET=1 bash "$GUARD" 2>&1)" || rc_block=$?
if [ "$rc_block" -ne 0 ]; then
  bad "(Q) block-comment extraction FAILED (exit $rc_block):"$'\n'"$GOT_BLOCK"
else
  if [ "$GOT_BLOCK" = 'kappa
mu_table' ]; then
    ok "(Q) block comments are inert: kappa stays FORCE'd, mu_table adds, ghost tables stay out"
  else
    bad "(Q) block-comment handling produced the WRONG set:"$'\n'"$GOT_BLOCK"$'\n'"expected exactly kappa + mu_table"
  fi
fi

# ── (R) comments INSIDE inline DO bodies never contribute (Astra r3 finding
# 1): the dollar-quote branch copied body text verbatim, so a block-commented
# NO FORCE inside `DO $$ … $$` removed a FORCE'd table (exit 0, table gone)
# and a block-commented FORCE added a ghost. The body is plpgsql source —
# single-line, multi-line, nested and `--` comment forms inside it must all be
# inert, while a REAL statement in the same body still counts.
mkdir -p "$WORK/dobodycomments"
cat > "$WORK/dobodycomments/V001__do_body_comments.sql" <<'SQL'
ALTER TABLE public.dob_alpha FORCE ROW LEVEL SECURITY;
DO $$ BEGIN /* ALTER TABLE public.dob_alpha NO FORCE ROW LEVEL SECURITY; */ END $$;
DO $$ BEGIN /* ALTER TABLE public.dob_ghost FORCE ROW LEVEL SECURITY; */ END $$;
DO $$ BEGIN -- ALTER TABLE public.dob_ghost2 NO FORCE ROW LEVEL SECURITY;
END $$;
DO $$ BEGIN /* outer /* ALTER TABLE public.dob_ghost3 NO FORCE ROW LEVEL SECURITY; */ still comment: ALTER TABLE public.dob_alpha NO FORCE ROW LEVEL SECURITY; */ END $$;
DO $$ BEGIN
  /* ALTER TABLE public.dob_ghost4 FORCE ROW LEVEL SECURITY; */
END $$;
DO $$ BEGIN /* noise */ ALTER TABLE public.dob_real FORCE ROW LEVEL SECURITY; END $$;
SQL
rc_dob=0
GOT_DOB="$(GATEWAY_DIR="$WORK" RLS_ALLOWLIST_FILE="$ALLOW_EMPTY" RLS_SCHEMA_DIR="$WORK/dobodycomments" RLS_PRINT_TABLE_SET=1 bash "$GUARD" 2>&1)" || rc_dob=$?
if [ "$rc_dob" -ne 0 ]; then
  bad "(R) DO-body comment extraction FAILED (exit $rc_dob):"$'\n'"$GOT_DOB"
else
  if [ "$GOT_DOB" = 'dob_alpha
dob_real' ]; then
    ok "(R) comments inside DO bodies are inert: dob_alpha stays FORCE'd, the real dob_real statement adds, ghost tables stay out"
  else
    bad "(R) DO-body comment handling produced the WRONG set:"$'\n'"$GOT_DOB"$'\n'"expected exactly dob_alpha + dob_real"
  fi
fi

# ── (S) an UNCONSUMED loop-body statement FAILS LOUDLY (Astra r3 D-1): the
# FOREACH branch discarded its body after consuming only EXECUTE format calls
# and the direct-form check excludes quoted identifiers, so a quoted
# `public."omega"` FORCE inside the loop exited 0 without omega. Both shapes —
# alongside a recognized format call and as the loop's only statement — must
# die; a loop with ONLY recognized calls still extracts (positive control in
# arms F/I/P).
mkdir -p "$WORK/loopbody1" "$WORK/loopbody2"
cat > "$WORK/loopbody1/V001__quoted_in_loop.sql" <<'SQL'
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['alpha'] LOOP
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);
    ALTER TABLE public."omega" FORCE ROW LEVEL SECURITY;
  END LOOP;
END $$;
SQL
cat > "$WORK/loopbody2/V001__quoted_loop_only.sql" <<'SQL'
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['alpha'] LOOP
    ALTER TABLE public."omega" NO FORCE ROW LEVEL SECURITY;
  END LOOP;
END $$;
SQL
for arm in 1 2; do
  rc_loop=0
  out_loop="$(GATEWAY_DIR="$WORK" RLS_ALLOWLIST_FILE="$ALLOW_EMPTY" RLS_SCHEMA_DIR="$WORK/loopbody$arm" RLS_PRINT_TABLE_SET=1 bash "$GUARD" 2>&1)" || rc_loop=$?
  if [ "$rc_loop" -eq 3 ] && printf '%s' "$out_loop" | grep -q 'FOREACH block body'; then
    ok "(S$arm) unconsumed loop-body statement fails LOUDLY with the extractor's exit 3"
  elif [ "$rc_loop" -ne 0 ]; then
    bad "(S$arm) loop-body failure used the generic exit 1 instead of the extractor's exit 3:"$'
'"$out_loop"
  else
    bad "(S$arm) unconsumed loop-body statement did NOT fail loudly (exit $rc_loop) — it silently vanished with the discarded body:"$'\n'"$out_loop"
  fi
done

echo ""
if [ "$fail" -ne 0 ]; then
  echo "check-rls-coverage selftest FAILED ($fail/$((pass+fail)) checks failed) — the guard does not behave as specified."
  exit 1
fi
echo "check-rls-coverage selftest: all $pass checks passed (guard fires + derives the exact FORCE'd set)."
