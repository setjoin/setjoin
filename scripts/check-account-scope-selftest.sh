#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-account-scope-selftest.sh — negative-case self-test for the seam guard.
#
# A guard that never fires is theater. This drives check-account-scope.sh against
# a TEMP reducer/test tree seeded with ONE deliberate violation per check (A–H)
# — PLUS the hardening cases #5 added: E2 (any jmap_*_state, not just email|tag),
# E3/F2 (case-insensitive PG_NOTIFY), G2/G3 (non-`u` users aliases usr/mu) — and
# the Wave-3 Check-E precision cases: E6 (jmap_state NOT first after SET) + E7
# (multi-line UPDATE with jmap_state on a later line), both of which slipped past
# the old line-local first-column regex — and
# the POSITIVE H cases (H/H2 declared-but-unused account slot fire; H-neg proves a
# param used once via a derived local does NOT false-fire) — and asserts the guard
# catches each (exit 1 + the right [X] tag). It also asserts the guard passes on a
# CLEAN temp tree. Uses the guard's REDUCERS_DIR / TESTS_DIR /
# WS_HANDLER overrides so the real repo tree is never touched.
#
# Usage: scripts/check-account-scope-selftest.sh   (exit 0 = all cases caught).
# Wired into scripts/test.sh ahead of the real guard run.
# ──────────────────────────────────────────────────────────────────────────
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUARD="$ROOT/scripts/check-account-scope.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/reducers" "$TMP/tests"

# Seed the seam owners + primitive-definers so the allowlists resolve as in prod.
for f in notify_state_change.sql utils.sql utils_tags.sql; do
  cp "$ROOT/mailserver/sql/reducers/$f" "$TMP/reducers/" 2>/dev/null || true
done
# A clean Go handler (so the Go-side check passes unless a case overrides it).
cat > "$TMP/handler_ok.go" <<'GO'
package ws
func x() { tagChannel := fmt.Sprintf("tag:%d", mailboxID); _ = tagChannel }
GO
OK_HANDLER="$TMP/handler_ok.go"

fail=0
pass() { echo "    ok   $1"; }
bad()  { echo "    FAIL $1"; fail=1; }

# run_guard <ws_handler> → writes $TMP/out, returns guard exit code
run_guard() {
  REDUCERS_DIR="$TMP/reducers" TESTS_DIR="$TMP/tests" WS_HANDLER="$1" \
    bash "$GUARD" > "$TMP/out" 2>&1
  return $?
}

# expect_catch <case-name> <tag>  — guard must exit 1 AND print [tag]
expect_catch() {
  local name="$1" tag="$2"
  if run_guard "$OK_HANDLER"; then
    bad "$name — guard did NOT fail (expected to catch [$tag])"
  elif grep -q "\[$tag\]" "$TMP/out"; then
    pass "$name — caught [$tag]"
  else
    bad "$name — failed but without a [$tag] line"; sed 's/^/        /' "$TMP/out"
  fi
}

echo "==> seam-guard self-test (each check must fire on an injected violation)"

# Sanity: clean tree passes.
if run_guard "$OK_HANDLER"; then pass "clean tree passes"; else bad "clean tree should pass"; sed 's/^/        /' "$TMP/out"; fi

# A — ownership predicate scopes a user by a mailbox id.
cat > "$TMP/reducers/case_a.sql" <<'SQL'
CREATE OR REPLACE FUNCTION case_a(p_mailbox_id BIGINT) RETURNS VOID AS $$
BEGIN
  UPDATE contacts SET x = 1 WHERE user_id = p_mailbox_id;
END; $$ LANGUAGE plpgsql;
SQL
expect_catch "A: user_id = p_mailbox_id" "A"
rm -f "$TMP/reducers/case_a.sql"

# B — a new p_account_id parameter.
cat > "$TMP/reducers/case_b.sql" <<'SQL'
CREATE OR REPLACE FUNCTION case_b(p_account_id BIGINT) RETURNS VOID AS $$
BEGIN NULL; END; $$ LANGUAGE plpgsql;
SQL
expect_catch "B: new p_account_id param" "B"
rm -f "$TMP/reducers/case_b.sql"

# C — mailbox id matched against the users table.
cat > "$TMP/reducers/case_c.sql" <<'SQL'
CREATE OR REPLACE FUNCTION case_c(p_mailbox_id BIGINT) RETURNS BIGINT AS $$
  SELECT id FROM users WHERE id = p_mailbox_id;
$$ LANGUAGE sql;
SQL
expect_catch "C: users WHERE id = p_mailbox_id" "C"
rm -f "$TMP/reducers/case_c.sql"

# D — coincident-id pgTAP fixture.
cat > "$TMP/tests/case_d.pg" <<'SQL'
INSERT INTO mailboxes (id, user_id, domain_id) VALUES (500, 500, 1);
SQL
expect_catch "D: coincident mailbox.id == user_id fixture" "D"
rm -f "$TMP/tests/case_d.pg"

# E — open-coded state bump + pg_notify outside notify_state_change.
cat > "$TMP/reducers/case_e.sql" <<'SQL'
CREATE OR REPLACE FUNCTION case_e(p_mailbox_id BIGINT) RETURNS VOID AS $$
BEGIN
  UPDATE mailboxes SET jmap_email_state = jmap_email_state + 1 WHERE id = p_mailbox_id;
  PERFORM pg_notify('tag:' || p_mailbox_id, '{}');
END; $$ LANGUAGE plpgsql;
SQL
expect_catch "E: inline state bump + pg_notify (seam bypass)" "E"
rm -f "$TMP/reducers/case_e.sql"

# F (reducer) — push channel keyed by a user id.
cat > "$TMP/reducers/case_f.sql" <<'SQL'
CREATE OR REPLACE FUNCTION case_f(p_user_id BIGINT) RETURNS VOID AS $$
BEGIN
  PERFORM pg_notify('tag:' || p_user_id, '{}');
END; $$ LANGUAGE plpgsql;
SQL
expect_catch "F: pg_notify('tag:' || p_user_id)" "F"
rm -f "$TMP/reducers/case_f.sql"

# F (Go) — handler subscribes by claims.UserID.
cat > "$TMP/handler_bad.go" <<'GO'
package ws
func x() { tagChannel := fmt.Sprintf("tag:%d", claims.UserID); _ = tagChannel }
GO
if run_guard "$TMP/handler_bad.go"; then
  bad "F(Go): handler claims.UserID — guard did NOT fail"
elif grep -q "\[F\]" "$TMP/out"; then
  pass "F(Go): handler subscribes by claims.UserID — caught [F]"
else
  bad "F(Go): failed but without an [F] line"; sed 's/^/        /' "$TMP/out"
fi
rm -f "$TMP/handler_bad.go"

# G — calendar reducer person-lookup by users.email only.
cat > "$TMP/reducers/calendar_case_g.sql" <<'SQL'
CREATE OR REPLACE FUNCTION calendar_case_g(p_email TEXT) RETURNS BIGINT AS $$
  SELECT u.id FROM users u WHERE u.email = p_email;
$$ LANGUAGE sql;
SQL
expect_catch "G: calendar users.email = (single address)" "G"
rm -f "$TMP/reducers/calendar_case_g.sql"

# ── Hardening cases (the bypasses #5 closed; each must now fire) ──────────────

# E2 — Check E state-column regex broadened beyond jmap_(email|tag)_state: an
# inline jmap_mailbox_state bump + pg_notify in a NON-allowlisted file is a bypass.
cat > "$TMP/reducers/case_e2.sql" <<'SQL'
CREATE OR REPLACE FUNCTION case_e2(p_mailbox_id BIGINT) RETURNS VOID AS $$
BEGIN
  UPDATE mailboxes SET jmap_mailbox_state = jmap_mailbox_state + 1 WHERE id = p_mailbox_id;
  PERFORM pg_notify('tag:' || p_mailbox_id, '{}');
END; $$ LANGUAGE plpgsql;
SQL
expect_catch "E2: inline jmap_mailbox_state bump + pg_notify (any jmap_*_state)" "E"
rm -f "$TMP/reducers/case_e2.sql"

# E3 — case-insensitive pg_notify: PG_NOTIFY( must not defeat Check E.
cat > "$TMP/reducers/case_e3.sql" <<'SQL'
CREATE OR REPLACE FUNCTION case_e3(p_mailbox_id BIGINT) RETURNS VOID AS $$
BEGIN
  UPDATE mailboxes SET jmap_email_state = jmap_email_state + 1 WHERE id = p_mailbox_id;
  PERFORM PG_NOTIFY('tag:' || p_mailbox_id, '{}');
END; $$ LANGUAGE plpgsql;
SQL
expect_catch "E3: PG_NOTIFY (uppercase) does not defeat Check E" "E"
rm -f "$TMP/reducers/case_e3.sql"

# E4 — Check E state-TABLE regex broadened beyond mailboxes (Wave 3): an inline
# UPDATE calendars SET jmap_state + pg_notify in a NON-seam file is a bypass —
# previously calendar/contact bumps were structurally invisible to Check E.
cat > "$TMP/reducers/case_e4.sql" <<'SQL'
CREATE OR REPLACE FUNCTION case_e4(p_mailbox_id BIGINT, p_calendar_id BIGINT) RETURNS VOID AS $$
BEGIN
  UPDATE calendars SET jmap_state = jmap_state + 1 WHERE id = p_calendar_id;
  PERFORM pg_notify('calendar:' || p_mailbox_id, '{}');
END; $$ LANGUAGE plpgsql;
SQL
expect_catch "E4: inline UPDATE calendars SET jmap_state + pg_notify (calendar table)" "E"
rm -f "$TMP/reducers/case_e4.sql"

# E5 — same for the contacts domain: inline UPDATE addressbooks SET jmap_state +
# pg_notify outside notify_contact_state is a bypass.
cat > "$TMP/reducers/case_e5.sql" <<'SQL'
CREATE OR REPLACE FUNCTION case_e5(p_mailbox_id BIGINT) RETURNS VOID AS $$
BEGIN
  UPDATE addressbooks SET jmap_state = jmap_state + 1 WHERE mailbox_id = p_mailbox_id;
  PERFORM pg_notify('contact:' || p_mailbox_id, '{}');
END; $$ LANGUAGE plpgsql;
SQL
expect_catch "E5: inline UPDATE addressbooks SET jmap_state + pg_notify (contact table)" "E"
rm -f "$TMP/reducers/case_e5.sql"

# E6 — Check E PRECISION (Wave 3 fix): jmap_state NOT first after SET. The old
# line-local regex required jmap_*state to be the first column; this single-line
# UPDATE puts is_shared first, jmap_state second, and MUST still fire.
cat > "$TMP/reducers/case_e6.sql" <<'SQL'
CREATE OR REPLACE FUNCTION case_e6(p_mailbox_id BIGINT, p_calendar_id BIGINT) RETURNS VOID AS $$
BEGIN
  UPDATE calendars SET is_shared = TRUE, jmap_state = jmap_state + 1 WHERE id = p_calendar_id;
  PERFORM pg_notify('calendar:' || p_mailbox_id, '{}');
END; $$ LANGUAGE plpgsql;
SQL
expect_catch "E6: jmap_state NOT first after SET (is_shared=…, jmap_state=…)" "E"
rm -f "$TMP/reducers/case_e6.sql"

# E7 — Check E PRECISION (Wave 3 fix): MULTI-LINE UPDATE. The UPDATE keyword, the
# SET, the column list, and the jmap_state assignment land on SEPARATE lines (the
# real jmap_calendar_set_update shape). The old single-line regex was blind to
# this; the statement-spanning awk MUST fire.
cat > "$TMP/reducers/case_e7.sql" <<'SQL'
CREATE OR REPLACE FUNCTION case_e7(p_mailbox_id BIGINT, p_id BIGINT) RETURNS VOID AS $$
BEGIN
  UPDATE calendars SET
    name = 'x',
    updated_at = now(),
    jmap_state = jmap_state + 1
  WHERE id = p_id AND mailbox_id = p_mailbox_id;
  PERFORM pg_notify('calendar:' || p_mailbox_id, '{}');
END; $$ LANGUAGE plpgsql;
SQL
expect_catch "E7: multi-line UPDATE with jmap_state on a later line" "E"
rm -f "$TMP/reducers/case_e7.sql"

# F2 — case-insensitive pg_notify: PG_NOTIFY('tag:' || p_user_id) must be caught.
cat > "$TMP/reducers/case_f2.sql" <<'SQL'
CREATE OR REPLACE FUNCTION case_f2(p_user_id BIGINT) RETURNS VOID AS $$
BEGIN
  PERFORM PG_NOTIFY('tag:' || p_user_id, '{}');
END; $$ LANGUAGE plpgsql;
SQL
expect_catch "F2: PG_NOTIFY (uppercase) keyed by p_user_id" "F"
rm -f "$TMP/reducers/case_f2.sql"

# G2 — non-`u` users alias: usr.email = must be caught (alias discovered from FROM).
cat > "$TMP/reducers/calendar_case_g2.sql" <<'SQL'
CREATE OR REPLACE FUNCTION calendar_case_g2(p_email TEXT) RETURNS BIGINT AS $$
  SELECT usr.id FROM users usr WHERE usr.email = p_email;
$$ LANGUAGE sql;
SQL
expect_catch "G2: calendar users alias 'usr'.email = (non-u alias)" "G"
rm -f "$TMP/reducers/calendar_case_g2.sql"

# G3 — non-`u` users alias 'mu' (the in-tree FROM users mu shape) must be caught.
cat > "$TMP/reducers/calendar_case_g3.sql" <<'SQL'
CREATE OR REPLACE FUNCTION calendar_case_g3(p_email TEXT) RETURNS BIGINT AS $$
  SELECT mu.id FROM users mu JOIN mailboxes mb ON mb.user_id = mu.id WHERE mu.email = p_email;
$$ LANGUAGE sql;
SQL
expect_catch "G3: calendar users alias 'mu'.email = (non-u alias)" "G"
rm -f "$TMP/reducers/calendar_case_g3.sql"

# H — POSITIVE: a reducer that DECLARES p_mailbox_id but never USES it.
cat > "$TMP/reducers/case_h.sql" <<'SQL'
CREATE OR REPLACE FUNCTION case_h(p_mailbox_id BIGINT, p_message_id BIGINT) RETURNS VOID AS $$
BEGIN
  -- forgets to scope by p_mailbox_id: mutates the row for ANY mailbox (R1 bug).
  UPDATE messages SET is_read = TRUE WHERE id = p_message_id;
END; $$ LANGUAGE plpgsql;
SQL
expect_catch "H: reducer declares p_mailbox_id but never uses it" "H"
rm -f "$TMP/reducers/case_h.sql"

# H2 — POSITIVE: the legacy p_account_id slot, declared-but-unused, also fires.
cat > "$TMP/reducers/case_h2.sql" <<'SQL'
CREATE OR REPLACE FUNCTION case_h2(p_account_id BIGINT, p_id BIGINT) RETURNS VOID AS $$
BEGIN
  DELETE FROM rules WHERE id = p_id;
END; $$ LANGUAGE plpgsql;
SQL
# case_h2 also trips Check B (new p_account_id param) — assert H is present too.
if run_guard "$OK_HANDLER"; then
  bad "H2: declared-but-unused p_account_id — guard did NOT fail"
elif grep -q "\[H\]" "$TMP/out"; then
  pass "H2: declared-but-unused p_account_id — caught [H]"
else
  bad "H2: failed but without an [H] line"; sed 's/^/        /' "$TMP/out"
fi
rm -f "$TMP/reducers/case_h2.sql"

# H-negative: a reducer that DOES use p_mailbox_id (even once, resolved into a
# local via account_scope) must NOT trip H — proves "param-is-used" tolerates the
# legitimate derived-local indirection (no false positive).
cat > "$TMP/reducers/case_h_ok.sql" <<'SQL'
CREATE OR REPLACE FUNCTION case_h_ok(p_mailbox_id BIGINT) RETURNS VOID AS $$
DECLARE v_domain_id BIGINT;
BEGIN
  SELECT domain_id INTO v_domain_id FROM account_scope(p_mailbox_id);
  UPDATE messages SET is_read = TRUE WHERE domain_id = v_domain_id;
END; $$ LANGUAGE plpgsql;
SQL
if run_guard "$OK_HANDLER"; then
  pass "H-neg: p_mailbox_id used once (resolved into a local) — not flagged"
else
  if grep -q "\[H\]" "$TMP/out"; then bad "H-neg: derived-local use FALSE-fired [H]"; sed 's/^/        /' "$TMP/out"; else pass "H-neg: not flagged by H (other check unrelated)"; fi
fi
rm -f "$TMP/reducers/case_h_ok.sql"

# Final: with all violations removed, the tree is clean again.
if run_guard "$OK_HANDLER"; then pass "tree clean again after removing all cases"; else bad "tree should be clean again"; sed 's/^/        /' "$TMP/out"; fi

if [ "$fail" -ne 0 ]; then
  echo "==> seam-guard self-test FAILED — the guard stopped catching a bug class."
  exit 1
fi
echo "    seam-guard self-test: all checks (A–H) fire as expected."
