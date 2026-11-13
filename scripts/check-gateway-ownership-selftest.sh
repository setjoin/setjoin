#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-gateway-ownership-selftest.sh — negative+positive self-test for the
# positive gateway-ownership guard (scripts/check-gateway-ownership.sh).
#
# A guard that never fires is theater; a positive guard that passes a brand-new
# UNSCOPED query is worse than nothing (it certifies the hole closed when it
# isn't). This proves BOTH ends against a TEMP gateway tree (via the guard's
# GATEWAY_DIR override, so the real repo tree is never touched):
#   · CLEAN tree (one properly-scoped query)        → guard PASSES.
#   · inject an UNSCOPED user-data query            → guard FIRES (exit 1, [OWN]).
#   · a PROJECTION-ONLY ownership token (recall.go:56 shape: token in the SELECT
#     column list, not the WHERE)                   → guard FIRES (precision).
#   · an INSERT with a token only in the column list/VALUES (no WHERE possible)
#                                                    → guard FIRES (precision).
#   · an unscoped read of a NEWLY-COVERED table (user_signatures) in UDT_RE
#                                                    → guard FIRES (coverage).
#   · scope that same query                         → guard PASSES again.
#   · a pure reducer call (no raw table touch)      → NOT flagged (excluded).
#   · an FK-collection handle (calendar_id)         → counts as scoped (PASSES).
#
# Usage: scripts/check-gateway-ownership-selftest.sh   (exit 0 = all cases pass).
# Wired into scripts/test.sh ahead of the real guard run.
# ──────────────────────────────────────────────────────────────────────────
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUARD="$ROOT/scripts/check-gateway-ownership.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/gw"

fail=0
pass() { echo "    ok   $1"; }
bad()  { echo "    FAIL $1"; fail=1; }

run_guard() { GATEWAY_DIR="$TMP/gw" bash "$GUARD" > "$TMP/out" 2>&1; return $?; }

echo "==> gateway-ownership guard self-test"

# ── Baseline: a properly-scoped query → CLEAN. ──────────────────────────────
cat > "$TMP/gw/ok.go" <<'GO'
package gw
func a(pool P, ctx C, mailboxID int64) {
	pool.Query(ctx, `SELECT id, subject FROM messages WHERE mailbox_id = $1`, mailboxID)
}
GO
if run_guard; then pass "scoped query — clean tree passes"; else bad "scoped query should pass"; sed 's/^/        /' "$TMP/out"; fi

# ── Negative: inject an UNSCOPED user-data query → guard must FIRE. ──────────
cat > "$TMP/gw/leak.go" <<'GO'
package gw
func b(pool P, ctx C, id int64) {
	pool.Query(ctx, `SELECT id, subject FROM messages WHERE id = $1`, id)
}
GO
if run_guard; then
  bad "unscoped query — guard did NOT fire"; sed 's/^/        /' "$TMP/out"
elif grep -q "\[OWN\]" "$TMP/out"; then
  pass "unscoped 'FROM messages WHERE id = \$1' — caught [OWN]"
else
  bad "unscoped query failed but without an [OWN] line"; sed 's/^/        /' "$TMP/out"
fi

# ── Precision: a PROJECTION-ONLY ownership token must NOT count as scoping. ──
# This is the recall.go:56 shape — `SELECT … mailbox_id … FROM messages WHERE
# id = $1`. The token lives in the SELECT column list, not the WHERE, so it does
# NOT scope rows: the guard MUST still fire [OWN]. (Before the 2026-06-18
# precision tightening this falsely passed — that was the missed IDOR.)
cat > "$TMP/gw/proj.go" <<'GO'
package gw
func p(pool P, ctx C, id int64) {
	pool.QueryRow(ctx, `SELECT from_addr, received_at, mailbox_id, message_id FROM messages WHERE id = $1`, id)
}
GO
if run_guard; then
  bad "projection-only token (recall.go:56 shape) — guard did NOT fire"; sed 's/^/        /' "$TMP/out"
elif grep -q "\[OWN\]" "$TMP/out"; then
  pass "projection-only 'SELECT … mailbox_id … FROM messages WHERE id = \$1' — caught [OWN]"
else
  bad "projection-only token failed but without an [OWN] line"; sed 's/^/        /' "$TMP/out"
fi
rm -f "$TMP/gw/proj.go"

# ── Precision (INSERT): an ownership token only in the INSERT column list /
# VALUES does NOT count as scoping (an INSERT cannot carry a WHERE). The guard
# MUST fire — these are allowlisted in the real tree as R2-INSERTs, not passed
# silently by the positive token check.
cat > "$TMP/gw/ins.go" <<'GO'
package gw
func i(pool P, ctx C, mailboxID int64) {
	pool.Exec(ctx, `INSERT INTO messages (mailbox_id, subject) VALUES ($1, $2)`, mailboxID, "x")
}
GO
if run_guard; then
  bad "INSERT column-list token — guard did NOT fire"; sed 's/^/        /' "$TMP/out"
elif grep -q "\[OWN\]" "$TMP/out"; then
  pass "INSERT column-list token (no WHERE) — caught [OWN]"
else
  bad "INSERT column-list token failed but without an [OWN] line"; sed 's/^/        /' "$TMP/out"
fi
rm -f "$TMP/gw/ins.go"

# ── Coverage: a newly-added per-user table (user_signatures) is in UDT_RE — an
# unscoped read of it must fire (proves the widened coverage actually guards it).
cat > "$TMP/gw/cov.go" <<'GO'
package gw
func c(pool P, ctx C, id int64) {
	pool.Query(ctx, `SELECT body FROM user_signatures WHERE id = $1`, id)
}
GO
if run_guard; then
  bad "newly-covered table user_signatures (unscoped) — guard did NOT fire"; sed 's/^/        /' "$TMP/out"
elif grep -q "\[OWN\]" "$TMP/out"; then
  pass "newly-covered table user_signatures (unscoped) — caught [OWN]"
else
  bad "user_signatures unscoped failed but without an [OWN] line"; sed 's/^/        /' "$TMP/out"
fi
rm -f "$TMP/gw/cov.go"

# ── Positive: scope the same query → guard passes again. ────────────────────
cat > "$TMP/gw/leak.go" <<'GO'
package gw
func b(pool P, ctx C, id int64, mailboxID int64) {
	pool.Query(ctx, `SELECT id, subject FROM messages WHERE id = $1 AND mailbox_id = $2`, id, mailboxID)
}
GO
if run_guard; then pass "scoping the injected query — guard passes again"; else bad "scoped variant should pass"; sed 's/^/        /' "$TMP/out"; fi
rm -f "$TMP/gw/leak.go"

# ── Exclusion: a pure reducer call (no raw table touch) → NOT flagged. ───────
cat > "$TMP/gw/reducer.go" <<'GO'
package gw
func c(pool P, ctx C, eventID int64) {
	pool.QueryRow(ctx, `SELECT jmap_email_set($1, $2, $3)`, eventID, 1, 2)
}
GO
if run_guard; then pass "pure reducer call (SELECT fn(...)) — not flagged"; else bad "reducer call must not be flagged"; sed 's/^/        /' "$TMP/out"; fi
rm -f "$TMP/gw/reducer.go"

# ── FK-collection handle: calendar_id counts as a scoping handle → PASSES. ──
cat > "$TMP/gw/fk.go" <<'GO'
package gw
func d(pool P, ctx C, calID int64) {
	pool.Query(ctx, `SELECT id, title FROM calendar_events WHERE calendar_id = $1`, calID)
}
GO
if run_guard; then pass "FK-collection handle (calendar_id) — counts as scoped"; else bad "FK handle should pass"; sed 's/^/        /' "$TMP/out"; fi
rm -f "$TMP/gw/fk.go"

# ── Final: with only the baseline scoped query, the tree is clean. ──────────
if run_guard; then pass "tree clean again"; else bad "tree should be clean again"; sed 's/^/        /' "$TMP/out"; fi

if [ "$fail" -ne 0 ]; then
  echo "==> gateway-ownership guard self-test FAILED — the positive guard mis-classified a case."
  exit 1
fi
echo "    gateway-ownership guard self-test: positive + negative cases behave."
