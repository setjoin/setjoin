#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-identity-writer-selftest.sh — negative+positive self-test for the
# identity-writer guard (scripts/check-identity-writer.sh).
#
# A guard that never fires is theater. This proves BOTH ends against TEMP copies
# of the writer tree (the real repo is untouched, via the SEARCH_ROOTS override):
#   · REAL tree (typed identity.ProvisionAccount seam only) → guard PASSES.
#   · injected raw `SELECT provision_account(...)` literal   → guard FIRES.
#   · injected raw SyncAttrs(rawEmail, …) (non-canonical 1st → guard FIRES.
#     arg)
#
# Usage: scripts/check-identity-writer-selftest.sh   (exit 0 = all cases pass).
# Wired into scripts/test.sh ahead of the real guard run.
# ──────────────────────────────────────────────────────────────────────────
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUARD="$ROOT/scripts/check-identity-writer.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail=0
pass() { echo "    ok   $1"; }
bad()  { echo "    FAIL $1"; fail=1; }

run_guard() {
  SEARCH_ROOTS="$1" bash "$GUARD" > "$TMP/out" 2>&1
  return $?
}

echo "==> identity-writer guard self-test"

# ── Positive: the REAL writer tree (typed seam only) must PASS. ──────────────
if run_guard "$ROOT/mailserver/internal/ad $ROOT/mailserver/internal/ldapsync $ROOT/mailserver/internal/admin"; then
  pass "real writer tree (typed identity.ProvisionAccount seam) passes"
else
  bad "real writer tree should pass"; sed 's/^/        /' "$TMP/out"
fi

# ── Negative 1: a raw `SELECT provision_account(...)` literal → FIRE. ────────
mkdir -p "$TMP/n1"
cat > "$TMP/n1/badwriter.go" <<'EOF'
package n1

func write(pool P, email string) {
	pool.Exec(ctx,
		`SELECT provision_account(p_email => $1)`,
		email)
}
EOF
if run_guard "$TMP/n1"; then
  bad "N1: raw provision_account literal — guard did NOT fire"; sed 's/^/        /' "$TMP/out"
elif grep -q "REGRESSION" "$TMP/out"; then
  pass "N1: raw provision_account literal — caught (REGRESSION)"
else
  bad "N1: fired but without a REGRESSION message"; sed 's/^/        /' "$TMP/out"
fi

# ── Negative 2: a raw SyncAttrs(rawEmail, …) first arg → FIRE. ──────────────
mkdir -p "$TMP/n2"
cat > "$TMP/n2/badupdate.go" <<'EOF'
package n2

func build(u U) map[string]string {
	return ldaputil.SyncAttrs(u.Email, u.DisplayName, "", "", "", "", u.UPN)
}
EOF
if run_guard "$TMP/n2"; then
  bad "N2: raw SyncAttrs first arg — guard did NOT fire"; sed 's/^/        /' "$TMP/out"
elif grep -q "REGRESSION" "$TMP/out"; then
  pass "N2: raw SyncAttrs(u.Email, …) — caught (REGRESSION)"
else
  bad "N2: fired but without a REGRESSION message"; sed 's/^/        /' "$TMP/out"
fi

# ── Positive 2: a canonicalized SyncAttrs(...) first arg → PASS. ────────────
mkdir -p "$TMP/p2"
cat > "$TMP/p2/goodupdate.go" <<'EOF'
package p2

func build(u U) map[string]string {
	return ldaputil.SyncAttrs(identity.CanonicalizeAddress(u.Email), u.DisplayName, "", "", "", "", u.UPN)
}
EOF
if run_guard "$TMP/p2"; then
  pass "P2: SyncAttrs(identity.CanonicalizeAddress(...), …) — passes"
else
  bad "P2: canonicalized SyncAttrs should pass"; sed 's/^/        /' "$TMP/out"
fi

# ── Negative 3: a raw `UPDATE users SET email` with NO CanonicalizeAddress → FIRE.
mkdir -p "$TMP/n3"
cat > "$TMP/n3/rawemail.go" <<'EOF'
package n3

func patch(pool P, raw string, id int64) {
	pool.Exec(ctx,
		`UPDATE users SET email = $1, updated_at = now() WHERE id = $2`,
		raw, id)
}
EOF
if run_guard "$TMP/n3"; then
  bad "N3: raw 'UPDATE users SET email' (no CanonicalizeAddress) — guard did NOT fire"; sed 's/^/        /' "$TMP/out"
elif grep -q "REGRESSION" "$TMP/out"; then
  pass "N3: raw users.email write w/o CanonicalizeAddress — caught (REGRESSION)"
else
  bad "N3: fired but without a REGRESSION message"; sed 's/^/        /' "$TMP/out"
fi

# ── Negative 4: a raw `INSERT INTO aliases (... email ...)` w/o fold → FIRE. ──
mkdir -p "$TMP/n4"
cat > "$TMP/n4/rawalias.go" <<'EOF'
package n4

func addAlias(pool P, raw string, mbox, dom int64) {
	pool.Exec(ctx,
		`INSERT INTO aliases (mailbox_id, email, domain_id) VALUES ($1, $2, $3)`,
		mbox, raw, dom)
}
EOF
if run_guard "$TMP/n4"; then
  bad "N4: raw 'INSERT INTO aliases (... email ...)' (no fold) — guard did NOT fire"; sed 's/^/        /' "$TMP/out"
elif grep -q "REGRESSION" "$TMP/out"; then
  pass "N4: raw aliases.email write w/o CanonicalizeAddress — caught (REGRESSION)"
else
  bad "N4: fired but without a REGRESSION message"; sed 's/^/        /' "$TMP/out"
fi

# ── Positive 3: the same raw write, but the file canonicalizes → PASS. ───────
mkdir -p "$TMP/p3"
cat > "$TMP/p3/goodemail.go" <<'EOF'
package p3

func patch(pool P, raw string, id int64) {
	canon := identity.CanonicalizeAddress(raw).String()
	pool.Exec(ctx,
		`UPDATE users SET email = $1, updated_at = now() WHERE id = $2`,
		canon, id)
}
EOF
if run_guard "$TMP/p3"; then
  pass "P3: raw users.email write wrapped in CanonicalizeAddress — passes"
else
  bad "P3: canonicalized users.email write should pass"; sed 's/^/        /' "$TMP/out"
fi

# ── Positive 4: raw write folded via the VALIDATING minter → PASS. ───────────
# ValidateAndCanonicalizeEmail is implemented over NormalizeAndValidate →
# CanonicalizeAddress (pinned output-equality invariant), so a file that mints
# through it proves the same fold — the admin alias writer's landed shape.
mkdir -p "$TMP/p4"
cat > "$TMP/p4/validatedemail.go" <<'EOF'
package p4

func addAlias(pool P, raw string, mbox, dom int64) error {
	validated, err := identity.ValidateAndCanonicalizeEmail(raw)
	if err != nil {
		return err
	}
	pool.Exec(ctx,
		`INSERT INTO aliases (mailbox_id, email, domain_id) VALUES ($1, $2, $3)`,
		mbox, validated.String(), dom)
	return nil
}
EOF
if run_guard "$TMP/p4"; then
  pass "P4: raw aliases.email write folded via ValidateAndCanonicalizeEmail — passes"
else
  bad "P4: validating-minter aliases.email write should pass"; sed 's/^/        /' "$TMP/out"
fi

if [ "$fail" -ne 0 ]; then
  echo "==> identity-writer guard self-test FAILED — the guard mis-classified a case."
  exit 1
fi
echo "    identity-writer guard self-test: all cases (positive + negative) behave."
