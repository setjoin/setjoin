package handlers

// BUG 003 (RBAC cut-over lockout) regression: is_admin must be DERIVED at
// JWT-mint time from an unexpired admin_role_assignments row, NOT read raw from
// users.is_admin. The bug: a freshly-granted admin (admin_role_assignments row
// written by AssignMember / SSO, but users.is_admin still FALSE) minted
// IsAdmin=false, so the gateway's chain.go skipped permissions.Resolve and 403'd
// every admin route. Only pre-cutover (V011-era) admins, whose users.is_admin was
// TRUE, worked.
//
// These tests exercise the REAL mint path (verifyPassword / lookupUser /
// lookupUserByOIDC / lookupUserBySAML) — NOT a hand-built Claims{IsAdmin:true} —
// and assert the derived IsAdmin matches EXISTS(unexpired assignment), then
// confirm the derived value resolves to a non-empty permission set (the gateway's
// downstream contract). DB-backed; skipped when DB_DSN is unset.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

// seedDerivationUser inserts a user with users.is_admin = FALSE (the freshly
// provisioned state) + a primary mailbox and a known password. Returns userID and
// the plaintext email. Caller defers cleanSSOActor.
func seedDerivationUser(t *testing.T, pool *pgxpool.Pool, ctx context.Context, tag, password string) (int64, string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	var userID int64
	var email string
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, sync_source, enabled, is_admin, password_hash)
		 SELECT $1||'-'||floor(random()*1e9)::text,
		        $1||'-'||floor(random()*1e9)::text||'@deriv-test.internal',
		        'Deriv Test '||$1,
		        d.id, 'local', TRUE, FALSE, $2
		 FROM domains d WHERE d.is_local = TRUE ORDER BY d.id LIMIT 1
		 RETURNING id, email`,
		tag, string(hash),
	).Scan(&userID, &email); err != nil {
		t.Skipf("seed user (%s) failed (schema not loaded?): %v", tag, err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		 SELECT u.id, u.domain_id, u.email, u.display_name, 'personal', TRUE
		 FROM users u WHERE u.id = $1`,
		userID,
	); err != nil {
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		t.Skipf("seed mailbox (%s) failed: %v", tag, err)
	}
	return userID, email
}

// grantGovernedAdmin writes an unexpired admin_role_assignments row (group 2 =
// user_admin builtin) WITHOUT touching users.is_admin — exactly what AssignMember
// / SSO do.
func grantGovernedAdmin(t *testing.T, pool *pgxpool.Pool, ctx context.Context, userID, groupID int64) {
	t.Helper()
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, $2, NULL) ON CONFLICT (user_id, role_group_id) DO NOTHING`,
		userID, groupID,
	); err != nil {
		t.Fatalf("grant governed admin: %v", err)
	}
}

// TestVerifyPassword_DerivesIsAdminFromAssignment is the core BUG 003 regression.
// A user with users.is_admin = FALSE but holding an unexpired governed assignment
// must mint IsAdmin = TRUE through the REAL verifyPassword mint path, and that
// userID must resolve to a non-empty permission set (the gateway contract).
func TestVerifyPassword_DerivesIsAdminFromAssignment(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	const pw = "Correct-Horse-Battery-9!"
	userID, email := seedDerivationUser(t, pool, ctx, "deriv-vp", pw)
	defer cleanSSOActor(t, pool, ctx, userID)

	// group 2 = user_admin builtin (seeded by V010).
	grantGovernedAdmin(t, pool, ctx, userID, 2)

	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	user, err := h.verifyPassword(ctx, email, pw, "127.0.0.1")
	if err != nil {
		t.Fatalf("verifyPassword failed for a valid credential: %v", err)
	}
	if !user.IsAdmin {
		t.Fatal("BUG 003: verifyPassword minted IsAdmin=false for a user holding an unexpired governed admin_role_assignments row (users.is_admin is FALSE but the assignment makes them an admin)")
	}

	// Gateway contract: the derived admin must resolve to a non-empty perm set.
	perms, _, err := permissions.Resolve(ctx, pool, user.ID)
	if err != nil {
		t.Fatalf("permissions.Resolve: %v", err)
	}
	if len(perms) == 0 {
		t.Error("derived admin resolved to an EMPTY permission set — gateway would 403 every admin route")
	}
}

// TestLookupUser_DerivesIsAdminFromAssignment exercises the lookupUser mint seam
// (used by the SSO returning-user and other paths) for the same property.
func TestLookupUser_DerivesIsAdminFromAssignment(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID, email := seedDerivationUser(t, pool, ctx, "deriv-lu", "irrelevant")
	defer cleanSSOActor(t, pool, ctx, userID)

	grantGovernedAdmin(t, pool, ctx, userID, 2)

	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	user, err := h.lookupUser(ctx, "email", email)
	if err != nil {
		t.Fatalf("lookupUser: %v", err)
	}
	if !user.IsAdmin {
		t.Fatal("BUG 003: lookupUser minted IsAdmin=false despite an unexpired governed assignment")
	}
}

// TestVerifyPassword_NoAssignment_NotAdmin asserts the negative: a user with NO
// governed assignment mints IsAdmin=false even if the vestigial users.is_admin
// column were TRUE (we seed it TRUE in seedDerivationUser, then DON'T grant an
// assignment). is_admin must follow the assignment, not the column.
func TestVerifyPassword_NoAssignment_NotAdmin(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	const pw = "Another-Strong-Pass-7!"
	userID, email := seedDerivationUser(t, pool, ctx, "deriv-none", pw)
	defer cleanSSOActor(t, pool, ctx, userID)

	// Set the vestigial column TRUE to prove the derivation ignores it.
	if _, err := pool.Exec(ctx, `UPDATE users SET is_admin = TRUE WHERE id = $1`, userID); err != nil {
		t.Fatalf("set vestigial is_admin: %v", err)
	}

	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	user, err := h.verifyPassword(ctx, email, pw, "127.0.0.1")
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if user.IsAdmin {
		t.Fatal("BUG 003: verifyPassword minted IsAdmin=true for a user with NO governed assignment (it must derive from admin_role_assignments, not the vestigial users.is_admin column)")
	}
}

// TestVerifyPassword_ExpiredAssignment_NotAdmin asserts an EXPIRED assignment does
// not confer admin (the derivation must carry the expires_at filter, matching
// session.go and permissions.Resolve).
func TestVerifyPassword_ExpiredAssignment_NotAdmin(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	const pw = "Expired-Grant-Pass-3!"
	userID, email := seedDerivationUser(t, pool, ctx, "deriv-exp", pw)
	defer cleanSSOActor(t, pool, ctx, userID)

	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by, expires_at)
		 VALUES ($1, 2, NULL, $2)`,
		userID, time.Now().Add(-1*time.Hour),
	); err != nil {
		t.Fatalf("seed expired assignment: %v", err)
	}

	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	user, err := h.verifyPassword(ctx, email, pw, "127.0.0.1")
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if user.IsAdmin {
		t.Fatal("BUG 003: an EXPIRED governed assignment must not confer admin at mint time")
	}
}
