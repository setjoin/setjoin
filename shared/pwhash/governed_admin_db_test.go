package pwhash

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"setjoin.com/shared/testsupport"
)

// TestCheckPasswordAndLookup_IsAdminRequiresGovernedAssignment is the DB-backed
// closure test for the legacy-admin-flag finding
// (occ_7512aa859c19ceb6691b64c7): users.is_admin is a LEGACY flag — it feeds
// Claims.IsAdmin, which the mail console uses as a visibility bypass (e.g.
// per-user rule-template visibility), so this shared seam must surface the
// GOVERNED admin signal (legacy flag AND a live admin_role_assignments row,
// the RBAC cut-over's single authority axis), never the bare column.
//
// Legs: flag without assignment → non-admin; flag + unexpired assignment →
// admin; flag + expired assignment → non-admin; LookupByEmail agrees. The
// governed rows here are self-granted test fixtures with an empty permission
// set — the test only reads the boolean, never exercises console authority.
func TestCheckPasswordAndLookup_IsAdminRequiresGovernedAssignment(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	password := "Sup3r-Secret-pw"
	email, userID := seedGovernedAdminUser(t, pool, password)

	// Leg 1: legacy flag set, NO governed assignment → non-admin at this seam.
	// (Before the closure the raw column was surfaced and the flag alone
	// established blanket admin, including visibility bypasses.)
	if u, err := CheckPassword(ctx, pool, email, password); err != nil {
		t.Fatalf("CheckPassword: %v", err)
	} else if u.IsAdmin {
		t.Fatal("legacy is_admin flag alone surfaced as admin — governed assignment required")
	}
	if u, err := LookupByEmail(ctx, pool, email); err != nil {
		t.Fatalf("LookupByEmail: %v", err)
	} else if u.IsAdmin {
		t.Fatal("LookupByEmail: legacy flag alone surfaced as admin")
	}

	// Leg 2: flag + live (unexpired, non-JIT) governed assignment → admin.
	groupID := seedRoleGroup(t, pool)
	assignmentID := seedAssignment(t, pool, userID, groupID, nil)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM admin_role_assignments WHERE id = $1`, assignmentID) })

	u, err := CheckPassword(ctx, pool, email, password)
	if err != nil {
		t.Fatalf("CheckPassword with assignment: %v", err)
	}
	if !u.IsAdmin {
		t.Fatal("flagged user with a live governed assignment must surface as admin")
	}
	if u, err := LookupByEmail(ctx, pool, email); err != nil || !u.IsAdmin {
		t.Fatalf("LookupByEmail with assignment: u.IsAdmin=%v err=%v, want true/nil", u.IsAdmin, err)
	}

	// Leg 3: expiry honored — expiring the assignment revokes the signal
	// (UPDATE, not insert: (user_id, role_group_id) is UNIQUE).
	if _, err := pool.Exec(ctx,
		`UPDATE admin_role_assignments SET expires_at = now() - interval '1 hour' WHERE id = $1`,
		assignmentID); err != nil {
		t.Fatalf("expire assignment: %v", err)
	}
	// CheckPassword caches verified logins for 60s keyed on
	// (email, stored-hash, password). Rotate the STORED HASH to mint a new
	// cache key so leg 3 exercises a fresh governed-assignment read instead of
	// the cached leg-2 entry — the same mechanism that makes credential
	// rotation take effect immediately at this seam.
	freshHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt re-hash: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET password_hash = $1 WHERE id = $2`, string(freshHash), userID); err != nil {
		t.Fatalf("rotate stored hash: %v", err)
	}
	if u, err := LookupByEmail(ctx, pool, email); err != nil || u.IsAdmin {
		t.Fatalf("LookupByEmail with expired assignment: u.IsAdmin=%v err=%v, want false/nil", u.IsAdmin, err)
	}
	if u, err := CheckPassword(ctx, pool, email, password); err != nil {
		t.Fatalf("CheckPassword with expired assignment: %v", err)
	} else if u.IsAdmin {
		t.Fatal("expired governed assignment must not surface as admin")
	}

	// Leg 4: un-flagged user with an assignment is still not "legacy admin"
	// (the flag remains a necessary precondition — the legacy column and the
	// governed row must BOTH hold). A second group avoids the UNIQUE
	// (user_id, role_group_id) constraint.
	if _, err := pool.Exec(ctx, `UPDATE users SET is_admin = FALSE WHERE id = $1`, userID); err != nil {
		t.Fatalf("clear is_admin: %v", err)
	}
	group2ID := seedRoleGroup(t, pool)
	_ = seedAssignment(t, pool, userID, group2ID, nil)
	if u, err := LookupByEmail(ctx, pool, email); err != nil || u.IsAdmin {
		t.Fatalf("assignment without the legacy flag: u.IsAdmin=%v err=%v, want false/nil", u.IsAdmin, err)
	}
}

// TestCheckPassword_EmptyHashFailsClosed pins the empty stored-hash leg of the
// governed seam: a user row with no password hash verifies nothing and yields
// ErrInvalidCredentials (indistinguishable from a bad password — no oracle).
func TestCheckPassword_EmptyHashFailsClosed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	email, _, userID := seedAdminUserWithFlag(t, pool, "irrelevant", false)
	t.Cleanup(func() {})
	if _, err := pool.Exec(ctx, `UPDATE users SET password_hash = '' WHERE id = $1`, userID); err != nil {
		t.Fatalf("clear password_hash: %v", err)
	}
	if _, err := CheckPassword(ctx, pool, email, "irrelevant"); err != ErrInvalidCredentials {
		t.Fatalf("CheckPassword on empty hash = %v, want ErrInvalidCredentials", err)
	}
}

// TestCheckPassword_DeadPoolFailsClosed pins the query-error leg: a closed
// pool (any transport-level failure) must surface ErrInvalidCredentials — the
// lookup failure is never converted into a success, and the governed-admin
// EXISTS clause never runs against untrusted state.
func TestCheckPassword_DeadPoolFailsClosed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	email, _, _ := seedAdminUserWithFlag(t, pool, "Sup3r-Secret-pw", true)

	pool.Close() // every subsequent query fails at the transport level
	if _, err := CheckPassword(context.Background(), pool, email, "Sup3r-Secret-pw"); err != ErrInvalidCredentials {
		t.Fatalf("CheckPassword on closed pool = %v, want ErrInvalidCredentials (fail closed)", err)
	}
}

// seedAdminUserWithFlag inserts a throwaway domain + user with the given
// is_admin value and the password hashed at bcrypt.MinCost. Returns the stored
// email, the domain id, and the user id. Mirrors seedCheckPasswordUser.
func seedAdminUserWithFlag(t *testing.T, pool *pgxpool.Pool, password string, isAdmin bool) (string, int64, int64) {
	t.Helper()
	ctx := context.Background()
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatalf("rand: %v", err)
	}
	uniq := hex.EncodeToString(suffix)
	dom := "pwhash-gov-" + uniq + ".local"
	stored := "govadmin@" + dom

	var domID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, dom,
	).Scan(&domID); err != nil {
		t.Skipf("could not seed domain (schema not loaded?): %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, domID) })

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt hash: %v", err)
	}
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash, enabled, is_admin)
		 VALUES ($1, $2, 'Gov Admin', $3, $4, TRUE, $5) RETURNING id`,
		"govadmin-"+uniq, stored, domID, string(hash), isAdmin,
	).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID) })
	return stored, domID, userID
}

// seedGovernedAdminUser inserts a throwaway domain + user with is_admin=TRUE
// and the given password (bcrypt MinCost). Returns the stored email and id.
func seedGovernedAdminUser(t *testing.T, pool *pgxpool.Pool, password string) (string, int64) {
	t.Helper()
	email, _, userID := seedAdminUserWithFlag(t, pool, password, true)
	return email, userID
}

// seedRoleGroup creates a dedicated non-builtin role group with an empty
// permission set (this test reads the admin boolean only) and registers
// cleanup. The name is per-run unique (admin_role_groups.name is globally
// UNIQUE) so reruns never collide with their own leftovers.
func seedRoleGroup(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	ctx := context.Background()
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatalf("rand: %v", err)
	}
	var groupID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO admin_role_groups (name, description, permissions, is_builtin)
		 VALUES ('pwhash-governed-test-' || $1, 'pwhash closure test fixture', '{}', FALSE)
		 RETURNING id`,
		hex.EncodeToString(suffix),
	).Scan(&groupID); err != nil {
		t.Skipf("could not seed admin_role_group (schema not loaded?): %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM admin_role_groups WHERE id = $1`, groupID)
	})
	return groupID
}

// seedAssignment grants userID the role group. expiresAt nil = permanent;
// granted_by = the user itself (test fixture, mirroring the V011 backfill).
func seedAssignment(t *testing.T, pool *pgxpool.Pool, userID, groupID int64, expiresAt *time.Time) int64 {
	t.Helper()
	ctx := context.Background()
	var assignmentID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by, expires_at)
		 VALUES ($1, $2, $1, $3) RETURNING id`,
		userID, groupID, expiresAt,
	).Scan(&assignmentID); err != nil {
		t.Fatalf("seed admin_role_assignments: %v", err)
	}
	return assignmentID
}
