// governed_admin_seams_db_test.go — permanent DB-gated regression coverage for
// the governed-admin qualification of the two non-password auth seams
// (occ_7512aa859c19ceb6691b64c7 follow-up): lookupByKerberosPrincipal
// (chain.go) and lookupByCertSubject (cert.go) both feed Claims.IsAdmin the
// same way the shared/pwhash password seam does, so both must surface the
// GOVERNED admin signal (legacy flag AND a live admin_role_assignments row —
// pwhash.GovernedAdminExpr), never the bare users.is_admin column. Mirrors
// guest_belt_db_test.go's DB-gated idiom (os.Getenv("DB_DSN") + t.Skip) and
// shared/pwhash/governed_admin_db_test.go's fixture shape (throwaway domain,
// non-builtin role group with an empty permission set, self-granted
// assignment — the test only reads the boolean, never exercises authority).
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// TestKerberosAndCertSeams_IsAdminRequiresGovernedAssignment drives BOTH
// seams against the same flagged fixture: a legacy-flagged user with no
// governed assignment must read IsAdmin=false via kerberos principal lookup
// AND via cert-subject lookup, while a live governed assignment flips both to
// true; expiring the assignment revokes the signal at both seams again.
func TestKerberosAndCertSeams_IsAdminRequiresGovernedAssignment(t *testing.T) {
	dsn := guestDSN(t)
	pool := guestTestPool(t, dsn)
	ctx := context.Background()

	// ── fixture: throwaway domain + flagged user with a krb5 principal ──
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatalf("rand: %v", err)
	}
	uniq := hex.EncodeToString(suffix)

	var domID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`,
		"govseam-"+uniq+".local",
	).Scan(&domID); err != nil {
		t.Skipf("could not seed domain (schema not loaded?): %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, domID) })

	email := "govseam-" + uniq + "@govseam.test"
	principal := "govseam-" + uniq + "@COMPANY.TEST"
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash, enabled, is_admin, krb5_principal)
		 VALUES ($1, $2, $3, 'Gov Seam', '', TRUE, TRUE, $4) RETURNING id`,
		"govseam-"+uniq, domID, email, principal,
	).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID) })

	krb := &kerberosAuthMethod{provider: nil, pool: pool} // provider only serves Authenticate; the lookup is pool-only

	// Leg 1: legacy flag set, NO governed assignment → BOTH seams read
	// non-admin. (Before the qualification the raw column surfaced here and
	// the flag alone established Claims.IsAdmin.)
	u, err := krb.lookupByKerberosPrincipal(ctx, principal)
	if err != nil {
		t.Fatalf("kerberos lookup: %v", err)
	}
	if u.IsAdmin {
		t.Fatal("kerberos seam: legacy is_admin flag alone surfaced as admin — governed assignment required")
	}
	u, err = lookupByCertSubject(ctx, pool, email, nil)
	if err != nil {
		t.Fatalf("cert lookup (CN): %v", err)
	}
	if u.IsAdmin {
		t.Fatal("cert seam: legacy is_admin flag alone surfaced as admin — governed assignment required")
	}

	// ── governed assignment: non-builtin group with an empty permission set ──
	var groupID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO admin_role_groups (name, description, permissions, is_builtin)
		 VALUES ('govseam-test-' || $1, 'auth seam closure test fixture', '{}', FALSE)
		 RETURNING id`, uniq,
	).Scan(&groupID); err != nil {
		t.Skipf("could not seed admin_role_group (schema not loaded?): %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM admin_role_groups WHERE id = $1`, groupID) })

	var assignmentID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, $2, $1) RETURNING id`, userID, groupID,
	).Scan(&assignmentID); err != nil {
		t.Fatalf("seed admin_role_assignments: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM admin_role_assignments WHERE id = $1`, assignmentID) })

	// Leg 2: flag + live governed assignment → BOTH seams read admin.
	if u, err := krb.lookupByKerberosPrincipal(ctx, principal); err != nil || !u.IsAdmin {
		t.Fatalf("kerberos seam with live assignment: IsAdmin=%v err=%v, want true/nil", u.IsAdmin, err)
	}
	if u, err := lookupByCertSubject(ctx, pool, email, nil); err != nil || !u.IsAdmin {
		t.Fatalf("cert seam with live assignment: IsAdmin=%v err=%v, want true/nil", u.IsAdmin, err)
	}

	// Leg 3: expiry honored — expiring the assignment revokes the signal at
	// both seams (UPDATE, not insert: (user_id, role_group_id) is UNIQUE).
	if _, err := pool.Exec(ctx,
		`UPDATE admin_role_assignments SET expires_at = now() - interval '1 hour' WHERE id = $1`,
		assignmentID); err != nil {
		t.Fatalf("expire assignment: %v", err)
	}
	if u, err := krb.lookupByKerberosPrincipal(ctx, principal); err != nil || u.IsAdmin {
		t.Fatalf("kerberos seam with expired assignment: IsAdmin=%v err=%v, want false/nil", u.IsAdmin, err)
	}
	if u, err := lookupByCertSubject(ctx, pool, email, nil); err != nil || u.IsAdmin {
		t.Fatalf("cert seam with expired assignment: IsAdmin=%v err=%v, want false/nil", u.IsAdmin, err)
	}
}

// TestCertSeam_EmailSANLookupSharesGovernedRule pins the email-SAN candidate
// arm of lookupByCertSubject (CN is tried first; the SAN walk must carry the
// same governed rule, not a divergent second query).
func TestCertSeam_EmailSANLookupSharesGovernedRule(t *testing.T) {
	dsn := guestDSN(t)
	pool := guestTestPool(t, dsn)
	ctx := context.Background()

	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatalf("rand: %v", err)
	}
	uniq := hex.EncodeToString(suffix)

	var domID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`,
		"govseamsan-"+uniq+".local",
	).Scan(&domID); err != nil {
		t.Skipf("could not seed domain (schema not loaded?): %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, domID) })

	email := "govseamsan-" + uniq + "@govseam.test"
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash, enabled, is_admin)
		 VALUES ($1, $2, $3, 'Gov Seam SAN', '', TRUE, TRUE) RETURNING id`,
		"govseamsan-"+uniq, domID, email,
	).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID) })

	// Flagged but ungoverned, reached through the email-SAN arm (no CN hit:
	// the CN candidate misses, the SAN resolves the row).
	u, err := lookupByCertSubject(ctx, pool, "no-such-cn-"+uniq, []string{email})
	if err != nil {
		t.Fatalf("cert lookup (email SAN): %v", err)
	}
	if u.IsAdmin {
		t.Fatal("cert seam email-SAN arm: legacy is_admin flag alone surfaced as admin")
	}
	if u.Email != email {
		t.Fatalf("cert lookup resolved %q, want the SAN %q", u.Email, email)
	}
}
