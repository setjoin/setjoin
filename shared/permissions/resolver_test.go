package permissions

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
)

// These tests require a loaded mailserver_test database (it carries the RBAC
// tables admin_role_groups / admin_role_assignments from migration V057). They
// are skipped when DB_DSN is unset so the package still builds/tests in a
// DB-less environment.
//
//	DB_DSN=postgres://mail@127.0.0.1:5432/mailserver_test?sslmode=disable go test ./permissions/...

func testPool(t *testing.T) *pgxpool.Pool {
	return testsupport.OpenTestPool(t)
}

func closedResolverPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(
		context.Background(),
		"postgres://setjoin-test:unused@127.0.0.1:1/setjoin?connect_timeout=1",
	)
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	return pool
}

func TestResolveAuthorityNilAndUnavailableStores(t *testing.T) {
	authority, err := ResolveAuthority(context.Background(), nil, 42)
	if err != nil || len(authority.Permissions) != 0 ||
		len(authority.GlobalPermissions) != 0 || authority.DomainScope != nil {
		t.Fatalf("nil store result=(%+v,%v), want empty authority", authority, err)
	}
	closed := closedResolverPool(t)
	if _, err := ResolveAuthority(context.Background(), closed, 42); err == nil {
		t.Fatal("closed authority store unexpectedly succeeded")
	}
	if _, _, err := Resolve(context.Background(), closed, 42); err == nil {
		t.Fatal("Resolve swallowed authority-store failure")
	}
}

// mintedScope returns the scope authserver STAMPS into the JWT. It is NO LONGER
// a hand-copied SQL twin: it delegates to permissions.MintDomainScope, the exact
// function authserver's issueTokensWithFactors now calls to mint. So this is the
// issuer's real code path, not a faithful-but-fictional copy of it.
//
// The twin is GONE (single-source: shared/permissions.MintDomainScope). That
// closes the fail-open bug this helper used to carry: when mint and enforce were
// two hand-copied queries, dropping the expires_at filter from one and not the
// other left the scope-agreement test comparing Resolve against a FICTIONAL mint
// query — green while mint and enforce actually disagreed (scope-broadening). A
// previous revision dropped that filter from auth.go but left it here, masking
// exactly that bug. Now both sides execute MintDomainScope, so the mutation is
// observable: deleting the expires_at clause inside MintDomainScope turns BOTH
// TestResolve_ScopeAgreesWithIssuance and TestMintDomainScope_HonorsExpiry red.
func mintedScope(t *testing.T, pool *pgxpool.Pool, userID int64) *int64 {
	t.Helper()
	scope, err := MintDomainScope(context.Background(), pool, userID)
	if err != nil {
		t.Fatalf("minted-scope query: %v", err)
	}
	return scope
}

// scopeFixture builds a multi-role admin with:
//   - two live (non-expired) role-group assignments, exercising the multi-role
//     union of permissions;
//   - a per-assignment domain_override on the live assignment whose role group
//     is otherwise global — the override is the narrowest LIVE scope;
//   - an EXPIRED assignment carrying an even narrower override that MUST be
//     ignored (it would win if expires_at were not honored).
//
// It returns the user id plus the three domain ids (broad, narrow-live,
// narrower-expired) so assertions can name the expected winner.
type scopeFixture struct {
	userID          int64
	domainBroad     int64 // role-group domain_scope on the second live role
	domainNarrowLiv int64 // domain_override on a live assignment (expected winner)
	domainExpired   int64 // domain_override on the EXPIRED assignment (must be ignored)
}

func setupScopeFixture(t *testing.T, pool *pgxpool.Pool) scopeFixture {
	t.Helper()
	ctx := context.Background()
	tag := time.Now().UnixNano()

	mkDomain := func(label string) int64 {
		var id int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`,
			fmt.Sprintf("perm-scope-%s-%d.example", label, tag),
		).Scan(&id); err != nil {
			t.Fatalf("insert domain %s: %v", label, err)
		}
		return id
	}
	// homeDom hosts the user; the three scoping domains are separate so the
	// "narrowest id" is well-defined and independent of the user's home domain.
	homeDom := mkDomain("home")
	var f scopeFixture
	// Create the EXPIRED override's domain FIRST so it gets the SMALLEST id.
	// Then if expires_at were not honored, the expired override would win the
	// MIN — so the assertion below genuinely proves expiry is respected.
	f.domainExpired = mkDomain("expired")
	f.domainBroad = mkDomain("broad")
	f.domainNarrowLiv = mkDomain("narrow-live")

	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name)
		 VALUES ($1, $2, $1 || '@home.example', $1) RETURNING id`,
		fmt.Sprintf("perm-scope-admin-%d", tag), homeDom,
	).Scan(&f.userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	// Three role groups: one global-scoped (override will narrow it on the live
	// assignment), one domain-scoped to the broad domain, one global (its
	// override lives on the EXPIRED assignment).
	mkRole := func(label string, perms []string, domainScope *int64) int64 {
		var id int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO admin_role_groups (name, permissions, domain_scope)
			 VALUES ($1, $2, $3) RETURNING id`,
			fmt.Sprintf("perm-scope-role-%s-%d", label, tag), perms, domainScope,
		).Scan(&id); err != nil {
			t.Fatalf("insert role %s: %v", label, err)
		}
		return id
	}
	roleGlobalA := mkRole("globalA", []string{PermUsersRead, PermUsersCreate}, nil)
	roleBroad := mkRole("broad", []string{PermQueueRead}, &f.domainBroad)
	roleGlobalExpired := mkRole("globalExpired", []string{PermAuditRead}, nil)

	mkAssign := func(roleID int64, override *int64, expiresAt *time.Time) {
		if _, err := pool.Exec(ctx,
			`INSERT INTO admin_role_assignments
			   (user_id, role_group_id, domain_override, granted_by, expires_at)
			 VALUES ($1, $2, $3, $1, $4)`,
			f.userID, roleID, override, expiresAt,
		); err != nil {
			t.Fatalf("insert assignment role=%d: %v", roleID, err)
		}
	}
	// Live: global role narrowed by an override to the narrow-live domain.
	mkAssign(roleGlobalA, &f.domainNarrowLiv, nil)
	// Live: domain-scoped role, no override (effective = broad domain).
	mkAssign(roleBroad, nil, nil)
	// EXPIRED: global role with an even-narrower override — must be ignored.
	past := time.Now().Add(-time.Hour)
	mkAssign(roleGlobalExpired, &f.domainExpired, &past)

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM admin_role_assignments WHERE user_id = $1`, f.userID)
		_, _ = pool.Exec(ctx, `DELETE FROM admin_role_groups WHERE name LIKE $1`,
			fmt.Sprintf("perm-scope-role-%%-%d", tag))
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, f.userID)
		_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id = ANY($1)`,
			[]int64{homeDom, f.domainBroad, f.domainNarrowLiv, f.domainExpired})
	})
	return f
}

// TestResolve_ScopeAgreesWithIssuance is the seam's load-bearing guarantee:
// mailserver's enforced Resolve(userID) scope must equal authserver's minted
// MIN(COALESCE(domain_override, domain_scope)) scope on a multi-role +
// domain_override + expired-assignment fixture. Before the resolver collapse
// these were two different queries that could disagree; this pins them.
func TestResolve_ScopeAgreesWithIssuance(t *testing.T) {
	pool := testPool(t)
	f := setupScopeFixture(t, pool)
	ctx := context.Background()

	perms, scope, err := Resolve(ctx, pool, f.userID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// Multi-role union: both LIVE roles' permissions present; the EXPIRED role's
	// permission (audit.read) absent.
	if !HasPermission(perms, PermUsersRead) || !HasPermission(perms, PermQueueRead) {
		t.Errorf("expected union of live roles to include users.read + queue.read, got %v", perms)
	}
	if HasPermission(perms, PermAuditRead) {
		t.Errorf("expired assignment's permission (audit.read) leaked into the resolved set: %v", perms)
	}

	// Scope agreement: Resolve == authserver's minted scope.
	minted := mintedScope(t, pool, f.userID)
	switch {
	case scope == nil && minted == nil:
		t.Fatalf("both nil, but fixture has scoped roles — expected the narrow-live override to win")
	case scope == nil || minted == nil:
		t.Fatalf("scope disagreement: Resolve=%v minted=%v", scope, minted)
	case *scope != *minted:
		t.Fatalf("scope disagreement: Resolve=%d minted=%d", *scope, *minted)
	}

	// The winner is the narrowest (smallest id) LIVE scope — the MIN of the
	// narrow-live override and the broad role's domain_scope — and is NEVER the
	// expired override, proving expires_at is honored identically on both sides.
	// (Domain ids are insertion-ordered, so we compute the expected MIN rather
	// than hardcode which live scope is smaller.)
	expectedWinner := f.domainNarrowLiv
	if f.domainBroad < expectedWinner {
		expectedWinner = f.domainBroad
	}
	if *scope != expectedWinner {
		t.Fatalf("expected narrowest LIVE scope %d (min of narrow-live=%d, broad=%d), got %d (expired override was %d)",
			expectedWinner, f.domainNarrowLiv, f.domainBroad, *scope, f.domainExpired)
	}
	if *scope == f.domainExpired {
		t.Fatalf("expired override %d won — expires_at not honored", f.domainExpired)
	}
}

func TestResolveAuthority_GlobalPermissionsExcludeNarrowedAssignments(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tag := time.Now().UnixNano()

	var domainID, userID, departmentID, scopeSetID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains(name,is_local) VALUES($1,TRUE) RETURNING id`,
		fmt.Sprintf("global-authority-%d.example", tag),
	).Scan(&domainID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO departments(name,path,ldap_ou) VALUES($1,$1,$1) RETURNING id`,
		fmt.Sprintf("global-authority-ou-%d", tag),
	).Scan(&departmentID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO admin_scope_sets(name,domain_id) VALUES($1,$2) RETURNING id`,
		fmt.Sprintf("global-authority-set-%d", tag), domainID,
	).Scan(&scopeSetID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO users(username,domain_id,email,display_name)
		 VALUES($1,$2,$1||'@global-authority.example',$1) RETURNING id`,
		fmt.Sprintf("global-authority-%d", tag), domainID,
	).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM admin_role_assignments WHERE user_id=$1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM admin_role_groups WHERE name LIKE $1`,
			fmt.Sprintf("global-authority-role-%%-%d", tag))
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM admin_scope_sets WHERE id=$1`, scopeSetID)
		_, _ = pool.Exec(ctx, `DELETE FROM departments WHERE id=$1`, departmentID)
		_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id=$1`, domainID)
	})

	type grant struct {
		label      string
		permission string
		domain     *int64
		scopeType  *string
		scopeID    *int64
	}
	ou, set := "ou", "set"
	grants := []grant{
		{label: "global", permission: PermIdentityWrite},
		{label: "domain", permission: PermUsersRead, domain: &domainID},
		{label: "ou", permission: PermAuditExport, scopeType: &ou, scopeID: &departmentID},
		{label: "set", permission: PermSystemUpgrade, scopeType: &set, scopeID: &scopeSetID},
	}
	for _, g := range grants {
		var roleID int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO admin_role_groups(name,permissions,domain_scope)
			 VALUES($1,ARRAY[$2]::text[],$3) RETURNING id`,
			fmt.Sprintf("global-authority-role-%s-%d", g.label, tag), g.permission, g.domain,
		).Scan(&roleID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO admin_role_assignments(
			   user_id,role_group_id,granted_by,scope_type,scope_id
			 ) VALUES($1,$2,$1,$3,$4)`,
			userID, roleID, g.scopeType, g.scopeID,
		); err != nil {
			t.Fatal(err)
		}
	}

	authority, err := ResolveAuthority(ctx, pool, userID)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range grants {
		if !HasPermission(authority.Permissions, g.permission) {
			t.Fatalf("effective permission %q missing from %+v", g.permission, authority)
		}
	}
	if !HasPermission(authority.GlobalPermissions, PermIdentityWrite) {
		t.Fatalf("global identity.write missing from %+v", authority.GlobalPermissions)
	}
	for _, narrowed := range []string{PermUsersRead, PermAuditExport, PermSystemUpgrade} {
		if HasPermission(authority.GlobalPermissions, narrowed) {
			t.Fatalf("narrowed permission %q leaked into global authority: %+v",
				narrowed, authority.GlobalPermissions)
		}
	}
}

// TestAdminEffectiveAuthority_PermsMatchResolve is the PERMS-only drift cross-
// check between the SQL helper admin_effective_authority() and Go Resolve().
//
// For every row in admin_role_groups it builds a fresh user with exactly that
// role assignment (live, no expiry), then asserts:
//
//	admin_effective_authority(userID).perms  ==  Resolve(userID).perms  (as sets)
//
// The SCOPE is NOT compared here: the two definitions deliberately diverge.
// admin_effective_authority uses broadest-reach (global/NULL wins);
// Resolve uses narrowest-non-NULL-wins. The brief calls for perms-only.
func TestAdminEffectiveAuthority_PermsMatchResolve(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	// Enumerate every seeded admin_role_groups row. Don't hand-pick — any new
	// seed added later is automatically covered.
	type roleRow struct {
		id          int64
		name        string
		permissions []string
	}
	rows, err := pool.Query(ctx,
		`SELECT id, name, permissions FROM admin_role_groups ORDER BY id`,
	)
	if err != nil {
		t.Fatalf("enumerate admin_role_groups: %v", err)
	}
	defer rows.Close()

	var roles []roleRow
	for rows.Next() {
		var r roleRow
		if err := rows.Scan(&r.id, &r.name, &r.permissions); err != nil {
			t.Fatalf("scan admin_role_groups row: %v", err)
		}
		roles = append(roles, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("admin_role_groups rows: %v", err)
	}
	if len(roles) == 0 {
		t.Skip("no admin_role_groups rows — DB may not be seeded; skipping cross-check")
	}

	tag := time.Now().UnixNano()
	// Shared home domain for all fixture users.
	var homeDomID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`,
		fmt.Sprintf("aea-drift-%d.example", tag),
	).Scan(&homeDomID); err != nil {
		t.Fatalf("insert home domain: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, homeDomID)
	})

	for _, role := range roles {
		role := role
		t.Run(role.name, func(t *testing.T) {
			// Create a user with exactly this one role assignment.
			var userID int64
			if err := pool.QueryRow(ctx,
				`INSERT INTO users (username, domain_id, email, display_name)
				 VALUES ($1, $2, $1 || '@aea-drift.example', $1) RETURNING id`,
				fmt.Sprintf("aea-drift-%d-%d", role.id, tag), homeDomID,
			).Scan(&userID); err != nil {
				t.Fatalf("insert user for role %s: %v", role.name, err)
			}
			t.Cleanup(func() {
				if role.id == 1 {
					// This fixture can be the database's only Super Admin. The
					// production last-admin trigger must remain enabled during
					// the assertion, but test teardown must not leak the row into
					// later packages. Bypass triggers only in this cleanup
					// transaction and on this connection.
					tx, err := pool.Begin(context.Background())
					if err != nil {
						t.Errorf("begin Super Admin fixture cleanup: %v", err)
						return
					}
					defer tx.Rollback(context.Background()) //nolint:errcheck
					if _, err := tx.Exec(context.Background(),
						`SET LOCAL session_replication_role = replica`); err != nil {
						t.Errorf("disable triggers for Super Admin fixture cleanup: %v", err)
						return
					}
					if _, err := tx.Exec(context.Background(),
						`DELETE FROM admin_role_assignments WHERE user_id = $1`, userID); err != nil {
						t.Errorf("delete Super Admin fixture assignment: %v", err)
						return
					}
					if _, err := tx.Exec(context.Background(),
						`DELETE FROM users WHERE id = $1`, userID); err != nil {
						t.Errorf("delete Super Admin fixture user: %v", err)
						return
					}
					if err := tx.Commit(context.Background()); err != nil {
						t.Errorf("commit Super Admin fixture cleanup: %v", err)
					}
					return
				}
				_, _ = pool.Exec(ctx, `DELETE FROM admin_role_assignments WHERE user_id = $1`, userID)
				_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
			})

			if _, err := pool.Exec(ctx,
				`INSERT INTO admin_role_assignments
				   (user_id, role_group_id, granted_by, expires_at)
				 VALUES ($1, $2, $1, NULL)`,
				userID, role.id,
			); err != nil {
				t.Fatalf("insert assignment role=%s: %v", role.name, err)
			}

			// SQL side: admin_effective_authority().perms
			var sqlPerms []string
			if err := pool.QueryRow(ctx,
				`SELECT (admin_effective_authority($1)).perms`, userID,
			).Scan(&sqlPerms); err != nil {
				t.Fatalf("admin_effective_authority(%d): %v", userID, err)
			}

			// Go side: Resolve().perms
			goPerms, _, err := Resolve(ctx, pool, userID)
			if err != nil {
				t.Fatalf("Resolve(%d): %v", userID, err)
			}

			// Compare as sets (order may differ).
			toSet := func(perms []string) map[string]bool {
				s := make(map[string]bool, len(perms))
				for _, p := range perms {
					s[p] = true
				}
				return s
			}
			sqlSet := toSet(sqlPerms)
			goSet := toSet(goPerms)

			for p := range sqlSet {
				if !goSet[p] {
					t.Errorf("role=%s perm %q in SQL but not in Go Resolve", role.name, p)
				}
			}
			for p := range goSet {
				if !sqlSet[p] {
					t.Errorf("role=%s perm %q in Go Resolve but not in SQL", role.name, p)
				}
			}
		})
	}
}

// TestResolve_JIT_DormantEligible_NoMint verifies the JIT gate in the Go
// resolver: an eligible assignment with no active window is dormant — it must
// NOT mint permissions while the rbac.jit toggle is ON, and MUST mint when the
// toggle is OFF (inert) or when an activation window is open.
func TestResolve_JIT_DormantEligible_NoMint(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tag := time.Now().UnixNano()

	// Home domain for the fixture user.
	var homeDomID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`,
		fmt.Sprintf("jit-test-%d.example", tag),
	).Scan(&homeDomID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name)
		 VALUES ($1, $2, $1 || '@jit-test.example', $1) RETURNING id`,
		fmt.Sprintf("jit-test-%d", tag), homeDomID,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	var roleID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO admin_role_groups (name, permissions, domain_scope)
		 VALUES ($1, $2, NULL) RETURNING id`,
		fmt.Sprintf("jit-test-role-%d", tag), []string{PermUsersRead},
	).Scan(&roleID); err != nil {
		t.Fatalf("insert role: %v", err)
	}

	// Seed ONE eligible assignment (dormant: eligible=true, activated_until=NULL).
	var assignID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO admin_role_assignments
		   (user_id, role_group_id, granted_by, eligible, activated_until)
		 VALUES ($1, $2, $1, true, NULL) RETURNING id`,
		userID, roleID,
	).Scan(&assignID); err != nil {
		t.Fatalf("insert assignment: %v", err)
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM admin_role_assignments WHERE id = $1`, assignID)
		_, _ = pool.Exec(ctx, `DELETE FROM admin_role_groups WHERE id = $1`, roleID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, homeDomID)
		// Restore toggle to OFF so other tests are unaffected.
		_, _ = pool.Exec(ctx, `UPDATE feature_toggles SET enabled=false WHERE key='rbac.jit'`)
	})

	// 1. Toggle OFF (default): dormant-eligible assignment is inert → mints perms.
	perms, _, err := Resolve(ctx, pool, userID)
	if err != nil {
		t.Fatalf("Resolve (toggle off): %v", err)
	}
	if !HasPermission(perms, PermUsersRead) {
		t.Errorf("toggle off: expected users.read minted (inert), got %v", perms)
	}

	// 2. Toggle ON: dormant-eligible assignment → NOT active → no perms.
	if _, err := pool.Exec(ctx, `UPDATE feature_toggles SET enabled=true WHERE key='rbac.jit'`); err != nil {
		t.Fatalf("enable rbac.jit: %v", err)
	}
	perms, _, err = Resolve(ctx, pool, userID)
	if err != nil {
		t.Fatalf("Resolve (toggle on, dormant): %v", err)
	}
	if HasPermission(perms, PermUsersRead) {
		t.Errorf("toggle on + dormant: expected no perms minted, got %v", perms)
	}

	// 3. Toggle ON + open activation window → active → mints perms.
	if _, err := pool.Exec(ctx,
		`UPDATE admin_role_assignments SET activated_until = now() + interval '1 hour' WHERE id = $1`,
		assignID,
	); err != nil {
		t.Fatalf("set activation window: %v", err)
	}
	perms, _, err = Resolve(ctx, pool, userID)
	if err != nil {
		t.Fatalf("Resolve (toggle on, activated): %v", err)
	}
	if !HasPermission(perms, PermUsersRead) {
		t.Errorf("toggle on + active window: expected users.read minted, got %v", perms)
	}
}

// TestMintDomainScope_HonorsExpiry pins the MINT rule directly (not only via the
// agreement test): authserver's issuance-time scope must DROP the expired
// narrowing override. The fixture's expired override carries the SMALLEST domain
// id, so it WOULD win the MIN if the expires_at clause inside MintDomainScope
// were absent. Asserting the live narrow scope wins proves the clause is present
// and load-bearing — and deleting that clause turns this test red, which is the
// load-bearing proof the seam is real.
func TestMintDomainScope_HonorsExpiry(t *testing.T) {
	pool := testPool(t)
	f := setupScopeFixture(t, pool)
	ctx := context.Background()

	scope, err := MintDomainScope(ctx, pool, f.userID)
	if err != nil {
		t.Fatalf("MintDomainScope: %v", err)
	}
	if scope == nil {
		t.Fatalf("expected a scoped mint (fixture has a live narrowing override), got nil/global")
	}

	// The minted winner is the narrowest (smallest id) LIVE scope — the MIN of
	// the narrow-live override and the broad role's domain_scope — and is NEVER
	// the smaller-id EXPIRED override, which the expires_at filter must exclude.
	expectedWinner := f.domainNarrowLiv
	if f.domainBroad < expectedWinner {
		expectedWinner = f.domainBroad
	}
	if *scope != expectedWinner {
		t.Fatalf("minted scope = %d, want narrowest LIVE scope %d (min of narrow-live=%d, broad=%d); expired override was %d",
			*scope, expectedWinner, f.domainNarrowLiv, f.domainBroad, f.domainExpired)
	}
	if *scope == f.domainExpired {
		t.Fatalf("minted the EXPIRED override %d — MintDomainScope dropped its expires_at filter", f.domainExpired)
	}
}
