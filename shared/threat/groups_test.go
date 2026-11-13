package threat

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestResolveUserGroupsAndRoles(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set — skipping integration test (set to postgres://mail@127.0.0.1:5432/mailserver_test_ca?sslmode=disable)")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()
	ctx := context.Background()

	// Pre-clean any leftovers from a prior run (crash, shared DB, re-run without cleanup).
	// Delete dependents first; domain last. Idempotent — safe even on a pristine DB.
	cleanFixtures := func() {
		_, _ = pool.Exec(ctx,
			`DELETE FROM admin_role_assignments
			 WHERE role_group_id IN (SELECT id FROM admin_role_groups WHERE name='test-role-group-resolver')`)
		_, _ = pool.Exec(ctx, `DELETE FROM admin_role_groups WHERE name='test-role-group-resolver'`)
		_, _ = pool.Exec(ctx,
			`DELETE FROM user_group_members
			 WHERE user_id IN (SELECT id FROM users WHERE email='grp-resolver@groups-test.example')`)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE email='grp-resolver@groups-test.example'`)
		_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE name='groups-test.example'`)
	}
	cleanFixtures()
	t.Cleanup(cleanFixtures)

	// Provision an isolated domain + user (user_group_members FKs users(id)).
	var domainID, uid int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ('groups-test.example') RETURNING id`).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name)
		 VALUES ('grp-resolver', $1, 'grp-resolver@groups-test.example', 'Grp Resolver') RETURNING id`,
		domainID).Scan(&uid); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	// Seed a group membership (group 42 is a synthetic ID with no FK — user_group_members.group_id
	// has no FK constraint to a groups table, it's a bare bigint).
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_group_members (user_id, group_id) VALUES ($1, 42)`, uid); err != nil {
		t.Fatalf("insert user_group_members: %v", err)
	}

	// ResolveUserGroups must return [42].
	groups := ResolveUserGroups(ctx, pool, uid)
	if len(groups) != 1 || groups[0] != 42 {
		t.Fatalf("ResolveUserGroups want [42], got %v", groups)
	}

	// No role assignment → empty (not nil-panic).
	if r := ResolveRoleGroups(ctx, pool, uid); len(r) != 0 {
		t.Fatalf("ResolveRoleGroups want empty, got %v", r)
	}

	// Seed an admin_role_groups row and an assignment.
	var rgID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO admin_role_groups (name) VALUES ('test-role-group-resolver') RETURNING id`).Scan(&rgID); err != nil {
		t.Fatalf("insert admin_role_groups: %v", err)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id) VALUES ($1, $2)`, uid, rgID); err != nil {
		t.Fatalf("insert admin_role_assignments: %v", err)
	}

	// ResolveRoleGroups must return [rgID] (unexpired, no expires_at).
	rgs := ResolveRoleGroups(ctx, pool, uid)
	if len(rgs) != 1 || rgs[0] != rgID {
		t.Fatalf("ResolveRoleGroups want [%d], got %v", rgID, rgs)
	}

	// Cross-user guard: another user ID must not receive these results.
	if g := ResolveUserGroups(ctx, pool, uid+99999); len(g) != 0 {
		t.Fatalf("ResolveUserGroups scoping fail: got results for non-existent user: %v", g)
	}
	if r := ResolveRoleGroups(ctx, pool, uid+99999); len(r) != 0 {
		t.Fatalf("ResolveRoleGroups scoping fail: got results for non-existent user: %v", r)
	}
}
