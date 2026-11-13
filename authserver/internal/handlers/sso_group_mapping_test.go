package handlers

// Task 4: SSO group-mapping writes governed admin_role_assignments rows.
//
// Tests are DB-backed (skipped when DB_DSN is unset).  They verify:
//   - Each known AdminRole enum value upserts the correct builtin group row
//     (super_admin→1, user_admin→2, auditor→4, read_only→8) with NULL granted_by.
//   - No write is made to users.admin_role.
//   - Under SoD-ON a cross-class mapping raises BZ001, which is caught +
//     logged (Warn) and does NOT roll back other mappings in the same call.
//   - upsertSSOAdminAssignment happy path: row created with NULL granted_by.
//   - upsertSSOAdminAssignment FK error path: logged at Warn, loop continues.

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/authserver/internal/federation"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/testsupport"
)

// ── helpers ───────────────────────────────────────────────────────────────────

type staticMapper struct {
	providerKey string
	mappings    []federation.GroupMapping
}

func (m *staticMapper) GetGroupMappings() []federation.GroupMapping { return m.mappings }
func (m *staticMapper) SSOProviderKey() string {
	if m.providerKey == "" {
		return "test:default"
	}
	return m.providerKey
}

func strPtr(s string) *string { return &s }

func TestApplyGroupMappingsRefusesUnboundedWorkBeforeDatabaseAccess(t *testing.T) {
	h := &deps{logger: discardLogger()}
	h.applyGroupMappings(
		context.Background(),
		1,
		make([]string, identity.MaxSSOGroupClaims+1),
		&staticMapper{
			providerKey: "oidc:bounded",
			mappings:    []federation.GroupMapping{{IDPGroup: "Engineering"}},
		},
	)

	mappings := make([]federation.GroupMapping, identity.MaxSSOGroupMappings+1)
	for i := range mappings {
		mappings[i].IDPGroup = "Engineering"
	}
	h.applyGroupMappings(
		context.Background(),
		1,
		[]string{"Engineering"},
		&staticMapper{providerKey: "oidc:bounded", mappings: mappings},
	)
	h.applyGroupMappings(
		context.Background(),
		1,
		[]string{"Engineering"},
		&staticMapper{
			providerKey: "\n",
			mappings:    []federation.GroupMapping{{IDPGroup: "Engineering"}},
		},
	)
}

// seedSSOTestActorDB inserts a user + primary mailbox into the test DB and
// returns the user ID.  The test is skipped (not failed) on any schema mismatch.
// Callers must call cleanSSOActor in a defer to remove the rows.
func seedSSOTestActorDB(t *testing.T, pool *pgxpool.Pool, ctx context.Context, tag string) int64 {
	t.Helper()
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, sync_source, enabled, is_admin)
		 SELECT $1||'-'||floor(random()*1e9)::text,
		        $1||'-'||floor(random()*1e9)::text||'@sso-test.internal',
		        'SSO Test '||$1,
		        d.id, 'sso', TRUE, FALSE
		 FROM domains d WHERE d.is_local = TRUE ORDER BY d.id LIMIT 1
		 RETURNING id`,
		tag,
	).Scan(&userID); err != nil {
		t.Skipf("seed user (%s) failed (schema not loaded?): %v", tag, err)
	}

	// Seed primary mailbox (needs domain_id from the user row).
	var mboxID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		 SELECT u.id, u.domain_id, u.email, u.display_name, 'personal', TRUE
		 FROM users u WHERE u.id = $1
		 RETURNING id`,
		userID,
	).Scan(&mboxID); err != nil {
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		t.Skipf("seed mailbox (%s) failed: %v", tag, err)
	}
	return userID
}

// cleanSSOActor removes the test actor's admin_role_assignments, mailbox, and user row.
// Bypasses trg_protect_last_super_admin (BZ064) by expiring role-1 rows first,
// and trg_mailbox_primary_enforce (BZ013) by clearing is_primary + user_id before
// deleting the mailbox rows.  See cleanSSOActorSweep in auth_sso_sweep_test.go
// for the trigger analysis.
func cleanSSOActor(t *testing.T, pool *pgxpool.Pool, ctx context.Context, userID int64) {
	t.Helper()

	rows, _ := pool.Query(ctx, `SELECT id FROM mailboxes WHERE user_id = $1`, userID)
	var mbIDs []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			mbIDs = append(mbIDs, id)
		}
	}
	rows.Close()

	pool.Exec(ctx, `UPDATE admin_role_assignments SET expires_at = now() - interval '1 second'
		WHERE user_id = $1 AND role_group_id = 1`, userID)
	pool.Exec(ctx, `DELETE FROM admin_role_assignments WHERE user_id = $1`, userID)
	pool.Exec(ctx, `UPDATE mailboxes SET is_primary = FALSE, user_id = NULL WHERE user_id = $1`, userID)
	for _, mbID := range mbIDs {
		pool.Exec(ctx, `DELETE FROM mailboxes WHERE id = $1`, mbID)
	}
	pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
}

func seedSSODistributionGroup(t *testing.T, pool *pgxpool.Pool, ctx context.Context, tag string) int64 {
	t.Helper()

	var mailboxID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO mailboxes (domain_id, email, display_name, type, is_primary)
		 SELECT d.id,
		        $1||'-'||floor(random()*1e9)::text||'@sso-test.internal',
		        'SSO Group '||$1,
		        'personal',
		        FALSE
		   FROM domains d
		  WHERE d.is_local = TRUE
		  ORDER BY d.id
		  LIMIT 1
		 RETURNING id`,
		tag,
	).Scan(&mailboxID); err != nil {
		t.Skipf("seed distribution-group mailbox (%s) failed: %v", tag, err)
	}

	var groupID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO distribution_groups (mailbox_id) VALUES ($1) RETURNING id`,
		mailboxID,
	).Scan(&groupID); err != nil {
		pool.Exec(ctx, `DELETE FROM mailboxes WHERE id = $1`, mailboxID)
		t.Skipf("seed distribution group (%s) failed: %v", tag, err)
	}

	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM distribution_group_members WHERE group_id = $1`, groupID)
		pool.Exec(context.Background(), `DELETE FROM distribution_groups WHERE id = $1`, groupID)
		pool.Exec(context.Background(), `DELETE FROM mailboxes WHERE id = $1`, mailboxID)
	})
	return groupID
}

func seedSSOAdminAssignmentForProvider(
	t *testing.T,
	pool *pgxpool.Pool,
	ctx context.Context,
	userID, groupID int64,
	providerKey string,
) int64 {
	t.Helper()

	var assignmentID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, $2, NULL)
		 RETURNING id`,
		userID, groupID,
	).Scan(&assignmentID); err != nil {
		t.Fatalf("seed prior SSO admin grant: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO sso_admin_role_provenance (provider_key, assignment_id)
		 VALUES ($1, $2)`,
		providerKey, assignmentID,
	); err != nil {
		t.Fatalf("seed prior SSO admin provenance: %v", err)
	}
	return assignmentID
}

func TestApplyGroupMappings_DistinctProvidersDoNotDeleteEachOthersMemberships(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID := seedSSOTestActorDB(t, pool, ctx, "sso-provider-isolation")
	defer cleanSSOActor(t, pool, ctx, userID)
	groupA := seedSSODistributionGroup(t, pool, ctx, "sso-provider-a")
	groupB := seedSSODistributionGroup(t, pool, ctx, "sso-provider-b")

	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
	h.applyGroupMappings(ctx, userID, []string{"a-members"}, &staticMapper{
		providerKey: "oidc:provider-a",
		mappings: []federation.GroupMapping{{
			IDPGroup:            "a-members",
			DistributionGroupID: &groupA,
		}},
	})
	h.applyGroupMappings(ctx, userID, []string{"b-members"}, &staticMapper{
		providerKey: "saml:42",
		mappings: []federation.GroupMapping{{
			IDPGroup:            "b-members",
			DistributionGroupID: &groupB,
		}},
	})

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*)
		   FROM distribution_group_members dgm
		   JOIN mailboxes mb ON mb.id = dgm.mailbox_id
		  WHERE mb.user_id = $1
		    AND dgm.group_id = ANY($2::bigint[])`,
		userID, []int64{groupA, groupB},
	).Scan(&count); err != nil {
		t.Fatalf("query provider-scoped memberships: %v", err)
	}
	if count != 2 {
		t.Fatalf("provider B login deleted provider A membership: want 2 effective memberships, got %d", count)
	}
}

func TestApplyGroupMappings_SharedMembershipSurvivesOneProviderRevocation(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID := seedSSOTestActorDB(t, pool, ctx, "sso-shared-provider")
	defer cleanSSOActor(t, pool, ctx, userID)
	groupID := seedSSODistributionGroup(t, pool, ctx, "sso-shared-group")
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	mapperA := &staticMapper{
		providerKey: "oidc:provider-a",
		mappings: []federation.GroupMapping{{
			IDPGroup:            "shared-members",
			DistributionGroupID: &groupID,
		}},
	}
	mapperB := &staticMapper{
		providerKey: "saml:42",
		mappings: []federation.GroupMapping{{
			IDPGroup:            "shared-members",
			DistributionGroupID: &groupID,
		}},
	}
	h.applyGroupMappings(ctx, userID, []string{"shared-members"}, mapperA)
	h.applyGroupMappings(ctx, userID, []string{"shared-members"}, mapperB)
	h.applyGroupMappings(ctx, userID, []string{"unrelated-group"}, mapperA)

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*)
		   FROM distribution_group_members dgm
		   JOIN mailboxes mb ON mb.id = dgm.mailbox_id
		  WHERE mb.user_id = $1 AND dgm.group_id = $2`,
		userID, groupID,
	).Scan(&count); err != nil {
		t.Fatalf("query shared effective membership: %v", err)
	}
	if count != 1 {
		t.Fatalf("provider A revocation deleted provider B's shared membership: want 1, got %d", count)
	}
}

func TestApplyGroupMappings_SharedAdminRoleSurvivesOneProviderRevocation(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID := seedSSOTestActorDB(t, pool, ctx, "sso-shared-admin-role")
	defer cleanSSOActor(t, pool, ctx, userID)
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	mapperA := &staticMapper{
		providerKey: "oidc:provider-a",
		mappings: []federation.GroupMapping{{
			IDPGroup:  "shared-admins",
			AdminRole: strPtr("user_admin"),
		}},
	}
	mapperB := &staticMapper{
		providerKey: "saml:42",
		mappings: []federation.GroupMapping{{
			IDPGroup:  "shared-admins",
			AdminRole: strPtr("user_admin"),
		}},
	}
	h.applyGroupMappings(ctx, userID, []string{"shared-admins"}, mapperA)
	h.applyGroupMappings(ctx, userID, []string{"shared-admins"}, mapperB)
	h.applyGroupMappings(ctx, userID, []string{"unrelated-group"}, mapperA)

	var effective, providerB int
	if err := pool.QueryRow(ctx,
		`SELECT count(*),
		        count(*) FILTER (
		            WHERE EXISTS (
		                SELECT 1
		                  FROM sso_admin_role_provenance p
		                 WHERE p.assignment_id = ara.id
		                   AND p.provider_key = 'saml:42'
		            )
		        )
		   FROM admin_role_assignments ara
		  WHERE ara.user_id = $1
		    AND ara.role_group_id = 2
		    AND ara.granted_by IS NULL`,
		userID,
	).Scan(&effective, &providerB); err != nil {
		t.Fatalf("query shared admin role: %v", err)
	}
	if effective != 1 || providerB != 1 {
		t.Fatalf(
			"provider A revocation removed provider B admin role: effective=%d provider_b=%d, want 1/1",
			effective, providerB,
		)
	}
}

func TestApplyGroupMappings_LegacyAmbiguousAdminRoleIsNeverSwept(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID := seedSSOTestActorDB(t, pool, ctx, "sso-legacy-admin-role")
	defer cleanSSOActor(t, pool, ctx, userID)

	var assignmentID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, 2, NULL)
		 RETURNING id`,
		userID,
	).Scan(&assignmentID); err != nil {
		t.Fatalf("seed legacy ambiguous admin role: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO sso_admin_role_legacy_inventory (assignment_id) VALUES ($1)`,
		assignmentID,
	); err != nil {
		t.Fatalf("inventory legacy ambiguous admin role: %v", err)
	}

	mapper := &staticMapper{
		providerKey: "oidc:provider-a",
		mappings: []federation.GroupMapping{{
			IDPGroup:  "legacy-admins",
			AdminRole: strPtr("user_admin"),
		}},
	}
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
	h.applyGroupMappings(ctx, userID, []string{"legacy-admins"}, mapper)
	h.applyGroupMappings(ctx, userID, []string{"unrelated-group"}, mapper)

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments WHERE id = $1`,
		assignmentID,
	).Scan(&count); err != nil {
		t.Fatalf("query legacy ambiguous admin role: %v", err)
	}
	if count != 1 {
		t.Fatalf("provider sweep deleted pre-V153 ambiguous admin role: want 1, got %d", count)
	}
}

func TestApplyGroupMappings_ExplicitEmptyGroupsRevokesProviderGrant(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID := seedSSOTestActorDB(t, pool, ctx, "sso-empty-groups")
	defer cleanSSOActor(t, pool, ctx, userID)
	seedSSOAdminAssignmentForProvider(t, pool, ctx, userID, 2, "oidc:provider-a")

	mapper := &staticMapper{
		providerKey: "oidc:provider-a",
		mappings: []federation.GroupMapping{{
			IDPGroup:  "admins",
			AdminRole: strPtr("user_admin"),
		}},
	}
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
	h.applyGroupMappings(ctx, userID, []string{}, mapper)

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments WHERE user_id = $1 AND role_group_id = 2`,
		userID,
	).Scan(&count); err != nil {
		t.Fatalf("query explicitly empty group reconciliation: %v", err)
	}
	if count != 0 {
		t.Fatalf("explicit empty groups claim retained stale provider grant: want 0, got %d", count)
	}
}

func TestApplyGroupMappings_MissingGroupsClaimDoesNotReconcile(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID := seedSSOTestActorDB(t, pool, ctx, "sso-missing-groups")
	defer cleanSSOActor(t, pool, ctx, userID)
	seedSSOAdminAssignmentForProvider(t, pool, ctx, userID, 2, "oidc:provider-a")

	mapper := &staticMapper{
		providerKey: "oidc:provider-a",
		mappings: []federation.GroupMapping{{
			IDPGroup:  "admins",
			AdminRole: strPtr("user_admin"),
		}},
	}
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
	h.applyGroupMappings(ctx, userID, nil, mapper)

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments WHERE user_id = $1 AND role_group_id = 2`,
		userID,
	).Scan(&count); err != nil {
		t.Fatalf("query missing group-claim behavior: %v", err)
	}
	if count != 1 {
		t.Fatalf("missing groups claim triggered destructive reconciliation: want 1, got %d", count)
	}
}

func TestApplyGroupMappings_StaticGuard_UsesExactProviderProvenance(t *testing.T) {
	src := funcSrc(t, "auth.go", "applyGroupMappings")
	for _, required := range []string{
		"SSOProviderKey",
		"sso_distribution_group_provenance",
		"sso_admin_role_provenance",
	} {
		if !strings.Contains(src, required) {
			t.Errorf("applyGroupMappings must use exact-provider provenance; missing %q", required)
		}
	}
}

// ── RED tests: applyGroupMappings SSO→admin_role_assignments ─────────────────

// TestApplyGroupMappings_SuperAdmin_UpsertsBIRow asserts that a mapping with
// AdminRole="super_admin" writes a row to admin_role_assignments with
// role_group_id=1 (Super Admin builtin) and granted_by IS NULL, and does NOT
// write to users.admin_role.
func TestApplyGroupMappings_SuperAdmin_UpsertsBIRow(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID := seedSSOTestActorDB(t, pool, ctx, "sso-super")
	defer cleanSSOActor(t, pool, ctx, userID)

	mapper := &staticMapper{mappings: []federation.GroupMapping{
		{IDPGroup: "idp-admins", AdminRole: strPtr("super_admin")},
	}}
	// Opt in to super_admin via SSO so this test exercises the upsert (the default
	// refusal is covered by TestApplyGroupMappings_SuperAdminRefusedByDefault).
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger(), SSOAllowSuperAdminMapping: true})
	h.applyGroupMappings(ctx, userID, []string{"idp-admins"}, mapper)

	// Assert: an assignment row exists with role_group_id=1 and NULL granted_by.
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments
		 WHERE user_id = $1 AND role_group_id = 1 AND granted_by IS NULL`,
		userID,
	).Scan(&count); err != nil {
		t.Fatalf("query assignment: %v", err)
	}
	if count != 1 {
		t.Errorf("super_admin mapping: want 1 assignment row (group 1, NULL granted_by), got %d", count)
	}

	// The RBAC cut-over DROPPED users.admin_role, so "SSO must not write the enum"
	// is now structurally guaranteed — there is no column to write. The remaining
	// invariant (the write targets the governed admin_role_assignments table, not
	// the enum) is pinned by TestApplyGroupMappings_NoUsersAdminRoleWrite's static
	// source guard and the assignment-row count asserted above.
}

// TestApplyGroupMappings_UserAdmin_UpsertsBIRow asserts user_admin→group 2.
func TestApplyGroupMappings_UserAdmin_UpsertsBIRow(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID := seedSSOTestActorDB(t, pool, ctx, "sso-ua")
	defer cleanSSOActor(t, pool, ctx, userID)

	mapper := &staticMapper{mappings: []federation.GroupMapping{
		{IDPGroup: "idp-ua", AdminRole: strPtr("user_admin")},
	}}
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
	h.applyGroupMappings(ctx, userID, []string{"idp-ua"}, mapper)

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments
		 WHERE user_id = $1 AND role_group_id = 2 AND granted_by IS NULL`,
		userID,
	).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Errorf("user_admin mapping: want 1 row (group 2, NULL granted_by), got %d", count)
	}
}

// TestApplyGroupMappings_Auditor_UpsertsBIRow asserts auditor→group 4.
func TestApplyGroupMappings_Auditor_UpsertsBIRow(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID := seedSSOTestActorDB(t, pool, ctx, "sso-aud")
	defer cleanSSOActor(t, pool, ctx, userID)

	mapper := &staticMapper{mappings: []federation.GroupMapping{
		{IDPGroup: "idp-aud", AdminRole: strPtr("auditor")},
	}}
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
	h.applyGroupMappings(ctx, userID, []string{"idp-aud"}, mapper)

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments
		 WHERE user_id = $1 AND role_group_id = 4 AND granted_by IS NULL`,
		userID,
	).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Errorf("auditor mapping: want 1 row (group 4, NULL granted_by), got %d", count)
	}
}

// TestApplyGroupMappings_ReadOnly_UpsertsBIRow asserts read_only→group 8.
func TestApplyGroupMappings_ReadOnly_UpsertsBIRow(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID := seedSSOTestActorDB(t, pool, ctx, "sso-ro")
	defer cleanSSOActor(t, pool, ctx, userID)

	mapper := &staticMapper{mappings: []federation.GroupMapping{
		{IDPGroup: "idp-ro", AdminRole: strPtr("read_only")},
	}}
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
	h.applyGroupMappings(ctx, userID, []string{"idp-ro"}, mapper)

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments
		 WHERE user_id = $1 AND role_group_id = 8 AND granted_by IS NULL`,
		userID,
	).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Errorf("read_only mapping: want 1 row (group 8, NULL granted_by), got %d", count)
	}
}

// TestApplyGroupMappings_SoDOn_Rejected_CaughtAndLoginContinues proves that
// under SoD-ON, an SSO admin mapping the SoD trigger rejects (BZ001):
//   - is caught (no panic, no error propagation out of applyGroupMappings),
//   - is logged at Warn level ("SoD partition"),
//   - leaves the rejected assignment UNWRITTEN (the savepoint-free autocommit
//     INSERT rolled back), while login continues.
//
// Post-V018 (sod_exclusion_perm_span, landed by the concurrent SQL agent) the
// SoD trigger ALSO rejects a role whose own permissions span ≥2 exclusive 等保
// classes — Super Admin (group 1) is exactly such a role, closing the prior
// NULL-sod_class escape. So under SoD-ON a super_admin SSO mapping now raises
// BZ001 directly (no seeded cross-class row needed). We opt into super_admin
// (SSOAllowSuperAdminMapping) so the mapping reaches the upsert and the trigger
// is the thing that refuses it — exactly the catch-and-continue path under test.
func TestApplyGroupMappings_SoDOn_Rejected_CaughtAndLoginContinues(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	// Turn SoD ON for this test; restore after.
	if _, err := pool.Exec(ctx,
		`UPDATE feature_toggles SET enabled = TRUE WHERE key = 'dengbao.sod_mode'`); err != nil {
		t.Skipf("could not enable sod_mode toggle: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `UPDATE feature_toggles SET enabled = FALSE WHERE key = 'dengbao.sod_mode'`)
	})

	userID := seedSSOTestActorDB(t, pool, ctx, "sso-sod")
	defer cleanSSOActor(t, pool, ctx, userID)

	// Confirm the trigger rejects a super_admin (group 1) assignment under SoD-ON
	// (V018 perm-span check). If it does not, the dengbao presets / V018 may not be
	// loaded — skip rather than assert pre-V018 behavior.
	_, rawErr := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, 1, NULL)`, userID)
	type sqlStater interface{ SQLState() string }
	if rawErr == nil {
		pool.Exec(ctx, `DELETE FROM admin_role_assignments WHERE user_id = $1`, userID)
		t.Skip("BZ001 was not raised on a Super Admin assignment under SoD-ON — V018 perm-span guard may not be loaded; skipping")
	}
	if pe, ok := rawErr.(sqlStater); !ok || pe.SQLState() != "BZ001" {
		t.Skipf("expected BZ001 from SoD trigger on Super Admin, got: %v", rawErr)
	}

	// Now drive the same rejection THROUGH applyGroupMappings with a log capture.
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mapper := &staticMapper{mappings: []federation.GroupMapping{
		{IDPGroup: "idp-super", AdminRole: strPtr("super_admin")},
	}}
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: logger, SSOAllowSuperAdminMapping: true})
	// Must not panic / must not propagate the BZ001 error:
	h.applyGroupMappings(ctx, userID, []string{"idp-super"}, mapper)

	// The rejected super_admin assignment must NOT have been written.
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments
		 WHERE user_id = $1 AND role_group_id = 1`,
		userID,
	).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Errorf("SoD test: a BZ001-rejected super_admin mapping must NOT be written; got %d group-1 rows", count)
	}
	// The rejection must have been Warn-logged as a SoD partition refusal.
	if !strings.Contains(logBuf.String(), "SoD partition") {
		t.Errorf("expected a Warn about the SoD-partition rejection; got: %s", logBuf.String())
	}
}

// TestUpsertSSOAdminAssignment_HappyPath verifies the extracted helper:
// a valid (userID, groupID) pair produces a row in admin_role_assignments with
// granted_by IS NULL and returns nil.
func TestUpsertSSOAdminAssignment_HappyPath(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID := seedSSOTestActorDB(t, pool, ctx, "sso-upsert-ok")
	defer cleanSSOActor(t, pool, ctx, userID)

	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	// group 2 = user_admin builtin (seeded by V010); must exist in every test DB.
	const groupID int64 = 2
	if err := h.upsertSSOAdminAssignment(ctx, userID, groupID, "test:upsert-ok"); err != nil {
		t.Fatalf("upsertSSOAdminAssignment returned unexpected error: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments
		 WHERE user_id = $1 AND role_group_id = $2 AND granted_by IS NULL`,
		userID, groupID,
	).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Errorf("happy path: want 1 row (group %d, NULL granted_by), got %d", groupID, count)
	}
}

// TestUpsertSSOAdminAssignment_FKError_LogsWarnAndContinues verifies that
// upsertSSOAdminAssignment returns an error (FK violation) when called with a
// nonexistent role_group_id, and that applyGroupMappings refuses a bad mapping
// with a Warn and continues processing other mappings rather than panicking or
// returning early.
//
// med-shard3-007 fence ordering: inside applyGroupMappings a mapping whose
// group does not exist is now refused by the grant-authority check BEFORE the
// upsert is reached (fail closed — no admin_role_groups row can ever be an
// authorized mint), so the in-loop injection below asserts the
// authority-check refusal; the direct seam call above keeps proving the FK
// error return of the upsert itself.
func TestUpsertSSOAdminAssignment_FKError_LogsWarnAndContinues(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID := seedSSOTestActorDB(t, pool, ctx, "sso-upsert-err")
	defer cleanSSOActor(t, pool, ctx, userID)

	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	// A role_group_id that cannot exist (admin_role_groups FK).
	const badGroupID int64 = 999999
	err := h.upsertSSOAdminAssignment(ctx, userID, badGroupID, "test:upsert-error")
	if err == nil {
		t.Fatal("upsertSSOAdminAssignment with nonexistent groupID must return an error (FK violation)")
	}

	// applyGroupMappings must log a Warn and NOT panic when a mapping is
	// refused. We inject two mappings: one bad (a fake role mapping to a
	// nonexistent group — refused by the grant-authority check), one valid
	// (user_admin → group 2).  We confirm:
	//   (a) the function returns without panicking,
	//   (b) the Warn was emitted for the bad mapping,
	//   (c) the valid mapping (user_admin → group 2) was still applied.
	//
	// To inject the bad mapping through applyGroupMappings, we temporarily
	// override adminRoleToGroupID to map a fake role to 999999, then restore it.
	origMap := adminRoleToGroupID
	adminRoleToGroupID = map[string]int64{
		"fake_role":  999999, // nonexistent group — refused before the upsert
		"user_admin": 2,      // valid — should still be applied
	}
	defer func() { adminRoleToGroupID = origMap }()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h2 := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: logger})

	mapper := &staticMapper{mappings: []federation.GroupMapping{
		{IDPGroup: "idp-bad", AdminRole: strPtr("fake_role")},
		{IDPGroup: "idp-ua2", AdminRole: strPtr("user_admin")},
	}}
	// Must not panic:
	h2.applyGroupMappings(ctx, userID, []string{"idp-bad", "idp-ua2"}, mapper)

	// (b) Warn must have been emitted for the bad mapping.
	logOut := logBuf.String()
	if !strings.Contains(logOut, "grant-authority check failed") {
		t.Errorf("expected Warn containing 'grant-authority check failed' in log output; got: %s", logOut)
	}
	// The refused mapping must have written nothing through the bad group.
	var badCount int
	if err2 := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments WHERE user_id = $1 AND role_group_id = 999999`,
		userID,
	).Scan(&badCount); err2 != nil {
		t.Fatalf("query bad group: %v", err2)
	}
	if badCount != 0 {
		t.Errorf("refused fake_role mapping wrote an assignment anyway; got %d", badCount)
	}

	// (c) The valid user_admin mapping (group 2) must still have been applied.
	var count int
	if err2 := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments
		 WHERE user_id = $1 AND role_group_id = 2 AND granted_by IS NULL`,
		userID,
	).Scan(&count); err2 != nil {
		t.Fatalf("query group 2: %v", err2)
	}
	if count != 1 {
		t.Errorf("after FK error on bad mapping, valid user_admin row (group 2) must still be inserted; got %d", count)
	}
}

func TestApplyGroupMappingsLogsDistributionGroupUpsertFailure(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	userID := seedSSOTestActorDB(t, pool, ctx, "sso-dg-upsert-error")
	defer cleanSSOActor(t, pool, ctx, userID)

	missingGroupID := int64(9_223_372_036_854_000_000)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(
		&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug},
	))
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: logger,
	})
	h.applyGroupMappings(
		ctx,
		userID,
		[]string{"missing-distribution-group"},
		&staticMapper{
			providerKey: "oidc:missing-distribution-group",
			mappings: []federation.GroupMapping{{
				IDPGroup:            "missing-distribution-group",
				DistributionGroupID: &missingGroupID,
			}},
		},
	)
	if !strings.Contains(logBuf.String(), "distribution-group membership upsert failed") {
		t.Fatalf("missing distribution-group failure was not recorded: %s", logBuf.String())
	}
}

// ── BUG 001: SSO grants must REVOKE stale rows ──────────────────────────────

// TestApplyGroupMappings_RevokesStaleSSOGrant proves an IdP group removal demotes
// the user: a prior SSO-granted super_admin (group 1, NULL granted_by) is DELETED
// when the user logs in without that mapping. Without the pre-loop delete, the
// stale row survived (privilege retention / failed demotion).
func TestApplyGroupMappings_RevokesStaleSSOGrant(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	// Keeper ensures trg_protect_last_super_admin does not block the revoke
	// delete (design: "provision another SA first to demote a sole SSO SA").
	keeperID := seedSSOTestActorWithRole(t, ctx, "revoke-keeper", 1)
	defer cleanSSOActorSweep(t, ctx, keeperID)

	userID := seedSSOTestActorDB(t, pool, ctx, "sso-revoke")
	defer cleanSSOActor(t, pool, ctx, userID)

	// Prior SSO-granted super_admin (group 1, NULL granted_by).
	seedSSOAdminAssignmentForProvider(t, pool, ctx, userID, 1, "test:default")

	// Login WITHOUT any admin mapping (mapper has a non-admin distribution mapping
	// only, so the loop runs but assigns no admin role).
	mapper := &staticMapper{mappings: []federation.GroupMapping{
		{IDPGroup: "idp-users", AdminRole: nil},
	}}
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
	h.applyGroupMappings(ctx, userID, []string{"idp-users"}, mapper)

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments WHERE user_id = $1 AND granted_by IS NULL`,
		userID,
	).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Errorf("BUG 001: stale SSO admin grant not revoked on login without the mapping; want 0 SSO rows, got %d", count)
	}
}

// TestApplyGroupMappings_RemappingReplacesRole proves a mapping change
// super_admin→user_admin REPLACES (the user ends with ONLY user_admin, group 2,
// not both group 1 and 2).
func TestApplyGroupMappings_RemappingReplacesRole(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	// Keeper ensures trg_protect_last_super_admin does not block the sweep delete
	// when the test user's super_admin grant is replaced by user_admin.
	keeperID := seedSSOTestActorWithRole(t, ctx, "remap-keeper", 1)
	defer cleanSSOActorSweep(t, ctx, keeperID)

	userID := seedSSOTestActorDB(t, pool, ctx, "sso-remap")
	defer cleanSSOActor(t, pool, ctx, userID)

	// Prior SSO-granted super_admin (group 1).
	seedSSOAdminAssignmentForProvider(t, pool, ctx, userID, 1, "test:default")

	// New login maps the user to user_admin instead.
	mapper := &staticMapper{mappings: []federation.GroupMapping{
		{IDPGroup: "idp-ua", AdminRole: strPtr("user_admin")},
	}}
	// Enable super_admin mapping so this test is not also gated by BUG 006 — here
	// we only seed group 1 directly; the mapping confers user_admin.
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger(), SSOAllowSuperAdminMapping: true})
	h.applyGroupMappings(ctx, userID, []string{"idp-ua"}, mapper)

	rows, err := pool.Query(ctx,
		`SELECT role_group_id FROM admin_role_assignments WHERE user_id = $1 AND granted_by IS NULL ORDER BY role_group_id`,
		userID)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var groups []int64
	for rows.Next() {
		var g int64
		if err := rows.Scan(&g); err != nil {
			t.Fatalf("scan: %v", err)
		}
		groups = append(groups, g)
	}
	if len(groups) != 1 || groups[0] != 2 {
		t.Errorf("BUG 001: remapping super_admin→user_admin must leave ONLY group 2; got %v", groups)
	}
}

// TestApplyGroupMappings_PreservesAdminUIGrant proves the revoke only sweeps
// SSO-provisioned rows (granted_by IS NULL); an admin-UI grant (real granter) is
// untouched.
func TestApplyGroupMappings_PreservesAdminUIGrant(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID := seedSSOTestActorDB(t, pool, ctx, "sso-preserve")
	defer cleanSSOActor(t, pool, ctx, userID)

	// An admin-UI grant uses a real granter (granted_by = the user themselves here,
	// any non-null users.id satisfies the FK).
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, 4, $1)`, userID); err != nil {
		t.Fatalf("seed admin-UI grant: %v", err)
	}

	mapper := &staticMapper{mappings: []federation.GroupMapping{
		{IDPGroup: "idp-users", AdminRole: nil},
	}}
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
	h.applyGroupMappings(ctx, userID, []string{"idp-users"}, mapper)

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments WHERE user_id = $1 AND role_group_id = 4 AND granted_by IS NOT NULL`,
		userID,
	).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Errorf("BUG 001: admin-UI grant (real granter) must survive the SSO revoke sweep; got %d", count)
	}
}

// ── BUG 006: SSO super_admin mapping gated by SSOAllowSuperAdminMapping ──────

// TestApplyGroupMappings_SuperAdminRefusedByDefault proves the safety knob:
// with SSOAllowSuperAdminMapping=false (default) an IdP super_admin mapping
// writes NO assignment and logs the refusal.
func TestApplyGroupMappings_SuperAdminRefusedByDefault(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID := seedSSOTestActorDB(t, pool, ctx, "sso-knob-off")
	defer cleanSSOActor(t, pool, ctx, userID)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mapper := &staticMapper{mappings: []federation.GroupMapping{
		{IDPGroup: "idp-super", AdminRole: strPtr("super_admin")},
	}}
	// Default: SSOAllowSuperAdminMapping is the zero value (false).
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: logger})
	h.applyGroupMappings(ctx, userID, []string{"idp-super"}, mapper)

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments WHERE user_id = $1 AND role_group_id = 1`,
		userID,
	).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Errorf("BUG 006: super_admin mapping must be REFUSED when SSOAllowSuperAdminMapping=false; got %d group-1 rows", count)
	}
	if !strings.Contains(logBuf.String(), "super_admin refused") {
		t.Errorf("BUG 006: expected a Warn about the refused super_admin mapping; got: %s", logBuf.String())
	}
}

// TestApplyGroupMappings_SuperAdminAllowedWhenOptedIn proves the knob ON writes
// the super_admin assignment.
func TestApplyGroupMappings_SuperAdminAllowedWhenOptedIn(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID := seedSSOTestActorDB(t, pool, ctx, "sso-knob-on")
	defer cleanSSOActor(t, pool, ctx, userID)

	mapper := &staticMapper{mappings: []federation.GroupMapping{
		{IDPGroup: "idp-super", AdminRole: strPtr("super_admin")},
	}}
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger(), SSOAllowSuperAdminMapping: true})
	h.applyGroupMappings(ctx, userID, []string{"idp-super"}, mapper)

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments WHERE user_id = $1 AND role_group_id = 1 AND granted_by IS NULL`,
		userID,
	).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Errorf("BUG 006: super_admin mapping must be WRITTEN when SSOAllowSuperAdminMapping=true; got %d", count)
	}
}

// TestApplyGroupMappings_BZ001WarnPath_StaticGuard asserts (via AST analysis)
// that applyGroupMappings:
//  1. Delegates the upsert to upsertSSOAdminAssignment (the extracted seam).
//  2. Checks the SoD-rejection error via the shared reducererr.IsCode seam
//     (arch #A8 — no hand-rolled pgErr.Code == "BZ001" branch; the BZ001
//     literal now lives once, as reducererr.ErrOverQuota, in shared/reducererr).
//  3. Calls h.logger.Warn (not silently swallows).
//  4. Does NOT use SAVEPOINT (no enclosing tx — autocommit isolation is sufficient).
//
// This is a cheap compile-time-equivalent guard that stays green even without
// a DB and ensures the implementation never regresses.
func TestApplyGroupMappings_BZ001WarnPath_StaticGuard(t *testing.T) {
	src := funcSrc(t, "auth.go", "applyGroupMappings")

	// The rewrite must delegate to the extracted seam.
	if !strings.Contains(src, "upsertSSOAdminAssignment") {
		t.Error("applyGroupMappings must call upsertSSOAdminAssignment (extracted seam)")
	}
	// The rewrite must classify the SoD-rejection error through the shared
	// reducererr.IsCode seam (arch #A8), never a hand-rolled pgErr.Code compare.
	if !strings.Contains(src, "reducererr.IsCode") || !strings.Contains(src, "reducererr.ErrOverQuota") {
		t.Error("applyGroupMappings must check reducererr.IsCode(execErr, reducererr.ErrOverQuota) for SoD rejection")
	}
	if strings.Contains(src, `pgErr.Code == "BZ001"`) {
		t.Error("applyGroupMappings must not hand-roll a pgErr.Code == \"BZ001\" branch — use reducererr.IsCode")
	}
	// The rewrite must log a Warn.
	if !strings.Contains(src, "Warn") {
		t.Error("applyGroupMappings must log a Warn on BZ001 SoD rejection")
	}
	// No savepoint — there is no enclosing transaction.
	if strings.Contains(src, "SAVEPOINT") {
		t.Error("applyGroupMappings must NOT use SAVEPOINT (no enclosing tx; autocommit isolation is sufficient)")
	}
	// The rewrite must NOT write to users.admin_role (that's Task 7's read).
	if strings.Contains(src, "UPDATE users SET admin_role") {
		t.Error("applyGroupMappings must not write users.admin_role (Task 4 removes the SSO write path)")
	}
	// cappedSSORole must no longer be called from applyGroupMappings.
	if strings.Contains(src, "cappedSSORole") {
		t.Error("applyGroupMappings must not call cappedSSORole (it has been removed in Task 4)")
	}
	// The upsert must target admin_role_assignments.
	if !strings.Contains(src, "admin_role_assignments") {
		t.Error("applyGroupMappings must upsert into admin_role_assignments")
	}
}
