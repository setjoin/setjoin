package handlers

// med-shard3-007 (F-004, Astra waves34 HOLD 2): the login-time SSO
// admin-role mint (applyGroupMappings → upsertSSOAdminAssignment) is gated on
// the grant authority — the system_config 'sso_admin_role_grant_authority'
// record for the role label must still cover the role group's LIVE permission
// set (Rule A, grant-only-what-you-hold, evaluated at mint time). The record
// is seeded for the four governed builtin labels by V244, so mappings that
// predate the fence ("legacy mappings") keep minting; removing the record or
// widening the role past its authorized_perms ceiling stops minting
// ("authority loss"). The mailserver console write boundary
// (admin_identity.go UpdateGroupMappings) is the roles.manage-side refresher.

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/authserver/internal/federation"
	"setjoin.com/shared/testsupport"
)

const ssoGrantAuthorityKey = "sso_admin_role_grant_authority"

// ssoGrantAuthorityFixture snapshots (and restores on cleanup) both halves of
// the fence state a test is about to mutate: the grant-authority record and
// the role group's live permission set.
func ssoGrantAuthorityFixture(t *testing.T, pool *pgxpool.Pool, ctx context.Context, groupID int64) {
	t.Helper()
	var recordValue *[]byte
	var rolePerms []string
	err := pool.QueryRow(ctx,
		`SELECT (SELECT value FROM system_config WHERE key = $1), permissions
		   FROM admin_role_groups WHERE id = $2`,
		ssoGrantAuthorityKey, groupID).Scan(&recordValue, &rolePerms)
	if err != nil {
		t.Skipf("grant-authority fence state unavailable (schema predates V244?): %v", err)
	}
	if recordValue == nil {
		t.Skipf("%s seed row missing — schema predates V244", ssoGrantAuthorityKey)
	}
	savedRecord := string(*recordValue)
	savedPerms := append([]string(nil), rolePerms...)
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `UPDATE system_config SET value = $2::jsonb WHERE key = $1`,
			ssoGrantAuthorityKey, savedRecord) //nolint:errcheck
		pool.Exec(c, `UPDATE admin_role_groups SET permissions = $2 WHERE id = $1`,
			groupID, savedPerms) //nolint:errcheck
	})
}

// TestApplyGroupMappings_LegacyMappingMintsUnderSeededAuthority pins the
// legacy-mappings arm of the fence: a mapping carrying a governed builtin
// label (written before the fence existed — no per-mapping stamp anywhere)
// still mints, because V244 seeded the label's mint authority. The role group's
// live permissions are within the seeded ceiling, so Rule A holds at mint time.
func TestApplyGroupMappings_LegacyMappingMintsUnderSeededAuthority(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	ssoGrantAuthorityFixture(t, pool, ctx, 2)
	userID := seedSSOTestActorDB(t, pool, ctx, "sso-legacy-mint")
	defer cleanSSOActor(t, pool, ctx, userID)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: logger})
	h.applyGroupMappings(ctx, userID, []string{"idp-legacy-admins"}, &staticMapper{
		mappings: []federation.GroupMapping{{IDPGroup: "idp-legacy-admins", AdminRole: strPtr("user_admin")}},
	})

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments
		 WHERE user_id = $1 AND role_group_id = 2 AND granted_by IS NULL`,
		userID).Scan(&count); err != nil {
		t.Fatalf("query assignment: %v", err)
	}
	if count != 1 {
		t.Fatalf("legacy mapping under seeded authority must mint: want 1 group-2 row, got %d", count)
	}
	if strings.Contains(logBuf.String(), "grant authority") {
		t.Fatalf("legacy mint was wrongly refused: %s", logBuf.String())
	}
}

// TestApplyGroupMappings_MintRefusedWhenGrantAuthorityLost is the authority-loss
// arm: once the operator record for the label is gone, the next login must NOT
// mint the assignment — the IdP group alone is not grant authority.
func TestApplyGroupMappings_MintRefusedWhenGrantAuthorityLost(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	ssoGrantAuthorityFixture(t, pool, ctx, 2)
	if _, err := pool.Exec(ctx,
		`UPDATE system_config SET value = value - 'user_admin' WHERE key = $1`,
		ssoGrantAuthorityKey); err != nil {
		t.Fatalf("drop user_admin grant authority: %v", err)
	}
	userID := seedSSOTestActorDB(t, pool, ctx, "sso-authority-lost")
	defer cleanSSOActor(t, pool, ctx, userID)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: logger})
	h.applyGroupMappings(ctx, userID, []string{"idp-admins"}, &staticMapper{
		mappings: []federation.GroupMapping{{IDPGroup: "idp-admins", AdminRole: strPtr("user_admin")}},
	})

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments WHERE user_id = $1 AND role_group_id = 2`,
		userID).Scan(&count); err != nil {
		t.Fatalf("query assignment: %v", err)
	}
	if count != 0 {
		t.Fatalf("lost grant authority must refuse the mint: got %d group-2 rows", count)
	}
	if !strings.Contains(logBuf.String(), "grant authority absent or exceeded") {
		t.Fatalf("authority loss was not logged as a refusal: %s", logBuf.String())
	}
}

// TestApplyGroupMappings_MintRefusedWhenRoleWidensBeyondAuthority is the Rule A
// arm: the role group's LIVE permissions must stay within the authorized_perms
// ceiling recorded when a roles.manage holder authorized the mapping. A role
// widened past its authorization (without re-authorization) stops minting.
func TestApplyGroupMappings_MintRefusedWhenRoleWidensBeyondAuthority(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	ssoGrantAuthorityFixture(t, pool, ctx, 2)
	if _, err := pool.Exec(ctx,
		`UPDATE admin_role_groups SET permissions = permissions || '{system.upgrade}' WHERE id = 2`); err != nil {
		t.Fatalf("widen user_admin permissions: %v", err)
	}
	userID := seedSSOTestActorDB(t, pool, ctx, "sso-role-widened")
	defer cleanSSOActor(t, pool, ctx, userID)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: logger})
	h.applyGroupMappings(ctx, userID, []string{"idp-admins"}, &staticMapper{
		mappings: []federation.GroupMapping{{IDPGroup: "idp-admins", AdminRole: strPtr("user_admin")}},
	})

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments WHERE user_id = $1 AND role_group_id = 2`,
		userID).Scan(&count); err != nil {
		t.Fatalf("query assignment: %v", err)
	}
	if count != 0 {
		t.Fatalf("role widened beyond its grant authority must refuse the mint: got %d group-2 rows", count)
	}
	if !strings.Contains(logBuf.String(), "grant authority absent or exceeded") {
		t.Fatalf("widened-role refusal was not logged: %s", logBuf.String())
	}
}

// TestApplyGroupMappings_GrantAuthorityEnforcedBeforeMint_StaticGuard keeps the
// non-DB arm honest: applyGroupMappings must call the grant-authority seam and
// the refusal must textually precede the mint call, so the assignment can never
// be written before its authority is established.
func TestApplyGroupMappings_GrantAuthorityEnforcedBeforeMint_StaticGuard(t *testing.T) {
	src := funcSrc(t, "auth.go", "applyGroupMappings")

	enforceIdx := strings.Index(src, "ssoMintAuthorityCovers")
	mintIdx := strings.Index(src, "h.upsertSSOAdminAssignment(")
	if enforceIdx < 0 {
		t.Fatal("applyGroupMappings must enforce the grant authority (ssoMintAuthorityCovers) before minting")
	}
	if mintIdx < 0 {
		t.Fatal("applyGroupMappings must delegate the mint to upsertSSOAdminAssignment")
	}
	if enforceIdx > mintIdx {
		t.Fatal("the grant-authority check must precede the upsertSSOAdminAssignment call")
	}
	if !strings.Contains(src, "grant authority absent or exceeded") {
		t.Fatal("a refused mint must be Warn-logged with the authority refusal")
	}
}
