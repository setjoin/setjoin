package admin

// med-shard3-007 (F-004): SSO group→role mapping writes that mint persistent
// admin_role_assignments at login (the authserver login-time
// upsertSSOAdminAssignment consumer) require roles.manage — the same
// held-permission check admin_roles.go AssignMember enforces for role
// assignment. An identity.write-only Identity Admin must not be able to wire
// an IdP group to an admin role (durable privilege escalation);
// distribution-group-only mappings stay identity.write.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

// Fixed fixture ids (distinct range: 9643x, not used by any other fixture in
// this package).
const (
	grpMapUser             = int64(96431)
	grpMapDomain           = int64(96430)
	grpMapIDPEntityPattern = "grpmap-%d.example.idp"
)

// seedGrpMapFixtures seeds the actor user and one enabled SAML SP registration
// per test run (unique idp_entity_id), with FK-safe cleanup.
func seedGrpMapFixtures(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`INSERT INTO domains (id, name, is_local) VALUES ($1, 'grpmap.test', TRUE)
		 ON CONFLICT (id) DO NOTHING`, grpMapDomain); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		 VALUES ($1, 'grpmap_u', $2, 'grpmap_u@grpmap.test', 'G', TRUE)
		 ON CONFLICT (id) DO NOTHING`, grpMapUser, grpMapDomain); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	entity := fmt.Sprintf(grpMapIDPEntityPattern, time.Now().UnixNano())
	if _, err := pool.Exec(ctx,
		`INSERT INTO saml_sp_registrations
		   (idp_entity_id, idp_sso_url, idp_cert_enc, sp_entity_id, sp_acs_url, enabled, group_mappings)
		 VALUES ($1, 'https://idp.example/sso', decode('00','hex'), 'setjoin-sp', 'https://setjoin.example/acs', TRUE, NULL)
		 ON CONFLICT DO NOTHING`, entity); err != nil {
		t.Fatalf("seed saml registration: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM saml_sp_registrations WHERE idp_entity_id = $1`, entity) //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, grpMapUser)                        //nolint:errcheck
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, grpMapDomain)                    //nolint:errcheck
	})
	return entity
}

// grpMapClaims returns unscoped claims holding exactly the given permissions,
// in both the JWT permission set (route gates / Rule A check) and the live
// global projection (requireUnscopedIdentityAdmin).
func grpMapClaims(perms ...string) *auth.Claims {
	return &auth.Claims{
		UserID:            grpMapUser,
		IsAdmin:           true,
		Permissions:       perms,
		GlobalPermissions: perms,
	}
}

// grpMapCall invokes UpdateGroupMappings for the seeded SAML provider.
func grpMapCall(t *testing.T, h *IdentityHandler, entity, body string, claims *auth.Claims) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/admin/identity/group-mappings/saml/"+entity, strings.NewReader(body))
	req.SetPathValue("type", "saml")
	req.SetPathValue("id", entity)
	if claims != nil {
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	}
	rec := httptest.NewRecorder()
	h.UpdateGroupMappings(rec, req)
	return rec
}

// grpMapPersisted fetches the seeded provider's persisted group_mappings JSON.
func grpMapPersisted(t *testing.T, pool *pgxpool.Pool, entity string) []byte {
	t.Helper()
	var raw []byte
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE(group_mappings, 'null'::JSONB) FROM saml_sp_registrations WHERE idp_entity_id = $1`,
		entity).Scan(&raw); err != nil {
		t.Fatalf("load group_mappings: %v", err)
	}
	return raw
}

// TestUpdateGroupMappings_AdminRoleMappingRequiresRolesManage proves an
// Identity Admin (identity.write, unscoped) cannot mint an admin-role grant
// via a group mapping without roles.manage — and, per the Astra waves34 HOLD-1
// correction (Rule A), that roles.manage ALONE is still not enough: the writer
// must hold EVERY permission the target role grants. The former version of
// this test permitted an identity.write + roles.manage principal to wire
// super_admin — exactly the escalation Rule A forbids. A fully-privileged
// holder writes the mapping (and refreshes the login-time grant-authority
// record), and a distribution-only mapping still needs only identity.write.
func TestUpdateGroupMappings_AdminRoleMappingRequiresRolesManage(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	entity := seedGrpMapFixtures(t, pool)
	h := NewIdentityHandler(pool, nil, testsupport.TestLogger())

	identityOnly := grpMapClaims(permissions.PermIdentityWrite)
	identityAndRoles := grpMapClaims(permissions.PermIdentityWrite, permissions.PermRolesManage)
	allPerms := grpMapClaims(permissions.AllPermissions...)

	// The Rule A scope arm resolves the writer's DB authority; give the fully
	// privileged actor a real object-unrestricted grant so the authorized arm
	// mirrors a production global admin.
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, 2, $1)`, grpMapUser); err != nil {
		t.Fatalf("seed actor authority: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(),
			`DELETE FROM admin_role_assignments WHERE user_id = $1 AND role_group_id = 2`, grpMapUser) //nolint:errcheck
	})

	// identity.write alone + an admin_role mapping → 403, nothing persisted.
	rec := grpMapCall(t, h, entity, `[{"idp_group":"idp-admins","admin_role":"super_admin"}]`, identityOnly)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("identity-only admin-role mapping: got %d body=%s, want 403", rec.Code, rec.Body.String())
	}
	if got := string(grpMapPersisted(t, pool, entity)); got != "null" {
		t.Fatalf("denied mapping persisted anyway: %s", got)
	}

	// Rule A (HOLD 1): identity.write + roles.manage but NOT every permission
	// super_admin grants → 403; roles.manage alone does not authorize minting
	// a role that outruns the writer's own permission set.
	rec = grpMapCall(t, h, entity, `[{"idp_group":"idp-admins","admin_role":"super_admin"}]`, identityAndRoles)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("roles.manage-only super_admin mapping: got %d body=%s, want 403", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "permission you do not hold") {
		t.Fatalf("refusal is not the Rule A arm: %s", rec.Body.String())
	}
	if got := string(grpMapPersisted(t, pool, entity)); got != "null" {
		t.Fatalf("Rule A-denied mapping persisted anyway: %s", got)
	}

	// A holder of identity.write + roles.manage + every permission the role
	// grants (the full Rule A) → the mapping persists and the login-time
	// grant-authority record is refreshed with this writer.
	rec = grpMapCall(t, h, entity, `[{"idp_group":"idp-admins","admin_role":"super_admin"}]`, allPerms)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("fully-privileged admin-role mapping: got %d body=%s, want 204", rec.Code, rec.Body.String())
	}
	if got := string(grpMapPersisted(t, pool, entity)); !strings.Contains(got, "super_admin") {
		t.Fatalf("authorized mapping not persisted: %s", got)
	}
	var authBy string
	if err := pool.QueryRow(context.Background(),
		`SELECT value->'super_admin'->>'authorized_by'
		   FROM system_config WHERE key = 'sso_admin_role_grant_authority'`).Scan(&authBy); err != nil {
		t.Fatalf("read grant-authority record: %v", err)
	}
	if authBy != fmt.Sprintf("%d", grpMapUser) {
		t.Fatalf("grant-authority authorized_by = %s, want %d", authBy, grpMapUser)
	}

	// Distribution-only mapping stays identity.write (no roles.manage needed):
	// reset to NULL first so the 204 is attributable to this call.
	if _, err := pool.Exec(context.Background(),
		`UPDATE saml_sp_registrations SET group_mappings = NULL WHERE idp_entity_id = $1`, entity); err != nil {
		t.Fatalf("reset mappings: %v", err)
	}
	rec = grpMapCall(t, h, entity, `[{"idp_group":"idp-dl","distribution_group_id":42}]`, identityOnly)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("identity-only distribution mapping: got %d body=%s, want 204", rec.Code, rec.Body.String())
	}
	if got := string(grpMapPersisted(t, pool, entity)); !strings.Contains(got, "idp-dl") {
		t.Fatalf("distribution mapping not persisted: %s", got)
	}
}
