package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/testsupport"
)

// putGroupMappings PUTs a mapping body for the provider and returns the
// recorder, acting as the given fixture actor (global claims, no middleware
// domain scope — the unscoped gate the handler requires).
func putGroupMappings(t *testing.T, h *IdentityHandler, actorID int64, ptype, pid, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/admin/identity/group-mappings/"+ptype+"/"+pid, strings.NewReader(body))
	req.SetPathValue("type", ptype)
	req.SetPathValue("id", pid)
	req = globalIdentityAdminRequestAs(actorID, req)
	rec := httptest.NewRecorder()
	h.UpdateGroupMappings(rec, req)
	return rec
}

// seedCovSAMLProvider registers a throwaway SAML SP row with empty mappings.
func seedCovSAMLProvider(t *testing.T, pool *pgxpool.Pool, entity string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO saml_sp_registrations
		   (idp_entity_id, idp_sso_url, idp_cert_enc, sp_entity_id, sp_acs_url, enabled, group_mappings)
		 VALUES ($1, 'https://idp.test/sso', '\x00'::bytea, 'https://sp.test', 'https://sp.test/acs', TRUE, '[]'::jsonb)`,
		entity); err != nil {
		t.Fatalf("seed saml: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM saml_sp_registrations WHERE idp_entity_id = $1`, entity) //nolint:errcheck
	})
}

// TestIdentityGroupMappings_MissingRoleGroupRowFailsClosed drives the
// ErrNoRows arm of the Rule A fence: when the governed label resolves to a
// role-group row the database does not hold, the write fails closed with 400
// and persists neither the mapping nor a grant-authority record. The label→row
// map is overridden (and restored) so no shared builtin fixture row is touched.
func TestIdentityGroupMappings_MissingRoleGroupRowFailsClosed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())

	suffix := rolesTestRandomSuffix(t)
	samlEntity := "urn:idtest:" + suffix
	seedCovSAMLProvider(t, pool, samlEntity)

	saved := governedSSORoleGroupIDs
	governedSSORoleGroupIDs = map[string]int64{"super_admin": 987654321} // no such admin_role_groups row
	t.Cleanup(func() { governedSSORoleGroupIDs = saved })

	actorID := seedUser(t, pool)
	rec := putGroupMappings(t, h, actorID, "saml", samlEntity,
		`[{"idp_group":"admins","admin_role":"super_admin"}]`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing role-group row: want 400, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "unknown admin role label") {
		t.Fatalf("missing role-group row: unexpected body %s", rec.Body.String())
	}
	var raw json.RawMessage
	if err := pool.QueryRow(t.Context(),
		`SELECT group_mappings FROM saml_sp_registrations WHERE idp_entity_id = $1`, samlEntity).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if string(raw) != "[]" {
		t.Fatalf("failed fence persisted mappings anyway: %s", raw)
	}
}

// TestIdentityGroupMappings_ScopeArmRejectsBroaderRoleScope drives the Rule A
// scope arm: an actor whose only DB authority is domain-scoped cannot mint a
// mapping to a globally-scoped role — the minted assignment would inherit a
// broader reach than the author holds. 403, nothing persisted.
func TestIdentityGroupMappings_ScopeArmRejectsBroaderRoleScope(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())

	suffix := rolesTestRandomSuffix(t)
	samlEntity := "urn:idtest:" + suffix
	seedCovSAMLProvider(t, pool, samlEntity)

	domainID := rolesTestEnsureDomain(t, pool)
	actorUsername := "idcov-actor-" + suffix
	var actorID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, password_hash, domain_id)
		 VALUES ($1, $2, 'Identity Coverage Scoped Actor', '$2a$10$placeholder', $3)
		 RETURNING id`,
		actorUsername, "idcov-actor-"+suffix+"@rolestest.example", domainID,
	).Scan(&actorID); err != nil {
		t.Fatalf("seed actor user: %v", err)
	}
	// Domain-confined authority: role 2 (User Admin, domain_scope NULL) granted
	// WITH domain_override — the actor's effective scope is this domain only.
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, domain_override, granted_by)
		 VALUES ($1, 2, $2, $1)`, actorID, domainID); err != nil {
		t.Fatalf("seed domain-scoped authority: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM admin_role_assignments WHERE user_id = $1`, actorID) //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, actorID)                       //nolint:errcheck
	})

	rec := putGroupMappings(t, h, actorID, "saml", samlEntity,
		`[{"idp_group":"admins","admin_role":"super_admin"}]`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("domain-scoped actor minting a global role: want 403, got %d (%s)",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "scope broader than your own reach") {
		t.Fatalf("scope arm: unexpected body %s", rec.Body.String())
	}
	var raw json.RawMessage
	if err := pool.QueryRow(ctx,
		`SELECT group_mappings FROM saml_sp_registrations WHERE idp_entity_id = $1`, samlEntity).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if string(raw) != "[]" {
		t.Fatalf("refused scope arm persisted mappings anyway: %s", raw)
	}
}

// seedCovFencedActor seeds a user whose DB authority is a plain (unrestricted)
// role-2 assignment, so the Rule A scope arm passes exactly like a production
// global admin and the test reaches the persist leg it targets.
func seedCovFencedActor(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	ctx := context.Background()
	domainID := rolesTestEnsureDomain(t, pool)
	suffix := rolesTestRandomSuffix(t)
	var actorID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, password_hash, domain_id)
		 VALUES ($1, $2, 'Identity Coverage Fenced Actor', '$2a$10$placeholder', $3)
		 RETURNING id`,
		"idcov-fenced-"+suffix, "idcov-fenced-"+suffix+"@rolestest.example", domainID,
	).Scan(&actorID); err != nil {
		t.Fatalf("seed fenced actor: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, 2, $1)`, actorID); err != nil {
		t.Fatalf("seed fenced actor authority: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM admin_role_assignments WHERE user_id = $1`, actorID) //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, actorID)                       //nolint:errcheck
	})
	return actorID
}

// TestIdentityGroupMappings_RolePathUnknownOIDCProviderWrites404 pins the
// errHandled propagation on the FENCED path: an admin-role mapping pointed at
// a missing OIDC provider surfaces the provider 404 instead of a generic 500.
func TestIdentityGroupMappings_RolePathUnknownOIDCProviderWrites404(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())
	actorID := seedCovFencedActor(t, pool)

	rec := putGroupMappings(t, h, actorID, "oidc", "idcov_missing_"+rolesTestRandomSuffix(t),
		`[{"idp_group":"eng","admin_role":"auditor"}]`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("fenced oidc unknown provider: want 404, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestIdentityGroupMappings_OIDCScalarConfigFailsClosed drives both
// persistGroupMappings callers against an OIDC provider whose stored config is
// a JSON scalar (not an object): the unparseable config fails the write closed
// with 500 on the fenced path AND on the plain identity.write path — a mapping
// must never clobber a config shape the handler cannot read.
func TestIdentityGroupMappings_OIDCScalarConfigFailsClosed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())

	oidcID := "idcov_scalar_" + rolesTestRandomSuffix(t)
	oidcKey := "oidc_provider_" + oidcID + "_config"
	if _, err := pool.Exec(ctx,
		`INSERT INTO system_config (key, value) VALUES ($1, '5'::jsonb)`, oidcKey); err != nil {
		t.Fatalf("seed scalar oidc config: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = $1`, oidcKey) //nolint:errcheck
	})
	actorID := seedCovFencedActor(t, pool)

	// Fenced path (mapping carries an admin role).
	if rec := putGroupMappings(t, h, actorID, "oidc", oidcID,
		`[{"idp_group":"eng","admin_role":"auditor"}]`); rec.Code != http.StatusInternalServerError {
		t.Fatalf("fenced scalar-config oidc: want 500, got %d (%s)", rec.Code, rec.Body.String())
	}
	// Plain path (distribution-group-only mapping).
	if rec := putGroupMappings(t, h, actorID, "oidc", oidcID,
		`[{"idp_group":"eng","distribution_group_id":42}]`); rec.Code != http.StatusInternalServerError {
		t.Fatalf("plain scalar-config oidc: want 500, got %d (%s)", rec.Code, rec.Body.String())
	}
}
