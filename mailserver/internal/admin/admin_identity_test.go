package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

func TestIdentityTransitionPreviewEnforcesOUReach(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())

	req := httptest.NewRequest(http.MethodPost, "/admin/identity/v2/transitions/preview",
		strings.NewReader(`{"userId":"`+strconv.FormatInt(st.userSales, 10)+`","reason":"approved scope test","idempotencyKey":"1a73c8e5-d125-4b47-8d96-070f8f5c55d0"}`))
	req.Header.Set("X-Audit-Reason", "approved scope test")
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: st.actorEngOUScoped, IsAdmin: true, Permissions: permissions.AllPermissions,
	}))

	rec := httptest.NewRecorder()
	middleware.RequireReason(permissions.PermIdentityWrite, pool)(
		http.HandlerFunc(h.TransitionPreview),
	).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("OU-scoped actor previewing an out-of-scope user: want 404, got %d (%s)",
			rec.Code, rec.Body.String())
	}
}

func TestIdentityHandlerRuntimeSetters(t *testing.T) {
	h := NewIdentityHandler(nil, nil, nil)
	codec := &ConfigSecretCodec{}
	h.SetSourceSecretCodec(codec)
	if h.sourceSecrets != codec {
		t.Fatal("source secret codec was not retained")
	}
	readiness := IdentityRuntimeReadiness{
		ExpectedSchemaVersion: 172,
		WorkerDSNReady:        true,
		OwnerDSNReady:         true,
		DirectDSNReady:        true,
		AuthserverConfigured:  true,
	}
	h.SetRuntimeReadiness(readiness)
	if h.runtime != readiness {
		t.Fatalf("runtime readiness=%+v, want %+v", h.runtime, readiness)
	}
}

func TestIdentityReasonMatchesHeaderWithoutOptionalPolicyContext(t *testing.T) {
	for _, tc := range []struct {
		name       string
		header     string
		body       string
		wantOK     bool
		wantStatus int
	}{
		{name: "exact", header: "approved migration", body: "approved migration", wantOK: true},
		{name: "missing header", body: "approved migration", wantStatus: http.StatusBadRequest},
		{name: "missing body", header: "approved migration", wantStatus: http.StatusBadRequest},
		{name: "mismatch", header: "approved migration", body: "different", wantStatus: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/admin/identity/v2/transitions/preview", nil)
			if tc.header != "" {
				req.Header.Set("X-Audit-Reason", tc.header)
			}
			rec := httptest.NewRecorder()
			if got := identityReasonMatches(rec, req, tc.body); got != tc.wantOK {
				t.Fatalf("identityReasonMatches() = %v, want %v", got, tc.wantOK)
			}
			if !tc.wantOK && rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

// TestIdentityGroupMappings drives the AD/SAML/OIDC group-mapping write path
// (UpdateGroupMappings) against the real DB and asserts the persisted
// group_mappings round-trip — the smallest guard that fails if the mutating
// write regresses. Admin-role-carrying mappings go through the Rule A
// authority fence (F-004), so the actor needs a real object-unrestricted DB
// assignment for the Rule A scope arm (admin_scope_within) to pass, exactly
// like a production global admin.
func TestIdentityGroupMappings(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())

	suffix := rolesTestRandomSuffix(t)
	samlEntity := "urn:idtest:" + suffix
	oidcID := "idtest_" + suffix
	oidcKey := "oidc_provider_" + oidcID + "_config"

	// Seed a SAML SP registration and an OIDC provider system_config row.
	if _, err := pool.Exec(ctx,
		`INSERT INTO saml_sp_registrations
		   (idp_entity_id, idp_sso_url, idp_cert_enc, sp_entity_id, sp_acs_url, enabled)
		 VALUES ($1, 'https://idp.test/sso', '\x00'::bytea, 'https://sp.test', 'https://sp.test/acs', TRUE)`,
		samlEntity); err != nil {
		t.Fatalf("seed saml: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO system_config (key, value) VALUES ($1, $2::jsonb)`,
		oidcKey, `{"name":"`+oidcID+`","group_mappings":[]}`); err != nil {
		t.Fatalf("seed oidc: %v", err)
	}
	// The fence's Rule A scope arm resolves the actor's DB authority; seed the
	// actor's user row and grant WITHIN the fixture (unique identity, own
	// cleanup) so the test never depends on a pre-existing seed user: the
	// granted_by FK targets a user another test's cleanup may have removed on
	// the shared DB. The claims-injected actor is this real user, so the happy
	// path mirrors a production global admin. Plain DELETE is safe: role 2 is
	// not the last-super-admin trigger's concern.
	domainID := rolesTestEnsureDomain(t, pool)
	actorUsername := "idtest-actor-" + suffix
	var actorID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, password_hash, domain_id)
		 VALUES ($1, $2, 'Identity GroupMappings Actor', '$2a$10$placeholder', $3)
		 RETURNING id`,
		actorUsername, "idtest-actor-"+suffix+"@rolestest.example", domainID,
	).Scan(&actorID); err != nil {
		t.Fatalf("seed actor user: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, 2, $1)`, actorID); err != nil {
		t.Fatalf("seed actor authority: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM saml_sp_registrations WHERE idp_entity_id = $1`, samlEntity) //nolint:errcheck
		pool.Exec(c, `DELETE FROM system_config WHERE key = $1`, oidcKey)                      //nolint:errcheck
		pool.Exec(c, `DELETE FROM admin_role_assignments WHERE user_id = $1`, actorID)         //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, actorID)                               //nolint:errcheck
	})

	put := func(ptype, pid, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/admin/identity/group-mappings/"+ptype+"/"+pid, strings.NewReader(body))
		req.SetPathValue("type", ptype)
		req.SetPathValue("id", pid)
		req = globalIdentityAdminRequestAs(actorID, req)
		rec := httptest.NewRecorder()
		h.UpdateGroupMappings(rec, req)
		return rec
	}

	// SAML round-trip: PUT then read the column back. The label must be one of
	// the governed builtin roles (authserver adminRoleToGroupID).
	if rec := put("saml", samlEntity, `[{"idp_group":"admins","admin_role":"super_admin"}]`); rec.Code != http.StatusNoContent {
		t.Fatalf("saml PUT: want 204, got %d (%s)", rec.Code, rec.Body.String())
	}
	var samlRaw json.RawMessage
	if err := pool.QueryRow(ctx,
		`SELECT group_mappings FROM saml_sp_registrations WHERE idp_entity_id = $1`, samlEntity).Scan(&samlRaw); err != nil {
		t.Fatalf("read saml mappings: %v", err)
	}
	var samlMappings []groupMapping
	if err := json.Unmarshal(samlRaw, &samlMappings); err != nil {
		t.Fatalf("unmarshal saml mappings: %v", err)
	}
	if len(samlMappings) != 1 || samlMappings[0].IDPGroup != "admins" ||
		samlMappings[0].AdminRole == nil || *samlMappings[0].AdminRole != "super_admin" {
		t.Fatalf("saml mappings did not persist round-trip: %+v", samlMappings)
	}

	// The fenced write refreshes the login-time mint-authority record for the
	// mapped label (the authserver applyGroupMappings fence consumes it).
	var authBy, authPerms json.RawMessage
	if err := pool.QueryRow(ctx,
		`SELECT value->'super_admin'->'authorized_by', value->'super_admin'->'authorized_perms'
		   FROM system_config WHERE key = 'sso_admin_role_grant_authority'`).Scan(&authBy, &authPerms); err != nil {
		t.Fatalf("read grant authority record: %v", err)
	}
	if string(authBy) != strconv.FormatInt(actorID, 10) {
		t.Fatalf("super_admin grant authority authorized_by = %s, want %d", authBy, actorID)
	}
	if !strings.Contains(string(authPerms), "system.upgrade") {
		t.Fatalf("super_admin grant authority perms missing the role's grant: %s", authPerms)
	}

	// OIDC round-trip: PUT merges group_mappings into the config JSON.
	if rec := put("oidc", oidcID, `[{"idp_group":"eng","admin_role":"user_admin"}]`); rec.Code != http.StatusNoContent {
		t.Fatalf("oidc PUT: want 204, got %d (%s)", rec.Code, rec.Body.String())
	}
	var oidcRaw json.RawMessage
	if err := pool.QueryRow(ctx, `SELECT value FROM system_config WHERE key = $1`, oidcKey).Scan(&oidcRaw); err != nil {
		t.Fatalf("read oidc config: %v", err)
	}
	var oidcCfg struct {
		GroupMappings []groupMapping `json:"group_mappings"`
	}
	if err := json.Unmarshal(oidcRaw, &oidcCfg); err != nil {
		t.Fatalf("unmarshal oidc config: %v", err)
	}
	if len(oidcCfg.GroupMappings) != 1 || oidcCfg.GroupMappings[0].IDPGroup != "eng" {
		t.Fatalf("oidc mappings did not persist: %+v", oidcCfg.GroupMappings)
	}

	// Guard branches.
	if rec := put("bogus", "x", `[]`); rec.Code != http.StatusBadRequest {
		t.Errorf("invalid provider type: want 400, got %d", rec.Code)
	}
	if rec := put("saml", samlEntity, `{not json`); rec.Code != http.StatusBadRequest {
		t.Errorf("malformed body: want 400, got %d", rec.Code)
	}
	if rec := put("oidc", "does_not_exist_"+suffix, `[]`); rec.Code != http.StatusNotFound {
		t.Errorf("unknown oidc provider: want 404, got %d", rec.Code)
	}
	tooMany := make([]groupMapping, identity.MaxSSOGroupMappings+1)
	for i := range tooMany {
		tooMany[i].IDPGroup = "Engineering"
	}
	tooManyBody, err := json.Marshal(tooMany)
	if err != nil {
		t.Fatalf("marshal oversized mappings: %v", err)
	}
	if rec := put("saml", samlEntity, string(tooManyBody)); rec.Code != http.StatusBadRequest {
		t.Errorf("oversized mappings: want 400, got %d", rec.Code)
	}
	if rec := put("saml", samlEntity, `[{"idp_group":"bad\nname"}]`); rec.Code != http.StatusBadRequest {
		t.Errorf("control-bearing mapping: want 400, got %d", rec.Code)
	}

	// GetGroupMappings returns the seeded shape for both providers.
	greq := globalIdentityAdminRequestAs(actorID,
		httptest.NewRequest(http.MethodGet, "/admin/identity/group-mappings", nil),
	)
	grec := httptest.NewRecorder()
	h.GetGroupMappings(grec, greq)
	if grec.Code != http.StatusOK {
		t.Fatalf("GetGroupMappings: want 200, got %d", grec.Code)
	}
	var got map[string]map[string][]groupMapping
	if err := json.Unmarshal(grec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode GetGroupMappings: %v", err)
	}
	if m, ok := got["saml"][samlEntity]; !ok || len(m) != 1 || m[0].IDPGroup != "admins" {
		t.Errorf("GetGroupMappings saml shape missing/wrong: %+v", got["saml"])
	}
	if m, ok := got["oidc"][oidcID]; !ok || len(m) != 1 || m[0].IDPGroup != "eng" {
		t.Errorf("GetGroupMappings oidc shape missing/wrong: %+v", got["oidc"])
	}
}

func TestIdentityGroupMappingsRejectDomainScopedAdministrator(t *testing.T) {
	h := NewIdentityHandler(nil, nil, testsupport.TestLogger())
	for _, tc := range []struct {
		name   string
		method string
		call   func(*IdentityHandler, http.ResponseWriter, *http.Request)
	}{
		{"read", http.MethodGet, (*IdentityHandler).GetGroupMappings},
		{"write", http.MethodPut, (*IdentityHandler).UpdateGroupMappings},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/admin/identity/group-mappings", nil)
			req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
				UserID: 1, IsAdmin: true,
				Permissions:       permissions.AllPermissions,
				GlobalPermissions: permissions.AllPermissions,
			}))
			req = req.WithContext(middleware.ContextWithDomainScope(req.Context(), 42))
			rec := httptest.NewRecorder()
			tc.call(h, rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("domain-scoped group mapping %s: want 403, got %d (%s)",
					tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestIdentityGroupMappingsRejectOUScopeWithoutGlobalGrant(t *testing.T) {
	h := NewIdentityHandler(nil, nil, testsupport.TestLogger())
	for _, tc := range []struct {
		name   string
		method string
		call   func(*IdentityHandler, http.ResponseWriter, *http.Request)
	}{
		{"read", http.MethodGet, (*IdentityHandler).GetGroupMappings},
		{"write", http.MethodPut, (*IdentityHandler).UpdateGroupMappings},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/admin/identity/group-mappings", nil)
			req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
				UserID: 1, IsAdmin: true,
				Permissions: []string{
					permissions.PermUsersRead,
					permissions.PermIdentityWrite,
				},
				GlobalPermissions: nil,
			}))
			rec := httptest.NewRecorder()
			tc.call(h, rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("OU-scoped group mapping %s: want 403, got %d (%s)",
					tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestIdentityGroupMappings_RejectsSuperAdminMappingWithoutHeldPermissions is
// the Astra waves34 HOLD-1 acceptance test: a principal holding identity.write
// + roles.manage but NOT every permission the target role grants must be
// refused — the old roles.manage-only check permitted exactly this super_admin
// mapping (durable escalation: the login-time mint hands the role's full
// permission set to every member of the mapped IdP group). The write must also
// persist nothing: neither the mapping nor a grant-authority record.
func TestIdentityGroupMappings_RejectsSuperAdminMappingWithoutHeldPermissions(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())

	suffix := rolesTestRandomSuffix(t)
	samlEntity := "urn:idtest:" + suffix
	if _, err := pool.Exec(ctx,
		`INSERT INTO saml_sp_registrations
		   (idp_entity_id, idp_sso_url, idp_cert_enc, sp_entity_id, sp_acs_url, enabled, group_mappings)
		 VALUES ($1, 'https://idp.test/sso', '\x00'::bytea, 'https://sp.test', 'https://sp.test/acs', TRUE, '[]'::jsonb)`,
		samlEntity); err != nil {
		t.Fatalf("seed saml: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM saml_sp_registrations WHERE idp_entity_id = $1`, samlEntity) //nolint:errcheck
	})

	// identity.write + roles.manage + users.read is enough to pass the unscoped
	// gate and the roles.manage gate — and deliberately NOT enough for Rule A:
	// super_admin also grants users.write (among others), which this principal
	// does not hold.
	limited := &auth.Claims{
		UserID: 1, IsAdmin: true,
		Permissions: []string{
			permissions.PermIdentityWrite,
			permissions.PermRolesManage,
			permissions.PermUsersRead,
		},
		GlobalPermissions: []string{
			permissions.PermIdentityWrite,
			permissions.PermRolesManage,
			permissions.PermUsersRead,
		},
	}
	// Snapshot any pre-existing grant-authority record: earlier legitimate
	// writes may have seeded one, and the refusal must leave it untouched.
	var preBy, preAt json.RawMessage
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE((SELECT value->'super_admin'->'authorized_by'
		                    FROM system_config WHERE key = 'sso_admin_role_grant_authority'),
		                 'null'::jsonb),
		        COALESCE((SELECT value->'super_admin'->'authorized_at'
		                    FROM system_config WHERE key = 'sso_admin_role_grant_authority'),
		                 'null'::jsonb)`).Scan(&preBy, &preAt); err != nil {
		t.Fatalf("snapshot grant authority record: %v", err)
	}

	req := httptest.NewRequest(http.MethodPut, "/admin/identity/group-mappings/saml/"+samlEntity,
		strings.NewReader(`[{"idp_group":"admins","admin_role":"super_admin"}]`))
	req.SetPathValue("type", "saml")
	req.SetPathValue("id", samlEntity)
	req = req.WithContext(auth.ContextWithUser(req.Context(), limited))
	rec := httptest.NewRecorder()
	h.UpdateGroupMappings(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("super_admin mapping by a principal not holding the role's permissions: want 403, got %d (%s)",
			rec.Code, rec.Body.String())
	}

	// Nothing persisted: the mapping stays empty.
	var raw json.RawMessage
	if err := pool.QueryRow(ctx,
		`SELECT group_mappings FROM saml_sp_registrations WHERE idp_entity_id = $1`, samlEntity).Scan(&raw); err != nil {
		t.Fatalf("read saml mappings: %v", err)
	}
	if string(raw) != "[]" {
		t.Fatalf("refused mapping persisted anyway: %s", raw)
	}
	// And no grant-authority record was minted or refreshed for the refused
	// label (any pre-existing record is byte-identical to the snapshot).
	var postBy, postAt json.RawMessage
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE((SELECT value->'super_admin'->'authorized_by'
		                    FROM system_config WHERE key = 'sso_admin_role_grant_authority'),
		                 'null'::jsonb),
		        COALESCE((SELECT value->'super_admin'->'authorized_at'
		                    FROM system_config WHERE key = 'sso_admin_role_grant_authority'),
		                 'null'::jsonb)`).Scan(&postBy, &postAt); err != nil {
		t.Fatalf("read grant authority record: %v", err)
	}
	if string(postBy) != string(preBy) || string(postAt) != string(preAt) {
		t.Fatalf("refused mapping changed the grant-authority record: authorized_by %s→%s, at %s→%s",
			preBy, postBy, preAt, postAt)
	}
}

// TestIdentityGroupMappings_RejectsUnknownAdminRoleLabel pins the governed
// label ceiling: only the four authserver-mintable builtin labels may be wired
// to an IdP group; anything else is a 400, never a silently unminted mapping.
func TestIdentityGroupMappings_RejectsUnknownAdminRoleLabel(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())

	suffix := rolesTestRandomSuffix(t)
	samlEntity := "urn:idtest:" + suffix
	if _, err := pool.Exec(ctx,
		`INSERT INTO saml_sp_registrations
		   (idp_entity_id, idp_sso_url, idp_cert_enc, sp_entity_id, sp_acs_url, enabled, group_mappings)
		 VALUES ($1, 'https://idp.test/sso', '\x00'::bytea, 'https://sp.test', 'https://sp.test/acs', TRUE, '[]'::jsonb)`,
		samlEntity); err != nil {
		t.Fatalf("seed saml: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM saml_sp_registrations WHERE idp_entity_id = $1`, samlEntity) //nolint:errcheck
	})

	req := httptest.NewRequest(http.MethodPut, "/admin/identity/group-mappings/saml/"+samlEntity,
		strings.NewReader(`[{"idp_group":"admins","admin_role":"superadmin"}]`))
	req.SetPathValue("type", "saml")
	req.SetPathValue("id", samlEntity)
	req = globalIdentityAdminRequest(req)
	rec := httptest.NewRecorder()
	h.UpdateGroupMappings(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("ungoverned admin role label: want 400, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestIdentityGroupMappings_DistributionOnlyStaysIdentityWrite preserves the
// non-escalation path: a mapping that carries no admin role never needed
// roles.manage and must keep working for an identity.write-only holder.
func TestIdentityGroupMappings_DistributionOnlyStaysIdentityWrite(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())

	suffix := rolesTestRandomSuffix(t)
	samlEntity := "urn:idtest:" + suffix
	if _, err := pool.Exec(ctx,
		`INSERT INTO saml_sp_registrations
		   (idp_entity_id, idp_sso_url, idp_cert_enc, sp_entity_id, sp_acs_url, enabled, group_mappings)
		 VALUES ($1, 'https://idp.test/sso', '\x00'::bytea, 'https://sp.test', 'https://sp.test/acs', TRUE, '[]'::jsonb)`,
		samlEntity); err != nil {
		t.Fatalf("seed saml: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM saml_sp_registrations WHERE idp_entity_id = $1`, samlEntity) //nolint:errcheck
	})

	identityOnly := &auth.Claims{
		UserID: 1, IsAdmin: true,
		Permissions:       []string{permissions.PermIdentityWrite},
		GlobalPermissions: []string{permissions.PermIdentityWrite},
	}
	req := httptest.NewRequest(http.MethodPut, "/admin/identity/group-mappings/saml/"+samlEntity,
		strings.NewReader(`[{"idp_group":"Engineering","distribution_group_id":42}]`))
	req.SetPathValue("type", "saml")
	req.SetPathValue("id", samlEntity)
	req = req.WithContext(auth.ContextWithUser(req.Context(), identityOnly))
	rec := httptest.NewRecorder()
	h.UpdateGroupMappings(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("distribution-only mapping without roles.manage: want 204, got %d (%s)",
			rec.Code, rec.Body.String())
	}
}
