package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

type failInventoryRow struct{ err error }

func (r failInventoryRow) Scan(...any) error { return r.err }

func globalIdentityAdminRequest(req *http.Request) *http.Request {
	return globalIdentityAdminRequestAs(1, req)
}

// globalIdentityAdminRequestAs injects global-admin claims for an EXPLICIT
// actor id. Tests whose fence path resolves the actor's DB authority (Rule A
// scope arm, granted_by FKs) must inject a user their own fixture created —
// user 1 is baseline seed data that a shared database gives no guarantee
// about.
func globalIdentityAdminRequestAs(userID int64, req *http.Request) *http.Request {
	return req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID:            userID,
		IsAdmin:           true,
		Permissions:       permissions.AllPermissions,
		GlobalPermissions: permissions.AllPermissions,
	}))
}

type failNthInventoryDB struct {
	delegate identityInventoryQuerier
	failAt   int
	calls    int
}

func (db *failNthInventoryDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	db.calls++
	if db.calls == db.failAt {
		return failInventoryRow{err: errors.New("injected inventory query failure")}
	}
	return db.delegate.QueryRow(ctx, sql, args...)
}

type invalidLifecycleInventoryDB struct {
	delegate identityInventoryQuerier
	calls    int
}

func (db *invalidLifecycleInventoryDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	db.calls++
	if db.calls == 3 {
		return invalidLifecycleRow{}
	}
	return db.delegate.QueryRow(ctx, sql, args...)
}

type invalidLifecycleRow struct{}

func (invalidLifecycleRow) Scan(dest ...any) error {
	target := dest[0].(*[]byte)
	*target = []byte(`{"invalid"`)
	return nil
}

func TestIdentityInventoryAggregateOnly(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())

	suffix := rolesTestRandomSuffix(t)
	email := "identity-inventory-" + suffix + "@mk.test"
	subject := "inventory-subject-" + suffix
	source := "ad"
	secretKey := "ad_sync_inventory_" + suffix + "_enc"
	attentionKey := "ldap_sync_inventory_" + suffix + "_enc"
	fakeCiphertext := "must-not-leak-" + suffix

	var domainID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO domains (name, is_local)
		VALUES ('mk.test', TRUE)
		ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		RETURNING id
	`).Scan(&domainID); err != nil {
		t.Fatalf("seed domain: %v", err)
	}

	var userID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (
			username, domain_id, email, display_name, password_hash,
			sync_source, oidc_subject, oidc_issuer
		)
		VALUES ($1, $2, $3, 'Inventory Fixture', 'x', $4, $5, 'https://issuer.example')
		RETURNING id
	`, "identity-inventory-"+suffix, domainID, email, source, subject).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO identity_legacy_federation_pair_inventory (
			user_id,
			oidc_subject_missing,
			oidc_issuer_missing,
			saml_name_id_missing,
			saml_idp_entity_missing
		)
		VALUES ($1, TRUE, FALSE, TRUE, TRUE)
	`, userID); err != nil {
		t.Fatalf("seed legacy inventory: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO system_config (key, value, encrypted)
		VALUES (
			$1,
			jsonb_build_object(
				'format', 'setjoin-config-secret',
				'version', 1,
				'keyVersion', 1,
				'sourceKey', 'legacy:ad',
				'ciphertext', $2::text
			),
			TRUE
		)
	`, secretKey, fakeCiphertext); err != nil {
		t.Fatalf("seed connector envelope: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO system_config (key, value, encrypted)
		VALUES ($1, to_jsonb('legacy-plaintext'::text), FALSE)
	`, attentionKey); err != nil {
		t.Fatalf("seed connector attention row: %v", err)
	}
	var assignmentID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		VALUES ($1, 4, NULL)
		RETURNING id
	`, userID).Scan(&assignmentID); err != nil {
		t.Fatalf("seed legacy role assignment: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO sso_admin_role_legacy_inventory (assignment_id)
		VALUES ($1)
	`, assignmentID); err != nil {
		t.Fatalf("seed legacy role inventory: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM admin_role_assignments WHERE id = $1`, assignmentID)           //nolint:errcheck
		pool.Exec(c, `DELETE FROM system_config WHERE key IN ($1, $2)`, secretKey, attentionKey) //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, userID)                                  //nolint:errcheck
	})

	req := globalIdentityAdminRequest(
		httptest.NewRequest(http.MethodGet, "/admin/identity/inventory", nil),
	)
	rec := httptest.NewRecorder()
	h.Inventory(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Inventory: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	var got IdentityInventory
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	if got.SchemaVersion != 1 {
		t.Errorf("schemaVersion = %d, want 1", got.SchemaVersion)
	}
	if got.LifecycleSources[source] < 1 {
		t.Errorf("lifecycle source count = %d, want at least fixture; got %+v", got.LifecycleSources[source], got.LifecycleSources)
	}
	if got.FederationPairs.OIDCComplete < 1 {
		t.Errorf("oidcComplete = %d, want at least fixture", got.FederationPairs.OIDCComplete)
	}
	if got.FederationPairs.LegacyInventoried < 1 {
		t.Errorf("legacyInventoried = %d, want at least fixture", got.FederationPairs.LegacyInventoried)
	}
	if got.ConnectorSecrets["ad"] != "encrypted" {
		t.Errorf("ad connector secret posture = %q, want encrypted", got.ConnectorSecrets["ad"])
	}
	if !containsString(got.Blockers, "unclassified_user_without_primary_mailbox") {
		t.Errorf("missing unclassified-user blocker: %v", got.Blockers)
	}
	if !containsString(got.Blockers, "legacy_incomplete_federation_pair") {
		t.Errorf("missing legacy-pair blocker: %v", got.Blockers)
	}
	if !containsString(got.Blockers, "legacy_sso_entitlement_provenance") {
		t.Errorf("missing legacy-entitlement blocker: %v", got.Blockers)
	}
	if !containsString(got.Blockers, "connector_secret_attention_required") {
		t.Errorf("missing connector-secret blocker: %v", got.Blockers)
	}

	body := rec.Body.String()
	for _, forbidden := range []string{email, subject, fakeCiphertext, secretKey, attentionKey} {
		if strings.Contains(body, forbidden) {
			t.Errorf("inventory leaked forbidden principal/secret material %q", forbidden)
		}
	}
}

func TestIdentityInventoryEveryQueryFailureFailsClosed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	for failAt := 1; failAt <= 6; failAt++ {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			h := NewIdentityHandler(pool, pool, testsupport.TestLogger())
			h.inventoryDB = &failNthInventoryDB{delegate: pool, failAt: failAt}
			rec := httptest.NewRecorder()
			h.Inventory(rec, globalIdentityAdminRequest(
				httptest.NewRequest(http.MethodGet, "/admin/identity/inventory", nil),
			))
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("query %d failure: want 500, got %d (%s)", failAt, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestIdentityInventoryRejectsMalformedLifecycleAggregate(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())
	h.inventoryDB = &invalidLifecycleInventoryDB{delegate: pool}
	rec := httptest.NewRecorder()
	h.Inventory(rec, globalIdentityAdminRequest(
		httptest.NewRequest(http.MethodGet, "/admin/identity/inventory", nil),
	))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("malformed lifecycle aggregate: want 500, got %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestIdentityInventoryFailsClosedWithoutWorkerPool(t *testing.T) {
	h := NewIdentityHandler(nil, nil, testsupport.TestLogger())
	req := globalIdentityAdminRequest(
		httptest.NewRequest(http.MethodGet, "/admin/identity/inventory", nil),
	)
	rec := httptest.NewRecorder()

	h.Inventory(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("Inventory without worker pool: want 500, got %d", rec.Code)
	}
}

func TestIdentityInventoryRejectsDomainScopedAdministratorBeforeQuery(t *testing.T) {
	db := &failNthInventoryDB{failAt: 1}
	h := NewIdentityHandler(nil, nil, testsupport.TestLogger())
	h.inventoryDB = db
	req := httptest.NewRequest(http.MethodGet, "/admin/identity/inventory", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: 1, IsAdmin: true,
		Permissions:       permissions.AllPermissions,
		GlobalPermissions: permissions.AllPermissions,
	}))
	req = req.WithContext(middleware.ContextWithDomainScope(req.Context(), 42))
	rec := httptest.NewRecorder()

	h.Inventory(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("domain-scoped inventory: want 403, got %d (%s)", rec.Code, rec.Body.String())
	}
	if db.calls != 0 {
		t.Fatalf("domain-scoped inventory reached database %d time(s)", db.calls)
	}
}

func TestIdentityInventoryRejectsOUScopeWithoutGlobalGrantBeforeQuery(t *testing.T) {
	db := &failNthInventoryDB{failAt: 1}
	h := NewIdentityHandler(nil, nil, testsupport.TestLogger())
	h.inventoryDB = db
	req := httptest.NewRequest(http.MethodGet, "/admin/identity/inventory", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: 1, IsAdmin: true,
		Permissions: []string{
			permissions.PermUsersRead,
			permissions.PermIdentityWrite,
		},
	}))
	rec := httptest.NewRecorder()

	h.Inventory(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("OU-scoped inventory: want 403, got %d (%s)", rec.Code, rec.Body.String())
	}
	if db.calls != 0 {
		t.Fatalf("OU-scoped inventory reached database %d time(s)", db.calls)
	}
}

func TestIdentityInventorySupportedArchetypesAndProtectedBoundary(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())
	suffix := rolesTestRandomSuffix(t)

	userIDs := make([]int64, 0, 3)
	for _, fixture := range []struct {
		label  string
		source string
	}{
		{"identity-local-" + suffix, "local"},
		{"identity-ad-" + suffix, "ad"},
		{"identity-ldap-" + suffix, "ldap"},
	} {
		var mailboxID, userID int64
		if err := pool.QueryRow(ctx, `SELECT public.mk_account($1)`, fixture.label).Scan(&mailboxID); err != nil {
			t.Fatalf("mk_account(%s): %v", fixture.label, err)
		}
		if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id = $1`, mailboxID).Scan(&userID); err != nil {
			t.Fatalf("resolve fixture user %s: %v", fixture.label, err)
		}
		if _, err := pool.Exec(ctx, `UPDATE users SET sync_source = $2 WHERE id = $1`, userID, fixture.source); err != nil {
			t.Fatalf("set fixture source %s: %v", fixture.label, err)
		}
		userIDs = append(userIDs, userID)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE users
		   SET oidc_subject = $2, oidc_issuer = 'https://issuer.example'
		 WHERE id = $1
	`, userIDs[0], "local-subject-"+suffix); err != nil {
		t.Fatalf("set local OIDC pair: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE users
		   SET saml_name_id = $2, saml_idp_entity_id = 'https://idp.example'
		 WHERE id = $1
	`, userIDs[1], "ad-nameid-"+suffix); err != nil {
		t.Fatalf("set AD SAML pair: %v", err)
	}

	var roleID, assignmentID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO admin_role_groups (name, permissions)
		VALUES ($1, ARRAY['identity.write'])
		RETURNING id
	`, "Identity Protected Fixture "+suffix).Scan(&roleID); err != nil {
		t.Fatalf("seed sensitive role: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		VALUES ($1, $2, $1)
		RETURNING id
	`, userIDs[0], roleID).Scan(&assignmentID); err != nil {
		t.Fatalf("seed sensitive assignment: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM admin_role_assignments WHERE id = $1`, assignmentID) //nolint:errcheck
		pool.Exec(c, `DELETE FROM admin_role_groups WHERE id = $1`, roleID)            //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id = ANY($1::bigint[])`, userIDs)        //nolint:errcheck
	})

	rec := httptest.NewRecorder()
	h.Inventory(rec, globalIdentityAdminRequest(
		httptest.NewRequest(http.MethodGet, "/admin/identity/inventory", nil),
	))
	if rec.Code != http.StatusOK {
		t.Fatalf("Inventory: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var got IdentityInventory
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	for _, source := range []string{"local", "ad", "ldap"} {
		if got.LifecycleSources[source] < 1 {
			t.Errorf("source %q count = %d, want at least fixture", source, got.LifecycleSources[source])
		}
	}
	if got.FederationPairs.OIDCComplete < 1 || got.FederationPairs.SAMLComplete < 1 {
		t.Errorf("complete federation pairs not inventoried: %+v", got.FederationPairs)
	}
	if got.ProtectedAccounts.SensitiveRoleHolders < 1 || got.ProtectedAccounts.Total < 1 {
		t.Errorf("sensitive role holder not protected: %+v", got.ProtectedAccounts)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
