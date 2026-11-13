package user

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/migration"
	"setjoin.com/shared/permissions"
)

// The tests in this file pin the M365 admin-consent callback remediation for
// D-MAILSERVER-INTERNAL-USER-F-002 (CWE-306): the callback must require a
// SERVER-SIDE, expiring, single-use consent authorization bound to the
// authenticated admin (m365_consent_states, V234) — an attacker-supplied
// equal cookie/query pair is not authentication — plus the mail.pipeline
// mutation permission, verify-before-persist ordering for the TenantID write,
// and a consent-completion audit row. The live expected state is never logged
// on mismatch.

const m365TestTenant = "11111111-2222-3333-4444-555555555555"

// consentTestClaims builds access-token claims for userID with (or without)
// the mail.pipeline mutation permission the callback requires.
func consentTestClaims(userID int64, withPerm bool) *auth.Claims {
	c := &auth.Claims{UserID: userID, Type: auth.TypeAccess}
	if withPerm {
		c.Permissions = []string{permissions.PermMailPipeline}
	}
	return c
}

// restoreM365AppConfig snapshots the m365.app system_config row (or its
// absence) and restores it on cleanup.
func restoreM365AppConfig(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var oldValue []byte
	var oldEncrypted bool
	var had bool
	if err := pool.QueryRow(context.Background(),
		`SELECT value, encrypted FROM system_config WHERE key='m365.app'`,
	).Scan(&oldValue, &oldEncrypted); err == nil {
		had = true
	}
	t.Cleanup(func() {
		if had {
			pool.Exec(context.Background(),
				`INSERT INTO system_config(key,value,encrypted) VALUES('m365.app',$1,$2)
				 ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, encrypted=EXCLUDED.encrypted`,
				oldValue, oldEncrypted)
		} else {
			pool.Exec(context.Background(), `DELETE FROM system_config WHERE key='m365.app'`)
		}
	})
}

// seedM365AppProfile replaces the m365.app system_config row with an
// encrypted app profile that carries NO tenant yet. Pair with
// restoreM365AppConfig for cleanup.
func seedM365AppProfile(t *testing.T, h *MigrationHandler, pool *pgxpool.Pool) {
	t.Helper()
	systemKey, err := migration.DeriveKey(h.orch.EncryptionRoot(), "system")
	if err != nil {
		t.Fatal(err)
	}
	enc, err := migration.EncryptConfigAny(migration.MigrationM365Config{
		ClientID:     "consent-test-client",
		ClientSecret: "consent-test-secret",
	}, systemKey)
	if err != nil {
		t.Fatal(err)
	}
	wrapper, _ := json.Marshal(map[string]string{"_enc": base64.StdEncoding.EncodeToString(enc)})
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO system_config(key,value,encrypted) VALUES('m365.app',$1,true)
		 ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, encrypted=true`, wrapper); err != nil {
		t.Fatal(err)
	}
}

// storedM365Config reads back and decrypts the m365.app system_config row.
func storedM365Config(t *testing.T, h *MigrationHandler, pool *pgxpool.Pool) migration.MigrationM365Config {
	t.Helper()
	var value []byte
	var encrypted bool
	if err := pool.QueryRow(context.Background(),
		`SELECT value, encrypted FROM system_config WHERE key='m365.app'`,
	).Scan(&value, &encrypted); err != nil {
		t.Fatalf("read m365.app: %v", err)
	}
	if !encrypted {
		t.Fatalf("m365.app must be stored encrypted")
	}
	var wrapper struct {
		Enc string `json:"_enc"`
	}
	if err := json.Unmarshal(value, &wrapper); err != nil {
		t.Fatalf("parse m365.app wrapper: %v", err)
	}
	encBytes, err := base64.StdEncoding.DecodeString(wrapper.Enc)
	if err != nil {
		t.Fatalf("decode m365.app: %v", err)
	}
	systemKey, err := migration.DeriveKey(h.orch.EncryptionRoot(), "system")
	if err != nil {
		t.Fatalf("derive system key: %v", err)
	}
	var cfg migration.MigrationM365Config
	if err := migration.DecryptConfigAny(encBytes, systemKey, &cfg); err != nil {
		t.Fatalf("decrypt m365.app: %v", err)
	}
	return cfg
}

// insertM365ConsentState seeds an m365_consent_states row for actor and
// returns the token. opts: expired/consumed controls for the negative tests.
func insertM365ConsentState(t *testing.T, pool *pgxpool.Pool, actor int64, token string, expired, consumed bool) string {
	t.Helper()
	ctx := context.Background()
	// Live rows: issued 1 minute ago with a 10-minute TTL (consumable).
	// Expired rows: issued 20 minutes ago, so the same 10-minute TTL lapsed
	// ~10 minutes ago while still satisfying the expires_at > issued_at CHECK.
	issued := time.Now().UTC().Add(-time.Minute)
	if expired {
		issued = time.Now().UTC().Add(-20 * time.Minute)
	}
	expires := issued.Add(10 * time.Minute)
	var consumedAt *time.Time
	if consumed {
		c := issued.Add(time.Second)
		consumedAt = &c
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO m365_consent_states (state_token, actor_user_id, cloud, issued_at, expires_at, consumed_at)
		VALUES ($1, $2, 'global', $3, $4, $5)`,
		token, actor, issued, expires, consumedAt,
	); err != nil {
		t.Fatalf("insertM365ConsentState: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM m365_consent_states WHERE state_token = $1`, token)
	})
	return token
}

// consentStateConsumed reports whether the named consent row is consumed.
func consentStateConsumed(t *testing.T, pool *pgxpool.Pool, token string) bool {
	t.Helper()
	var consumed bool
	if err := pool.QueryRow(context.Background(),
		`SELECT consumed_at IS NOT NULL FROM m365_consent_states WHERE state_token = $1`, token,
	).Scan(&consumed); err != nil {
		t.Fatalf("consentStateConsumed: %v", err)
	}
	return consumed
}

// m365ConsentAuditCount counts completed-consent audit rows for actor.
// admin_audit_log is append-only (trg_audit_append_only), so these rows are
// permanent evidence — no cleanup; every run uses a fresh user id, so the
// per-actor count is exact.
func m365ConsentAuditCount(t *testing.T, pool *pgxpool.Pool, actor int64) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM admin_audit_log WHERE action = 'm365_consent_completed' AND user_id = $1`,
		actor,
	).Scan(&n); err != nil {
		t.Fatalf("m365ConsentAuditCount: %v", err)
	}
	return n
}

// consentStateCloud reads the cloud value minted into a consent row.
func consentStateCloud(t *testing.T, pool *pgxpool.Pool, token string) string {
	t.Helper()
	var cloud string
	if err := pool.QueryRow(context.Background(),
		`SELECT cloud FROM m365_consent_states WHERE state_token = $1`, token,
	).Scan(&cloud); err != nil {
		t.Fatalf("consentStateCloud: %v", err)
	}
	return cloud
}

// restoreAuditFullLevel temporarily sets audit_policy.level to 'full' so the
// routine-tier consent audit row is actually written (it is suppressed at
// lean); restores the prior level on cleanup.
func restoreAuditFullLevel(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var prior string
	if err := pool.QueryRow(context.Background(),
		`SELECT level FROM audit_policy WHERE id = 1`,
	).Scan(&prior); err != nil {
		t.Skipf("audit_policy not available: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE audit_policy SET level = 'full' WHERE id = 1`); err != nil {
		t.Fatalf("set audit level full: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `UPDATE audit_policy SET level = $1 WHERE id = 1`, prior)
	})
}

// postM365Callback invokes the M365Callback handler as the given claims with
// the supplied cookie and query state values (a nil claims simulates an
// unauthenticated IdP redirect).
func postM365Callback(t *testing.T, h *MigrationHandler, claims *auth.Claims, cookieState, queryState string) *httptest.ResponseRecorder {
	t.Helper()
	target := "/admin/migration/m365/callback?admin_consent=True&tenant=" + m365TestTenant
	if queryState != "" {
		target += "&state=" + queryState
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if claims != nil {
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	}
	if cookieState != "" {
		req.AddCookie(&http.Cookie{Name: "m365_oauth_state", Value: cookieState})
	}
	rec := httptest.NewRecorder()
	h.M365Callback(rec, req)
	return rec
}

// TestM365Callback_RejectsFabricatedStateWithoutConsentAuthorization pins the
// core finding: an attacker-supplied equal cookie/query state pair — with no
// captured state and no admin interaction — is rejected and writes nothing to
// system_config, unauthenticated or authenticated. Even a genuine captured
// state is worthless to a DIFFERENT principal: the server-side authorization
// is bound to the minting admin.
func TestM365Callback_RejectsFabricatedStateWithoutConsentAuthorization(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	restoreM365AppConfig(t, pool)
	seedM365AppProfile(t, h, pool)

	fabricated := "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233"
	adminID := createTestUser(t, pool)
	attackerID := createTestUser(t, pool)

	before := storedM365Config(t, h, pool)

	// (a) Fully unauthenticated IdP-redirect lookalike.
	if rec := postM365Callback(t, h, nil, fabricated, fabricated); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated fabricated callback returned %d, want 401: %s", rec.Code, rec.Body.String())
	}
	// (b) Authenticated caller with a fabricated pair and NO server-side
	// consent authorization.
	if rec := postM365Callback(t, h, consentTestClaims(attackerID, true), fabricated, fabricated); rec.Code != http.StatusBadRequest {
		t.Fatalf("fabricated callback returned %d, want 400: %s", rec.Code, rec.Body.String())
	}
	// (c) A genuine state CAPTURED from the admin is still worthless to a
	// different principal — the row is bound to the minting admin's session.
	captured := insertM365ConsentState(t, pool, adminID, "captured-live-state-0001", false, false)
	if rec := postM365Callback(t, h, consentTestClaims(attackerID, true), captured, captured); rec.Code != http.StatusBadRequest {
		t.Fatalf("cross-principal captured-state callback returned %d, want 400: %s", rec.Code, rec.Body.String())
	}

	after := storedM365Config(t, h, pool)
	if after.TenantID != before.TenantID {
		t.Fatalf("system_config tenant changed by fabricated callback: before=%q after=%q", before.TenantID, after.TenantID)
	}
	if n := m365ConsentAuditCount(t, pool, attackerID); n != 0 {
		t.Fatalf("fabricated callback wrote %d audit rows, want 0", n)
	}
	// The captured row must still be unconsumed — the attacker's attempt
	// must not burn the admin's authorization.
	if consentStateConsumed(t, pool, captured) {
		t.Fatalf("attacker request consumed the admin's consent authorization")
	}
}

// TestM365Callback_RejectsReplayOfConsumedConsentState pins single-use
// enforcement server-side: the first successful callback consumes the
// authorization; replaying the same state is rejected before any
// re-verification or second write.
func TestM365Callback_RejectsReplayOfConsumedConsentState(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	restoreM365AppConfig(t, pool)
	seedM365AppProfile(t, h, pool)
	restoreAuditFullLevel(t, pool)

	adminID := createTestUser(t, pool)
	claims := consentTestClaims(adminID, true)

	var verifyCalls atomic.Int64
	h.verifyM365Tenant = func(ctx context.Context, cfg migration.MigrationM365Config) error {
		verifyCalls.Add(1)
		return nil
	}

	state := insertM365ConsentState(t, pool, adminID, "replay-first-use-0002", false, false)

	// First use completes (positive control for the replay below).
	if rec := postM365Callback(t, h, claims, state, state); rec.Code != http.StatusFound {
		t.Fatalf("first consent use returned %d, want 302: %s", rec.Code, rec.Body.String())
	}
	if got := verifyCalls.Load(); got != 1 {
		t.Fatalf("first use ran %d verifications, want 1", got)
	}
	if !consentStateConsumed(t, pool, state) {
		t.Fatalf("successful callback did not consume the consent state")
	}

	// Replay of the identical state: rejected server-side, no second
	// verification, no second audit row.
	if rec := postM365Callback(t, h, claims, state, state); rec.Code != http.StatusBadRequest {
		t.Fatalf("replayed consent state returned %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if got := verifyCalls.Load(); got != 1 {
		t.Fatalf("replay re-ran tenant verification: %d calls, want still 1", got)
	}
	if n := m365ConsentAuditCount(t, pool, adminID); n != 1 {
		t.Fatalf("audit rows after replay = %d, want exactly 1", n)
	}
}

// TestM365Callback_RejectsExpiredConsentState pins expiry: a consent
// authorization past its TTL is dead even if never consumed, and proves
// nothing is persisted or verified on its presentation.
func TestM365Callback_RejectsExpiredConsentState(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	restoreM365AppConfig(t, pool)
	seedM365AppProfile(t, h, pool)

	adminID := createTestUser(t, pool)
	var verifyCalls atomic.Int64
	h.verifyM365Tenant = func(ctx context.Context, cfg migration.MigrationM365Config) error {
		verifyCalls.Add(1)
		return nil
	}

	state := insertM365ConsentState(t, pool, adminID, "expired-consent-state-0003", true, false)
	before := storedM365Config(t, h, pool)

	if rec := postM365Callback(t, h, consentTestClaims(adminID, true), state, state); rec.Code != http.StatusBadRequest {
		t.Fatalf("expired consent state returned %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if got := verifyCalls.Load(); got != 0 {
		t.Fatalf("expired state reached tenant verification: %d calls, want 0", got)
	}
	if after := storedM365Config(t, h, pool); after.TenantID != before.TenantID {
		t.Fatalf("system_config tenant changed by expired-state callback: before=%q after=%q", before.TenantID, after.TenantID)
	}
	if n := m365ConsentAuditCount(t, pool, adminID); n != 0 {
		t.Fatalf("expired-state callback wrote %d audit rows, want 0", n)
	}
}

// TestM365Callback_VerifyFailurePersistsNoTenantID pins verify-before-persist
// ordering: when the candidate tenant connection does not verify, NO TenantID
// reaches system_config (the old flow wrote first and verified after). The
// consent state is spent either way — single use is not conditional on the
// verification outcome.
func TestM365Callback_VerifyFailurePersistsNoTenantID(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	restoreM365AppConfig(t, pool)
	seedM365AppProfile(t, h, pool)

	adminID := createTestUser(t, pool)
	h.verifyM365Tenant = func(ctx context.Context, cfg migration.MigrationM365Config) error {
		if cfg.TenantID != m365TestTenant {
			t.Errorf("verifier got TenantID %q, want the callback's tenant", cfg.TenantID)
		}
		return context.DeadlineExceeded // any verification failure
	}

	state := insertM365ConsentState(t, pool, adminID, "verify-fail-state-0004", false, false)
	before := storedM365Config(t, h, pool)

	if rec := postM365Callback(t, h, consentTestClaims(adminID, true), state, state); rec.Code != http.StatusInternalServerError {
		t.Fatalf("failed-verification callback returned %d, want 500: %s", rec.Code, rec.Body.String())
	}
	if after := storedM365Config(t, h, pool); after.TenantID != before.TenantID {
		t.Fatalf("failed verification persisted TenantID: before=%q after=%q", before.TenantID, after.TenantID)
	}
	if !consentStateConsumed(t, pool, state) {
		t.Fatalf("failed-verification callback did not consume the single-use state")
	}
	if n := m365ConsentAuditCount(t, pool, adminID); n != 0 {
		t.Fatalf("failed-verification callback wrote %d completion audit rows, want 0", n)
	}
}

// TestM365Callback_PositiveCompletesWithAuditAndPermission is the positive
// flow: the authenticated admin consent completes, TenantID+Cloud are
// persisted only then, the completion audit row lands, and the mail.pipeline
// mutation permission is REQUIRED — a claims without it is rejected 403
// before anything is verified or written.
func TestM365Callback_PositiveCompletesWithAuditAndPermission(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	restoreM365AppConfig(t, pool)
	seedM365AppProfile(t, h, pool)
	restoreAuditFullLevel(t, pool)

	adminID := createTestUser(t, pool)
	var verifyCalls atomic.Int64
	h.verifyM365Tenant = func(ctx context.Context, cfg migration.MigrationM365Config) error {
		verifyCalls.Add(1)
		return nil
	}

	// (a) Without the mutation permission: 403, nothing verified or written.
	noPermState := insertM365ConsentState(t, pool, adminID, "noperm-consent-state-0005", false, false)
	rec := postM365Callback(t, h, consentTestClaims(adminID, false), noPermState, noPermState)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("callback without mail.pipeline returned %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if got := verifyCalls.Load(); got != 0 {
		t.Fatalf("permission-less callback reached verification: %d calls, want 0", got)
	}
	if after := storedM365Config(t, h, pool); after.TenantID != "" {
		t.Fatalf("permission-less callback persisted TenantID %q", after.TenantID)
	}

	// (b) With the permission: the consent completes end-to-end.
	state := insertM365ConsentState(t, pool, adminID, "positive-consent-state-0006", false, false)
	rec = postM365Callback(t, h, consentTestClaims(adminID, true), state, state)
	if rec.Code != http.StatusFound {
		t.Fatalf("positive consent callback returned %d, want 302: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/migration?m365_connected=true" {
		t.Fatalf("positive consent redirect = %q, want /admin/migration?m365_connected=true", loc)
	}
	if got := verifyCalls.Load(); got != 1 {
		t.Fatalf("positive flow ran %d verifications, want 1", got)
	}
	cfg := storedM365Config(t, h, pool)
	if cfg.TenantID != m365TestTenant {
		t.Fatalf("persisted TenantID = %q, want %q", cfg.TenantID, m365TestTenant)
	}
	if cfg.Cloud != "global" {
		t.Fatalf("persisted Cloud = %q, want the consent row's cloud \"global\"", cfg.Cloud)
	}
	if !consentStateConsumed(t, pool, state) {
		t.Fatalf("successful callback did not consume the consent state")
	}
	if n := m365ConsentAuditCount(t, pool, adminID); n != 1 {
		t.Fatalf("completion audit rows = %d, want 1", n)
	}
	var notes string
	if err := pool.QueryRow(context.Background(),
		`SELECT notes FROM admin_audit_log WHERE action = 'm365_consent_completed' AND user_id = $1`,
		adminID,
	).Scan(&notes); err != nil {
		t.Fatalf("read completion audit row: %v", err)
	}
	if !strings.Contains(notes, m365TestTenant) || !strings.Contains(notes, "cloud=global") {
		t.Fatalf("completion audit notes %q must carry tenant and cloud", notes)
	}
}

// TestM365Connect_MintsSingleUseStateBoundToAdmin drives the full consent
// flow from the real mint: M365Connect (as the authenticated admin) must
// create the server-side authorization row carrying the selected cloud and
// put the SAME random token in both the OAuth state and the cookie; the
// callback then consumes exactly that row and persists the tenant with the
// minted cloud. A fabricated state still fails next to a live mint.
func TestM365Connect_MintsSingleUseStateBoundToAdmin(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	restoreM365AppConfig(t, pool)
	seedM365AppProfile(t, h, pool)
	restoreAuditFullLevel(t, pool)

	adminID := createTestUser(t, pool)
	claims := consentTestClaims(adminID, true)
	h.verifyM365Tenant = func(ctx context.Context, cfg migration.MigrationM365Config) error {
		return nil
	}

	// (a) Unauthenticated connect is refused.
	req := httptest.NewRequest(http.MethodGet, "/admin/migration/m365/connect?cloud=china", nil)
	rec := httptest.NewRecorder()
	h.M365Connect(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated connect returned %d, want 401", rec.Code)
	}

	// (b) Authenticated connect mints the server-side state.
	req = httptest.NewRequest(http.MethodGet, "/admin/migration/m365/connect?cloud=china", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec = httptest.NewRecorder()
	h.M365Connect(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("connect returned %d, want 302: %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse consent redirect %q: %v", rec.Header().Get("Location"), err)
	}
	if !strings.HasPrefix(loc.Scheme+"://"+loc.Host, "https://login.chinacloudapi.cn") {
		t.Fatalf("china cloud connect redirected to %q, want the chinacloudapi authority", loc)
	}
	minted := loc.Query().Get("state")
	if minted == "" || len(minted) != 64 { // 32 random bytes, hex-encoded
		t.Fatalf("consent redirect state %q is not a 32-byte server-generated token", minted)
	}
	if consentStateConsumed(t, pool, minted) {
		t.Fatalf("freshly minted consent state is already consumed")
	}
	if got := consentStateCloud(t, pool, minted); got != "china" {
		t.Fatalf("minted consent cloud = %q, want the connect request's \"china\"", got)
	}

	// (c) The callback consumes exactly the minted row end-to-end.
	rec = postM365Callback(t, h, claims, minted, minted)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback with minted state returned %d, want 302: %s", rec.Code, rec.Body.String())
	}
	cfg := storedM365Config(t, h, pool)
	if cfg.TenantID != m365TestTenant || cfg.Cloud != "china" {
		t.Fatalf("persisted tenant/cloud = %q/%q, want %q/china", cfg.TenantID, cfg.Cloud, m365TestTenant)
	}
	if !consentStateConsumed(t, pool, minted) {
		t.Fatalf("completed callback did not consume the minted consent state")
	}

	// (d) A fabricated state still cannot complete next to the spent mint.
	if rec := postM365Callback(t, h, claims, minted, minted); rec.Code != http.StatusBadRequest {
		t.Fatalf("replayed minted state returned %d, want 400", rec.Code)
	}
}
