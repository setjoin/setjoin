package user

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/migration"
)

// newTestMigrationHandler builds a MigrationHandler backed by a nil MinIO
// client — fine for these tests since the ownership/authz guards under test
// must reject the request before any orchestrator upload/job-start call ever
// touches MinIO.
func newTestMigrationHandler(pool *pgxpool.Pool) *MigrationHandler {
	orch := migration.NewOrchestrator(pool, nil, "test-bucket", "test-root-key", testLogger(), context.Background(), nil)
	return NewMigrationHandler(orch, pool, testLogger())
}

// insertTestMigrationJob inserts a pending migration_jobs row owned by
// userID and returns its ID. Cleans up after the test.
func insertTestMigrationJob(t *testing.T, pool *pgxpool.Pool, userID, mailboxID int64) int64 {
	t.Helper()
	ctx := context.Background()
	var jobID int64
	err := pool.QueryRow(ctx, `
		INSERT INTO migration_jobs (user_id, source_type, target_mailbox_id, conflict_strategy, status)
		VALUES ($1, 'ics', $2, 'skip', 'pending')
		RETURNING id`,
		userID, mailboxID,
	).Scan(&jobID)
	if err != nil {
		t.Fatalf("insertTestMigrationJob: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM migration_jobs WHERE id = $1`, jobID)
	})
	return jobID
}

// TestStartMigration_RejectsBulkTargets is the regression test for BUG 1: the
// self-service route (POST /auth/me/migration) must not accept a
// targets[] bulk/impersonation payload — that would let any authenticated
// user import content into an arbitrary target mailbox with no ownership or
// admin check. Bulk migration has its own admin-gated surface
// (POST /admin/migration/start).
func TestStartMigration_RejectsBulkTargets(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)

	attackerID := createTestUser(t, pool)
	victimID := createTestUser(t, pool)
	victimMailboxID := ensureTestMailbox(t, pool, victimID)

	var before int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM migration_jobs WHERE target_mailbox_id = $1`, victimMailboxID,
	).Scan(&before); err != nil {
		t.Fatalf("count before: %v", err)
	}

	body := `{"sourceType":"ews","targets":[{"targetEmail":"` + emailForUser(t, pool, victimID) + `"}]}`
	req := httptest.NewRequest(http.MethodPost, "/auth/me/migration", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: attackerID, Type: auth.TypeAccess}
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()

	h.StartMigration(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("StartMigration with targets returned %d, want 403: %s", rec.Code, rec.Body.String())
	}

	var after int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM migration_jobs WHERE target_mailbox_id = $1`, victimMailboxID,
	).Scan(&after); err != nil {
		t.Fatalf("count after: %v", err)
	}
	if after != before {
		t.Fatalf("migration_jobs row created against victim mailbox: before=%d after=%d", before, after)
	}
}

// emailForUser looks up the email address of a test user (mirrors how
// getMailboxIDByEmail resolves targets by email).
func emailForUser(t *testing.T, pool *pgxpool.Pool, userID int64) string {
	t.Helper()
	var email string
	if err := pool.QueryRow(context.Background(), `SELECT email FROM users WHERE id = $1`, userID).Scan(&email); err != nil {
		t.Fatalf("emailForUser: %v", err)
	}
	return email
}

// ewsJobCount returns the number of EWS migration jobs owned by userID.
func ewsJobCount(t *testing.T, pool *pgxpool.Pool, userID int64) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM migration_jobs WHERE user_id = $1 AND source_type = 'ews'`, userID,
	).Scan(&n); err != nil {
		t.Fatalf("ewsJobCount: %v", err)
	}
	return n
}

// postStartMigration invokes the self-service StartMigration handler as the
// given user with a JSON body and returns the recorder.
func postStartMigration(t *testing.T, h *MigrationHandler, userID int64, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/auth/me/migration", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: userID, Type: auth.TypeAccess}
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.StartMigration(rec, req)
	return rec
}

// TestStartMigration_RejectsSelfServiceImpersonation is the regression test
// for D-MAILSERVER-INTERNAL-MIGRATION-F-002: in the default admin profile the
// global EWS auth mode allowed impersonation, and the self-service single-job
// path copied a caller-supplied impersonateAs verbatim into the effective
// connector — any authenticated user could act AS another mailbox with the
// shared service account. Impersonation is admin-only now: the field is
// rejected (not silently stripped) so the caller knows it is not honored.
func TestStartMigration_RejectsSelfServiceImpersonation(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)

	userID := createTestUser(t, pool)
	ensureTestMailbox(t, pool, userID)

	before := ewsJobCount(t, pool, userID)
	body := `{"sourceType":"ews","config":{"serverURL":"https://exchange.example/EWS/Exchange.asmx","username":"me@corp.example","password":"pw","impersonateAs":"someone-else@corp.example"}}`
	rec := postStartMigration(t, h, userID, body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("StartMigration with impersonateAs returned %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "impersonation is admin-only") {
		t.Fatalf("rejection body must name the admin-only rule: %s", rec.Body.String())
	}
	if after := ewsJobCount(t, pool, userID); after != before {
		t.Fatalf("migration job created despite impersonateAs rejection: before=%d after=%d", before, after)
	}
}

// TestStartMigration_EWSWithoutImpersonateAsCreatesJob pins the positive
// self-service path: an EWS job without impersonateAs works as before, and the
// stored per-job config carries no impersonation principal.
func TestStartMigration_EWSWithoutImpersonateAsCreatesJob(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)

	userID := createTestUser(t, pool)
	ensureTestMailbox(t, pool, userID)

	// Port 9 (discard) on loopback: the background StartJob connector phase
	// fails fast at dial and never reaches the (nil) MinIO client.
	body := `{"sourceType":"ews","config":{"serverURL":"https://127.0.0.1:9/EWS/Exchange.asmx","username":"me@corp.example","password":"pw","includeMail":true}}`
	rec := postStartMigration(t, h, userID, body)

	if rec.Code != http.StatusCreated {
		t.Fatalf("StartMigration without impersonateAs returned %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == 0 {
		t.Fatalf("201 body missing job id: %s", rec.Body.String())
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM migration_jobs WHERE id = $1`, created.ID)
	})

	var enc []byte
	if err := pool.QueryRow(context.Background(),
		`SELECT source_config_enc FROM migration_jobs WHERE id = $1 AND user_id = $2`, created.ID, userID,
	).Scan(&enc); err != nil {
		t.Fatalf("load created job: %v", err)
	}
	var jobCfg migration.MigrationJobConfig
	if err := migration.DecryptConfigAny(enc, h.orch.EncryptionKey(), &jobCfg); err != nil {
		t.Fatalf("decrypt job config: %v", err)
	}
	if jobCfg.EWS == nil {
		t.Fatalf("job config has no EWS section: %+v", jobCfg)
	}
	if jobCfg.EWS.ImpersonateAs != "" {
		t.Fatalf("self-service job stored an impersonation principal: %q", jobCfg.EWS.ImpersonateAs)
	}
	if jobCfg.EWS.ServerURL != "https://127.0.0.1:9/EWS/Exchange.asmx" {
		t.Fatalf("job config serverURL regressed: %q", jobCfg.EWS.ServerURL)
	}
}

// restoreEWSGlobal snapshots the ews.global system_config row (or its
// absence) and restores it on cleanup.
func restoreEWSGlobal(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var oldValue []byte
	var oldEncrypted bool
	var had bool
	if err := pool.QueryRow(context.Background(),
		`SELECT value, encrypted FROM system_config WHERE key='ews.global'`,
	).Scan(&oldValue, &oldEncrypted); err == nil {
		had = true
	}
	t.Cleanup(func() {
		if had {
			pool.Exec(context.Background(),
				`INSERT INTO system_config(key,value,encrypted) VALUES('ews.global',$1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, encrypted=EXCLUDED.encrypted`,
				oldValue, oldEncrypted)
		} else {
			pool.Exec(context.Background(), `DELETE FROM system_config WHERE key='ews.global'`)
		}
	})
}

// storedEWSGlobal reads back and decrypts the ews.global system_config row.
func storedEWSGlobal(t *testing.T, h *MigrationHandler, pool *pgxpool.Pool) migration.GlobalEWSConfig {
	t.Helper()
	var value []byte
	var encrypted bool
	if err := pool.QueryRow(context.Background(),
		`SELECT value, encrypted FROM system_config WHERE key='ews.global'`,
	).Scan(&value, &encrypted); err != nil {
		t.Fatalf("read ews.global: %v", err)
	}
	if !encrypted {
		t.Fatalf("ews.global must be stored encrypted")
	}
	var wrapper struct {
		Enc string `json:"_enc"`
	}
	if err := json.Unmarshal(value, &wrapper); err != nil {
		t.Fatalf("parse ews.global wrapper: %v", err)
	}
	encBytes, err := base64.StdEncoding.DecodeString(wrapper.Enc)
	if err != nil {
		t.Fatalf("decode ews.global: %v", err)
	}
	systemKey, err := migration.DeriveKey(h.orch.EncryptionRoot(), "system")
	if err != nil {
		t.Fatalf("derive system key: %v", err)
	}
	var cfg migration.GlobalEWSConfig
	if err := migration.DecryptConfigAny(encBytes, systemKey, &cfg); err != nil {
		t.Fatalf("decrypt ews.global: %v", err)
	}
	return cfg
}

// TestSaveGlobalEWSConfig_EmptyAuthModeDefaultsToPerUser is the second
// regression test for D-MAILSERVER-INTERNAL-MIGRATION-F-002: an empty-save
// global EWS config used to DEFAULT to impersonation mode, which is what made
// the self-service selector effective for every user. Impersonation requires
// explicit admin opt-in now; empty saves get per_user. An explicit
// impersonation save is still honored (opt-in preserved).
func TestSaveGlobalEWSConfig_EmptyAuthModeDefaultsToPerUser(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	restoreEWSGlobal(t, pool)

	post := func(t *testing.T, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPut, "/admin/migration/sources/ews", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.SaveGlobalEWSConfig(rec, req)
		return rec
	}

	// Empty authMode: defaults to per_user, never impersonation.
	if rec := post(t, `{"serverURL":"https://exchange.internal/EWS/Exchange.asmx","username":"svc-migration","password":"svc-secret"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("empty authMode save returned %d, want 204: %s", rec.Code, rec.Body.String())
	}
	if cfg := storedEWSGlobal(t, h, pool); cfg.AuthMode != migration.EWSAuthModePerUser {
		t.Fatalf("empty-save AuthMode = %q, want per_user", cfg.AuthMode)
	}

	// Explicit admin opt-in to impersonation mode is still stored verbatim.
	if rec := post(t, `{"serverURL":"https://exchange.internal/EWS/Exchange.asmx","username":"svc-migration","password":"svc-secret","authMode":"impersonation"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("explicit impersonation save returned %d, want 204: %s", rec.Code, rec.Body.String())
	}
	if cfg := storedEWSGlobal(t, h, pool); cfg.AuthMode != migration.EWSAuthModeImpersonation {
		t.Fatalf("explicit impersonation save lost: AuthMode = %q", cfg.AuthMode)
	}

	// Even with the profile explicitly in impersonation mode, the self-service
	// per-job rejection still holds (defense in depth: the ingress check is
	// unconditional, not qualified by the global auth mode).
	if rec := postStartMigration(t, h, mustTestUserWithMailbox(t, pool),
		`{"sourceType":"ews","config":{"serverURL":"https://exchange.example/EWS/Exchange.asmx","impersonateAs":"someone-else@corp.example"}}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("self-service impersonateAs accepted in impersonation mode: %d %s", rec.Code, rec.Body.String())
	}
}

// mustTestUserWithMailbox creates a user with a primary mailbox and returns
// the user ID (failure is fatal to the test).
func mustTestUserWithMailbox(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	userID := createTestUser(t, pool)
	ensureTestMailbox(t, pool, userID)
	return userID
}

// TestUploadMigrationFiles_RejectsCrossUserJobID is the regression test for
// BUG 2: UploadMigrationFiles must verify the job_id belongs to the caller
// before storing upload content — otherwise any authenticated user can
// inject ICS/VCF content into another user's migration job by
// guessing/enumerating job_id. The handler is wired to an orchestrator with
// a nil MinIO client, so if the ownership check were skipped, the fallthrough
// to orch.StoreUpload would nil-pointer-panic — the 404 assertion below only
// passes if the guard runs first.
func TestUploadMigrationFiles_RejectsCrossUserJobID(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)

	attackerID := createTestUser(t, pool)
	victimID := createTestUser(t, pool)
	victimMailboxID := ensureTestMailbox(t, pool, victimID)
	victimJobID := insertTestMigrationJob(t, pool, victimID, victimMailboxID)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile("ics", "attack.ics")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	part.Write([]byte("BEGIN:VCALENDAR\nEND:VCALENDAR\n"))
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/auth/me/migration/upload?job_id="+strconv.FormatInt(victimJobID, 10), &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	claims := &auth.Claims{UserID: attackerID, Type: auth.TypeAccess}
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()

	h.UploadMigrationFiles(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("UploadMigrationFiles cross-user upload returned %d, want 404: %s", rec.Code, rec.Body.String())
	}
}

// seedEWSGlobalProfile replaces the ews.global system_config row with an
// encrypted service-account profile (mirrors seedEWSGlobalConfig in the
// migration package tests). Call restoreEWSGlobal first so cleanup restores
// the prior row.
func seedEWSGlobalProfile(t *testing.T, h *MigrationHandler, pool *pgxpool.Pool) {
	t.Helper()
	systemKey, err := migration.DeriveKey(h.orch.EncryptionRoot(), "system")
	if err != nil {
		t.Fatal(err)
	}
	enc, err := migration.EncryptConfigAny(migration.GlobalEWSConfig{
		ServerURL: "https://exchange.internal/EWS/Exchange.asmx",
		Username:  "svc-migration",
		Password:  "svc-secret",
		AuthMode:  migration.EWSAuthModePerUser,
	}, systemKey)
	if err != nil {
		t.Fatal(err)
	}
	wrapper, _ := json.Marshal(map[string]string{"_enc": base64.StdEncoding.EncodeToString(enc)})
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO system_config(key,value,encrypted) VALUES('ews.global',$1,true)
		 ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, encrypted=true`, wrapper); err != nil {
		t.Fatal(err)
	}
}

// TestStartMigration_EWSRequiresCallerCredentials is the regression test for
// the shared-credential inheritance hole: a self-service request containing
// ONLY an EWS server URL used to pass ingress and inherit the global
// username/password, so with no impersonation selector the connector read the
// SHARED service account's own mailbox into the caller's mailbox. Self-service
// now requires the CALLER'S OWN complete credentials — unconditionally,
// regardless of whether a global EWS profile exists.
func TestStartMigration_EWSRequiresCallerCredentials(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	userID := mustTestUserWithMailbox(t, pool)

	body := `{"sourceType":"ews","config":{"serverURL":"https://exchange.example/EWS/Exchange.asmx"}}`
	assertRejected := func(t *testing.T, stage string) {
		t.Helper()
		before := ewsJobCount(t, pool, userID)
		rec := postStartMigration(t, h, userID, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: URL-only EWS request returned %d, want 400: %s", stage, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "self-service EWS migration requires your own username and password") {
			t.Fatalf("%s: rejection body must name the credential rule: %s", stage, rec.Body.String())
		}
		if after := ewsJobCount(t, pool, userID); after != before {
			t.Fatalf("%s: migration job created despite missing caller credentials: before=%d after=%d", stage, before, after)
		}
	}

	// Without a global profile: the rule is unconditional.
	restoreEWSGlobal(t, pool)
	if _, err := pool.Exec(context.Background(), `DELETE FROM system_config WHERE key='ews.global'`); err != nil {
		t.Fatal(err)
	}
	assertRejected(t, "no global profile")

	// With the shared service-account profile PRESENT: still refused — the
	// global username/password must never be inherited as the caller identity.
	seedEWSGlobalProfile(t, h, pool)
	assertRejected(t, "global profile present")
}

// TestStartMigration_EWSWithGlobalProfileStoresCallerCredentials pins the
// positive self-service path WITH a global profile present: the job is
// accepted (caller supplied their own credentials), stored with the
// SelfService marker, and carries the caller's credentials — never the shared
// service account's.
func TestStartMigration_EWSWithGlobalProfileStoresCallerCredentials(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	userID := mustTestUserWithMailbox(t, pool)
	restoreEWSGlobal(t, pool)
	seedEWSGlobalProfile(t, h, pool)

	// The effective origin is the admin-owned global one (exchange.internal),
	// so the background StartJob connector phase fails fast at DNS and never
	// reaches the (nil) MinIO client.
	body := `{"sourceType":"ews","config":{"serverURL":"https://exchange.internal/EWS/Exchange.asmx","username":"alice@corp.example","password":"alice-pw","includeMail":true}}`
	rec := postStartMigration(t, h, userID, body)

	if rec.Code != http.StatusCreated {
		t.Fatalf("StartMigration with own credentials returned %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == 0 {
		t.Fatalf("201 body missing job id: %s", rec.Body.String())
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM migration_jobs WHERE id = $1`, created.ID)
	})

	var enc []byte
	if err := pool.QueryRow(context.Background(),
		`SELECT source_config_enc FROM migration_jobs WHERE id = $1 AND user_id = $2`, created.ID, userID,
	).Scan(&enc); err != nil {
		t.Fatalf("load created job: %v", err)
	}
	var jobCfg migration.MigrationJobConfig
	if err := migration.DecryptConfigAny(enc, h.orch.EncryptionKey(), &jobCfg); err != nil {
		t.Fatalf("decrypt job config: %v", err)
	}
	if jobCfg.SelfService == nil || !*jobCfg.SelfService {
		t.Fatalf("self-service job stored without the SelfService credential-boundary marker")
	}
	if jobCfg.EWS == nil {
		t.Fatalf("job config has no EWS section: %+v", jobCfg)
	}
	if jobCfg.EWS.Username != "alice@corp.example" || jobCfg.EWS.Password != "alice-pw" {
		t.Fatalf("caller credentials lost: username=%q password set=%v", jobCfg.EWS.Username, jobCfg.EWS.Password != "")
	}
	if jobCfg.EWS.Username == "svc-migration" || jobCfg.EWS.Password == "svc-secret" {
		t.Fatalf("shared service-account credentials leaked into the self-service job config")
	}
	if jobCfg.EWS.ImpersonateAs != "" {
		t.Fatalf("self-service job stored an impersonation principal: %q", jobCfg.EWS.ImpersonateAs)
	}
}
