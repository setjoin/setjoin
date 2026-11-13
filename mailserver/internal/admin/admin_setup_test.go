package admin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/backup"
	"setjoin.com/mailserver/internal/restore"
	"setjoin.com/mailserver/internal/storage"
	"setjoin.com/shared/testsupport"
)

// ─── PostSetupAdminRequest parsing tests ──────────────────────────────────

func TestCreateAdminRequestParsing(t *testing.T) {
	payload := `{"email":"admin@example.com","password":"secure-password-123"}`
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal([]byte(payload), &req); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if req.Email != "admin@example.com" {
		t.Errorf("email = %q, want admin@example.com", req.Email)
	}
	if req.Password != "secure-password-123" {
		t.Errorf("password = %q, want secure-password-123", req.Password)
	}
}

// ── Mock DB interfaces and types ─────────────────────────────────────────

// mockRow implements pgx.Row for testing.
type mockRow struct {
	scanFunc func(dest ...any) error
}

func (m *mockRow) Scan(dest ...any) error {
	return m.scanFunc(dest...)
}

// mockQuerier satisfies dbQuerier, returning the specified row for every call.
type mockQuerier struct {
	row pgx.Row
}

func (m *mockQuerier) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return m.row
}

// newSetupHandlerForTest creates a SetupHandler safe for tests (no pool needed).
func newSetupHandlerForTest(q dbQuerier) *SetupHandler {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return &SetupHandler{pool: nil, db: q, logger: logger}
}

// ── HTTP handler tests (with mocked DB) ───────────────────────────────────

func TestCreateInitialAdmin_EmptyEmail(t *testing.T) {
	q := &mockQuerier{}
	h := newSetupHandlerForTest(q)

	body := `{"email":"","password":"strong-password-123"}`
	req := httptest.NewRequest("POST", "/setup/create-admin", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.CreateInitialAdmin(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestCreateInitialAdmin_ShortPassword(t *testing.T) {
	q := &mockQuerier{}
	h := newSetupHandlerForTest(q)

	body := `{"email":"admin@test.com","password":"short"}`
	req := httptest.NewRequest("POST", "/setup/create-admin", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.CreateInitialAdmin(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestCreateInitialAdmin_InvalidJSON(t *testing.T) {
	q := &mockQuerier{}
	h := newSetupHandlerForTest(q)

	req := httptest.NewRequest("POST", "/setup/create-admin", strings.NewReader(`not json`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.CreateInitialAdmin(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestCreateInitialAdmin_MethodNotAllowed(t *testing.T) {
	q := &mockQuerier{}
	h := newSetupHandlerForTest(q)

	req := httptest.NewRequest("GET", "/setup/create-admin", nil)
	rec := httptest.NewRecorder()

	h.CreateInitialAdmin(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestCreateInitialAdmin_AlreadyInitialized(t *testing.T) {
	q := &mockQuerier{
		row: &mockRow{
			scanFunc: func(dest ...any) error {
				*(dest[0].(*int)) = 3 // 3 users exist
				return nil
			},
		},
	}
	h := newSetupHandlerForTest(q)

	body := `{"email":"admin@test.com","password":"strong-password-123"}`
	req := httptest.NewRequest("POST", "/setup/create-admin", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.CreateInitialAdmin(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestCreateInitialAdmin_DBErrorOnUserCheck(t *testing.T) {
	q := &mockQuerier{
		row: &mockRow{
			scanFunc: func(dest ...any) error {
				return errors.New("connection refused")
			},
		},
	}
	h := newSetupHandlerForTest(q)

	body := `{"email":"admin@test.com","password":"strong-password-123"}`
	req := httptest.NewRequest("POST", "/setup/create-admin", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.CreateInitialAdmin(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestSetupStatus_NotInitialized(t *testing.T) {
	q := &mockQuerier{
		row: &mockRow{
			scanFunc: func(dest ...any) error {
				*(dest[0].(*int)) = 0
				return nil
			},
		},
	}
	h := newSetupHandlerForTest(q)

	req := httptest.NewRequest("GET", "/setup/status", nil)
	rec := httptest.NewRecorder()

	h.SetupStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var resp map[string]bool
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["initialized"] != false {
		t.Errorf("initialized = %v, want false", resp["initialized"])
	}
}

func TestSetupStatus_AlreadyInitialized(t *testing.T) {
	q := &mockQuerier{
		row: &mockRow{
			scanFunc: func(dest ...any) error {
				*(dest[0].(*int)) = 5
				return nil
			},
		},
	}
	h := newSetupHandlerForTest(q)

	req := httptest.NewRequest("GET", "/setup/status", nil)
	rec := httptest.NewRecorder()

	h.SetupStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var resp map[string]bool
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["initialized"] != true {
		t.Errorf("initialized = %v, want true", resp["initialized"])
	}
}

func TestRestoreFinalizeContextSurvivesRequestCancellation(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	cancelParent()
	ctx, cancel := restoreFinalizeContext(parent)
	defer cancel()
	if err := ctx.Err(); err != nil {
		t.Fatalf("finalize context inherited request cancellation: %v", err)
	}
	if _, ok := ctx.Deadline(); !ok {
		t.Fatal("finalize context has no bounded deadline")
	}
}

// ─── Config value backup request parsing ──────────────────────────────────
// (existing tests preserved below, keep to avoid removal warnings)

func TestSetupHandler_ParseRestoreRequest(t *testing.T) {
	body := `{
		"provider": "s3",
		"endpoint": "https://s3.amazonaws.com",
		"region": "us-east-1",
		"bucket": "prism-backup",
		"access_key": "AKIATEST",
		"secret_key": "test-secret",
		"volume_path": "/data/seaweedfs",
		"type": "full"
	}`
	req := httptest.NewRequest("POST", "/setup/restore", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	var rr restoreRequest
	if err := json.NewDecoder(req.Body).Decode(&rr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rr.Provider != "s3" {
		t.Errorf("Provider = %q, want s3", rr.Provider)
	}
	if rr.Type != "full" {
		t.Errorf("Type = %q, want full", rr.Type)
	}
	if rr.VolumePath != "/data/seaweedfs" {
		t.Errorf("VolumePath = %q, want /data/seaweedfs", rr.VolumePath)
	}
}

func TestSetupHandler_ValidateRestoreRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     restoreRequest
		wantErr string
	}{
		{
			name: "valid full restore",
			req: restoreRequest{
				Provider: "s3", Bucket: "bkt", AccessKey: "k",
				SecretKey: "s", Type: "full",
			},
			wantErr: "",
		},
		{
			name: "valid config-only restore",
			req: restoreRequest{
				Provider: "s3", Bucket: "bkt", AccessKey: "k",
				SecretKey: "s", Type: "config",
			},
			wantErr: "",
		},
		{
			name: "missing bucket",
			req: restoreRequest{
				Provider: "s3", AccessKey: "k", SecretKey: "s", Type: "full",
			},
			wantErr: "bucket",
		},
		{
			name: "missing access key",
			req: restoreRequest{
				Provider: "s3", Bucket: "bkt", SecretKey: "s", Type: "full",
			},
			wantErr: "access_key",
		},
		{
			name: "invalid type",
			req: restoreRequest{
				Provider: "s3", Bucket: "bkt", AccessKey: "k",
				SecretKey: "s", Type: "invalid",
			},
			wantErr: "type",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.validate()
			if tt.wantErr == "" && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
			if tt.wantErr != "" && err == nil {
				t.Errorf("expected error containing %q, got nil", tt.wantErr)
			}
			if tt.wantErr != "" && err != nil && !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestSetupHandler_PreflightResponse(t *testing.T) {
	pf := preflightResponse{
		Timestamp:     "20260621T030000Z",
		ConfigSize:    1024,
		BlobCount:     100,
		BlobTotalSize: 5000,
		UserCount:     50,
		DomainCount:   2,
		Warnings:      []string{},
	}
	data, err := json.Marshal(pf)
	if err != nil {
		t.Fatal(err)
	}
	// The wire contract uses snake_case keys; assert the exact shape.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"timestamp", "blob_count", "blob_total_size_bytes", "config_size_bytes", "user_count", "domain_count", "warnings"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("preflight response missing contract key %q", k)
		}
	}
	var pf2 preflightResponse
	if err := json.Unmarshal(data, &pf2); err != nil {
		t.Fatal(err)
	}
	if pf2.BlobCount != 100 || pf2.ConfigSize != 1024 || pf2.Timestamp != "20260621T030000Z" {
		t.Errorf("round-trip mismatch: %+v", pf2)
	}
}

// ── Restore endpoints: PreFlight + StartRestore ───────────────────────────

// memStore is an in-memory restore.RestoreStore holding real content, used as
// both the fake backup (source) and fake primary (target) in handler tests.
type memStore struct {
	objs map[string][]byte
}

func newMemStore() *memStore { return &memStore{objs: map[string][]byte{}} }

func (m *memStore) HeadObject(_ context.Context, key string) (*storage.ObjectInfo, error) {
	b, ok := m.objs[key]
	if !ok {
		return nil, fmt.Errorf("not found: %s", key)
	}
	return &storage.ObjectInfo{Key: key, Size: int64(len(b))}, nil
}

func (m *memStore) GetObject(_ context.Context, key string) (io.ReadCloser, error) {
	b, ok := m.objs[key]
	if !ok {
		return nil, fmt.Errorf("not found: %s", key)
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (m *memStore) PutObject(_ context.Context, key string, data io.Reader, _ int64) error {
	b, err := io.ReadAll(data)
	if err != nil {
		return err
	}
	m.objs[key] = b
	return nil
}

func setupTestLogger() *slog.Logger {
	return testsupport.TestLogger()
}

// setupTestPool opens a pool to DB_DSN, skipping the test if it is unset.
func setupTestPool(t *testing.T) *pgxpool.Pool {
	return testsupport.OpenTestPool(t)
}

// usersExist reports whether the test DB already has users — the no-users guard
// returns 409 in that case, so the happy-path restore tests skip then.
func usersExist(t *testing.T, pool *pgxpool.Pool) bool {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), "SELECT COUNT(*) FROM users").Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	return n > 0
}

func validRestoreBody(typ string) string {
	return fmt.Sprintf(`{"provider":"s3","endpoint":"x","region":"r","bucket":"b","access_key":"k","secret_key":"s","type":%q}`, typ)
}

// newCountQuerier returns a mockQuerier whose user-count scan yields n.
func newCountQuerier(n int) *mockQuerier {
	return &mockQuerier{row: &mockRow{scanFunc: func(dest ...any) error {
		*(dest[0].(*int)) = n
		return nil
	}}}
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// ── validate() now accepts "blobs" ─────────────────────────────────────────

func TestRestoreRequest_BlobsTypeIsValid(t *testing.T) {
	r := restoreRequest{Provider: "s3", Bucket: "b", AccessKey: "k", SecretKey: "s", Type: "blobs"}
	if err := r.validate(); err != nil {
		t.Errorf("blobs type should be valid, got %v", err)
	}
}

// ── PreFlight ──────────────────────────────────────────────────────────────

func TestPreFlight_409WhenUsersExist(t *testing.T) {
	h := &SetupHandler{db: newCountQuerier(3), logger: setupTestLogger()}
	req := httptest.NewRequest("POST", "/setup/preflight", strings.NewReader(validRestoreBody("full")))
	rec := httptest.NewRecorder()
	h.PreFlight(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
}

func TestPreFlight_503WhenPrimaryNil(t *testing.T) {
	h := &SetupHandler{db: newCountQuerier(0), primary: nil, logger: setupTestLogger()}
	req := httptest.NewRequest("POST", "/setup/preflight", strings.NewReader(validRestoreBody("full")))
	rec := httptest.NewRecorder()
	h.PreFlight(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

func TestPreFlight_400OnInvalidBody(t *testing.T) {
	h := &SetupHandler{db: newCountQuerier(0), logger: setupTestLogger()}
	req := httptest.NewRequest("POST", "/setup/preflight", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	h.PreFlight(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// TestPreFlight_ReturnsManifestPreview seeds a fake backup-manifest.json and
// asserts the preview is returned. DB-backed (real pool for the user/domain
// counts); skips if the test DB already has users (the 409 guard fires).
func TestPreFlight_ReturnsManifestPreview(t *testing.T) {
	pool := setupTestPool(t)
	if usersExist(t, pool) {
		t.Skip("test DB has users — no-users guard returns 409; happy path not exercisable")
	}

	backupStore := newMemStore()
	man := backup.BackupManifest{
		Timestamp:     "20260621T030000Z",
		ConfigSize:    321,
		BlobCount:     2,
		BlobTotalSize: 99,
		BlobManifest:  backup.Manifest{Count: 2, TotalSize: 99, Hashes: []string{"a", "b"}},
	}
	raw, _ := json.Marshal(man)
	backupStore.objs["backup-manifest.json"] = raw

	h := &SetupHandler{
		pool:          pool,
		db:            pool,
		primary:       newMemStore(),
		logger:        setupTestLogger(),
		backupFactory: func(restoreRequest) (restore.RestoreStore, error) { return backupStore, nil },
	}
	req := httptest.NewRequest("POST", "/setup/preflight", strings.NewReader(validRestoreBody("full")))
	rec := httptest.NewRecorder()
	h.PreFlight(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp preflightResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Timestamp != "20260621T030000Z" || resp.BlobCount != 2 || resp.BlobTotalSize != 99 || resp.ConfigSize != 321 {
		t.Errorf("preview mismatch: %+v", resp)
	}
	if resp.Warnings == nil {
		t.Error("warnings must be a (possibly empty) array, not null")
	}
}

// TestPreFlight_400OnMissingManifest: a missing/corrupt backup-manifest.json is
// a 400, not a 500.
func TestPreFlight_400OnMissingManifest(t *testing.T) {
	pool := setupTestPool(t)
	if usersExist(t, pool) {
		t.Skip("test DB has users — guard returns 409 before manifest is read")
	}
	h := &SetupHandler{
		pool:          pool,
		db:            pool,
		primary:       newMemStore(),
		logger:        setupTestLogger(),
		backupFactory: func(restoreRequest) (restore.RestoreStore, error) { return newMemStore(), nil }, // empty: no manifest
	}
	req := httptest.NewRequest("POST", "/setup/preflight", strings.NewReader(validRestoreBody("full")))
	rec := httptest.NewRecorder()
	h.PreFlight(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for missing manifest; body=%s", rec.Code, rec.Body.String())
	}
}

// ── StartRestore ───────────────────────────────────────────────────────────

func TestStartRestore_409WhenUsersExist(t *testing.T) {
	h := &SetupHandler{db: newCountQuerier(2), logger: setupTestLogger()}
	req := httptest.NewRequest("POST", "/setup/restore", strings.NewReader(validRestoreBody("config")))
	rec := httptest.NewRecorder()
	h.StartRestore(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
}

func TestStartRestore_503WhenPrimaryNil(t *testing.T) {
	h := &SetupHandler{db: newCountQuerier(0), primary: nil, logger: setupTestLogger()}
	req := httptest.NewRequest("POST", "/setup/restore", strings.NewReader(validRestoreBody("config")))
	rec := httptest.NewRecorder()
	h.StartRestore(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

// TestStartRestore_RestoresConfig seeds a config.json in the fake backup and
// asserts the key lands in system_config and the response reports it. DB-backed.
func TestStartRestore_RestoresConfig(t *testing.T) {
	pool := setupTestPool(t)
	ctx := context.Background()
	if usersExist(t, pool) {
		t.Skip("test DB has users — no-users guard returns 409")
	}
	const key = "backup.admin_restore_config_test"
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key = $1`, key)
		_, _ = pool.Exec(ctx, `DELETE FROM restore_jobs WHERE restore_type = 'config' AND status IN ('completed','failed')`)
	})

	backupStore := newMemStore()
	cfg := map[string]backup.ConfigEntry{key: {Value: `"restored-by-handler"`}}
	raw, _ := json.Marshal(cfg)
	backupStore.objs["config.json"] = raw

	h := &SetupHandler{
		pool: pool, db: pool, primary: newMemStore(), logger: setupTestLogger(),
		backupFactory: func(restoreRequest) (restore.RestoreStore, error) { return backupStore, nil },
	}
	req := httptest.NewRequest("POST", "/setup/restore", strings.NewReader(validRestoreBody("config")))
	rec := httptest.NewRecorder()
	h.StartRestore(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp restoreResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "completed" {
		t.Errorf("status = %q, want completed", resp.Status)
	}
	if resp.RestoredConfigKeys < 1 {
		t.Errorf("restored_config_keys = %d, want >= 1", resp.RestoredConfigKeys)
	}
	if resp.RestoreJobID == 0 {
		t.Error("restore_job_id should be nonzero")
	}
	var got string
	if err := pool.QueryRow(ctx, `SELECT value FROM system_config WHERE key = $1`, key).Scan(&got); err != nil {
		t.Fatalf("config key not restored: %v", err)
	}
	if got != `"restored-by-handler"` {
		t.Errorf("restored value = %q, want %q", got, `"restored-by-handler"`)
	}
}

// TestStartRestore_RestoresBlobs seeds a blob in the fake backup + manifest and
// asserts it is written to the fake primary. DB-backed (for the restore_jobs row).
func TestStartRestore_RestoresBlobs(t *testing.T) {
	pool := setupTestPool(t)
	ctx := context.Background()
	if usersExist(t, pool) {
		t.Skip("test DB has users — no-users guard returns 409")
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM restore_jobs WHERE restore_type = 'blobs' AND status IN ('completed','failed')`)
	})

	content := []byte("blob-content-restored-by-handler")
	hash := sha256hex(content)
	backupStore := newMemStore()
	backupStore.objs["blobs/"+hash] = content
	man := backup.BackupManifest{BlobManifest: backup.Manifest{Hashes: []string{hash}, Count: 1}}
	raw, _ := json.Marshal(man)
	backupStore.objs["backup-manifest.json"] = raw

	primary := newMemStore()
	h := &SetupHandler{
		pool: pool, db: pool, primary: primary, logger: setupTestLogger(),
		backupFactory: func(restoreRequest) (restore.RestoreStore, error) { return backupStore, nil },
	}
	req := httptest.NewRequest("POST", "/setup/restore", strings.NewReader(validRestoreBody("blobs")))
	rec := httptest.NewRecorder()
	h.StartRestore(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp restoreResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.RestoredBlobs != 1 {
		t.Errorf("restored_blobs = %d, want 1", resp.RestoredBlobs)
	}
	if got, ok := primary.objs["blobs/"+hash]; !ok || !bytes.Equal(got, content) {
		t.Errorf("blob not written to primary: ok=%v", ok)
	}
}

// TestStartRestore_SingleFlight409: a second concurrent restore is rejected with
// 409 while one is already running. DB-backed — seed a running restore_jobs row.
func TestStartRestore_SingleFlight409(t *testing.T) {
	pool := setupTestPool(t)
	ctx := context.Background()
	if usersExist(t, pool) {
		t.Skip("test DB has users — no-users guard returns 409 before single-flight")
	}
	var runningID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO restore_jobs (status, restore_type, started_at) VALUES ('running','config', now()) RETURNING id`,
	).Scan(&runningID); err != nil {
		t.Fatalf("seed running job: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM restore_jobs WHERE id = $1`, runningID) })

	h := &SetupHandler{
		pool: pool, db: pool, primary: newMemStore(), logger: setupTestLogger(),
		backupFactory: func(restoreRequest) (restore.RestoreStore, error) { return newMemStore(), nil },
	}
	req := httptest.NewRequest("POST", "/setup/restore", strings.NewReader(validRestoreBody("config")))
	rec := httptest.NewRecorder()
	h.StartRestore(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409 (single-flight); body=%s", rec.Code, rec.Body.String())
	}
}
