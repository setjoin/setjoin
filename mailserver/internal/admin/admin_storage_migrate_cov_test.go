package admin

// Coverage suite for the storage-migration admin handler: the constructor,
// Status health projection against an unreachable endpoint, StartMigrate's
// target validation / admission / admission-closed arms, MigrateStatus's DB
// read model, MigrateCancel's typed-outcome mapping, and ListMigrations.
//
// The handler is exercised against the REAL process Migrator and database —
// the migration run itself targets an unreachable source endpoint, so the
// spawned run fails fast into a terminal status (asserted, never leaked).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/storage"
	"setjoin.com/shared/testsupport"
)

// newStorageMigrateCovHandler builds the handler over a minio client pointed
// at a closed loopback port (no network is ever reachable in these tests) and
// a real Migrator over the test pool.
func newStorageMigrateCovHandler(t *testing.T, pool *pgxpool.Pool, bucket string) (*StorageMigrateHandler, *storage.Migrator) {
	t.Helper()
	mc, err := minio.New("127.0.0.1:1", &minio.Options{
		Creds: credentials.NewStaticV4("cov", "cov", ""), Secure: false,
	})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}
	migrator := storage.NewMigrator(context.Background(), pool, testsupport.TestLogger())
	h := NewStorageMigrateHandler(migrator, pool, mc, bucket, testsupport.TestLogger())
	return h, migrator
}

// storageMigrateCovInsertRow inserts a migration row directly (the read-model
// fixture) and registers cleanup.
func storageMigrateCovInsertRow(t *testing.T, pool *pgxpool.Pool, status string, total, migrated int64) int64 {
	t.Helper()
	var id int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO storage_migrations (source_driver, target_driver, status, total_blobs, migrated, completed_at)
		 VALUES ('s3', 'posix', $1, $2, $3, CASE WHEN $1 IN ('completed','cancelled','cutover') THEN now() END)
		 RETURNING id`, status, total, migrated,
	).Scan(&id); err != nil {
		t.Fatalf("insert migration row: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM storage_migrations WHERE id = $1`, id)
	})
	return id
}

// TestStorageMigrateStatus_HealthOfUnreachableEndpoint covers Status: an
// unreachable bucket yields healthy=false / bucket=false with the provider
// projection — a 200 read model, not an error.
func TestStorageMigrateStatus_HealthOfUnreachableEndpoint(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h, _ := newStorageMigrateCovHandler(t, pool, "cov-bucket")

	req := httptest.NewRequest(http.MethodGet, "/admin/storage/migrate/status", nil)
	rec := httptest.NewRecorder()
	h.Status(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Status: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if body["healthy"] != false || body["bucket"] != false {
		t.Errorf("unreachable endpoint must report healthy=false bucket=false: %v", body)
	}
	if body["provider"] != "s3" {
		t.Errorf("provider = %v, want s3", body["provider"])
	}
}

// TestStorageMigrateStartMigrate_TargetValidation covers the target arms: a
// missing target (no env default) and the same-provider target are refused
// with 400; an unknown provider fails target-driver creation with 500.
func TestStorageMigrateStartMigrate_TargetValidation(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h, _ := newStorageMigrateCovHandler(t, pool, "cov-bucket")

	for _, tc := range []struct {
		name   string
		target string
		want   int
	}{
		{"missing target", "", http.StatusBadRequest},
		{"same provider s3", "s3", http.StatusBadRequest},
		{"unknown provider", "tapedeck", http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/admin/storage/migrate?target="+tc.target, nil)
			rec := httptest.NewRecorder()
			h.StartMigrate(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("target=%q: want %d, got %d (body=%s)", tc.target, tc.want, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestStorageMigrateStartMigrate_AdmissionLifecycle covers the Migrator
// admission contract end to end: a posix target (temp root) admits the
// migration durably (202 with the row id), the spawned run over an
// unreachable source terminates in a terminal row status, and a START after
// Shutdown is refused with 503 (admission closed) — the request never
// creates a zombie worker.
func TestStorageMigrateStartMigrate_AdmissionLifecycle(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h, migrator := newStorageMigrateCovHandler(t, pool, t.TempDir())

	req := httptest.NewRequest(http.MethodPost, "/admin/storage/migrate?target=posix", nil)
	rec := httptest.NewRecorder()
	h.StartMigrate(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("start: want 202, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var started struct {
		ID     int64  `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &started); err != nil {
		t.Fatalf("decode start: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM storage_migrations WHERE id = $1`, started.ID)
	})
	if started.Status != "started" || started.ID == 0 {
		t.Fatalf("start response = %+v", started)
	}

	// The admission row exists; the spawned run hits the unreachable source
	// and the row must reach a terminal status on its own (no zombie run).
	deadline := time.Now().Add(15 * time.Second)
	for {
		var status string
		if err := pool.QueryRow(context.Background(),
			`SELECT status FROM storage_migrations WHERE id = $1`, started.ID).Scan(&status); err != nil {
			t.Fatalf("read migration row: %v", err)
		}
		if status == "failed" || status == "completed" || status == "cancelled" || status == "cutover" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("migration %d never reached a terminal status (last=%q)", started.ID, status)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// After shutdown, admission is closed: 503, no new row.
	if err := migrator.Shutdown(context.Background(), 5*time.Second); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "/admin/storage/migrate?target=posix", nil)
	rec = httptest.NewRecorder()
	h.StartMigrate(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("start after shutdown: want 503, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestStorageMigrateMigrateStatus_ReadModel covers the DB read model: a known
// id returns the row projection; an unknown id is a 404 problem.
func TestStorageMigrateMigrateStatus_ReadModel(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h, _ := newStorageMigrateCovHandler(t, pool, "cov-bucket")
	id := storageMigrateCovInsertRow(t, pool, "dual_write", 0, 0)

	req := httptest.NewRequest(http.MethodGet, "/admin/storage/migrate/1", nil)
	req.SetPathValue("id", fmtInt(id))
	rec := httptest.NewRecorder()
	h.MigrateStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "dual_write" {
		t.Errorf("status = %v, want dual_write", body["status"])
	}

	// Unparseable id → 400.
	req = httptest.NewRequest(http.MethodGet, "/admin/storage/migrate/abc", nil)
	req.SetPathValue("id", "abc")
	rec = httptest.NewRecorder()
	h.MigrateStatus(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unparseable id: want 400, got %d", rec.Code)
	}

	// Unknown id → 404 problem.
	req = httptest.NewRequest(http.MethodGet, "/admin/storage/migrate/999999999", nil)
	req.SetPathValue("id", "999999999")
	rec = httptest.NewRecorder()
	h.MigrateStatus(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown id: want 404, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestStorageMigrateMigrateCancel_TypedOutcomes covers the typed cancel
// mapping: unknown → 404, terminal row → 409 (unchanged), and an
// in-progress row with NO live run in this process → 409 (local absence
// cannot authorize mutating another executor's row).
func TestStorageMigrateMigrateCancel_TypedOutcomes(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h, _ := newStorageMigrateCovHandler(t, pool, "cov-bucket")

	cancel := func(id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/admin/storage/migrate/1/cancel", nil)
		req.SetPathValue("id", id)
		rec := httptest.NewRecorder()
		h.MigrateCancel(rec, req)
		return rec
	}

	if rec := cancel("abc"); rec.Code != http.StatusBadRequest {
		t.Fatalf("unparseable id: want 400, got %d", rec.Code)
	}
	if rec := cancel("999999999"); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown migration: want 404, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	completedID := storageMigrateCovInsertRow(t, pool, "completed", 10, 10)
	rec := cancel(fmtInt(completedID))
	if rec.Code != http.StatusConflict {
		t.Fatalf("terminal migration: want 409, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	dualWriteID := storageMigrateCovInsertRow(t, pool, "dual_write", 0, 0)
	rec = cancel(fmtInt(dualWriteID))
	if rec.Code != http.StatusConflict {
		t.Fatalf("no-live-run migration: want 409, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	// The refused cancels left both rows unchanged.
	var status string
	if err := pool.QueryRow(context.Background(),
		`SELECT status FROM storage_migrations WHERE id = $1`, completedID).Scan(&status); err != nil || status != "completed" {
		t.Fatalf("terminal row disturbed: %q %v", status, err)
	}
	if err := pool.QueryRow(context.Background(),
		`SELECT status FROM storage_migrations WHERE id = $1`, dualWriteID).Scan(&status); err != nil || status != "dual_write" {
		t.Fatalf("no-live-run row disturbed: %q %v", status, err)
	}
}

// TestStorageMigrateListMigrations_Projection covers the list read model: the
// seeded rows project with source/target/status and a progress_pct when
// total > 0.
func TestStorageMigrateListMigrations_Projection(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h, _ := newStorageMigrateCovHandler(t, pool, "cov-bucket")
	progressID := storageMigrateCovInsertRow(t, pool, "completed", 4, 1)
	plainID := storageMigrateCovInsertRow(t, pool, "failed", 0, 0)

	req := httptest.NewRequest(http.MethodGet, "/admin/storage/migrate", nil)
	rec := httptest.NewRecorder()
	h.ListMigrations(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var listed []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	find := func(id int64) map[string]any {
		for _, item := range listed {
			if int64(item["id"].(float64)) == id {
				return item
			}
		}
		return nil
	}
	progress := find(progressID)
	if progress == nil {
		t.Fatalf("progress row %d missing from list (%d rows)", progressID, len(listed))
	}
	if progress["progress_pct"] != 25.0 {
		t.Errorf("progress_pct = %v, want 25", progress["progress_pct"])
	}
	if progress["completed"] == nil {
		t.Errorf("completed timestamp not projected: %v", progress)
	}
	plain := find(plainID)
	if plain == nil {
		t.Fatalf("plain row %d missing from list", plainID)
	}
	if _, has := plain["progress_pct"]; has {
		t.Errorf("zero-total row must not project progress_pct: %v", plain)
	}
	if _, has := plain["completed"]; has {
		t.Errorf("non-terminal row must not project completed: %v", plain)
	}
}

// TestStorageMigrate_ShadowSchemaFailures proves the checked Start and list
// branches: a shadow storage_migrations lacking the projected columns fails
// the durable admission INSERT and the list SELECT — each answers 5xx.
func TestStorageMigrate_ShadowSchemaFailures(t *testing.T) {
	shadowPool := openMAMListFixturePool(t, `
		CREATE TABLE __SCHEMA__.storage_migrations(id bigint);`)
	h, _ := newStorageMigrateCovHandler(t, shadowPool, t.TempDir())

	req := httptest.NewRequest(http.MethodPost, "/admin/storage/migrate?target=posix", nil)
	rec := httptest.NewRecorder()
	h.StartMigrate(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("start against broken read model: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/storage/migrate", nil)
	rec = httptest.NewRecorder()
	h.ListMigrations(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("list against broken read model: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// The fresh row written by admission has no total yet; list must agree with
// the single-row status projection instead of silently swallowing Scan failure.
func TestStorageMigrateListMigrations_NullProgress(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h, _ := newStorageMigrateCovHandler(t, pool, "cov-bucket")
	id := storageMigrateCovInsertRow(t, pool, "dual_write", 0, 0)
	if _, err := pool.Exec(context.Background(), `UPDATE storage_migrations SET total_blobs = NULL, migrated = NULL WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ListMigrations(rec, httptest.NewRequest(http.MethodGet, "/admin/storage/migrate", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("NULL list response: %d %s", rec.Code, rec.Body.String())
	}
	var items []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &items); err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item["id"] != float64(id) {
			continue
		}
		if item["total"] != float64(0) || item["migrated"] != float64(0) || item["status"] != "dual_write" || item["started"] == nil {
			t.Fatalf("NULL list projection: %v", item)
		}
		if _, exists := item["progress_pct"]; exists {
			t.Fatalf("invented progress: %v", item)
		}
		return
	}
	t.Fatalf("fresh row %d missing", id)
}

// ListMigrations' readStorageMigrationRows error arm (nightly-17 coverage):
// against a real PostgreSQL database the query's COALESCE/NOT NULL columns
// make the row scan genuinely unable to fail — the only deterministic way to
// exercise the handler's read-error arm is the established shadow-schema
// fault-injection technique: a per-test schema holds a hostile
// storage_migrations (bytea status column fails the string Scan) and the
// handler's pool pins search_path to it. Asserts the typed 500 and that the
// shadow schema is dropped in cleanup.
func TestStorageMigrateListMigrationsReadErrorArmFaultInjected(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	schema := "cfgstore_storage_migrate_readerr"
	if _, err := pool.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create shadow schema: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`)
	})
	if _, err := pool.Exec(ctx, `CREATE TABLE `+schema+`.storage_migrations (
		id bigint, source_driver bytea, target_driver bytea, status bytea,
		total_blobs bigint, migrated bigint, started_at timestamptz, completed_at timestamptz)`); err != nil {
		t.Fatalf("create shadow table: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.storage_migrations VALUES (1, 'x'::bytea, 'y'::bytea, 'z'::bytea, 4, 1, now(), NULL)`); err != nil {
		t.Fatalf("insert hostile row: %v", err)
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SET search_path=`+schema+`,pg_catalog,public`); err != nil {
		t.Fatalf("pin shadow search_path: %v", err)
	}

	// pgxpool rotates connections; the handler must observe the pinned one.
	// A dedicated single-connection pool guarantees the shadow search_path
	// survives into the handler's query (config_store fault-injection genre).
	cfg, err := pgxpool.ParseConfig(os.Getenv("DB_DSN"))
	if err != nil {
		t.Fatalf("parse DSN: %v", err)
	}
	cfg.MaxConns = 1
	// RuntimeParams puts the pin on EVERY connection the pool opens — a
	// session-level SET would be lost across release/reacquire.
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",pg_catalog,public"
	shadowPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("shadow pool: %v", err)
	}
	t.Cleanup(shadowPool.Close)
	hShadow, _ := newStorageMigrateCovHandler(t, shadowPool, "cov-bucket")
	req := httptest.NewRequest(http.MethodGet, "/admin/storage/migrations", nil)
	rec := httptest.NewRecorder()
	hShadow.ListMigrations(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("read-error arm: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "query failed") {
		t.Fatalf("read-error arm: want the typed query-failed detail, got %s", rec.Body.String())
	}
}
