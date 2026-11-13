package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"setjoin.com/shared/testsupport"
)

// TestDRScanReconcile drives StorageHandler.DRScanReconcile against the real DB
// + an S3 stub: a seeded completed scan with one orphaned detail re-imports the
// object into blobs (ref_count=0) and bumps reimported_count. The smallest
// guard that fails if the re-import INSERT or the completed-status gate regresses.
func TestDRScanReconcile(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	// Fresh sha unlikely to collide with fixtures/other tests.
	const sha = "a1a1a1a1cafe0000000000000000000000000000000000000000000000009521"
	const bucket = "drscan-bucket"
	const objSize = 4242

	// S3 stub: StatObject issues a HEAD; serve metadata for our sha, 404 otherwise.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/"+bucket+"/")
		if key != sha {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(objSize))
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("ETag", `"d41d8cd98f00b204e9800998ecf8427e"`)
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat)) // minio-go requires it
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	mc, err := minio.New(strings.TrimPrefix(ts.URL, "http://"), &minio.Options{
		Creds: credentials.NewStaticV4("test", "test", ""), Secure: false, Region: "us-east-1",
	})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}
	h := NewStorageHandler(mc, "", pool, bucket, testsupport.TestLogger())

	seedScan := func(status, details string) int64 {
		var id int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO storage_dr_scans (status, details) VALUES ($1, $2::jsonb) RETURNING id`,
			status, details).Scan(&id); err != nil {
			t.Fatalf("seed scan (%s): %v", status, err)
		}
		t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM storage_dr_scans WHERE id = $1`, id) }) //nolint:errcheck
		return id
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM blobs WHERE sha256 = $1`, sha) }) //nolint:errcheck

	reconcile := func(id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/admin/storage/dr-scans/"+id+"/reconcile", nil)
		req.SetPathValue("id", id)
		rec := httptest.NewRecorder()
		h.DRScanReconcile(rec, req)
		return rec
	}

	// Happy path: completed scan with one orphaned detail.
	scanID := seedScan("completed", fmt.Sprintf(`[{"issue":"orphaned","sha256":"%s","size":%d}]`, sha, objSize))
	rec := reconcile(strconv.FormatInt(scanID, 10))
	if rec.Code != http.StatusOK {
		t.Fatalf("reconcile: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Reimported int64 `json:"reimported"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Reimported != 1 {
		t.Errorf("reimported = %d, want 1", body.Reimported)
	}

	// blobs row inserted with ref_count=0.
	var refCount int
	var sizeBytes int64
	if err := pool.QueryRow(ctx, `SELECT ref_count, size_bytes FROM blobs WHERE sha256 = $1`, sha).Scan(&refCount, &sizeBytes); err != nil {
		t.Fatalf("blobs row not inserted: %v", err)
	}
	if refCount != 0 {
		t.Errorf("blobs ref_count = %d, want 0", refCount)
	}
	if sizeBytes != objSize {
		t.Errorf("blobs size_bytes = %d, want %d", sizeBytes, objSize)
	}

	// reimported_count persisted on the scan row.
	var reimportedCount int64
	if err := pool.QueryRow(ctx, `SELECT reimported_count FROM storage_dr_scans WHERE id = $1`, scanID).Scan(&reimportedCount); err != nil {
		t.Fatalf("read reimported_count: %v", err)
	}
	if reimportedCount != 1 {
		t.Errorf("reimported_count = %d, want 1", reimportedCount)
	}

	// Guard branches.
	if rec := reconcile("not-a-number"); rec.Code != http.StatusBadRequest {
		t.Errorf("invalid id: want 400, got %d", rec.Code)
	}
	if rec := reconcile("999999999"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown id: want 404, got %d", rec.Code)
	}
	runningID := seedScan("running", `[]`)
	if rec := reconcile(strconv.FormatInt(runningID, 10)); rec.Code != http.StatusConflict {
		t.Errorf("non-completed scan: want 409, got %d", rec.Code)
	}
}
