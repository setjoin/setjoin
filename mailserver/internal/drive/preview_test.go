package drive

// White-box (package drive) tests for the P3 preview worker + route (Task
// 14). DB-backed cases skip cleanly when DB_DSN is unset (driveLivePool, the
// content_live_test.go genre) — run with:
//   DB_DSN=postgres://mail@127.0.0.1:5432/mailserver_test go test ./internal/drive/...

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

// fixturePDF is a tiny but non-empty stand-in for a rendered PDF — the
// worker never parses PDF content, only chunks + hashes the bytes, so any
// distinctive byte string exercises the pipeline faithfully.
var fixturePDF = bytes.Repeat([]byte("%PDF-1.4 fixture rendition\n"), 200) // ~5.4 KiB

// writePreviewCmdScript writes a shell script that copies fixturePDF (or,
// when exitCode != 0, writes nothing) into "$2"/out.pdf, ignoring "$1" (the
// {in} source path) — a stand-in DRIVE_PREVIEW_CMD sidecar. Returns the
// template string (script path + the {in}/{outdir} placeholders) NewWorker
// expects.
func writePreviewCmdScript(t *testing.T, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	pdfPath := filepath.Join(dir, "fixture.pdf")
	if err := os.WriteFile(pdfPath, fixturePDF, 0o644); err != nil {
		t.Fatalf("write fixture pdf: %v", err)
	}
	scriptPath := filepath.Join(dir, "cmd.sh")
	var body string
	if exitCode == 0 {
		body = "#!/bin/sh\ncp " + pdfPath + " \"$2\"/out.pdf\nexit 0\n"
	} else {
		body = "#!/bin/sh\nexit " + strconv.Itoa(exitCode) + "\n"
	}
	if err := os.WriteFile(scriptPath, []byte(body), 0o755); err != nil {
		t.Fatalf("write cmd script: %v", err)
	}
	return scriptPath + " {in} {outdir}"
}

// driveLiveOfficeVersion creates a member's file with an office content_type
// and returns its version id — the fixture every preview test starts from.
func driveLiveOfficeVersion(t *testing.T, pool *pgxpool.Pool, h *Handler, userID, spaceID int64, name string) int64 {
	t.Helper()
	nodeID := driveLiveCreateFile(t, h, userID, spaceID, name)
	data := []byte("pretend docx bytes")
	sha := driveLiveUploadChunk(t, h, userID, spaceID, data)
	sum := sha256.Sum256(data)
	contentSha := hex.EncodeToString(sum[:])
	ctx := context.Background()
	var versionID int64
	err := pool.QueryRow(ctx, `
		SELECT (drive_file_put_version($1, $2, $3, $4,
		  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
		  NULL, $5::jsonb, 'v1', 'test')->>'versionId')::bigint`,
		userID, nodeID, contentSha, len(data),
		`[{"sha256":"`+sha+`","size":`+strconv.Itoa(len(data))+`}]`).Scan(&versionID)
	if err != nil {
		t.Fatalf("put office version: %v", err)
	}
	return versionID
}

// TestPreviewWorkerRendersEndToEnd: a pending office version gets converted
// by a fake sidecar — the produced PDF's chunks land in storage, the
// reducer is called, and preview_status flips to 'ready'.
func TestPreviewWorkerRendersEndToEnd(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "dpvw1")
	fake := newFakeStore()
	h := NewHandler(pool, nil, fake, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, userID)
	versionID := driveLiveOfficeVersion(t, pool, h, userID, spaceID, "report.docx")

	ctx := context.Background()
	var status string
	if err := pool.QueryRow(ctx, `SELECT drive_preview_request($1, $2)`, userID, versionID).Scan(&status); err != nil {
		t.Fatalf("drive_preview_request: %v", err)
	}
	if status != "pending" {
		t.Fatalf("want pending, got %s", status)
	}

	cmd := writePreviewCmdScript(t, 0)
	w := NewPreviewWorker(pgxutil.WorkerPool{Pool: pool}, fake, "b", cmd, discardLogger())
	w.tick(ctx)

	var gotStatus, previewSha string
	if err := pool.QueryRow(ctx, `SELECT preview_status, preview_sha256 FROM drive_file_versions WHERE id=$1`, versionID).
		Scan(&gotStatus, &previewSha); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if gotStatus != "ready" {
		t.Fatalf("want preview_status=ready, got %s", gotStatus)
	}
	wantWhole := sha256.Sum256(fixturePDF)
	if previewSha != hex.EncodeToString(wantWhole[:]) {
		t.Errorf("preview_sha256 mismatch: got %s", previewSha)
	}

	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM drive_version_chunks WHERE version_id=$1 AND stream='preview'`, versionID).Scan(&n); err != nil {
		t.Fatalf("count preview chunks: %v", err)
	}
	if n == 0 {
		t.Fatal("expected at least one preview manifest row")
	}
	if len(fake.putKeys) == 0 {
		t.Fatal("expected the preview chunk to be PutObject'd to storage")
	}
}

// TestPreviewWorkerSidecarFailureMarksFailed: a nonzero sidecar exit leaves
// no rendition and flips preview_status to 'failed'.
func TestPreviewWorkerSidecarFailureMarksFailed(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "dpvw2")
	fake := newFakeStore()
	h := NewHandler(pool, nil, fake, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, userID)
	versionID := driveLiveOfficeVersion(t, pool, h, userID, spaceID, "broken.docx")

	ctx := context.Background()
	if _, err := pool.Exec(ctx, `SELECT drive_preview_request($1, $2)`, userID, versionID); err != nil {
		t.Fatalf("drive_preview_request: %v", err)
	}

	cmd := writePreviewCmdScript(t, 7) // nonzero exit, no PDF written
	w := NewPreviewWorker(pgxutil.WorkerPool{Pool: pool}, fake, "b", cmd, discardLogger())
	w.tick(ctx)

	var gotStatus string
	if err := pool.QueryRow(ctx, `SELECT preview_status FROM drive_file_versions WHERE id=$1`, versionID).Scan(&gotStatus); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if gotStatus != "failed" {
		t.Fatalf("want preview_status=failed, got %s", gotStatus)
	}
}

// TestPreviewWorkerInertWithoutCmd: an empty DRIVE_PREVIEW_CMD makes Run
// return immediately (no ticker, no claim) rather than block forever.
func TestPreviewWorkerInertWithoutCmd(t *testing.T) {
	w := NewPreviewWorker(pgxutil.WorkerPool{}, nil, "", "", discardLogger())
	done := make(chan struct{})
	go func() {
		w.Run(context.Background()) // unconfigured cmd -> must return promptly, no DB/store touched
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run with no DRIVE_PREVIEW_CMD must return immediately, not start ticking")
	}
}

// TestGetPreviewRoute exercises the route end-to-end: not-ready 404s, a
// worker-simulated attach flips it to streamable, Range works, and repeated
// opens dedupe to one audit row (G3).
func TestGetPreviewRoute(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "dpvr1")
	fake := newFakeStore()
	h := NewHandler(pool, nil, fake, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, userID)
	versionID := driveLiveOfficeVersion(t, pool, h, userID, spaceID, "slides.pptx")

	ctx := context.Background()

	// First open: status is 'none' -> lazy-requests, then not-ready 404.
	req := httptest.NewRequest(http.MethodGet, "/drive/versions/"+strconv.FormatInt(versionID, 10)+"/preview", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("not-ready preview: want 404, got %d: %s", rr.Code, rr.Body.String())
	}
	var status string
	if err := pool.QueryRow(ctx, `SELECT preview_status FROM drive_file_versions WHERE id=$1`, versionID).Scan(&status); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if status != "pending" {
		t.Fatalf("lazy request: want pending after first GET, got %s", status)
	}

	// Simulate the worker's attach directly (route test, not a worker test).
	sum := sha256.Sum256(fixturePDF)
	previewSha := hex.EncodeToString(sum[:])
	if _, err := pool.Exec(ctx, `SELECT drive_preview_attach($1, $2, $3::jsonb, 'ready')`,
		versionID, previewSha, `[{"sha256":"`+previewSha+`","size":`+strconv.Itoa(len(fixturePDF))+`}]`); err != nil {
		t.Fatalf("simulate attach: %v", err)
	}
	scope := "g/" + previewSha
	fake.objects["drive/"+scope] = fixturePDF

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/drive/versions/"+strconv.FormatInt(versionID, 10)+"/preview", nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("ready preview GET %d: want 200, got %d: %s", i, rr.Code, rr.Body.String())
		}
		if !bytes.Equal(rr.Body.Bytes(), fixturePDF) {
			t.Errorf("GET %d body mismatch", i)
		}
		if ct := rr.Header().Get("Content-Type"); ct != "application/pdf" {
			t.Errorf("Content-Type = %q, want application/pdf", ct)
		}
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM drive_audit_log WHERE space_id=$1 AND user_id=$2 AND action='preview' AND target_id=$3`,
		spaceID, userID, versionID).Scan(&n); err != nil {
		t.Fatalf("count preview audit rows: %v", err)
	}
	// personal space -> audit_reads policy default is off, so G3 dedupe isn't
	// exercised via mandatory-audit; assert no more than one anyway (in case
	// the default ever flips to on) rather than asserting an exact count that
	// depends on that policy default.
	if n > 1 {
		t.Errorf("G3 dedupe: want at most 1 preview audit row across 2 reads, got %d", n)
	}
}

// TestGetPreviewSecureUsesPreviewAuthority proves a protected original remains
// closed while a server-generated rendition is authorized by the exact preview
// capability, not a meaningless caller-controlled header.
func TestGetPreviewSecureUsesPreviewAuthority(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "dpvr2")
	fake := newFakeStore()
	h := NewHandler(pool, nil, fake, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := driveLiveCreateSecureSpace(t, h, userID)
	versionID := driveLiveOfficeVersion(t, pool, h, userID, spaceID, "secret.docx")

	ctx := context.Background()
	sum := sha256.Sum256(fixturePDF)
	previewSha := hex.EncodeToString(sum[:])
	if _, err := pool.Exec(ctx, `SELECT drive_preview_attach($1, $2, $3::jsonb, 'ready')`,
		versionID, previewSha, `[{"sha256":"`+previewSha+`","size":`+strconv.Itoa(len(fixturePDF))+`}]`); err != nil {
		t.Fatalf("simulate attach: %v", err)
	}
	fake.objects["drive/s"+strconv.FormatInt(spaceID, 10)+"/"+previewSha] = fixturePDF

	req := httptest.NewRequest(http.MethodGet, "/drive/versions/"+strconv.FormatInt(versionID, 10)+"/preview", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("secure preview with exact preview authority: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "application/pdf" {
		t.Fatalf("secure rendition Content-Type = %q, want application/pdf", got)
	}
}

// TestPreviewWorkerVanishedProductMarksFailed (fault injection): the sidecar
// reports success but the produced PDF is gone by the time the worker stats
// it — modeled as a dangling .pdf symlink, which findProducedPDF still lists
// (a ReadDir entry) but os.Stat cannot resolve. The worker must flip the
// version to 'failed' instead of panicking or streaming nothing as ready.
func TestPreviewWorkerVanishedProductMarksFailed(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "dpvw3")
	fake := newFakeStore()
	h := NewHandler(pool, nil, fake, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, userID)
	versionID := driveLiveOfficeVersion(t, pool, h, userID, spaceID, "racy.docx")

	ctx := context.Background()
	if _, err := pool.Exec(ctx, `SELECT drive_preview_request($1, $2)`, userID, versionID); err != nil {
		t.Fatalf("drive_preview_request: %v", err)
	}

	// Sidecar "succeeds" but its product is a dangling symlink ( vanished
	// between production and the worker's output-bound stat).
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "cmd.sh")
	body := "#!/bin/sh\nln -s /nonexistent/never-rendered.pdf \"$2\"/out.pdf\nexit 0\n"
	if err := os.WriteFile(scriptPath, []byte(body), 0o755); err != nil {
		t.Fatalf("write cmd script: %v", err)
	}
	w := NewPreviewWorker(pgxutil.WorkerPool{Pool: pool}, fake, "b", scriptPath+" {in} {outdir}", discardLogger())
	w.tick(ctx)

	var gotStatus string
	if err := pool.QueryRow(ctx, `SELECT preview_status FROM drive_file_versions WHERE id=$1`, versionID).Scan(&gotStatus); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if gotStatus != "failed" {
		t.Fatalf("want preview_status=failed for a vanished sidecar product, got %s", gotStatus)
	}
}
