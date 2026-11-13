package jmap

// blob_upload_handler_edges_er5s11_test.go — end-to-end proofs for the JMAP
// upload handler's MEASURED-bytes accounting (D-...-BLOB-002) and the
// Email/set attachment-ownership gate's edge branches (er5-s11).
//
// The accounting test drives JMAPHandler.Upload through a stub S3 endpoint
// (the admin storage tests' httptest + minio.New pattern) so the streamed
// uploadByteCounter — not a request-asserted or zero-size fallback — is what
// lands in blob_user_charges and in the response's size field.
//
// The gate edge units call gateAttachmentBlobOwnership directly (same
// package): non-object creates pass through untouched, per-creation shapes the
// reducer's notCreated path owns are tolerated, empty blobIds never reach the
// ownership query, and a broken worker pool surfaces as an error (serverFail),
// never as an allow.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/pgxutil"
)

// newUploadStubS3 spins the smallest S3-compatible stub the upload path needs:
// PUT (stream to temp key) → 200 + ETag, PUT with x-amz-copy-source (temp →
// canonical promote) → 200 + CopyObjectResult XML, DELETE (temp cleanup) →
// 204. deletes counts the DELETEs so the temp-cleanup contract is assertable.
func newUploadStubS3(t *testing.T) (mc *minio.Client, deletes *int) {
	t.Helper()
	deletes = new(int)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.Header.Get("x-amz-copy-source") != "" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<CopyObjectResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ETag>"5d41402abc4b2a76b9719d911017c592"</ETag></CopyObjectResult>`))
			return
		}
		switch r.Method {
		case http.MethodPut:
			w.Header().Set("ETag", `"5d41402abc4b2a76b9719d911017c592"`)
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			*deletes++
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(ts.Close)
	mc, err := minio.New(strings.TrimPrefix(ts.URL, "http://"), &minio.Options{
		Creds: credentials.NewStaticV4("test", "test", ""), Secure: false, Region: "us-east-1",
	})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}
	return mc, deletes
}

// uploadRequest builds an authenticated Upload call for the caller's primary
// mailbox (the only accountId the gatePersonal upload path accepts as own).
func uploadRequest(t *testing.T, h *JMAPHandler, mailboxID, userID int64, contentType string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/jmap/upload/"+strconv.FormatInt(mailboxID, 10), strings.NewReader(string(body)))
	req.SetPathValue("accountId", strconv.FormatInt(mailboxID, 10))
	req.Header.Set("Content-Type", contentType)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.Upload(rr, req)
	return rr
}

// TestUploadHandlerChargesMeasuredBytes (fault injection at the accounting
// boundary): a streamed upload must charge and report the MEASURED byte count
// (uploadByteCounter), persist the blobs row at ref_count=0, and arm exactly
// one reclamation row — the reducer facts, observed through the full HTTP
// upload path instead of a direct accountUpload call.
func TestUploadHandlerChargesMeasuredBytes(t *testing.T) {
	pool := testPoolDB(t)
	mc, _ := newUploadStubS3(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", mc, "test-bucket", 10_000_000, testLoggerDB(t))
	_, userID, mailboxID := insertTestUserWithMailbox(t, pool, true)
	ctx := context.Background()

	body := []byte(strings.Repeat("measured-bytes-", 83)) // 1245 bytes, non-power-of-2
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM blob_cleanup_queue WHERE blob_sha256 = $1`, sha) //nolint:errcheck
		_, _ = pool.Exec(ctx, `DELETE FROM blobs WHERE sha256 = $1`, sha)                   //nolint:errcheck
	})

	rr := uploadRequest(t, h, mailboxID, userID, "text/plain", body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("Upload = %d, want 201: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		AccountID string `json:"accountId"`
		BlobID    string `json:"blobId"`
		Type      string `json:"type"`
		Size      int64  `json:"size"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode upload response: %v (%s)", err, rr.Body.String())
	}
	if resp.BlobID != sha {
		t.Errorf("blobId = %q, want the SHA-256 of the streamed body %q", resp.BlobID, sha)
	}
	if resp.Size != int64(len(body)) {
		t.Errorf("size = %d, want the measured %d (never a zero-size fallback)", resp.Size, len(body))
	}
	if resp.Type != "text/plain" {
		t.Errorf("type = %q, want the request Content-Type", resp.Type)
	}

	var refCount int
	if err := pool.QueryRow(ctx,
		`SELECT ref_count FROM blobs WHERE sha256 = $1`, sha).Scan(&refCount); err != nil {
		t.Fatalf("blobs row missing after upload: %v", err)
	}
	if refCount != 0 {
		t.Errorf("blobs.ref_count = %d, want 0 (an upload is NOT yet a reference)", refCount)
	}
	var chargedUserID int64
	var chargedBytes int64
	if err := pool.QueryRow(ctx,
		`SELECT user_id, size_bytes FROM blob_user_charges WHERE blob_sha256 = $1`, sha,
	).Scan(&chargedUserID, &chargedBytes); err != nil {
		t.Fatalf("charge row missing after upload: %v", err)
	}
	if chargedUserID != userID || chargedBytes != int64(len(body)) {
		t.Errorf("charge = (%d, %d), want (%d, %d) — the measured bytes", chargedUserID, chargedBytes, userID, len(body))
	}
	var queueRows int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM blob_cleanup_queue WHERE blob_sha256 = $1`, sha,
	).Scan(&queueRows); err != nil {
		t.Fatalf("read cleanup queue: %v", err)
	}
	if queueRows != 1 {
		t.Errorf("want exactly 1 armed reclamation row, got %d", queueRows)
	}
}

// TestUploadHandlerAccountingFailureIs500AndCleansTemp: a reducer-level
// accounting failure (here: a pre-seeded blobs.minio_ref UNIQUE collision on
// the canonical key the upload would claim) must surface as serverFail 500,
// must clean the streamed temp object, and must persist NOTHING for the new
// content — the accounting-before-promote ordering.
func TestUploadHandlerAccountingFailureIs500AndCleansTemp(t *testing.T) {
	pool := testPoolDB(t)
	mc, deletes := newUploadStubS3(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", mc, "test-bucket", 10_000_000, testLoggerDB(t))
	_, userID, mailboxID := insertTestUserWithMailbox(t, pool, true)
	ctx := context.Background()

	body := []byte("accounting-collision-victim")
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])
	collideRef := "test-bucket/" + sha
	// The collision: a DIFFERENT sha256 already holds the minio_ref this
	// upload's admission would claim, so blob_upload_account's INSERT fails a
	// UNIQUE constraint — a non-BZ001 reducer failure.
	const squatSha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550000"
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM blob_cleanup_queue WHERE blob_sha256 IN ($1, $2)`, sha, squatSha) //nolint:errcheck
		_, _ = pool.Exec(ctx, `DELETE FROM blobs WHERE sha256 IN ($1, $2)`, sha, squatSha)                   //nolint:errcheck
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO blobs (sha256, minio_ref, size_bytes, content_type, ref_count)
		 VALUES ($1, $2, 1, 'application/x-squat', 0) ON CONFLICT (sha256) DO NOTHING`,
		squatSha, collideRef); err != nil {
		t.Fatalf("seed minio_ref collision: %v", err)
	}

	rr := uploadRequest(t, h, mailboxID, userID, "text/plain", body)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("Upload = %d, want 500 on accounting failure: %s", rr.Code, rr.Body.String())
	}
	if *deletes == 0 {
		t.Error("temp object must be removed after a failed accounting (no orphaned bytes)")
	}
	var persisted int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM blobs WHERE sha256 = $1`, sha).Scan(&persisted); err != nil {
		t.Fatalf("count victim blobs rows: %v", err)
	}
	if persisted != 0 {
		t.Error("a failed accounting must persist no blobs row for the upload")
	}
}

// TestGateAttachmentBlobOwnershipEdges pins the gate's tolerance edges:
// non-object creates pass through for dispatchSet/reducer validation, shapes
// that cannot carry attachments are tolerated without a DB round-trip, empty
// blobIds are dropped from the ownership query, and a broken worker pool is an
// error (serverFail), never an allow.
func TestGateAttachmentBlobOwnershipEdges(t *testing.T) {
	h := &JMAPHandler{logger: testLoggerDB(t)}

	// Non-object create map: returned untouched for the reducer's validation.
	nonObject := json.RawMessage(`["kept","as-is"]`)
	got, denied, err := h.gateAttachmentBlobOwnership(context.Background(), 1, nonObject)
	if err != nil {
		t.Fatalf("non-object create: %v", err)
	}
	if string(got) != string(nonObject) || len(denied) != 0 {
		t.Errorf("non-object create must pass through untouched, got %s denied=%v", got, denied)
	}

	// Per-creation values that cannot carry attachments (not an attachment
	// shape) are tolerated: the reducer's notCreated path owns them, and with
	// no collectible blobIds the ownership query is never reached.
	malformed := json.RawMessage(`{"m1": 5}`)
	got, denied, err = h.gateAttachmentBlobOwnership(context.Background(), 1, malformed)
	if err != nil {
		t.Fatalf("malformed creation: %v", err)
	}
	if string(got) != string(malformed) || len(denied) != 0 {
		t.Errorf("malformed creation must pass through untouched, got %s denied=%v", got, denied)
	}

	// Empty blobIds never reach the ownership query.
	empties := json.RawMessage(`{"m1": {"attachments": [{"blobId": ""}, {}]}}`)
	got, denied, err = h.gateAttachmentBlobOwnership(context.Background(), 1, empties)
	if err != nil {
		t.Fatalf("empty blobIds: %v", err)
	}
	if string(got) != string(empties) || len(denied) != 0 {
		t.Errorf("empty-blobId creation must pass through untouched, got %s denied=%v", got, denied)
	}

	// A broken worker pool (closed pool) must surface as an error — the
	// ownership gate is fail-closed: no DB, no admission.
	pool := testPoolDB(t)
	pool.Close()
	broken := &JMAPHandler{
		logger:     testLoggerDB(t),
		workerPool: pool,
	}
	withBlob := json.RawMessage(`{"m1": {"attachments": [{"blobId": "aab b"}]}}`)
	if _, _, err := broken.gateAttachmentBlobOwnership(context.Background(), 1, withBlob); err == nil {
		t.Fatal("ownership gate on a broken pool must error, not allow")
	}
}

// TestOwnedBlobSetEmptyInputIsVacuouslyOwned: an empty id list short-circuits
// to an empty (vacuously-owned) set without touching the pool.
func TestOwnedBlobSetEmptyInputIsVacuouslyOwned(t *testing.T) {
	h := &JMAPHandler{logger: testLoggerDB(t)}
	owned, err := h.ownedBlobSet(context.Background(), 1, nil)
	if err != nil {
		t.Fatalf("ownedBlobSet(nil ids): %v", err)
	}
	if len(owned) != 0 {
		t.Errorf("ownedBlobSet(nil ids) = %v, want an empty set", owned)
	}
}

// TestEmailSetAttachmentGateBrokenWorkerPoolIsServerFail (fail-closed at the
// method boundary): a live validation pool with a broken worker pool must turn
// the gate error into a serverFail method error, never into a dispatch.
func TestEmailSetAttachmentGateBrokenWorkerPoolIsServerFail(t *testing.T) {
	pool := testPoolDB(t)
	closed := testPoolDB(t)
	closed.Close()
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: closed}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))
	_, userID, mailboxID := insertTestUserWithMailbox(t, pool, true)

	args := mustMarshal(map[string]any{
		"accountId": strconv.FormatInt(mailboxID, 10),
		"create": map[string]any{
			"c1": map[string]any{
				"mailboxIds":  map[string]any{},
				"attachments": []any{map[string]any{"blobId": "aa", "name": "x.bin", "size": 1}},
			},
		},
	})
	state, resp := h.emailSet(context.Background(), &auth.Claims{UserID: userID}, args)
	if state != "error" {
		t.Fatalf("emailSet state = %q, want \"error\" on gate failure", state)
	}
	var errResp struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(resp, &errResp); err != nil {
		t.Fatalf("decode emailSet error: %v (%s)", err, resp)
	}
	if errResp.Type != "serverFail" && !strings.HasSuffix(errResp.Type, ":serverFail") {
		t.Errorf("error type = %q, want \"serverFail\" (a gate infrastructure failure must not dispatch)", errResp.Type)
	}
}
