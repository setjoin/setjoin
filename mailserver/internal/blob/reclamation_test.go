package blob

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/testsupport"
)

// This file covers the med-blob-reclamation-001 acceptance contract:
//   1. an uploaded-never-attached blob is reclaimed after the grace window;
//   2. a blob attached or dedup-referenced inside the window survives
//      reclamation, and the UPDATE-to-zero trigger path still reclaims;
//   3. concurrent uploads never exceed the per-user bound;
//   4. an unknown-length (chunked) upload's accounting equals its measured
//      byte count, not zero.

// reclamationStore is a mutex-guarded in-memory objectStore: the concurrent
// bound test drives several Puts through ONE handler, and fakeStore (the
// single-threaded fake in handler_test.go) has unsynchronized maps.
type reclamationStore struct {
	mu      sync.Mutex
	objects map[string][]byte
	removed []string
}

func newReclamationStore() *reclamationStore {
	return &reclamationStore{objects: map[string][]byte{}}
}

func (s *reclamationStore) PutObject(_ context.Context, _, object string, reader io.Reader, _ int64, _ minio.PutObjectOptions) (minio.UploadInfo, error) {
	data, err := io.ReadAll(reader) // drains the TeeReader so the handler's hasher sees the body
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		return minio.UploadInfo{}, err
	}
	s.objects[object] = data
	return minio.UploadInfo{Key: object, Size: int64(len(data))}, nil
}

func (s *reclamationStore) CopyObject(_ context.Context, dst minio.CopyDestOptions, src minio.CopySrcOptions) (minio.UploadInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.objects[src.Object]
	if !ok {
		return minio.UploadInfo{}, fmt.Errorf("copy source not found: %s", src.Object)
	}
	s.objects[dst.Object] = data
	return minio.UploadInfo{Key: dst.Object}, nil
}

func (s *reclamationStore) RemoveObject(_ context.Context, _, object string, _ minio.RemoveObjectOptions) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.objects, object)
	s.removed = append(s.removed, object)
	return nil
}

func (s *reclamationStore) GetObject(_ context.Context, _, _ string, _ minio.GetObjectOptions) (*minio.Object, error) {
	return nil, fmt.Errorf("not implemented") // Put never reads
}

func (s *reclamationStore) has(object string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.objects[object]
	return ok
}

// reclamationUser returns a throwaway per-user accounting id (no users-table
// row: blob_user_charges/blob_user_usage deliberately carry no users FK —
// V048 login_events posture) and registers its cleanup.
func reclamationUser(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	userID := int64(9_100_000) + int64(b[0])<<24 + int64(b[1])<<16 + int64(b[2])<<8 + int64(b[3])
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM blob_user_usage WHERE user_id = $1`, userID) //nolint:errcheck
	})
	return userID
}

// reclamationBlobScope registers cleanup for one blob's row + queue entry
// (charges cascade off blobs; the dec trigger credits the usage row, which the
// user-scope cleanup then removes).
func reclamationBlobScope(t *testing.T, pool *pgxpool.Pool, sha256hex string) {
	t.Helper()
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM blob_cleanup_queue WHERE blob_sha256 = $1`, sha256hex) //nolint:errcheck
		_, _ = pool.Exec(bg, `DELETE FROM blobs WHERE sha256 = $1`, sha256hex)                   //nolint:errcheck
	})
}

func putAsUser(t *testing.T, h *Handler, userID int64, sha256hex string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/blobs/"+sha256hex, bytes.NewReader(body))
	req.SetPathValue("sha256", sha256hex)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.Put(rec, req)
	return rec
}

// rewindQueueDue makes the blob's reclamation entry immediately due the way a
// real grace-window expiry would be (the sweep itself is unchanged).
func rewindQueueDue(t *testing.T, pool *pgxpool.Pool, sha256hex string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`UPDATE blob_cleanup_queue SET scheduled_at = now() - interval '1 minute', delay_minutes = 0
		 WHERE blob_sha256 = $1`, sha256hex,
	); err != nil {
		t.Fatalf("rewind queue row: %v", err)
	}
}

// sweepOwnedDue runs the production candidate scan (cleanupCandidates) but
// reaps ONLY the shas this test created. The tests share one database
// (testsupport.OpenTestPool → DB_DSN) with a fake object store, so the global
// processCleanupQueue drain is off-limits here: it would delete every due,
// unreferenced blobs row in the database while RemoveObject hits the fake —
// orphaning the real objects behind rows some other fixture/test enqueued.
// Scanning globally and reaping owned fixtures keeps the exercised path
// identical (same due-candidate query, same atomic recheck delete) without
// mutating anyone else's rows.
func sweepOwnedDue(t *testing.T, h *Handler, owned ...string) {
	t.Helper()
	want := make(map[string]bool, len(owned))
	for _, sha := range owned {
		want[sha] = true
	}
	for _, sha := range h.cleanupCandidates(context.Background()) {
		if want[sha] {
			h.reapCleanupCandidate(context.Background(), sha)
		}
	}
}

func usageFor(t *testing.T, pool *pgxpool.Pool, userID int64) int64 {
	t.Helper()
	var charged int64
	if err := pool.QueryRow(context.Background(),
		`SELECT charged_bytes FROM blob_user_usage WHERE user_id = $1`, userID,
	).Scan(&charged); err != nil {
		t.Fatalf("read blob_user_usage for user %d: %v", userID, err)
	}
	return charged
}

func chargeFor(t *testing.T, pool *pgxpool.Pool, sha256hex string) (userID, sizeBytes int64) {
	t.Helper()
	if err := pool.QueryRow(context.Background(),
		`SELECT user_id, size_bytes FROM blob_user_charges WHERE blob_sha256 = $1`, sha256hex,
	).Scan(&userID, &sizeBytes); err != nil {
		t.Fatalf("read blob_user_charges for %s: %v", sha256hex, err)
	}
	return userID, sizeBytes
}

func blobRefCount(t *testing.T, pool *pgxpool.Pool, sha256hex string) int {
	t.Helper()
	var refCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT ref_count FROM blobs WHERE sha256 = $1`, sha256hex,
	).Scan(&refCount); err != nil {
		t.Fatalf("read blobs row for %s: %v", sha256hex, err)
	}
	return refCount
}

// queueRowFor returns (delay_minutes, due-now?) for the blob's reclamation
// entry, failing if the entry is missing.
func queueRowFor(t *testing.T, pool *pgxpool.Pool, sha256hex string) (delayMinutes int, due bool) {
	t.Helper()
	if err := pool.QueryRow(context.Background(),
		`SELECT delay_minutes, scheduled_at + make_interval(mins => delay_minutes) < now()
		 FROM blob_cleanup_queue WHERE blob_sha256 = $1`, sha256hex,
	).Scan(&delayMinutes, &due); err != nil {
		t.Fatalf("read blob_cleanup_queue for %s: %v", sha256hex, err)
	}
	return delayMinutes, due
}

// (blobRowExists lives in cleanup_test.go and is reused here.)

// TestPutArmsReclamationAndUnattachedBlobIsReclaimed is acceptance clause 1:
// PUT queues the blob into blob_cleanup_queue with the configured grace
// window, so an uploaded-NEVER-attached object reaches the (unchanged) atomic
// recheck sweeper once the window expires — the exact hole the finding names.
// The reclaim must also credit the user's accounting via the V235 cascade.
func TestPutArmsReclamationAndUnattachedBlobIsReclaimed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	userID := reclamationUser(t, pool)

	data := []byte("uploaded, never attached, reclaimed after the grace window")
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	reclamationBlobScope(t, pool, sha)

	store := newReclamationStore()
	h := &Handler{minio: store, pool: pool, bucket: "blobs", logger: discardLogger()}
	h.SetReclamationPolicy(1440, 0) // 24h grace, enforcement off

	if rec := putAsUser(t, h, userID, sha, data); rec.Code != http.StatusCreated {
		t.Fatalf("put status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}

	// Arming proof: queue row exists with the configured grace delay, not yet due.
	delay, due := queueRowFor(t, pool, sha)
	if delay != 1440 {
		t.Errorf("queue delay_minutes = %d, want 1440 (configured grace window)", delay)
	}
	if due {
		t.Error("freshly armed queue row must not be due")
	}

	// Accounting proof: the upload charged its measured bytes to the uploader.
	if chargeUser, size := chargeFor(t, pool, sha); chargeUser != userID || size != int64(len(data)) {
		t.Errorf("charge = (user %d, %d bytes), want (user %d, %d bytes)", chargeUser, size, userID, len(data))
	}
	if got := usageFor(t, pool, userID); got != int64(len(data)) {
		t.Errorf("usage = %d, want %d", got, len(data))
	}

	// Grace window expires; the unchanged sweeper reclaims the unattached blob.
	rewindQueueDue(t, pool, sha)
	sweepOwnedDue(t, h, sha)

	if blobRowExists(t, pool, sha) {
		t.Error("uploaded-never-attached blob must be reclaimed (blobs row) after the grace window")
	}
	if store.has(sha) {
		t.Error("uploaded-never-attached blob must be reclaimed (MinIO object) after the grace window")
	}
	// Accounting credit: the blobs deletion cascades the charge, and the dec
	// trigger debits the aggregate back to zero.
	if _, _, err := scanChargeAbsent(t, pool, sha); err == nil {
		t.Error("charge row must be cascade-deleted when the blob is reclaimed")
	}
	if got := usageFor(t, pool, userID); got != 0 {
		t.Errorf("usage after reclaim = %d, want 0 (credited)", got)
	}
}

// scanChargeAbsent exists so the reclaim test can distinguish "no charge row"
// from helper fatals; returns err from the underlying scan.
func scanChargeAbsent(t *testing.T, pool *pgxpool.Pool, sha256hex string) (userID, size int64, err error) {
	t.Helper()
	err = pool.QueryRow(context.Background(),
		`SELECT user_id, size_bytes FROM blob_user_charges WHERE blob_sha256 = $1`, sha256hex,
	).Scan(&userID, &size)
	return userID, size, err
}

// TestPutAttachedInsideGraceWindowSurvivesReclamation is acceptance clause 2a:
// an attach (ref_count 0→1, as the V075/V110 refcount triggers perform it)
// inside the window makes the atomic recheck skip the reclaim — referenced
// bytes are never deleted.
func TestPutAttachedInsideGraceWindowSurvivesReclamation(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	userID := reclamationUser(t, pool)

	data := []byte("attached inside the grace window — must survive")
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	reclamationBlobScope(t, pool, sha)

	store := newReclamationStore()
	h := &Handler{minio: store, pool: pool, bucket: "blobs", logger: discardLogger()}
	h.SetReclamationPolicy(1440, 0)

	if rec := putAsUser(t, h, userID, sha, data); rec.Code != http.StatusCreated {
		t.Fatalf("put status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}

	// The attach: message_attachments/hr_expense_receipts refcount triggers do
	// exactly this UPDATE OF ref_count.
	if _, err := pool.Exec(context.Background(),
		`UPDATE blobs SET ref_count = 1 WHERE sha256 = $1`, sha,
	); err != nil {
		t.Fatalf("simulate attach: %v", err)
	}

	// Window expires while attached.
	rewindQueueDue(t, pool, sha)
	sweepOwnedDue(t, h, sha)

	if !blobRowExists(t, pool, sha) {
		t.Fatal("attached blob's row must survive reclamation")
	}
	if !store.has(sha) {
		t.Fatal("attached blob's bytes must survive reclamation")
	}
	if got := blobRefCount(t, pool, sha); got != 1 {
		t.Errorf("ref_count = %d, want 1", got)
	}
	chargeUser, size := chargeFor(t, pool, sha) // fatals if the charge vanished
	if chargeUser != userID || size != int64(len(data)) {
		t.Errorf("charge = (user %d, %d bytes), want (user %d, %d bytes)", chargeUser, size, userID, len(data))
	}
	if got := usageFor(t, pool, userID); got != int64(len(data)) {
		t.Errorf("usage = %d, want %d (referenced charge must not be credited)", got, len(data))
	}

	// Acceptance clause 2b: the UPDATE-to-zero trigger path still reclaims.
	// Detach (ref_count 1→0) fires trg_blob_refcount_zero, which re-arms the
	// queue row; once due, the unchanged sweeper reclaims it.
	if _, err := pool.Exec(context.Background(),
		`UPDATE blobs SET ref_count = 0 WHERE sha256 = $1`, sha,
	); err != nil {
		t.Fatalf("simulate detach: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE blob_cleanup_queue SET scheduled_at = now() - interval '1 minute' WHERE blob_sha256 = $1`, sha,
	); err != nil {
		t.Fatalf("expire re-armed queue row: %v", err)
	}
	sweepOwnedDue(t, h, sha)

	if blobRowExists(t, pool, sha) {
		t.Error("detached-to-zero blob must be reclaimed via the zero-trigger arming path")
	}
	if store.has(sha) {
		t.Error("detached-to-zero blob's bytes must be reclaimed via the zero-trigger arming path")
	}
	if got := usageFor(t, pool, userID); got != 0 {
		t.Errorf("usage after zero-trigger reclaim = %d, want 0 (credited)", got)
	}
}

// TestPutDedupReferenceInsideWindowSurvivesAndIsNotDoubleCharged is acceptance
// clause 2c + the accounting dedup rule: a second user's re-upload of the same
// content inside the window re-arms the queue row (the blob survives) and
// stores no new bytes, so only the first uploader is charged.
func TestPutDedupReferenceInsideWindowSurvivesAndIsNotDoubleCharged(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	userA := reclamationUser(t, pool)
	userB := reclamationUser(t, pool)

	data := []byte("same content, second user's dedup re-upload inside the window")
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	reclamationBlobScope(t, pool, sha)

	store := newReclamationStore()
	h := &Handler{minio: store, pool: pool, bucket: "blobs", logger: discardLogger()}
	h.SetReclamationPolicy(1440, 0)

	if rec := putAsUser(t, h, userA, sha, data); rec.Code != http.StatusCreated {
		t.Fatalf("user A put status = %d, want 201", rec.Code)
	}
	// Let the window lapse, then re-upload the SAME content as user B.
	rewindQueueDue(t, pool, sha)
	if rec := putAsUser(t, h, userB, sha, data); rec.Code != http.StatusCreated {
		t.Fatalf("user B dedup put status = %d, want 201", rec.Code)
	}

	// Dedup accounting: only A is charged; B stored no new bytes.
	if chargeUser, size := chargeFor(t, pool, sha); chargeUser != userA || size != int64(len(data)) {
		t.Errorf("charge = (user %d, %d bytes), want (user A %d, %d bytes)", chargeUser, size, userA, len(data))
	}
	if got := usageFor(t, pool, userA); got != int64(len(data)) {
		t.Errorf("user A usage = %d, want %d", got, len(data))
	}
	var bRows int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM blob_user_usage WHERE user_id = $1`, userB,
	).Scan(&bRows); err != nil {
		t.Fatalf("count user B usage rows: %v", err)
	}
	if bRows != 0 {
		t.Errorf("user B must have no usage row after a dedup re-upload, got %d", bRows)
	}

	// The dedup re-upload re-armed the grace window: the entry is no longer due
	// and the sweeper must leave the blob alone.
	delay, due := queueRowFor(t, pool, sha)
	if due {
		t.Errorf("dedup re-upload must re-arm the grace window (delay_minutes=%d)", delay)
	}
	sweepOwnedDue(t, h, sha)
	if !blobRowExists(t, pool, sha) {
		t.Error("dedup-referenced blob must survive reclamation")
	}
	if !store.has(sha) {
		t.Error("dedup-referenced blob's bytes must survive reclamation")
	}
}

// TestConcurrentUploadsNeverExceedPerUserBound is acceptance clause 3: with a
// 1000-byte bound and 400-byte uploads, simultaneous uploads by one user
// serialize on the per-user row lock inside the PUT transaction — exactly two
// can charge (800 ≤ 1000 < 1200); every other upload is rejected 413, and the
// aggregate never exceeds the bound.
func TestConcurrentUploadsNeverExceedPerUserBound(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	userID := reclamationUser(t, pool)

	const uploads = 6
	// Each probe body is 400 filler bytes plus a per-index prefix, so the
	// effective charge per upload is len(bodies[i]) — read it back, don't
	// restate it.
	const fillerSize = 400
	quotaBytes := int64(1000)

	bodies := make([][]byte, uploads)
	shas := make([]string, uploads)
	for i := range bodies {
		bodies[i] = []byte(fmt.Sprintf("concurrent bound probe %02d %s", i, bytes.Repeat([]byte("x"), fillerSize)))
		sum := sha256.Sum256(bodies[i])
		shas[i] = hex.EncodeToString(sum[:])
		reclamationBlobScope(t, pool, shas[i])
	}
	perUpload := int64(len(bodies[0]))
	// The bound admits exactly two of these uploads: 2×perUpload ≤ quota < 3×perUpload.
	if 3*perUpload <= quotaBytes || 2*perUpload > quotaBytes {
		t.Fatalf("test misconfigured: perUpload=%d quota=%d does not admit exactly two uploads", perUpload, quotaBytes)
	}

	store := newReclamationStore()
	h := &Handler{minio: store, pool: pool, bucket: "blobs", logger: discardLogger()}
	h.SetReclamationPolicy(1440, quotaBytes)

	var wg sync.WaitGroup
	codes := make([]int, uploads)
	for i := 0; i < uploads; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPut, "/blobs/"+shas[i], bytes.NewReader(bodies[i]))
			req.SetPathValue("sha256", shas[i])
			req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
			rec := httptest.NewRecorder()
			h.Put(rec, req)
			codes[i] = rec.Code
		}(i)
	}
	wg.Wait()

	accepted, rejected := 0, 0
	for i, code := range codes {
		switch code {
		case http.StatusCreated:
			accepted++
		case http.StatusRequestEntityTooLarge:
			rejected++
		default:
			t.Errorf("upload %d: status = %d, want 201 or 413", i, code)
		}
	}
	if accepted != 2 {
		t.Errorf("accepted uploads = %d, want exactly 2 (2×perUpload ≤ bound < 3×perUpload)", accepted)
	}
	if rejected != uploads-accepted {
		t.Errorf("rejected uploads = %d, want %d", rejected, uploads-accepted)
	}
	if got := usageFor(t, pool, userID); got != perUpload*int64(accepted) {
		t.Errorf("usage = %d, want %d — the bound must equal accepted bytes exactly", got, perUpload*int64(accepted))
	}
	if got := usageFor(t, pool, userID); got > quotaBytes {
		t.Errorf("usage = %d exceeds the per-user bound %d", got, quotaBytes)
	}
	var chargedRows int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM blob_user_charges WHERE user_id = $1`, userID,
	).Scan(&chargedRows); err != nil {
		t.Fatalf("count charges: %v", err)
	}
	if chargedRows != accepted {
		t.Errorf("charge rows = %d, want %d (one per accepted upload)", chargedRows, accepted)
	}
}

// TestUnknownLengthUploadChargesMeasuredBytes is acceptance clause 4: a
// chunked upload arrives with ContentLength < 0; the old code stored a
// zero-size fallback. Accounting (and the stored row) must equal the bytes
// actually measured from the stream.
func TestUnknownLengthUploadChargesMeasuredBytes(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	userID := reclamationUser(t, pool)

	data := []byte("chunked!")
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	reclamationBlobScope(t, pool, sha)

	store := newReclamationStore()
	h := &Handler{minio: store, pool: pool, bucket: "blobs", logger: discardLogger()}
	h.SetReclamationPolicy(60, 0)

	req := httptest.NewRequest(http.MethodPut, "/blobs/"+sha, bytes.NewReader(data))
	req.SetPathValue("sha256", sha)
	req.ContentLength = -1 // chunked/unknown length: no usable ContentLength
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.Put(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("put status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}

	var storedSize int64
	if err := pool.QueryRow(context.Background(),
		`SELECT size_bytes FROM blobs WHERE sha256 = $1`, sha,
	).Scan(&storedSize); err != nil {
		t.Fatalf("read blobs row: %v", err)
	}
	if storedSize != int64(len(data)) {
		t.Errorf("blobs.size_bytes = %d, want %d (measured, not the zero-size fallback)", storedSize, len(data))
	}
	if chargeUser, size := chargeFor(t, pool, sha); chargeUser != userID || size != int64(len(data)) {
		t.Errorf("charge = (user %d, %d bytes), want (user %d, %d measured bytes)", chargeUser, size, userID, len(data))
	}
	if got := usageFor(t, pool, userID); got != int64(len(data)) {
		t.Errorf("usage = %d, want %d (measured byte count, not zero)", got, len(data))
	}
}
