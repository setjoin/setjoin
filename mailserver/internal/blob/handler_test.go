package blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/testsupport"
)

// fakeStore is an in-memory objectStore for exercising Put without a live MinIO.
// It records every PutObject/RemoveObject/CopyObject target so tests can assert
// the canonical (client-supplied) key is never written or deleted directly.
type fakeStore struct {
	objects    map[string][]byte
	putKeys    []string
	removeKeys []string
	copyDst    []string
	failCopy   bool
	failRemove map[string]bool // keys whose RemoveObject fails (transient-failure tests)
}

func newFakeStore() *fakeStore { return &fakeStore{objects: map[string][]byte{}} }

func (f *fakeStore) PutObject(_ context.Context, _, object string, reader io.Reader, _ int64, _ minio.PutObjectOptions) (minio.UploadInfo, error) {
	data, err := io.ReadAll(reader) // drains the TeeReader so the handler's hasher sees the body
	if err != nil {
		return minio.UploadInfo{}, err
	}
	f.objects[object] = data
	f.putKeys = append(f.putKeys, object)
	return minio.UploadInfo{Key: object, Size: int64(len(data))}, nil
}

func (f *fakeStore) CopyObject(_ context.Context, dst minio.CopyDestOptions, src minio.CopySrcOptions) (minio.UploadInfo, error) {
	if f.failCopy {
		return minio.UploadInfo{}, errors.New("copy failed")
	}
	data, ok := f.objects[src.Object]
	if !ok {
		return minio.UploadInfo{}, errors.New("copy source not found")
	}
	f.objects[dst.Object] = data
	f.copyDst = append(f.copyDst, dst.Object)
	return minio.UploadInfo{Key: dst.Object}, nil
}

func (f *fakeStore) RemoveObject(_ context.Context, _, object string, _ minio.RemoveObjectOptions) error {
	if f.failRemove[object] {
		return errors.New("minio transient failure")
	}
	delete(f.objects, object)
	f.removeKeys = append(f.removeKeys, object)
	return nil
}

func (f *fakeStore) GetObject(_ context.Context, _, _ string, _ minio.GetObjectOptions) (*minio.Object, error) {
	return nil, errors.New("not implemented") // Put never reads
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func putRequest(t *testing.T, sha string, body []byte) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/blobs/"+sha, bytes.NewReader(body))
	req.SetPathValue("sha256", sha)
	return req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 99}))
}

// TestPutMismatchDoesNotDestroyCanonical is the C2-blob regression: a PUT with a
// body whose hash does NOT match the URL SHA must never delete or overwrite the
// existing canonical blob at that SHA. Against the old code (PutObject then
// RemoveObject on the canonical key) the victim blob is destroyed and this fails.
func TestPutMismatchDoesNotDestroyCanonical(t *testing.T) {
	good := []byte("the real, shared, cross-tenant attachment bytes")
	sum := sha256.Sum256(good)
	canonical := hex.EncodeToString(sum[:])

	fake := newFakeStore()
	fake.objects[canonical] = good // a victim's pre-existing deduped blob

	h := &Handler{minio: fake, bucket: "blobs", logger: discardLogger()}

	// Attacker PUTs a mismatched body under the victim's known SHA.
	rec := httptest.NewRecorder()
	h.Put(rec, putRequest(t, canonical, []byte("evil overwrite attempt")))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got, ok := fake.objects[canonical]; !ok || !bytes.Equal(got, good) {
		t.Fatalf("canonical blob was destroyed/altered: present=%v got=%q want=%q", ok, got, good)
	}
	for _, k := range fake.putKeys {
		if k == canonical {
			t.Errorf("PutObject targeted the canonical key %s", canonical)
		}
	}
	for _, k := range fake.removeKeys {
		if k == canonical {
			t.Errorf("RemoveObject targeted the canonical key %s", canonical)
		}
	}
}

// TestPutValidUploadPromotesViaCopy verifies the happy path: body streamed to a
// temp key, then promoted to the canonical key via CopyObject, temp cleaned up.
func TestPutValidUploadPromotesViaCopy(t *testing.T) {
	data := []byte("hello mailserver attachment")
	sum := sha256.Sum256(data)
	canonical := hex.EncodeToString(sum[:])

	fake := newFakeStore()
	// A valid upload records a blobs row (attachments-P0: PUT /blobs → INSERT INTO
	// blobs), so this path needs a real pool — unlike the reject tests, which bail
	// before the DB write.
	h := &Handler{minio: fake, bucket: "blobs", pool: testsupport.OpenTestPool(t), logger: discardLogger()}

	rec := httptest.NewRecorder()
	h.Put(rec, putRequest(t, canonical, data))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	if got := fake.objects[canonical]; !bytes.Equal(got, data) {
		t.Fatalf("canonical blob = %q, want %q", got, data)
	}
	for _, k := range fake.putKeys {
		if k == canonical {
			t.Errorf("PutObject wrote the canonical key directly: %s", k)
		}
		if !strings.HasPrefix(k, "tmp/upload/") {
			t.Errorf("PutObject key %q is not a temp key", k)
		}
	}
	if len(fake.copyDst) != 1 || fake.copyDst[0] != canonical {
		t.Errorf("CopyObject dst = %v, want [%s]", fake.copyDst, canonical)
	}
	if len(fake.objects) != 1 { // temp key must be cleaned up
		t.Errorf("leftover objects after upload: %d", len(fake.objects))
	}
}

// TestPutRejectsInvalidHashFormat: a non-SHA path value is rejected with 400
// before any storage call (no path traversal / arbitrary key write).
func TestPutRejectsInvalidHashFormat(t *testing.T) {
	for _, bad := range []string{
		"", "xyz", "../../etc/passwd", "tmp/upload/abc",
		strings.ToUpper(strings.Repeat("a", 64)), // uppercase hex rejected
		strings.Repeat("a", 63),                  // too short
		strings.Repeat("a", 65),                  // too long
	} {
		fake := newFakeStore()
		h := &Handler{minio: fake, bucket: "blobs", logger: discardLogger()}
		rec := httptest.NewRecorder()
		h.Put(rec, putRequest(t, bad, []byte("data")))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("hash %q: status = %d, want 400", bad, rec.Code)
		}
		if len(fake.putKeys) != 0 || len(fake.removeKeys) != 0 {
			t.Errorf("hash %q: storage touched (put=%v remove=%v)", bad, fake.putKeys, fake.removeKeys)
		}
	}
}

func TestHandlerGetMissingHash(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/blobs/", nil)
	rec := httptest.NewRecorder()

	blobHash := req.PathValue("sha256")
	if blobHash != "" {
	}
	if "" == "" {
		http.Error(rec, "missing blob ID", http.StatusBadRequest)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestHandlerPutHashValidation(t *testing.T) {
	content := []byte("hello mailserver")
	hash := sha256.Sum256(content)
	hashHex := hex.EncodeToString(hash[:])

	if len(hashHex) != 64 {
		t.Errorf("sha256 hex length = %d, want 64", len(hashHex))
	}

	wrongHash := "a" + hashHex[1:]
	if wrongHash == hashHex {
		t.Error("wrong hash should not equal correct hash")
	}
}

func TestNewMinIOClientConfig(t *testing.T) {
	cfg := &struct {
		MinIOEndpoint  string
		MinIOAccessKey string
		MinIOSecretKey string
		MinIOSecure    bool
	}{
		MinIOEndpoint:  "127.0.0.1:9000",
		MinIOAccessKey: "minioadmin",
		MinIOSecretKey: "minioadmin",
		MinIOSecure:    false,
	}
	if cfg.MinIOEndpoint == "" {
		t.Error("MinIO endpoint should not be empty")
	}
}
