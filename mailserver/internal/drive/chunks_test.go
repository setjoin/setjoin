package drive

// White-box (package drive, not drive_test) — the blob/handler_test.go genre:
// tests build a *Handler literal directly and call its unexported methods,
// so the storage-only mismatch/oversized behaviors need no database.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"

	"setjoin.com/mailserver/internal/auth"
)

// fakeStore is an in-memory objectStore for exercising the chunk pipeline
// without a live MinIO — cloned from blob/handler_test.go's double, narrowed
// GetObject signature (io.ReadCloser, not *minio.Object). putTimes backs
// ListObjects' LastModified so worker_test.go's tmp-reaper tests can control
// object age without a live clock.
type fakeStore struct {
	objects    map[string][]byte
	putTimes   map[string]time.Time
	putKeys    []string
	removeKeys []string
	removeErrs map[string]error
	copyDst    []string
	failCopy   bool
}

func newFakeStore() *fakeStore {
	return &fakeStore{objects: map[string][]byte{}, putTimes: map[string]time.Time{}, removeErrs: map[string]error{}}
}

func (f *fakeStore) PutObject(_ context.Context, _, object string, reader io.Reader, _ int64, _ minio.PutObjectOptions) (minio.UploadInfo, error) {
	data, err := io.ReadAll(reader) // drains the TeeReader so the handler's hasher sees the body
	if err != nil {
		return minio.UploadInfo{}, err
	}
	f.objects[object] = data
	f.putTimes[object] = time.Now()
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
	f.putTimes[dst.Object] = time.Now()
	f.copyDst = append(f.copyDst, dst.Object)
	return minio.UploadInfo{Key: dst.Object}, nil
}

func (f *fakeStore) RemoveObject(_ context.Context, _, object string, _ minio.RemoveObjectOptions) error {
	f.removeKeys = append(f.removeKeys, object)
	if err := f.removeErrs[object]; err != nil {
		return err
	}
	delete(f.objects, object)
	delete(f.putTimes, object)
	return nil
}

// GetObject honors a "Range: bytes=start-end" header exactly like a real S3
// endpoint would, so content_test.go's Range-streaming assertions exercise
// real byte-slicing logic rather than trusting an untested fake.
func (f *fakeStore) GetObject(_ context.Context, _, object string, opts minio.GetObjectOptions) (io.ReadCloser, error) {
	data, ok := f.objects[object]
	if !ok {
		return nil, errors.New("not found")
	}
	if rangeHeader := opts.Header().Get("Range"); rangeHeader != "" {
		start, end, ok := parseSingleRange(rangeHeader, int64(len(data)))
		if !ok {
			return nil, fmt.Errorf("fakeStore: unparseable Range %q", rangeHeader)
		}
		data = data[start : end+1]
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// ListObjects enumerates objects whose key has opts.Prefix, reporting each
// one's tracked put time as LastModified — enough for worker.go's tmp reaper
// to be exercised without a live MinIO.
func (f *fakeStore) ListObjects(_ context.Context, _ string, opts minio.ListObjectsOptions) <-chan minio.ObjectInfo {
	ch := make(chan minio.ObjectInfo, len(f.objects))
	keys := make([]string, 0, len(f.objects))
	for key := range f.objects {
		if opts.Prefix != "" && !strings.HasPrefix(key, opts.Prefix) {
			continue
		}
		if opts.StartAfter != "" && key <= opts.StartAfter {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		ch <- minio.ObjectInfo{Key: key, Size: int64(len(f.objects[key])), LastModified: f.putTimes[key]}
	}
	close(ch)
	return ch
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fakeStore satisfies the exported ChunkPromoter seam too — the meet
// package's ingest worker (Task 7) reuses this exact PromoteChunk path via
// its own stagingStore, which is a superset of ChunkPromoter.
var _ ChunkPromoter = (*fakeStore)(nil)

func promoteChunkForTest(ctx context.Context, store ChunkPromoter, bucket, scope, want string, body io.Reader) (int32, error) {
	staged, err := StageChunk(ctx, store, bucket, want, body, -1)
	if err != nil {
		return 0, err
	}
	defer staged.Cleanup(ctx, store, bucket)
	if err := promoteStagedChunk(ctx, store, bucket, scope, staged); err != nil {
		return 0, err
	}
	return staged.Size(), nil
}

// TestPromoteChunkMismatch pins the C2-blob-shaped regression for drive: a
// body whose sha256 does NOT match the URL hash must never promote to the
// canonical key, and the temp object is removed.
func TestPromoteChunkMismatch(t *testing.T) {
	good := []byte("the real chunk bytes")
	sum := sha256.Sum256(good)
	want := hex.EncodeToString(sum[:])

	fake := newFakeStore()

	_, err := promoteChunkForTest(context.Background(), fake, "b", "g", want, bytes.NewReader([]byte("evil mismatched body")))
	if !errors.Is(err, errChunkMismatch) {
		t.Fatalf("want errChunkMismatch, got %v", err)
	}
	if len(fake.copyDst) != 0 {
		t.Errorf("CopyObject must never be called on a mismatch, got %v", fake.copyDst)
	}
	if _, exists := fake.objects["drive/g/"+want]; exists {
		t.Errorf("canonical key must never be written on a mismatch")
	}
	if len(fake.removeKeys) != 1 {
		t.Errorf("temp object must be removed on a mismatch, removeKeys=%v", fake.removeKeys)
	}
}

// TestPromoteChunkHappyPath is the storage-layer happy path: promote lands
// the bytes at drive/<scope>/<sha>, the temp key is cleaned up, and the
// reported size matches.
func TestPromoteChunkHappyPath(t *testing.T) {
	data := []byte("a real 4-byte-aligned-ish chunk")
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])

	fake := newFakeStore()

	size, err := promoteChunkForTest(context.Background(), fake, "b", "g", sha, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("promoteChunk: %v", err)
	}
	if size != int32(len(data)) {
		t.Errorf("size = %d, want %d", size, len(data))
	}
	if got, ok := fake.objects["drive/g/"+sha]; !ok || !bytes.Equal(got, data) {
		t.Errorf("canonical object missing or wrong bytes: ok=%v got=%q", ok, got)
	}
	for _, k := range fake.removeKeys {
		if k == "drive/g/"+sha {
			t.Errorf("RemoveObject must never target the canonical key")
		}
	}
}

func TestStageChunkRejectsKnownZeroSizeBeforeStorage(t *testing.T) {
	fake := newFakeStore()
	_, err := StageChunk(context.Background(), fake, "b", strings.Repeat("0", 64), bytes.NewReader(nil), 0)
	if !errors.Is(err, errChunkSize) {
		t.Fatalf("want errChunkSize, got %v", err)
	}
	if len(fake.putKeys) != 0 {
		t.Fatalf("known-invalid size must not write a temp object, got %v", fake.putKeys)
	}
}

// TestPutChunkOversizedBody pins the 413 mapping: a body exceeding the fixed
// 4 MiB chunk cap is rejected via http.MaxBytesReader; putChunk must map
// that specific error to 413, not the generic 500 every other storage
// failure gets. Uses promoteChunk directly (no space/DB round trip) with a
// reader pre-wrapped exactly like putChunk wraps r.Body.
func TestPutChunkOversizedBody(t *testing.T) {
	rr := httptest.NewRecorder()
	oversized := bytes.Repeat([]byte("x"), maxChunkBytes+1)
	req := httptest.NewRequest(http.MethodPut, "/drive/chunks/x?space=1", bytes.NewReader(oversized))
	req.Body = http.MaxBytesReader(rr, req.Body, maxChunkBytes)

	fake := newFakeStore()

	_, err := promoteChunkForTest(context.Background(), fake, "b", "g", "deadbeef", req.Body)
	var maxBytesErr *http.MaxBytesError
	if !errors.As(err, &maxBytesErr) {
		t.Fatalf("want *http.MaxBytesError, got %v", err)
	}
}

// TestHeadChunkInvalidSha pins that an invalid sha256 400s before any DB hit
// (pool is nil — a DB call would panic).
func TestHeadChunkInvalidSha(t *testing.T) {
	h := &Handler{logger: discardLogger()} // pool intentionally nil
	req := httptest.NewRequest(http.MethodHead, "/drive/chunks/not-a-sha?space=1", nil)
	req.SetPathValue("sha256", "not-a-sha")
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 7}))
	rr := httptest.NewRecorder()
	h.headChunk(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400 for invalid sha256, got %d", rr.Code)
	}
}

// TestPutChunkInvalidSha mirrors TestHeadChunkInvalidSha for PUT — no DB hit.
func TestPutChunkInvalidSha(t *testing.T) {
	h := &Handler{logger: discardLogger()} // pool intentionally nil
	req := httptest.NewRequest(http.MethodPut, "/drive/chunks/not-a-sha?space=1", bytes.NewReader(nil))
	req.SetPathValue("sha256", "not-a-sha")
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 7}))
	rr := httptest.NewRecorder()
	h.putChunk(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400 for invalid sha256, got %d", rr.Code)
	}
}

func TestChunkRoutesRejectPartialACLBindingBeforeDatabase(t *testing.T) {
	t.Parallel()
	h := &Handler{logger: discardLogger()} // pool intentionally nil
	sha := strings.Repeat("a", 64)
	for _, method := range []string{http.MethodHead, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/drive/chunks/"+sha+"?space=1&target=2", bytes.NewReader(nil))
			req.SetPathValue("sha256", sha)
			req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 7}))
			rr := httptest.NewRecorder()
			if method == http.MethodHead {
				h.headChunk(rr, req)
			} else {
				h.putChunk(rr, req)
			}
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("partial ACL binding: want 400, got %d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}
