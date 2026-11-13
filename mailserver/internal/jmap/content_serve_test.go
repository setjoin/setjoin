package jmap

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/middleware"
)

type zeroReaderAt struct{}

func (zeroReaderAt) ReadAt(p []byte, _ int64) (int, error) {
	clear(p)
	return len(p), nil
}

const testBlobSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func serveTestBlob(t *testing.T, method, rangeHeader, ifRange string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/mail-attachment/"+testBlobSHA, nil)
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}
	if ifRange != "" {
		req.Header.Set("If-Range", ifRange)
	}
	rec := httptest.NewRecorder()
	// WP2: assert through the assembled middleware at the attachment-transfer
	// route this helper actually serves — its SUCCESS branch reached
	// serveImmutableBlob (:296), whose Set overwrote the earlier no-store, so
	// the effective pre-wave value was the immutable one (astra round 1).
	middleware.CacheControl(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveImmutableBlob(w, r, bytes.NewReader([]byte("0123456789")), "file.txt", "text/plain", "attachment", testBlobSHA)
	})).ServeHTTP(rec, req)
	return rec
}

func TestServeImmutableBlobFullAndRangeHeaders(t *testing.T) {
	full := serveTestBlob(t, http.MethodGet, "", "")
	if full.Code != http.StatusOK || full.Body.String() != "0123456789" {
		t.Fatalf("full response = %d %q", full.Code, full.Body.String())
	}
	for key, want := range map[string]string{
		"ETag":          `"` + testBlobSHA + `"`,
		"Accept-Ranges": "bytes",
		"Cache-Control": "private, max-age=31536000, immutable, no-transform",
	} {
		if got := full.Header().Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if got := full.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want implicit identity", got)
	}

	partial := serveTestBlob(t, http.MethodGet, "bytes=3-6", `"`+testBlobSHA+`"`)
	if partial.Code != http.StatusPartialContent || partial.Body.String() != "3456" {
		t.Fatalf("partial response = %d %q", partial.Code, partial.Body.String())
	}
	if got := partial.Header().Get("Content-Range"); got != "bytes 3-6/10" {
		t.Fatalf("Content-Range = %q", got)
	}
	if got := partial.Header().Get("Content-Length"); got != "4" {
		t.Fatalf("Content-Length = %q", got)
	}
}

func TestServeImmutableBlobIfRangeMismatchAndOutOfBounds(t *testing.T) {
	changed := serveTestBlob(t, http.MethodGet, "bytes=3-6", `"different"`)
	if changed.Code != http.StatusOK || changed.Body.String() != "0123456789" {
		t.Fatalf("changed validator must return full 200, got %d %q", changed.Code, changed.Body.String())
	}

	outOfBounds := serveTestBlob(t, http.MethodGet, "bytes=99-100", `"`+testBlobSHA+`"`)
	if outOfBounds.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("out-of-bounds = %d, want 416", outOfBounds.Code)
	}
	if got := outOfBounds.Header().Get("Content-Range"); got != "bytes */10" {
		t.Fatalf("416 Content-Range = %q", got)
	}
}

func TestServeImmutableBlobZeroByteAndHead(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/mail-attachment/"+testBlobSHA, nil)
	rec := httptest.NewRecorder()
	serveImmutableBlob(rec, req, bytes.NewReader(nil), "empty.bin", "application/octet-stream", "attachment", testBlobSHA)
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("zero response = %d len=%d headers=%v", rec.Code, rec.Body.Len(), rec.Header())
	}

	head := serveTestBlob(t, http.MethodHead, "", "")
	if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Length") != "10" {
		t.Fatalf("HEAD response = %d len=%d headers=%v", head.Code, head.Body.Len(), head.Header())
	}
	if !strings.Contains(head.Header().Get("Content-Disposition"), "file.txt") {
		t.Fatalf("Content-Disposition = %q", head.Header().Get("Content-Disposition"))
	}
}

func TestServeImmutableBlobConditionalCacheAndEightGiBBoundary(t *testing.T) {
	cacheReq := httptest.NewRequest(http.MethodGet, "/mail-attachment/"+testBlobSHA, nil)
	cacheReq.Header.Set("If-None-Match", `"`+testBlobSHA+`"`)
	notModified := httptest.NewRecorder()
	serveImmutableBlob(notModified, cacheReq, bytes.NewReader([]byte("0123456789")), "file.txt", "text/plain", "attachment", testBlobSHA)
	if notModified.Code != http.StatusNotModified || notModified.Body.Len() != 0 {
		t.Fatalf("If-None-Match response = %d len=%d", notModified.Code, notModified.Body.Len())
	}

	const size = int64(8) << 30
	req := httptest.NewRequest(http.MethodGet, "/mail-attachment/"+testBlobSHA, nil)
	req.Header.Set("Range", "bytes=8589934591-8589934591")
	req.Header.Set("If-Range", `"`+testBlobSHA+`"`)
	rec := httptest.NewRecorder()
	serveImmutableBlob(rec, req, io.NewSectionReader(zeroReaderAt{}, 0, size), "large.bin", "application/octet-stream", "attachment", testBlobSHA)
	if rec.Code != http.StatusPartialContent || rec.Body.Len() != 1 {
		t.Fatalf("8 GiB boundary range = %d len=%d", rec.Code, rec.Body.Len())
	}
	if got := rec.Header().Get("Content-Range"); got != "bytes 8589934591-8589934591/8589934592" {
		t.Fatalf("Content-Range = %q", got)
	}
}
