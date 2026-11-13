package carddav

import (
	"context"
	"strings"
	"testing"
)

// TestEtagFromResult_NoBareQuotes guards the double-quoting fix: etagFromResult
// must return a bare hex string (no embedded quotes) so that the single
// fmt.Sprintf(`"%s"`, ...) call in handlePut produces a valid RFC 7232 ETag
// rather than the malformed `""%x""` the old code produced.
func TestEtagFromResult_NoBareQuotes(t *testing.T) {
	h := &Handler{} // pool is nil; DB path not taken when uid is ""

	// Non-empty result with no DB → falls back to sha256 hex of result bytes.
	// uid="" so the (scoped) DB lookup is skipped; abID/userID are unused here.
	etag := h.etagFromResult(context.Background(), []byte(`{"created":{"k1":1}}`), "", 0, 0)
	if strings.HasPrefix(etag, `"`) || strings.HasSuffix(etag, `"`) {
		t.Errorf("etagFromResult returned embedded quotes: %q (must be bare hex)", etag)
	}
	if etag == "" {
		t.Error("etagFromResult returned empty string for non-empty result")
	}

	// Ensure the caller-side wrapping produces a valid RFC 7232 ETag.
	wrapped := `"` + etag + `"`
	if !strings.HasPrefix(wrapped, `"`) || !strings.HasSuffix(wrapped, `"`) ||
		strings.Count(wrapped, `"`) != 2 {
		t.Errorf("wrapped ETag is not valid: %q", wrapped)
	}
}
