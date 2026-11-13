package jmap

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"setjoin.com/shared/httputil"
)

// serveImmutableBlob is the single byte-serving seam for immutable mail blobs.
// Setting the strong validator before http.ServeContent lets the standard
// library own RFC-compliant Range, If-Range, 206, and 416 behavior without a
// second hand-written range parser. A zero modtime intentionally suppresses a
// weaker Last-Modified validator.
func serveImmutableBlob(
	w http.ResponseWriter,
	r *http.Request,
	content io.ReadSeeker,
	name, contentType, disposition, sha256 string,
) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`%s; filename="%s"`, disposition, sanitizeFilename(name)))
	w.Header().Set("ETag", `"`+sha256+`"`)
	w.Header().Set("Accept-Ranges", "bytes")
	// No Content-Encoding header means the selected representation is identity;
	// `no-transform` forbids intermediaries from compressing a byte range. An
	// explicit `identity` header would make net/http suppress Content-Length.
	// Blob bytes are attacker-controlled and share the authenticated app origin.
	httputil.SetUntrustedBlobHeaders(w)
	http.ServeContent(w, r, name, time.Time{}, content)
}
