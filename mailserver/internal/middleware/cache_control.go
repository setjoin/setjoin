// cache_control.go — the single Cache-Control authority for the network mux.
//
// WP2 (review remediation wave, decision 2B): every Cache-Control value the
// gateway emits comes from THIS policy table — per-handler w.Header().Set
// calls were removed in the same change, and a downstream handler that still
// tries to set the header loses (the table's value is stamped at first-write
// time, so conflicts resolve by policy, not execution order). Unlisted paths
// and unsafe methods resolve to `no-store`, so a route that forgets to
// register can never become cacheable.
//
// The one surface that cannot be derived from the request path alone is the
// SPA static handler: GET /settings may be served the index.html
// representation (no-cache) while GET /_app/immutable/x.js is served its
// immutable asset. The handler identifies the RESOLVED representation through
// the narrow ResolveStaticCacheRepresentation hook — a middleware-owned
// context marker recording a fact only the handler knows, never a
// handler-authored header or policy value. The policy for that representation
// stays table-owned (staticCachePolicy below).
package middleware

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
)

// cacheEntry is one policy row. Matching is boundary-aware (the path must
// equal the prefix or continue with '/'), rows are scanned FIRST MATCH WINS,
// and suffix optionally pins the tail of the path (used to split the identity
// diagnostics download from the identity v2 JSON surface). The final row is
// the SPA-static catch-all and doubles as the no-store default (its hook is
// unset on every non-static terminal, including auth/CSRF/rate-limit
// rejections that previously emitted no caching header).
type cacheEntry struct {
	prefix string
	suffix string // "" = any tail
	value  string // effective Cache-Control
	// exact pins the row to prefix as a full path (boundary matching off):
	// census rows whose handler previously stamped exactly one path must not
	// spill onto sibling redirect handlers under the same prefix.
	exact bool
	// static marks the SPA-static catch-all: the value comes from the
	// per-request resolved representation (hook) rather than the row itself.
	static bool
}

// cachePolicyTable — every non-`no-store` value the gateway emits, plus the
// exact-value exceptions the September census pinned. Everything else
// (authenticated API/admin, recovery, link-protect, attachment transfer,
// sync preferences, error paths) falls through the static catch-all to
// no-store. Most-specific rows first; the static catch-all is LAST.
var cachePolicyTable = []cacheEntry{
	// Immutable content.
	{prefix: "/favicon.ico", value: "public, max-age=604800, immutable"},
	{prefix: "/chat/unfurl/image/", value: "private, max-age=31536000, immutable"},
	{prefix: "/jmap/download/", value: "private, max-age=31536000, immutable, no-transform"},
	{prefix: "/blobs/", value: "private, max-age=31536000, immutable"},
	{prefix: "/api/fonts/", value: "public, max-age=31536000, immutable"},

	// Public short.
	{prefix: "/.well-known/autoconfig/", value: "public, max-age=86400"},
	{prefix: "/.well-known/setjoin", value: "public, max-age=3600"},
	{prefix: "/updates/appcast", exact: true, value: "public, max-age=300"},
	{prefix: "/downloads", exact: true, value: "public, max-age=3600"},
	{prefix: "/api/openapi.yaml", exact: true, value: "public, max-age=300"},
	{prefix: "/api/openapi.json", exact: true, value: "public, max-age=300"},
	{prefix: "/api/redoc.standalone.js", exact: true, value: "public, max-age=86400"},
	{prefix: "/api/logo.svg", exact: true, value: "public, max-age=86400"},

	// Exact-value exceptions (census-pinned).
	{prefix: "/jmap/eventsource", value: "no-cache"},
	{prefix: "/mail-attachment/", value: "private, max-age=31536000, immutable, no-transform"},
	{prefix: "/jmap/recovery-raw/", value: "private, no-store"},
	{prefix: "/admin/identity/v2/diagnostics/", suffix: "/download", value: "private, no-store"},
	{prefix: "/admin/identity/v2/", value: "private, no-cache"},

	// SPA static catch-all + no-store default. Keep LAST.
	{prefix: "/", static: true},
}

// cacheRepresentationHolder carries the resolved static representation from
// the terminal static handler back to this middleware at first-write time.
type cacheRepresentationHolder struct {
	resolvedPath string
}

type cacheRepresentationKeyType struct{}

var cacheRepresentationKey cacheRepresentationKeyType

// ResolveStaticCacheRepresentation records the RESOLVED asset/SPA
// representation path for the current request (e.g. "/index.html" when an SPA
// fallback served the shell, "/_app/immutable/a1b2.js" for a hashed asset).
// It is a no-op on contexts that did not come through the Cache-Control
// middleware (the unix-socket setup mux), so the static handler stays usable
// on both.
func ResolveStaticCacheRepresentation(ctx context.Context, resolvedPath string) {
	if holder, ok := ctx.Value(cacheRepresentationKey).(*cacheRepresentationHolder); ok {
		holder.resolvedPath = resolvedPath
	}
}

// staticCachePolicy is the table-owned policy for the resolved static
// representation — the former static_responder.staticCacheControl, moved here
// so TTL decisions live in exactly one place.
func staticCachePolicy(resolvedPath string) string {
	if strings.HasPrefix(resolvedPath, "/_app/immutable/") {
		return "public, max-age=31536000, immutable"
	}
	switch resolvedPath {
	case "/index.html", "/service-worker.js", "/critical-shell.v1.json",
		"/static-representations.v1.json", "/manifest.webmanifest", "/_app/version.json":
		return "no-cache"
	default:
		return "public, max-age=3600"
	}
}

// noStore is the deny-by-default value.
const noStore = "no-store"

// resolveCacheControl resolves the effective value for a request against the
// table. Exported for the behavioral table tests.
func resolveCacheControl(path, method string, holder *cacheRepresentationHolder) string {
	// Cacheability is a safe-method property; POST/PUT/DELETE responses are
	// never cacheable regardless of path.
	if method != http.MethodGet && method != http.MethodHead {
		return noStore
	}
	// The table's LAST row is the SPA-static catch-all; rows before it are
	// specific entries scanned first-match-wins.
	specific := cachePolicyTable[:len(cachePolicyTable)-1]
	for i := range specific {
		entry := &specific[i]
		if entry.exact {
			if path != entry.prefix {
				continue
			}
		} else if !matchCachePrefix(path, entry.prefix) {
			continue
		}
		if entry.suffix != "" && !strings.HasSuffix(path, entry.suffix) {
			continue
		}
		return entry.value
	}
	// Catch-all: the handler-recorded representation when the static
	// responder ran, no-store otherwise (auth rejections, rate-limit
	// refusals and every other terminal that previously emitted no caching
	// header).
	if holder != nil && holder.resolvedPath != "" {
		return staticCachePolicy(holder.resolvedPath)
	}
	return noStore
}

func matchCachePrefix(path, prefix string) bool {
	if prefix == "/" {
		return true
	}
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	// Boundary: "/api/docs" must not match "/api/docs-bad", while a prefix
	// already ending in '/' admits any continuation segment.
	return len(path) == len(prefix) || strings.HasSuffix(prefix, "/") || path[len(prefix)] == '/'
}

// CacheControl wraps next with the policy-table authority: the effective
// value is resolved at the first write — after the terminal handler had its
// chance to record the static representation, ahead of any header flush — so
// a downstream Set cannot override the table. STATUS-AWARE: the table value
// applies to success responses (2xx, and 304 revalidations of the same
// resource); every other status — 4xx/5xx rejections, redirects — is
// no-store, matching the pre-migration handlers which set their header only
// on success branches (a blob ownership 404 must not inherit
// private-immutable-1y; an auth/rate-limit 429 must not inherit a public
// lifetime).
func CacheControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		holder := &cacheRepresentationHolder{}
		r = r.WithContext(context.WithValue(r.Context(), cacheRepresentationKey, holder))

		var value string
		stampWith := func(status int) {
			if value == "" {
				value = resolveCacheControl(r.URL.Path, r.Method, holder)
				if status != 0 && status != http.StatusNotModified && (status < 200 || status > 299) {
					value = noStore
				}
			}
			w.Header().Set("Cache-Control", value)
		}

		next.ServeHTTP(&cacheControlWriter{ResponseWriter: w, stamp: stampWith}, r)
		// A handler that wrote neither headers nor body still gets the policy
		// (implicit 200).
		stampWith(0)
	})
}

// cacheControlWriter stamps the table's value at the first WriteHeader/Write/
// Flush and then behaves as a pure pass-through (no buffering; Flush/Hijack/
// ReadFrom forwarded so SSE and sendfile keep working).
type cacheControlWriter struct {
	http.ResponseWriter
	stamp func(status int)
	done  bool
}

func (c *cacheControlWriter) stampOnce(status int) {
	if !c.done {
		c.done = true
		c.stamp(status)
	}
}

func (c *cacheControlWriter) WriteHeader(status int) {
	c.stampOnce(status)
	c.ResponseWriter.WriteHeader(status)
}

func (c *cacheControlWriter) Write(b []byte) (int, error) {
	c.stampOnce(0)
	return c.ResponseWriter.Write(b)
}

func (c *cacheControlWriter) Flush() {
	c.stampOnce(0)
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (c *cacheControlWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := c.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// ReadFrom preserves the sendfile path: ServeContent's io.CopyN finds this
// (not the bare ResponseWriter) and we delegate to the underlying
// ReaderFrom when the response writer still offers it.
func (c *cacheControlWriter) ReadFrom(r io.Reader) (int64, error) {
	c.stampOnce(0)
	if rf, ok := c.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(c.ResponseWriter, r)
}
