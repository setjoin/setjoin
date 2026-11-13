package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCacheControlTable_PinsTheSeptemberCensus is the WP2 behavioral freeze:
// every route whose pre-middleware handler set its own Cache-Control keeps
// the EXACT effective value through the assembled middleware (plan WP2 req
// 2-3). Values come from resolveCacheControl — the same resolution the
// stamped wrapper performs at first write.
func TestCacheControlTable_PinsTheSeptemberCensus(t *testing.T) {
	cases := []struct {
		path   string
		method string
		want   string
	}{
		// ── immutable content ────────────────────────────────────────────
		{"/favicon.ico", http.MethodGet, "public, max-age=604800, immutable"},
		{"/api/fonts/ibm-plex-sans-400.woff2", http.MethodGet, "public, max-age=31536000, immutable"},
		{"/api/fonts/ibm-plex-sans-500.woff2", http.MethodGet, "public, max-age=31536000, immutable"},
		{"/chat/unfurl/image/deadbeef", http.MethodGet, "private, max-age=31536000, immutable"},
		{"/jmap/download/acc/blob/name.txt", http.MethodGet, "private, max-age=31536000, immutable, no-transform"},
		{"/blobs/" + strings.Repeat("a", 64), http.MethodGet, "private, max-age=31536000, immutable"},

		// ── public short (exact-path census rows; sibling redirects stay
		// no-store — they previously emitted no caching header at all) ────
		{"/.well-known/autoconfig/mail/config-v1.1.xml", http.MethodGet, "public, max-age=86400"},
		{"/.well-known/setjoin", http.MethodGet, "public, max-age=3600"},
		{"/updates/appcast", http.MethodGet, "public, max-age=300"},
		{"/updates/slug/file.pkg", http.MethodGet, noStore},
		{"/downloads", http.MethodGet, "public, max-age=3600"},
		{"/downloads/macos", http.MethodGet, noStore},
		{"/downloads/asset/pkg-1", http.MethodGet, noStore},
		{"/api/openapi.yaml", http.MethodGet, "public, max-age=300"},
		{"/api/openapi.json", http.MethodGet, "public, max-age=300"},
		// /api/docs emitted NO Cache-Control pre-migration (the census 86400 was
		// the renderer/logo, not the docs HTML) — it stays deny-by-default.
		{"/api/docs", http.MethodGet, noStore},
		{"/api/redoc.standalone.js", http.MethodGet, "public, max-age=86400"},
		{"/api/logo.svg", http.MethodGet, "public, max-age=86400"},

		// ── exact-value exceptions ───────────────────────────────────────
		{"/jmap/eventsource", http.MethodGet, "no-cache"},
		{"/mail-attachment/" + strings.Repeat("a", 64), http.MethodGet, "private, max-age=31536000, immutable, no-transform"},
		{"/jmap/recovery-raw/1/2", http.MethodGet, "private, no-store"},
		{"/admin/identity/v2/diagnostics/42/download", http.MethodGet, "private, no-store"},
		{"/admin/identity/v2/diagnostics/42", http.MethodGet, "private, no-cache"},
		{"/admin/identity/v2/sources", http.MethodGet, "private, no-cache"},

		// ── no-store bucket (formerly explicit per-handler Sets) ─────────
		{"/link-protect", http.MethodGet, noStore},
		{"/admin/system/upgrades", http.MethodGet, noStore},
		{"/admin/system/offline", http.MethodGet, noStore},
		{"/admin/mailboxes/7/lifecycle", http.MethodGet, noStore},
		{"/recovery/uploads", http.MethodGet, noStore},
		{"/settings/sender-control", http.MethodGet, noStore},
		{"/user/offline/sync-preferences", http.MethodGet, noStore},
		{"/drive/export/token", http.MethodGet, noStore},

		// ── deny-by-default: unlisted routes and unsafe methods ─────────
		{"/some/future/route", http.MethodGet, noStore},
		{"/admin/audit/csv", http.MethodPost, noStore},
		{"/blobs/" + strings.Repeat("a", 64), http.MethodPut, noStore},
		{"/jmap/download/acc/blob/name.txt", http.MethodPost, noStore},
		{"/updates/appcast", http.MethodPost, noStore},
	}
	for _, c := range cases {
		if got := resolveCacheControl(c.path, c.method, nil); got != c.want {
			t.Errorf("resolveCacheControl(%q, %s) = %q, want %q", c.path, c.method, got, c.want)
		}
	}
}

// TestStaticCachePolicy_PinsRepresentations pins the resolved-representation
// policy (the former static_responder.staticCacheControl): the SPA fallback
// distinction lives in the RESOLVED path, not the request path.
func TestStaticCachePolicy_PinsRepresentations(t *testing.T) {
	cases := []struct{ resolved, want string }{
		{"/index.html", "no-cache"},
		{"/service-worker.js", "no-cache"},
		{"/critical-shell.v1.json", "no-cache"},
		{"/static-representations.v1.json", "no-cache"},
		{"/manifest.webmanifest", "no-cache"},
		{"/_app/version.json", "no-cache"},
		{"/_app/immutable/app.12345678.js", "public, max-age=31536000, immutable"},
		{"/favicon.ico", "public, max-age=3600"}, // hashed asset copy, not the route
	}
	for _, c := range cases {
		if got := staticCachePolicy(c.resolved); got != c.want {
			t.Errorf("staticCachePolicy(%q) = %q, want %q", c.resolved, got, c.want)
		}
	}
}

// TestCacheControl_RequestPathVsResolvedRepresentation proves the hook: the
// same request path resolves differently once the static handler records the
// representation it actually served.
func TestCacheControl_RequestPathVsResolvedRepresentation(t *testing.T) {
	// A bare SPA route with no hook yet → no-store (nothing resolved; a
	// non-static terminal such as an auth rejection).
	if got := resolveCacheControl("/settings", http.MethodGet, nil); got != noStore {
		t.Fatalf("unresolved SPA route = %q, want no-store", got)
	}
	// The static handler resolved the request to index.html → no-cache.
	holder := &cacheRepresentationHolder{resolvedPath: "/index.html"}
	if got := resolveCacheControl("/settings", http.MethodGet, holder); got != "no-cache" {
		t.Fatalf("SPA fallback /settings via index.html = %q, want no-cache", got)
	}
	// An immutable asset resolved under its own request path.
	holder = &cacheRepresentationHolder{resolvedPath: "/_app/immutable/app.1.js"}
	if got := resolveCacheControl("/_app/immutable/app.1.js", http.MethodGet, holder); got != "public, max-age=31536000, immutable" {
		t.Fatalf("immutable asset = %q, want the immutable value", got)
	}
}

// TestCacheControl_ConflictResolvedByTable proves a downstream Set cannot
// override the table (plan WP2 req 4): the handler writes LAST, the table
// still wins.
func TestCacheControl_ConflictResolvedByTable(t *testing.T) {
	sneaky := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=999999")
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	CacheControl(sneaky).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/openapi.yaml", nil))
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Fatalf("downstream Set overrode the table: %q", got)
	}
}

// TestCacheControl_UnsafeMethodGetsNoStoreEvenWhenHandlerSetsPublic proves
// the method gate outranks any table row.
func TestCacheControl_UnsafeMethodGetsNoStoreEvenWhenHandlerSetsPublic(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	CacheControl(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/blobs/abc", nil))
	if got := rec.Header().Get("Cache-Control"); got != noStore {
		t.Fatalf("PUT response Cache-Control = %q, want no-store", got)
	}
}

// TestCacheControl_PreservesStreamingAndOtherHeaders proves no buffering
// (SSE flush reaches the underlying writer) and unrelated headers survive.
func TestCacheControl_PreservesStreamingAndOtherHeaders(t *testing.T) {
	sse := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); !ok {
			t.Error("flusher capability lost through the wrapper")
		} else {
			_, _ = w.Write([]byte("data: hi\n\n"))
			f.Flush()
		}
	})
	rec := httptest.NewRecorder()
	CacheControl(sse).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/jmap/eventsource", nil))
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("eventsource Cache-Control = %q, want no-cache", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("Content-Type lost: %q", got)
	}
	// httptest.ResponseRecorder has no real flush semantics; the assertion
	// above proves the wrapper type-asserts and forwards without panic.
}

// TestCacheControl_RejectionsNeverInheritSuccessLifetimes pins the astra P2:
// a 404 on a registered immutable route is no-store, not private-immutable-1y;
// a 429 on a registered public route is no-store; a 304 revalidation keeps
// the table value (it is the same cached resource).
func TestCacheControl_RejectionsNeverInheritSuccessLifetimes(t *testing.T) {
	cases := []struct {
		path   string
		status int
		want   string
	}{
		{"/blobs/" + strings.Repeat("a", 64), http.StatusNotFound, noStore},
		{"/.well-known/autoconfig/mail/config-v1.1.xml", http.StatusNotFound, noStore},
		{"/downloads", http.StatusTooManyRequests, noStore},
		{"/favicon.ico", http.StatusInternalServerError, noStore},
		{"/blobs/" + strings.Repeat("a", 64), http.StatusNotModified, "private, max-age=31536000, immutable"},
	}
	for _, c := range cases {
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(c.status)
		})
		rec := httptest.NewRecorder()
		CacheControl(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, c.path, nil))
		if got := rec.Header().Get("Cache-Control"); got != c.want {
			t.Errorf("%s @%d: Cache-Control = %q, want %q", c.path, c.status, got, c.want)
		}
	}
}

// TestCacheControl_NoStoreOnAuthRejectionShape proves an unregistered terminal
// (the shape of an auth/CSRF/rate-limit rejection: WriteHeader without body,
// no static hook) gets the deny-by-default value, not silence.
func TestCacheControl_NoStoreOnAuthRejectionShape(t *testing.T) {
	rejection := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	rec := httptest.NewRecorder()
	CacheControl(rejection).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/system/config", nil))
	if got := rec.Header().Get("Cache-Control"); got != noStore {
		t.Fatalf("rejection shape Cache-Control = %q, want no-store", got)
	}
}

// TestCacheControl_BoundaryPrefixMatching proves prefix rows cannot bleed
// into sibling paths.
func TestCacheControl_BoundaryPrefixMatching(t *testing.T) {
	if got := resolveCacheControl("/api/docs-bad", http.MethodGet, nil); got != noStore {
		t.Fatalf("/api/docs-bad matched /api/docs: %q", got)
	}
	if got := resolveCacheControl("/admin/identity/v2x/sources", http.MethodGet, nil); got != noStore {
		t.Fatalf("/admin/identity/v2x matched /admin/identity/v2/: %q", got)
	}
	if got := resolveCacheControl("/downloads", http.MethodGet, nil); got != "public, max-age=3600" {
		t.Fatalf("/downloads exact path must match: %q", got)
	}
}
