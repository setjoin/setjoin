package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// CSRF here is an Origin/Referer same-origin check (no CSRF token), and only
// applies to state-changing methods. See csrf.go.

func newCSRFHandler() http.Handler {
	return CSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func TestCSRFRejectsMismatchedOrigin(t *testing.T) {
	handler := newCSRFHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://mail.example.com/api/send", nil)
	r.Header.Set("Origin", "https://evil.example.com")
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("mismatched Origin: status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestCSRFRejectsMismatchedReferer(t *testing.T) {
	handler := newCSRFHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://mail.example.com/api/send", nil)
	r.Header.Set("Referer", "https://evil.example.com/phish")
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("mismatched Referer: status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestCSRFRejectsMalformedOrigin(t *testing.T) {
	handler := newCSRFHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://mail.example.com/api/send", nil)
	// A control character makes url.Parse fail, exercising the parse-error branch.
	r.Header.Set("Origin", "https://\x7f.example.com")
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("malformed Origin: status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestCSRFAllowsMatchingOrigin(t *testing.T) {
	handler := newCSRFHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://mail.example.com/api/send", nil)
	r.Host = "mail.example.com"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Origin", "https://mail.example.com")
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("matching Origin: status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestCSRFAllowsMatchingOriginOverDirectTLS(t *testing.T) {
	// Direct (non-proxied) TLS deployment: no X-Forwarded-Proto exists, so the
	// connection itself decides the scheme.
	handler := newCSRFHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://mail.example.com/api/send", nil)
	r.Host = "mail.example.com"
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Origin", "https://mail.example.com")
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("matching Origin over direct TLS: status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestCSRFAllowsMatchingRefererWhenNoOrigin(t *testing.T) {
	handler := newCSRFHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "https://mail.example.com/api/settings", nil)
	r.Host = "mail.example.com"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Referer", "https://mail.example.com/inbox")
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("matching Referer: status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestCSRFAllowsMatchingOriginWithMatchingExplicitPort(t *testing.T) {
	// Ports are part of the tuple, normalized against the scheme default:
	// an explicit :8443 on both sides is the same origin.
	handler := newCSRFHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "https://mail.example.com:8443/api/thing/1", nil)
	r.Host = "mail.example.com:8443"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Origin", "https://mail.example.com:8443")
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Origin with matching explicit port: status = %d, want %d", w.Code, http.StatusOK)
	}

	// The explicit default port is equivalent to no port at all.
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "https://mail.example.com/api/send", nil)
	r.Host = "mail.example.com"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Origin", "https://mail.example.com:443")
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Origin with explicit default port: status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestCSRFRejectsElidedPortMismatch(t *testing.T) {
	// occ_c4b68750211fc1a7e3eb82e9 (csrf-origin-port-elision): the old
	// host-only comparison stripped BOTH ports, so any attacker-chosen port
	// on the right host passed. Same host, attacker port → 403.
	handler := newCSRFHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "https://mail.example.com:8443/api/thing/1", nil)
	r.Host = "mail.example.com:8443"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Origin", "https://mail.example.com") // default :443 ≠ :8443
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("port-eliding Origin: status = %d, want %d", w.Code, http.StatusForbidden)
	}

	// And an explicit wrong port is equally refused.
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "https://mail.example.com/api/send", nil)
	r.Host = "mail.example.com"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Origin", "https://mail.example.com:8443")
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("wrong-port Origin: status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestCSRFRejectsSchemeDowngrade(t *testing.T) {
	// occ_c4b68750211fc1a7e3eb82e9: the old comparison ignored scheme, so an
	// http:// origin was accepted on an https site. Scheme now matches the
	// client-facing edge; an http origin against an https site is refused.
	handler := newCSRFHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://mail.example.com/api/send", nil)
	r.Host = "mail.example.com"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Origin", "http://mail.example.com")
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("scheme-downgraded Origin: status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestCSRFRejectsNullOrigin(t *testing.T) {
	// The string "null" (sandboxed iframe / opaque origin) carries no scheme
	// and can never equal the site tuple.
	handler := newCSRFHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://mail.example.com/api/send", nil)
	r.Host = "mail.example.com"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Origin", "null")
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("null Origin: status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestCSRFAllowsPlainHTTPTuple(t *testing.T) {
	// Plain-http deployments (dev, S2S-adjacent UIs): an http origin matches
	// an http client-facing scheme, including the explicit default port.
	handler := newCSRFHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8444/auth/login", nil)
	r.Host = "127.0.0.1:8444"
	r.Header.Set("X-Forwarded-Proto", "http")
	r.Header.Set("Origin", "http://127.0.0.1:8444")
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("matching http tuple: status = %d, want %d", w.Code, http.StatusOK)
	}

	// Case-insensitive scheme, explicit default port equivalent.
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "http://mail.example.com/api", nil)
	r.Host = "mail.example.com"
	r.Header.Set("X-Forwarded-Proto", "HTTP")
	r.Header.Set("Origin", "HTTP://MAIL.EXAMPLE.COM:80")
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("case-insensitive http tuple: status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestCSRFRejectsNonHTTPOriginScheme(t *testing.T) {
	// Schemes outside the http(s) family can never match the tuple.
	handler := newCSRFHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://mail.example.com/api/send", nil)
	r.Host = "mail.example.com"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Origin", "ftp://mail.example.com")
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("ftp Origin: status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestCSRFRejectsPortlessHostWithPortOrigin(t *testing.T) {
	// An origin whose URL carries a port but no host ("https://:8443") has an
	// empty hostname that never equals the site host.
	handler := newCSRFHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://mail.example.com/api/send", nil)
	r.Host = "mail.example.com"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Origin", "https://:8443")
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("empty-hostname Origin: status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestSanitizedForwardedProto(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"https", "https"},
		{"HTTPS", "https"},
		{"http", "http"},
		{" http ", "http"},
		// Anything else is not a scheme token the gateway could have derived:
		// list syntax, junk, and empty values all fall back to the connection.
		{"https, http", ""},
		{"ftp", ""},
		{"", ""},
		{"\x00https", ""},
	} {
		if got := sanitizedForwardedProto(tc.in); got != tc.want {
			t.Errorf("sanitizedForwardedProto(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCSRFAllowsMissingOriginAndReferer(t *testing.T) {
	// Documented behavior: browserless/S2S/native clients send neither header
	// and are allowed through — this middleware is Origin/Referer-based, not
	// a CSRF-token check.
	handler := newCSRFHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://mail.example.com/api/send", nil)
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("no Origin/Referer: status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestCSRFBypassesSafeMethods(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		handler := newCSRFHandler()
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, "https://mail.example.com/api/messages", nil)
		r.Header.Set("Origin", "https://evil.example.com")
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("%s with mismatched Origin: status = %d, want %d (safe methods must bypass)", method, w.Code, http.StatusOK)
		}
	}
}

func TestCSRFPrefersForwardedHostBehindProxy(t *testing.T) {
	// The gateway's authproxy rewrites the upstream Host to AUTHSERVER_URL's
	// host and sets X-Forwarded-Host (and X-Forwarded-Proto) to the site the
	// browser actually used — the Origin must be compared against THAT tuple,
	// or every browser login through the proxy 403s when the two hostnames
	// differ (B1 gate finding).
	handler := newCSRFHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8444/auth/login", nil)
	r.Host = "127.0.0.1:8444" // proxy-rewritten upstream host
	r.Header.Set("X-Forwarded-Host", "mail.example.com")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Origin", "https://mail.example.com")
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Origin matching X-Forwarded-Host behind proxy: status = %d, want %d", w.Code, http.StatusOK)
	}

	// And a genuinely foreign Origin still fails against X-Forwarded-Host.
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8444/auth/login", nil)
	r.Host = "127.0.0.1:8444"
	r.Header.Set("X-Forwarded-Host", "mail.example.com")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Origin", "https://evil.example.com")
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("foreign Origin with X-Forwarded-Host: status = %d, want %d", w.Code, http.StatusForbidden)
	}

	// A same-host DIFFERENT-SCHEME origin is refused too: the proxy attests
	// the client used https, so an http:// origin cannot impersonate the site
	// even with the right host (the downgrade the tuple check closes).
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8444/auth/login", nil)
	r.Host = "127.0.0.1:8444"
	r.Header.Set("X-Forwarded-Host", "mail.example.com")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Origin", "http://mail.example.com")
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("downgraded Origin behind proxy: status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestCSRFOriginMismatchTakesPrecedenceOverReferer(t *testing.T) {
	// When Origin is present, only Origin is checked (Referer isn't consulted),
	// per the current implementation's early return.
	handler := newCSRFHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://mail.example.com/api/send", nil)
	r.Header.Set("Origin", "https://evil.example.com")
	r.Header.Set("Referer", "https://mail.example.com/inbox")
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("bad Origin with good Referer: status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestCSRFRejectsCrossSiteFetchMetadataWithoutOrigin(t *testing.T) {
	// A cross-site browser request whose Origin/Referer are absent (stripped
	// upstream) is denied via its own Sec-Fetch-Site: cross-site value
	// instead of sailing through the header-absence fallback.
	handler := CSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("POST", "/login", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site Sec-Fetch-Site without Origin = %d, want 403", rec.Code)
	}
}

func TestCSRFAllowsSameSiteAndNoFetchMetadataWithoutOrigin(t *testing.T) {
	handler := CSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for _, secFetchSite := range []string{"same-origin", "same-site", "none"} {
		req := httptest.NewRequest("POST", "/api", nil)
		req.Header.Set("Sec-Fetch-Site", secFetchSite)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("Sec-Fetch-Site %s = %d, want 200", secFetchSite, rec.Code)
		}
	}
	// Browserless client: no fetch metadata at all keeps the documented
	// header-absence passthrough.
	req := httptest.NewRequest("POST", "/api", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("no fetch metadata = %d, want 200 (browserless passthrough)", rec.Code)
	}
}

func TestSanitizedForwardedHost(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"mail.example.com", "mail.example.com"},
		{"127.0.0.1:8444", "127.0.0.1:8444"},
		{"[::1]:8444", "[::1]:8444"},
		{"", ""},
		// List/append syntax and junk are never trusted: the re-derived
		// header is always a single host token.
		{"evil.com, mail.example.com", ""},
		{"mail.example.com evil.com", ""},
		{"mail.example.com\r\nX-Injected: 1", ""},
		{"evil host", ""},
	} {
		if got := sanitizedForwardedHost(tc.in); got != tc.want {
			t.Errorf("sanitizedForwardedHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCSRFIgnoresMultiValueForwardedHost(t *testing.T) {
	// A non-stripping topology must not let appended XFH values steer origin
	// binding: the malformed list falls back to r.Host, which mismatches the
	// attacker origin and denies.
	handler := CSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("POST", "/login", nil)
	req.Header.Set("X-Forwarded-Host", "evil.example, real.example")
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("appended XFH steering origin = %d, want 403", rec.Code)
	}
}

// TestSanitizedForwardedHostOverlongHeaderRejected pins the length guard: a
// forwarded host header beyond 255 bytes is never trusted.
func TestSanitizedForwardedHostOverlongHeaderRejected(t *testing.T) {
	long := strings.Repeat("a", 300) + ".example.com"
	if got := sanitizedForwardedHost(long); got != "" {
		t.Fatalf("sanitizedForwardedHost(<300 bytes>) = %q, want empty", got)
	}
	// A 255-byte single host label still passes (boundary).
	ok := strings.Repeat("a", 243) + ".example.com"
	if len(ok) != 255 {
		t.Fatalf("fixture bug: boundary host is %d bytes", len(ok))
	}
	if got := sanitizedForwardedHost(ok); got != ok {
		t.Fatalf("sanitizedForwardedHost(255-byte host) = %q, want verbatim", got)
	}
}
