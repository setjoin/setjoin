package apispec

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/middleware"
)

// TestDocsRenderUnderRealCSP is the browser-free guard for the exact bug that
// shipped: /api/docs rendered BLANK on every install because the gateway CSP
// (`script-src 'self'`) blocked a CDN-loaded Redoc <script>. The pre-existing
// apidocs_test.go only string-matches the served HTML, so it stays green even
// when the page would render blank.
//
// This test composes the REAL SecurityHeaders middleware (the one mounted on the
// gateway in middleware/security.go — no fake/duplicated CSP string) wrapping the
// REAL HandleDocs/HandleRedocJS handlers in an httptest server, then GETs
// /api/docs over the wire and asserts the renderer the page loads would actually
// pass that CSP. "The Redoc renderer can load under our own CSP" thus becomes a
// machine-checked invariant that runs in CI with zero browser.
//
// No import cycle: this package (apispec) imports nothing from
// setjoin.com/mailserver; internal/middleware does not import apispec. Verified
// with `go list -deps ./internal/middleware`.
func TestDocsRenderUnderRealCSP(t *testing.T) {
	// Mount the docs page and the renderer behind the production security
	// middleware. ANY response (including /api/docs) gets the real CSP header.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/docs", HandleDocs)
	mux.HandleFunc("/api/redoc.standalone.js", HandleRedocJS)
	srv := httptest.NewServer(middleware.SecurityHeaders(mux))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/docs")
	if err != nil {
		t.Fatalf("GET /api/docs: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(bodyBytes)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/docs: status = %d, want 200", resp.StatusCode)
	}

	// (a) The response carries the real gateway CSP, and its script-src restricts
	//     scripts to 'self' — i.e. a cross-origin/CDN <script> WOULD be blocked.
	//     This is the production header (not a re-typed copy), so if security.go
	//     ever loosens or drops script-src the assertion below moves with it.
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("response has no Content-Security-Policy header — the real gateway middleware was not exercised")
	}
	scriptSrc := cspDirective(csp, "script-src")
	if scriptSrc == "" {
		t.Fatalf("CSP has no script-src directive (would fall back to default-src, but the contract is an explicit script-src); CSP=%q", csp)
	}
	if !strings.Contains(scriptSrc, "'self'") {
		t.Errorf("CSP script-src = %q, must contain 'self' (a same-origin renderer relies on it); full CSP=%q", scriptSrc, csp)
	}

	// (b) The <script src=...> the page actually loads must be SAME-ORIGIN
	//     (a /api/-rooted relative URL), NOT an absolute http/https/CDN URL —
	//     because under the script-src above an absolute external src renders the
	//     page blank. This is the precise regression that shipped.
	srcs := scriptSrcAttrs(body)
	if len(srcs) == 0 {
		t.Fatal("HandleDocs served no <script src=...> — the Redoc renderer is never loaded")
	}
	for _, src := range srcs {
		if !strings.HasPrefix(src, "/api/") {
			t.Errorf("docs page loads <script src=%q> — not same-origin under /api/; CDN/absolute URLs are blocked by script-src %q and render the page blank", src, scriptSrc)
		}
		if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") || strings.HasPrefix(src, "//") {
			t.Errorf("docs page loads an absolute/protocol-relative <script src=%q> — blocked by the gateway CSP", src)
		}
	}

	// Cross-check the served script is actually served same-origin (200, JS):
	// proves the relative /api/... URL resolves to a real same-origin endpoint,
	// not a 404 that the browser would silently fail to render.
	for _, src := range srcs {
		if !strings.HasPrefix(src, "/api/") {
			continue
		}
		jsResp, err := http.Get(srv.URL + src)
		if err != nil {
			t.Errorf("GET same-origin script %q: %v", src, err)
			continue
		}
		ct := jsResp.Header.Get("Content-Type")
		_ = jsResp.Body.Close()
		if jsResp.StatusCode != http.StatusOK {
			t.Errorf("same-origin script %q: status = %d, want 200", src, jsResp.StatusCode)
		}
		if !strings.Contains(ct, "javascript") {
			t.Errorf("same-origin script %q: Content-Type = %q, want javascript", src, ct)
		}
	}

	// (c) The Redoc custom element + its spec-url are present, so the page that
	//     loads under the CSP actually mounts the renderer against our spec.
	if !strings.Contains(body, "<redoc") {
		t.Error("docs page has no <redoc> element — nothing for the renderer to mount")
	}
	if !strings.Contains(body, `spec-url="/api/openapi.yaml"`) {
		t.Error(`docs page is missing spec-url="/api/openapi.yaml" on the <redoc> element`)
	}
}

// cspDirective returns the value (everything after the directive name) of the
// named CSP directive, or "" if absent. CSP directives are ';'-separated and the
// directive name is the first space-delimited token.
func cspDirective(csp, name string) string {
	for _, part := range strings.Split(csp, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.SplitN(part, " ", 2)
		if fields[0] == name {
			if len(fields) == 2 {
				return strings.TrimSpace(fields[1])
			}
			return "" // directive present but valueless
		}
	}
	return ""
}

var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]*\bsrc\s*=\s*["']([^"']+)["']`)

// scriptSrcAttrs extracts every <script src="..."> URL from the served HTML.
func scriptSrcAttrs(html string) []string {
	var out []string
	for _, m := range scriptSrcRe.FindAllStringSubmatch(html, -1) {
		out = append(out, m[1])
	}
	return out
}
