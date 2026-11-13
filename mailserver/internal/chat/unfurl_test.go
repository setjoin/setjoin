// unfurl_test.go — Pillar A3 QoL Task 13: unit tests for the pure/near-pure
// fetch-and-parse helpers (package-internal so they can call unexported
// functions directly). DB-gated round-trip + SSRF-denial-through-the-real-
// route tests live in unfurl_integration_test.go (package chat_test).
package chat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/ssrf"
)

// localhostURL rewrites an httptest.Server's URL (always a literal
// "127.0.0.1" — a real IP text) to use the "localhost" hostname instead.
// followRedirects runs ssrf.ValidateURL as a defense-in-depth pre-check on
// every hop (in ADDITION to the dial-time Control hook the real
// ssrf.SafeHTTPClient carries — see the package doc), and ValidateURL's
// literal-IP fast path only matches text that net.ParseIP accepts as an IP;
// "localhost" is a hostname, not IP literal text, so it passes that
// pre-check exactly like any real public hostname would, while a plain
// (non-SSRF) *http.Client — the httptest-server-reaching test double the
// whole package uses, same posture as internal/webhook's precedent — still
// resolves and dials it locally without issue. This lets a test actually
// reach the httptest origin and exercise size-cap/content-type/redirect-
// following logic, instead of every request being rejected before it dials.
func localhostURL(raw string) string {
	return strings.Replace(raw, "127.0.0.1", "localhost", 1)
}

func TestExtractFirstURL(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
		ok   bool
	}{
		{"plain url", "check this out https://example.com/a", "https://example.com/a", true},
		{"trailing punctuation trimmed", "see https://example.com/a).", "https://example.com/a", true},
		{"first of two urls", "https://one.example/x and https://two.example/y", "https://one.example/x", true},
		{"no url", "just some text", "", false},
		{"userinfo url rejected", "https://user:pass@example.com/x", "", false},
		{"private literal rejected", "http://10.1.2.3/internal", "", false},
		{"loopback literal rejected", "http://127.0.0.1/admin", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := extractFirstURL(c.body)
			if ok != c.ok {
				t.Fatalf("extractFirstURL(%q) ok = %v, want %v (got %q)", c.body, ok, c.ok, got)
			}
			if ok && got != c.want {
				t.Errorf("extractFirstURL(%q) = %q, want %q", c.body, got, c.want)
			}
		})
	}
}

func TestParsePreviewHTML(t *testing.T) {
	html := `<html><head>
		<title>Fallback Title</title>
		<meta property="og:title" content="OG Title">
		<meta property="og:description" content="OG Description">
		<meta property="og:image" content="/img/cover.png">
	</head><body>hi</body></html>`
	title, desc, image := parsePreviewHTML(strings.NewReader(html), "https://example.com/article")
	if title != "OG Title" {
		t.Errorf("title = %q, want OG Title", title)
	}
	if desc != "OG Description" {
		t.Errorf("description = %q, want OG Description", desc)
	}
	if image != "https://example.com/img/cover.png" {
		t.Errorf("image = %q, want resolved absolute URL", image)
	}
}

func TestParsePreviewHTML_FallsBackToPlainTitle(t *testing.T) {
	html := `<html><head><title>Just A Title</title></head><body></body></html>`
	title, desc, image := parsePreviewHTML(strings.NewReader(html), "https://example.com/")
	if title != "Just A Title" {
		t.Errorf("title = %q, want fallback <title>", title)
	}
	if desc != "" || image != "" {
		t.Errorf("desc/image should be empty, got %q / %q", desc, image)
	}
}

func TestFollowRedirects_CapsHopCount(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/next", http.StatusFound) // redirects forever
	}))
	defer srv.Close()

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	_, err := followRedirects(context.Background(), client, localhostURL(srv.URL), 3)
	if err == nil {
		t.Fatal("followRedirects on an infinite-redirect server: want error (hop cap), got nil")
	}
}

func TestFollowRedirects_DeniesRedirectToPrivateTarget(t *testing.T) {
	// The origin itself is reachable (a plain, non-SSRF client — httptest
	// always binds loopback, so it stands in for "the public first hop" the
	// same way webhook_deliveries_test.go's precedent does). The interesting
	// assertion is that the REDIRECT TARGET is validated before being
	// followed, never that the origin itself passed the real SSRF dialer.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	_, err := followRedirects(context.Background(), client, localhostURL(srv.URL), 3)
	if err == nil {
		t.Fatal("followRedirects: want denial when a redirect Location is a metadata/private address, got nil")
	}
}

func TestFollowRedirects_FollowsSafeRedirectToFinalBody(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, localhostURL(srv.URL)+"/final", http.StatusFound)
			return
		}
		w.Write([]byte("final body"))
	}))
	defer srv.Close()

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := followRedirects(context.Background(), client, localhostURL(srv.URL)+"/start", 3)
	if err != nil {
		t.Fatalf("followRedirects: unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("followRedirects: final status = %d, want 200", resp.StatusCode)
	}
}

// TestRealSSRFClientDeniesInternalTargets proves the fetch path actually
// rides shared/ssrf.SafeHTTPClient in production — not a re-test of
// shared/ssrf itself (already covered by ssrf_test.go), just that plugging
// the real client into followRedirects still denies internal targets.
func TestRealSSRFClientDeniesInternalTargets(t *testing.T) {
	client := ssrf.SafeHTTPClient(2 * time.Second)
	for _, u := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://10.1.2.3/",
		"http://127.0.0.1:1/",
	} {
		if _, err := followRedirects(context.Background(), client, u, 3); err == nil {
			t.Errorf("followRedirects(%q) with the real SSRF client: want denial, got nil error", u)
		}
	}
}

func TestFetchPreview_OversizedHTMLIsRejected(t *testing.T) {
	big := strings.Repeat("a", int(maxHTMLBytes)+1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><head><title>" + big + "</title></head></html>"))
	}))
	defer srv.Close()

	h := &Handler{unfurlClient: &http.Client{}}
	title, desc, imageSha, status := h.fetchPreview(context.Background(), localhostURL(srv.URL))
	if status != "error" {
		t.Fatalf("status = %q, want error for an oversized page (title=%q desc=%q img=%q)", status, title, desc, imageSha)
	}
}

func TestFetchPreview_WrongContentTypeIsRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"not":"html"}`))
	}))
	defer srv.Close()

	h := &Handler{unfurlClient: &http.Client{}}
	_, _, _, status := h.fetchPreview(context.Background(), localhostURL(srv.URL))
	if status != "error" {
		t.Fatalf("status = %q, want error for a non-text/html content-type", status)
	}
}

func TestFetchPreview_HappyPathTitleAndDescription(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<html><head>
			<meta property="og:title" content="Great Page">
			<meta property="og:description" content="A great description">
		</head></html>`))
	}))
	defer srv.Close()

	h := &Handler{unfurlClient: &http.Client{}}
	title, desc, imageSha, status := h.fetchPreview(context.Background(), localhostURL(srv.URL))
	if status != "ok" {
		t.Fatalf("status = %q, want ok", status)
	}
	if title != "Great Page" || desc != "A great description" {
		t.Errorf("title/desc = %q/%q, want Great Page/A great description", title, desc)
	}
	if imageSha != "" {
		t.Errorf("imageSha = %q, want empty (no og:image on the page)", imageSha)
	}
}

// boundUnfurlText + the fetchPreview mirror pin the Go half of the unfurl
// metadata bound (occ_980dba9c476e43f3e6d8ef7e): og:title/og:description from
// attacker-controlled page bytes are truncated-with-marker before they leave
// fetchPreview, with character (not byte) semantics matching the SQL authority
// (chat_unfurl_bound_text in chat_unfurl.sql, 512/1024).

func TestBoundUnfurlText(t *testing.T) {
	t.Run("under cap passes through unmarked", func(t *testing.T) {
		if got := boundUnfurlText("short", maxUnfurlTitleChars); got != "short" {
			t.Errorf("boundUnfurlText under cap = %q, want unchanged", got)
		}
	})
	t.Run("at cap passes through unmarked", func(t *testing.T) {
		in := strings.Repeat("a", maxUnfurlTitleChars)
		if got := boundUnfurlText(in, maxUnfurlTitleChars); got != in {
			t.Errorf("boundUnfurlText at cap changed the input (len=%d)", len([]rune(got)))
		}
	})
	t.Run("over cap truncates with the ellipsis marker at exactly the cap", func(t *testing.T) {
		got := boundUnfurlText(strings.Repeat("a", 5000), maxUnfurlTitleChars)
		runes := []rune(got)
		if len(runes) != maxUnfurlTitleChars {
			t.Fatalf("truncated length = %d, want %d", len(runes), maxUnfurlTitleChars)
		}
		if runes[maxUnfurlTitleChars-1] != '…' {
			t.Errorf("truncation marker missing: last rune %q", runes[maxUnfurlTitleChars-1])
		}
		if got != strings.Repeat("a", maxUnfurlTitleChars-1)+"…" {
			t.Errorf("truncated body drifted: %q", got[:20])
		}
	})
	t.Run("counts characters not bytes", func(t *testing.T) {
		got := boundUnfurlText(strings.Repeat("好", 600), maxUnfurlTitleChars)
		if n := len([]rune(got)); n != maxUnfurlTitleChars {
			t.Fatalf("CJK truncated rune length = %d, want %d", n, maxUnfurlTitleChars)
		}
		if want := strings.Repeat("好", maxUnfurlTitleChars-1) + "…"; got != want {
			t.Errorf("CJK truncation is not whole-glyph + marker")
		}
	})
}

func TestFetchPreview_BoundsOverLongMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<html><head>
			<meta property="og:title" content="` + strings.Repeat("T", 5000) + `">
			<meta property="og:description" content="` + strings.Repeat("D", 9000) + `">
		</head></html>`))
	}))
	defer srv.Close()

	h := &Handler{unfurlClient: &http.Client{}}
	title, desc, _, status := h.fetchPreview(context.Background(), localhostURL(srv.URL))
	if status != "ok" {
		t.Fatalf("status = %q, want ok (bounding degrades silently, never fails the fetch)", status)
	}
	titleRunes, descRunes := []rune(title), []rune(desc)
	if len(titleRunes) != maxUnfurlTitleChars {
		t.Errorf("title length = %d, want bounded %d", len(titleRunes), maxUnfurlTitleChars)
	}
	if len(descRunes) != maxUnfurlDescriptionChars {
		t.Errorf("description length = %d, want bounded %d", len(descRunes), maxUnfurlDescriptionChars)
	}
	if titleRunes[len(titleRunes)-1] != '…' || descRunes[len(descRunes)-1] != '…' {
		t.Errorf("truncation markers missing on title/description")
	}
}
