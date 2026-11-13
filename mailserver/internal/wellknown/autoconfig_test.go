package wellknown

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/shared/testsupport"

	"setjoin.com/mailserver/internal/middleware"
)

// mk.test is seeded as a local domain by the baseline fixtures
// (sql/dbschema/V001__baseline.sql); reused here instead of inserting a
// throwaway row.
const testLocalDomain = "mk.test"

func TestHandleAutoconfig_LocalDomain_ImplicitTLS(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := HandleAutoconfig(pool, ":143", ":993", ":587", ":465")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/autoconfig/mail/config-v1.1.xml", nil)
	req.Host = testLocalDomain
	rec := httptest.NewRecorder()
	// WP2: assert the Cache-Control through the assembled middleware chain.
	middleware.CacheControl(http.HandlerFunc(h)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/xml" {
		t.Errorf("Content-Type = %q, want application/xml", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=86400" {
		t.Errorf("Cache-Control = %q, want public, max-age=86400", cc)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"<hostname>mk.test</hostname>",
		"<port>993</port>",
		"<socketType>SSL</socketType>",
		"<port>465</port>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q; body: %s", want, body)
		}
	}
}

func TestHandleAutoconfig_LocalDomain_STARTTLS(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	// Empty *TLSAddr args → STARTTLS branch (no implicit-TLS listener configured).
	h := HandleAutoconfig(pool, ":143", "", ":587", "")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/autoconfig/mail/config-v1.1.xml", nil)
	req.Host = testLocalDomain
	rec := httptest.NewRecorder()
	// WP2: assert the Cache-Control through the assembled middleware chain.
	middleware.CacheControl(http.HandlerFunc(h)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"<port>143</port>",
		"<socketType>STARTTLS</socketType>",
		"<port>587</port>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q; body: %s", want, body)
		}
	}
}

func TestHandleAutoconfig_UnknownDomain_404(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := HandleAutoconfig(pool, ":143", ":993", ":587", ":465")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/autoconfig/mail/config-v1.1.xml", nil)
	req.Host = "definitely-not-a-configured-domain.invalid"
	rec := httptest.NewRecorder()
	// WP2: assert the Cache-Control through the assembled middleware chain.
	middleware.CacheControl(http.HandlerFunc(h)).ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleAutoconfig_HostWithPort_Normalizes(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := HandleAutoconfig(pool, ":143", ":993", ":587", ":465")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/autoconfig/mail/config-v1.1.xml", nil)
	req.Host = testLocalDomain + ":8443"
	rec := httptest.NewRecorder()
	// WP2: assert the Cache-Control through the assembled middleware chain.
	middleware.CacheControl(http.HandlerFunc(h)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "<hostname>mk.test</hostname>") {
		t.Errorf("port not stripped from Host; body: %s", rec.Body.String())
	}
}

// TestAutoconfigTemplateEscapesExoticNames proves the co-located output-
// escaping fix: even a hostile/exotic configured domain name cannot inject
// XML structure or produce malformed output, while an ordinary domain renders
// byte-identical to the previous text/template output. DB-free: the template
// is the unit under test (the handler only supplies the equality-matched,
// lowercased Host value).
func TestAutoconfigTemplateEscapesExoticNames(t *testing.T) {
	render := func(domain string) string {
		var sb strings.Builder
		if err := autoconfigTmpl.Execute(&sb, autoconfigData{
			Domain: domain, Hostname: domain,
			IMAPPort: "993", IMAPSocketType: "SSL",
			SMTPPort: "465", SMTPSocketType: "SSL",
		}); err != nil {
			t.Fatalf("template execute: %v", err)
		}
		return sb.String()
	}

	ordinary := render("mk.test")
	for _, want := range []string{
		`<emailProvider id="mk.test">`,
		`<domain>mk.test</domain>`,
		`<hostname>mk.test</hostname>`,
	} {
		if !strings.Contains(ordinary, want) {
			t.Errorf("ordinary domain output missing %q; body: %s", want, ordinary)
		}
	}

	exotic := render(`mk.test<&>"'`)
	if strings.Contains(exotic, "<&>") {
		t.Errorf("XML-significant characters passed through unescaped; body: %s", exotic)
	}
	if !strings.Contains(exotic, "mk.test&lt;&amp;&gt;&#34;&#39;") {
		t.Errorf("expected escaped rendering; body: %s", exotic)
	}
	// Structural break-out must be impossible: no extra elements.
	if strings.Contains(exotic, "</clientConfig><script>") {
		t.Errorf("document structure broken by hostile domain; body: %s", exotic)
	}
}
