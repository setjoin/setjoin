package discovery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandleDiscoverMissingDomain pins the ingress guard: GET /api/discover
// without a domain parameter answers 400 with the "domain parameter required"
// problem — never a DNS lookup.
func TestHandleDiscoverMissingDomain(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/discover", nil)
	rr := httptest.NewRecorder()
	HandleDiscover()(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if want := "domain parameter required"; !strings.Contains(rr.Body.String(), want) {
		t.Fatalf("body = %s, want it to contain %q", rr.Body.String(), want)
	}
}

// TestHandleDiscoverServesFromCache pins the cache-hit branch: a pre-warmed
// entry is served as JSON without a DNS round-trip, so a resolvable-looking
// domain still returns exactly the cached config.
func TestHandleDiscoverServesFromCache(t *testing.T) {
	const domain = "cache-hit.example"
	cached := &ServerConfig{URL: "https://jmap." + domain}
	t.Cleanup(func() {
		cacheMu.Lock()
		delete(cache, domain)
		cacheMu.Unlock()
	})
	cachePut(domain, cached)

	req := httptest.NewRequest(http.MethodGet, "/api/discover?domain="+domain, nil)
	rr := httptest.NewRecorder()
	HandleDiscover()(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "json") {
		t.Fatalf("content-type = %q, want JSON", ct)
	}
	var got ServerConfig
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode cached config: %v (%s)", err, rr.Body.String())
	}
	if got.URL != cached.URL {
		t.Fatalf("served URL = %q, want cached %q", got.URL, cached.URL)
	}
}
