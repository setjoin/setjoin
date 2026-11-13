package authproxy

// Integration coverage for med-shard3-008: through the auth reverse proxy,
// the authserver-bound request must carry the OBSERVED client identity, not
// the gateway's socket peer. In the documented HTTPMode=proxy topology (TLS
// terminated upstream) SetXForwarded() attributed every request to the
// trusted proxy's IP (collapsing per-client-IP rate limiting into one bucket)
// and labeled the client-facing scheme "http" (session cookies lost Secure).
// Direct-TLS default behavior is unchanged: the socket peer and socket scheme
// are forwarded and spoofed forwarded headers are discarded.

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"setjoin.com/mailserver/internal/config"
	"setjoin.com/shared/clientip"
)

// newProxiedBackend starts a recording authserver backend and returns the
// auth proxy bound to it plus a getter for the headers the backend received.
func newProxiedBackend(t *testing.T) (http.Handler, func() http.Header) {
	t.Helper()
	var mu sync.Mutex
	got := http.Header{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	h, err := New(&config.Config{AuthServerURL: backend.URL})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return h, func() http.Header {
		t.Helper()
		mu.Lock()
		defer mu.Unlock()
		if got == nil {
			t.Fatal("request never reached the backend")
		}
		return got
	}
}

func TestAuthProxyForwardsObservedClientIdentity(t *testing.T) {
	orig := os.Getenv("TRUSTED_PROXY_IP")
	t.Cleanup(func() { clientip.SetTrustedProxy(orig) })

	t.Run("HTTPMode=proxy: real client IP and https forwarded despite upstream proxy peer", func(t *testing.T) {
		clientip.SetTrustedProxy("10.0.0.1")
		h, received := newProxiedBackend(t)

		// The gateway's socket peer is the TLS-terminating reverse proxy; the
		// attacker-chosen first XFF line must not win, and the
		// upstream-terminated TLS must surface as https.
		req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Host = "mail.example.com"
		req.Header["X-Forwarded-For"] = []string{"6.6.6.6", "203.0.113.9"}
		req.Header.Set("X-Forwarded-Proto", "https")
		h.ServeHTTP(httptest.NewRecorder(), req)

		got := received()
		if xff := got.Get("X-Forwarded-For"); xff != "203.0.113.9" {
			t.Errorf("X-Forwarded-For = %q, want observed real client %q (per-client-IP controls key on it)", xff, "203.0.113.9")
		}
		if xfp := got.Get("X-Forwarded-Proto"); xfp != "https" {
			t.Errorf("X-Forwarded-Proto = %q, want %q (session cookies must carry Secure)", xfp, "https")
		}
		if xfh := got.Get("X-Forwarded-Host"); xfh != "mail.example.com" {
			t.Errorf("X-Forwarded-Host = %q, want %q", xfh, "mail.example.com")
		}
	})

	t.Run("direct-TLS default unchanged: socket peer forwarded, spoofed headers discarded", func(t *testing.T) {
		clientip.SetTrustedProxy("")
		h, received := newProxiedBackend(t)

		req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
		req.RemoteAddr = "198.51.100.4:9"
		req.TLS = &tls.ConnectionState{}
		req.Header.Set("X-Forwarded-For", "6.6.6.6")
		req.Header.Set("X-Forwarded-Proto", "https")
		h.ServeHTTP(httptest.NewRecorder(), req)

		got := received()
		if xff := got.Get("X-Forwarded-For"); xff != "198.51.100.4" {
			t.Errorf("X-Forwarded-For = %q, want socket peer %q", xff, "198.51.100.4")
		}
		if xfp := got.Get("X-Forwarded-Proto"); xfp != "https" {
			t.Errorf("X-Forwarded-Proto = %q, want %q from the TLS socket", xfp, "https")
		}
	})

	t.Run("plain HTTP untrusted: spoofed https proto not honored", func(t *testing.T) {
		clientip.SetTrustedProxy("")
		h, received := newProxiedBackend(t)

		req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
		req.RemoteAddr = "198.51.100.4:9"
		req.Header.Set("X-Forwarded-For", "6.6.6.6")
		req.Header.Set("X-Forwarded-Proto", "https")
		h.ServeHTTP(httptest.NewRecorder(), req)

		got := received()
		if xff := got.Get("X-Forwarded-For"); xff != "198.51.100.4" {
			t.Errorf("X-Forwarded-For = %q, want socket peer %q", xff, "198.51.100.4")
		}
		if xfp := got.Get("X-Forwarded-Proto"); xfp != "http" {
			t.Errorf("X-Forwarded-Proto = %q, want fail-closed %q (spoofed https must not grant Secure)", xfp, "http")
		}
	})
}
