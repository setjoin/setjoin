package auth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// #221: the operator-configured authserver JWKS URL is a trusted internal
// endpoint. A default-constructed client (the production wiring in chain.go)
// must reach it even on loopback/private addresses, while nothing else widens.

func jwksServer(t *testing.T, hits *atomic.Int32) (*httptest.Server, string) {
	t.Helper()
	priv := newP256(t)
	kid := es256KID(t, &priv.PublicKey)
	doc := marshalJWKS(t, map[string]*ecdsa.PublicKey{kid: &priv.PublicKey})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	}))
	t.Cleanup(srv.Close)
	return srv, kid
}

func TestJWKSClient_ConfiguredInternalURLIsFetched(t *testing.T) {
	var hits atomic.Int32
	srv, kid := jwksServer(t, &hits) // httptest listens on 127.0.0.1 (loopback)

	c := NewJWKSClient(srv.URL + "/.well-known/jwks.json")
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh against configured loopback authserver: %v", err)
	}
	if _, ok := c.KeyByKID(kid); !ok {
		t.Fatalf("kid %q not resolved after fetching the configured JWKS", kid)
	}
	if hits.Load() == 0 {
		t.Fatal("configured JWKS endpoint was never contacted")
	}
}

func TestJWKSClient_RedirectAwayFromConfiguredOriginRefused(t *testing.T) {
	var targetHits atomic.Int32
	target, _ := jwksServer(t, &targetHits)

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/.well-known/jwks.json", http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	c := NewJWKSClient(redirector.URL + "/.well-known/jwks.json")
	if err := c.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh followed a redirect away from the configured origin")
	}
	if n := targetHits.Load(); n != 0 {
		t.Fatalf("redirect target (a different origin) was contacted %d times", n)
	}
}

func TestJWKSClient_SameOriginRedirectAlsoRefused(t *testing.T) {
	// Redirects are never followed, even within the configured origin: the
	// operator configured one exact URL.
	var hits atomic.Int32
	srv, _ := jwksServer(t, &hits)
	mux := http.NewServeMux()
	mux.HandleFunc("/old", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/.well-known/jwks.json", http.StatusFound)
	})
	same := httptest.NewServer(mux)
	t.Cleanup(same.Close)

	c := NewJWKSClient(same.URL + "/old")
	if err := c.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh followed a redirect")
	}
	if hits.Load() != 0 {
		t.Fatal("redirect target was contacted")
	}
}

// #225: a JWKS URL the trusted-origin client cannot use must not fall back to
// the strict client silently: the operator needs the reason in the log, and
// the log must not carry credentials embedded in the configured URL.
func TestJWKSClient_TrustedClientBuildFailureIsLoggedWithoutSecrets(t *testing.T) {
	for name, raw := range map[string]string{
		"userinfo":    "https://svc:hunter2@authserver.internal/.well-known/jwks.json",
		"unparseable": "http://svc:hunter2@[::1/jwks",
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
			t.Cleanup(func() { slog.SetDefault(prev) })

			_ = NewJWKSClient(raw)

			out := buf.String()
			if !strings.Contains(out, "strict") || !strings.Contains(out, "reason=") {
				t.Fatalf("fallback to the strict client was not logged with its reason; log=%q", out)
			}
			if strings.Contains(out, "hunter2") {
				t.Fatalf("log leaked URL credentials: %q", out)
			}
		})
	}
}
