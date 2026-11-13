package auth

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	neturl "net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"setjoin.com/shared/ssrf"
)

// JWKS client (ADR-005, the gateway half).
//
// The gateway verifies ES256 first-party access tokens against the authserver's
// published JWKS. This client fetches that JWKS, parses it into a kid→public-key
// map, and caches it in memory. It is the ONLY source of trust for ES256
// verification keys — the configured URL is the sole endpoint ever contacted; a
// token's own jku/x5u/embedded-key header fields are never honored (that closure
// lives in the shared jwtutil.ParseES256 primitive, which resolves keys solely
// via the func this client supplies).

const (
	// defaultJWKSCacheTTL is how long a successfully-fetched JWKS is served
	// before a background-eligible refresh. Public signing keys rotate on the
	// order of an access-token lifetime, so a few minutes of staleness is safe.
	defaultJWKSCacheTTL = 5 * time.Minute

	// defaultJWKSRefreshMinInterval rate-limits refreshes triggered by an
	// unknown kid. An attacker presenting a stream of bogus kids must not be
	// able to make the gateway hammer the authserver — at most one refresh per
	// this window is attempted on cache miss.
	defaultJWKSRefreshMinInterval = 30 * time.Second

	// defaultJWKSFetchTimeout bounds the HTTP GET so a slow/hung authserver
	// cannot stall request-path verification.
	defaultJWKSFetchTimeout = 5 * time.Second
)

// fetchFunc retrieves the raw JWKS document bytes from the trusted endpoint.
// It is a field on JWKSClient so tests can stub the network entirely.
type fetchFunc func(ctx context.Context) ([]byte, error)

// JWKSClient fetches and caches the authserver JWKS, exposing a kid→public-key
// lookup. It is safe for concurrent use.
type JWKSClient struct {
	url                string
	fetch              fetchFunc
	cacheTTL           time.Duration
	refreshMinInterval time.Duration
	now                func() time.Time // injectable clock for tests

	mu          sync.RWMutex
	keys        map[string]*ecdsa.PublicKey
	fetchedAt   time.Time // zero until the first successful fetch
	lastAttempt time.Time // last fetch attempt (success or failure), for rate-limiting
}

// JWKSOption configures a JWKSClient.
type JWKSOption func(*JWKSClient)

// WithJWKSHTTPClient overrides the *http.Client used for fetching. Useful in
// tests (a transport stub) or to apply a custom proxy/TLS config.
func WithJWKSHTTPClient(hc *http.Client) JWKSOption {
	return func(c *JWKSClient) {
		c.fetch = httpFetch(c.url, hc)
	}
}

// WithJWKSFetchFunc replaces the fetch entirely — the primary test seam, letting
// a test serve a static JWKS fixture without any network or HTTP server.
func WithJWKSFetchFunc(f fetchFunc) JWKSOption {
	return func(c *JWKSClient) { c.fetch = f }
}

// WithJWKSCacheTTL overrides the cache TTL.
func WithJWKSCacheTTL(d time.Duration) JWKSOption {
	return func(c *JWKSClient) { c.cacheTTL = d }
}

// WithJWKSRefreshMinInterval overrides the minimum interval between refreshes.
func WithJWKSRefreshMinInterval(d time.Duration) JWKSOption {
	return func(c *JWKSClient) { c.refreshMinInterval = d }
}

// withJWKSClock overrides the clock (test-only).
func withJWKSClock(now func() time.Time) JWKSOption {
	return func(c *JWKSClient) { c.now = now }
}

// NewJWKSClient constructs a client that trusts exactly one JWKS URL. The first
// KeyByKID call (or an explicit Refresh) performs the initial fetch lazily; the
// constructor itself does no network I/O, so startup never blocks on authserver.
func NewJWKSClient(url string, opts ...JWKSOption) *JWKSClient {
	c := &JWKSClient{
		url:                url,
		cacheTTL:           defaultJWKSCacheTTL,
		refreshMinInterval: defaultJWKSRefreshMinInterval,
		now:                time.Now,
		keys:               map[string]*ecdsa.PublicKey{},
	}
	// SSRF posture (#221): the JWKS URL is operator-configured and normally an
	// internal authserver address, so exactly its scheme+host+port is trusted
	// (loopback/private allowed); any other destination keeps the strict
	// post-DNS guard and redirects are never followed. An unusable URL leaves
	// the strict guard in place, so the fetch fails closed.
	// WithJWKSHTTPClient can still override. See shared/ssrf.
	hc, err := ssrf.TrustedOriginHTTPClient(url, defaultJWKSFetchTimeout)
	if err != nil {
		slog.Warn("auth.jwks: trusted-origin JWKS client unavailable; using the strict SSRF client (internal JWKS fetches will fail closed)",
			"reason", jwksClientBuildReason(err))
		hc = ssrf.SafeHTTPClient(defaultJWKSFetchTimeout)
	}
	c.fetch = httpFetch(url, hc)
	for _, o := range opts {
		o(c)
	}
	return c
}

// jwksClientBuildReason renders why the trusted-origin client could not be
// built without echoing the configured URL: a *url.Error carries the raw
// string, which may embed credentials, so only its underlying cause is kept.
func jwksClientBuildReason(err error) string {
	var ue *neturl.Error
	if errors.As(err, &ue) {
		return "trusted URL does not parse: " + ue.Err.Error()
	}
	return err.Error()
}

// httpFetch GETs the JWKS document from the trusted URL with a context timeout.
func httpFetch(url string, hc *http.Client) fetchFunc {
	return func(ctx context.Context) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, defaultJWKSFetchTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("jwks: build request: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		resp, err := hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("jwks: fetch %s: %w", url, err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			// Drain a bounded amount so the connection can be reused, but never
			// surface the body to callers.
			_, _ = io.CopyN(io.Discard, resp.Body, 4096)
			return nil, fmt.Errorf("jwks: fetch %s: status %d", url, resp.StatusCode)
		}
		// Cap the read — a JWKS is small; a runaway body must not OOM the gateway.
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, fmt.Errorf("jwks: read body: %w", err)
		}
		return body, nil
	}
}

// KeyByKID returns the EC public key for kid. It satisfies the keyByKID seam of
// jwtutil.ParseES256.
//
// Behavior:
//   - cache hit → return the key immediately.
//   - cache miss (unknown kid) → attempt a rate-limited refresh, then re-check.
//     A fresh key may have been published since the last fetch.
//   - the refresh is skipped if one was attempted within refreshMinInterval, so
//     a flood of bogus kids cannot turn into a flood of authserver requests.
//   - on a fetch error, the existing (stale) cache is retained and still served;
//     with no cache, the lookup simply misses (fail closed — verification fails).
func (c *JWKSClient) KeyByKID(kid string) (*ecdsa.PublicKey, bool) {
	if kid == "" {
		return nil, false
	}

	c.mu.RLock()
	key, ok := c.keys[kid]
	stale := c.fetchedAt.IsZero() || c.now().Sub(c.fetchedAt) >= c.cacheTTL
	c.mu.RUnlock()
	if ok && !stale {
		return key, true
	}

	// Either the kid is unknown, or the cache is past its TTL. Try a
	// rate-limited refresh, then re-resolve.
	c.maybeRefresh(context.Background())

	c.mu.RLock()
	key, ok = c.keys[kid]
	c.mu.RUnlock()
	return key, ok
}

// maybeRefresh fetches+parses the JWKS at most once per refreshMinInterval. On
// success it atomically swaps in the new key map; on failure it leaves the
// existing cache untouched (serve-stale).
func (c *JWKSClient) maybeRefresh(ctx context.Context) {
	c.mu.Lock()
	if !c.lastAttempt.IsZero() && c.now().Sub(c.lastAttempt) < c.refreshMinInterval {
		c.mu.Unlock()
		return
	}
	c.lastAttempt = c.now()
	c.mu.Unlock()

	_ = c.doFetch(ctx) // Serve-stale refresh failures are intentionally retried later.
}

// Refresh forces a fetch regardless of the rate-limit window. Returns the fetch
// error (nil on success). Useful at startup to warm the cache / surface a
// misconfigured URL early.
func (c *JWKSClient) Refresh(ctx context.Context) error {
	c.mu.Lock()
	c.lastAttempt = c.now()
	c.mu.Unlock()
	return c.doFetch(ctx)
}

// doFetch performs the network fetch + parse and installs the result. It updates
// fetchedAt only on success, so the staleness clock reflects real freshness.
func (c *JWKSClient) doFetch(ctx context.Context) error {
	raw, err := c.fetch(ctx)
	if err != nil {
		return err // cache (if any) left intact — serve-stale
	}
	keys, err := parseJWKS(raw)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.keys = keys
	c.fetchedAt = c.now()
	c.mu.Unlock()
	return nil
}

// parseJWKS decodes a JWKS document into a kid→*ecdsa.PublicKey map. Only EC
// public keys flagged for signature use (or with no use, per the JWKS default)
// are admitted; anything else (RSA, private material, encryption-use) is skipped
// so the gateway never treats a non-signing or non-EC key as an ES256 verifier.
func parseJWKS(raw []byte) (map[string]*ecdsa.PublicKey, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("jwks: parse document: %w", err)
	}
	out := make(map[string]*ecdsa.PublicKey, len(set.Keys))
	for i := range set.Keys {
		k := set.Keys[i]
		if k.KeyID == "" {
			continue // unkeyed entries can never be matched to a token kid
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		// Only ES256 (EC) keys are verification keys for first-party tokens.
		// An explicit alg, when present, must be ES256.
		if k.Algorithm != "" && k.Algorithm != "ES256" {
			continue
		}
		pub, ok := k.Key.(*ecdsa.PublicKey)
		if !ok || pub == nil {
			continue
		}
		out[k.KeyID] = pub
	}
	if len(out) == 0 {
		return nil, errors.New("jwks: document contains no usable EC signing keys")
	}
	return out, nil
}
