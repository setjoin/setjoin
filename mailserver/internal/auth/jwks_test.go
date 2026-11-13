package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// es256KID derives the same kid the authserver KeySet does:
// "es256-" + first 16 hex chars of SHA-256(SPKI DER). Kept in lockstep so the
// cross-end contract test mints tokens with a kid the gateway can resolve.
func es256KID(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal SPKI: %v", err)
	}
	sum := sha256.Sum256(der)
	return "es256-" + hex.EncodeToString(sum[:8])
}

// marshalJWKS marshals the given public keys into a JWKS document EXACTLY as the
// authserver KeySet does (jose JWK, use=sig, alg=ES256, kid). This is the wire
// contract between the two services.
func marshalJWKS(t *testing.T, keys map[string]*ecdsa.PublicKey) []byte {
	t.Helper()
	set := jose.JSONWebKeySet{}
	for kid, pub := range keys {
		set.Keys = append(set.Keys, jose.JSONWebKey{
			Key:       pub,
			KeyID:     kid,
			Algorithm: "ES256",
			Use:       "sig",
		})
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	return raw
}

func newP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256: %v", err)
	}
	return priv
}

func TestJWKSClient_ParseAndKeyByKID(t *testing.T) {
	priv := newP256(t)
	kid := es256KID(t, &priv.PublicKey)
	raw := marshalJWKS(t, map[string]*ecdsa.PublicKey{kid: &priv.PublicKey})

	c := NewJWKSClient("https://authserver.invalid/keys",
		WithJWKSFetchFunc(func(ctx context.Context) ([]byte, error) { return raw, nil }))

	// hit
	got, ok := c.KeyByKID(kid)
	if !ok {
		t.Fatal("expected key for known kid")
	}
	if !got.Equal(&priv.PublicKey) {
		t.Error("returned key does not match the published key")
	}

	// miss (unknown kid) — even after refresh, no key
	if _, ok := c.KeyByKID("es256-deadbeefdeadbeef"); ok {
		t.Error("expected miss for unknown kid")
	}

	// empty kid is never resolved
	if _, ok := c.KeyByKID(""); ok {
		t.Error("expected miss for empty kid")
	}
}

func TestJWKSClient_RefreshOnMissRateLimited(t *testing.T) {
	priv := newP256(t)
	kid := es256KID(t, &priv.PublicKey)
	raw := marshalJWKS(t, map[string]*ecdsa.PublicKey{kid: &priv.PublicKey})

	var mu sync.Mutex
	var fetches int
	now := time.Unix(1_000_000, 0)

	c := NewJWKSClient("https://authserver.invalid/keys",
		WithJWKSRefreshMinInterval(30*time.Second),
		WithJWKSCacheTTL(5*time.Minute),
		withJWKSClock(func() time.Time { return now }),
		WithJWKSFetchFunc(func(ctx context.Context) ([]byte, error) {
			mu.Lock()
			fetches++
			mu.Unlock()
			return raw, nil
		}),
	)

	// First miss → one fetch (cache is empty).
	c.KeyByKID("bogus-1")
	// A flood of further bogus kids within the window must NOT fetch again.
	for i := 0; i < 50; i++ {
		c.KeyByKID("bogus-2")
	}
	mu.Lock()
	got := fetches
	mu.Unlock()
	if got != 1 {
		t.Fatalf("expected exactly 1 fetch within the refresh window, got %d", got)
	}

	// Advance past the refresh window — a new miss is allowed to refresh again.
	now = now.Add(31 * time.Second)
	c.KeyByKID("bogus-3")
	mu.Lock()
	got = fetches
	mu.Unlock()
	if got != 2 {
		t.Fatalf("expected a 2nd fetch after the window elapsed, got %d", got)
	}
}

func TestJWKSClient_ServeStaleOnFetchError(t *testing.T) {
	priv := newP256(t)
	kid := es256KID(t, &priv.PublicKey)
	good := marshalJWKS(t, map[string]*ecdsa.PublicKey{kid: &priv.PublicKey})

	now := time.Unix(2_000_000, 0)
	var fail bool

	c := NewJWKSClient("https://authserver.invalid/keys",
		WithJWKSCacheTTL(time.Minute),
		WithJWKSRefreshMinInterval(0), // allow refresh every call to exercise the error path
		withJWKSClock(func() time.Time { return now }),
		WithJWKSFetchFunc(func(ctx context.Context) ([]byte, error) {
			if fail {
				return nil, errors.New("authserver down")
			}
			return good, nil
		}),
	)

	// Warm the cache successfully.
	if _, ok := c.KeyByKID(kid); !ok {
		t.Fatal("expected key after initial successful fetch")
	}

	// Now fetches fail AND the cache is stale → the stale key must still serve.
	fail = true
	now = now.Add(2 * time.Minute) // past TTL → triggers refresh, which now errors
	got, ok := c.KeyByKID(kid)
	if !ok {
		t.Fatal("expected stale cache to still serve the known key on fetch error")
	}
	if !got.Equal(&priv.PublicKey) {
		t.Error("stale-served key does not match")
	}
}

func TestJWKSClient_FailClosedEmptyCache(t *testing.T) {
	c := NewJWKSClient("https://authserver.invalid/keys",
		WithJWKSRefreshMinInterval(0),
		WithJWKSFetchFunc(func(ctx context.Context) ([]byte, error) {
			return nil, errors.New("authserver unreachable")
		}),
	)

	// No cache + fetch error ⇒ miss (verification fails), never a panic.
	if _, ok := c.KeyByKID("anything"); ok {
		t.Error("expected fail-closed miss when no cache and fetch errors")
	}
}

func TestParseJWKS_SkipsNonSigningKeys(t *testing.T) {
	priv := newP256(t)
	kid := es256KID(t, &priv.PublicKey)

	// An EC sig key (good) plus an EC key marked use=enc (must be skipped).
	encKey := newP256(t)
	set := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: &priv.PublicKey, KeyID: kid, Algorithm: "ES256", Use: "sig"},
			{Key: &encKey.PublicKey, KeyID: "enc-key", Algorithm: "ES256", Use: "enc"},
		},
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	keys, err := parseJWKS(raw)
	if err != nil {
		t.Fatalf("parseJWKS: %v", err)
	}
	if _, ok := keys[kid]; !ok {
		t.Error("expected the sig key to be admitted")
	}
	if _, ok := keys["enc-key"]; ok {
		t.Error("expected the enc-use key to be skipped")
	}
}

func TestParseJWKS_EmptyDocumentErrors(t *testing.T) {
	if _, err := parseJWKS([]byte(`{"keys":[]}`)); err == nil {
		t.Error("expected error for a JWKS with no usable keys")
	}
	if _, err := parseJWKS([]byte(`not json`)); err == nil {
		t.Error("expected error for a malformed JWKS document")
	}
}
