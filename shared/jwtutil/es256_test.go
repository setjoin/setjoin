package jwtutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256: %v", err)
	}
	return k
}

// signES256 mints an ES256 token with the given kid header.
func signES256(t *testing.T, key *ecdsa.PrivateKey, kid string, claims jwt.Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign ES256: %v", err)
	}
	return s
}

func basicClaims() *Claims {
	now := time.Now()
	return &Claims{
		UserID: 7,
		Type:   TypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}
}

// keySet returns a keyByKID closure over a fixed kid→public-key map.
func keySet(m map[string]*ecdsa.PublicKey) func(string) (*ecdsa.PublicKey, bool) {
	return func(kid string) (*ecdsa.PublicKey, bool) {
		pub, ok := m[kid]
		return pub, ok
	}
}

func TestParseES256_ValidVerifies(t *testing.T) {
	key := newP256(t)
	tokenStr := signES256(t, key, "es256-1", basicClaims())

	got := &Claims{}
	tok, err := ParseES256(tokenStr, got, keySet(map[string]*ecdsa.PublicKey{"es256-1": &key.PublicKey}))
	if err != nil {
		t.Fatalf("ParseES256 valid token: %v", err)
	}
	if !tok.Valid {
		t.Fatal("expected token.Valid == true")
	}
	if got.UserID != 7 {
		t.Fatalf("UserID = %d, want 7", got.UserID)
	}
}

func TestParseES256_RejectsHS256_AlgConfusion(t *testing.T) {
	key := newP256(t)
	// An HS256 token whose `kid` names the EC key. The classic alg-confusion
	// attack: the attacker HMACs with the verifier's PUBLIC key bytes as the
	// secret. ParseES256 must reject it on method, never reaching the key func.
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, basicClaims())
	hs.Header["kid"] = "es256-1"
	// Use the marshaled public key as the "secret" — the attack's whole premise.
	pubBytes := elliptic.MarshalCompressed(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
	tokenStr, err := hs.SignedString(pubBytes)
	if err != nil {
		t.Fatalf("sign HS256: %v", err)
	}

	got := &Claims{}
	if _, err := ParseES256(tokenStr, got, keySet(map[string]*ecdsa.PublicKey{"es256-1": &key.PublicKey})); err == nil {
		t.Fatal("expected ParseES256 to reject an HS256 token (alg confusion), got nil error")
	}
}

func TestParseES256_RejectsNoneAlg(t *testing.T) {
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, basicClaims())
	tok.Header["kid"] = "es256-1"
	tokenStr, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	key := newP256(t)
	if _, err := ParseES256(tokenStr, &Claims{}, keySet(map[string]*ecdsa.PublicKey{"es256-1": &key.PublicKey})); err == nil {
		t.Fatal("expected ParseES256 to reject alg=none, got nil error")
	}
}

func TestParseES256_RejectsMissingKID(t *testing.T) {
	key := newP256(t)
	tokenStr := signES256(t, key, "", basicClaims()) // no kid header

	_, err := ParseES256(tokenStr, &Claims{}, keySet(map[string]*ecdsa.PublicKey{"es256-1": &key.PublicKey}))
	if err == nil {
		t.Fatal("expected error for missing kid, got nil")
	}
	if !errors.Is(err, ErrES256NoKID) {
		t.Fatalf("expected ErrES256NoKID, got %v", err)
	}
}

func TestParseES256_RejectsUnknownKID(t *testing.T) {
	key := newP256(t)
	tokenStr := signES256(t, key, "es256-unknown", basicClaims())

	_, err := ParseES256(tokenStr, &Claims{}, keySet(map[string]*ecdsa.PublicKey{"es256-1": &key.PublicKey}))
	if err == nil {
		t.Fatal("expected error for unknown kid, got nil")
	}
	if !errors.Is(err, ErrES256UnknownKID) {
		t.Fatalf("expected ErrES256UnknownKID, got %v", err)
	}
}

func TestParseES256_RejectsTamperedSig(t *testing.T) {
	key := newP256(t)
	tokenStr := signES256(t, key, "es256-1", basicClaims())
	// Tamper a character in the MIDDLE of the signature segment. Flipping the
	// LAST base64url char is unreliable — its trailing 6-bit group can re-encode
	// to the same signature bytes, so the signature still verifies and the test
	// flakes. A mid-segment char maps to whole signature bytes, so any change
	// always alters the decoded signature → deterministic rejection.
	dot := strings.LastIndexByte(tokenStr, '.')
	if dot < 0 || dot+1 >= len(tokenStr) {
		t.Fatalf("malformed token, no signature segment: %q", tokenStr)
	}
	sig := []byte(tokenStr[dot+1:])
	mid := len(sig) / 2
	if sig[mid] == 'A' {
		sig[mid] = 'B'
	} else {
		sig[mid] = 'A'
	}
	tampered := tokenStr[:dot+1] + string(sig)

	if _, err := ParseES256(tampered, &Claims{}, keySet(map[string]*ecdsa.PublicKey{"es256-1": &key.PublicKey})); err == nil {
		t.Fatal("expected error for tampered signature, got nil")
	}
}

// A token signed by a DIFFERENT key than the one published under the kid must
// fail verification (wrong-key, not just wrong-byte).
func TestParseES256_RejectsWrongKey(t *testing.T) {
	signer := newP256(t)
	other := newP256(t)
	tokenStr := signES256(t, signer, "es256-1", basicClaims())

	if _, err := ParseES256(tokenStr, &Claims{}, keySet(map[string]*ecdsa.PublicKey{"es256-1": &other.PublicKey})); err == nil {
		t.Fatal("expected error when kid maps to the wrong public key, got nil")
	}
}
