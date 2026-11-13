package jwtutil

import (
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	vSecret   = "shared-verifier-32-byte-test-secret!"
	vIssuer   = "mailserver"
	vAudience = "mailserver-gateway"
	vHMACKID  = "authserver-hmac-1"
)

func vClaims(ttl time.Duration) *Claims {
	now := time.Now()
	return &Claims{
		UserID: 5,
		Email:  "v@example.com",
		Type:   TypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    vIssuer,
			Audience:  jwt.ClaimStrings{vAudience},
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
}

func vSignHS(t *testing.T, secret, kid, alg string, claims *Claims) string {
	t.Helper()
	method := jwt.SigningMethodHS256
	tok := jwt.NewWithClaims(method, claims)
	tok.Header["kid"] = kid
	if alg != "" {
		tok.Header["alg"] = alg // allow forging the header alg for confusion tests
	}
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func TestVerifier_AcceptsValidHS256(t *testing.T) {
	v := NewVerifier([]byte(vSecret), nil, nil, vIssuer, vAudience, vHMACKID)
	tok := vSignHS(t, vSecret, vHMACKID, "", vClaims(time.Hour))
	c, err := v.Validate(tok)
	if err != nil {
		t.Fatalf("valid HS256 rejected: %v", err)
	}
	if c.UserID != 5 {
		t.Errorf("UserID=%d want 5", c.UserID)
	}
}

func TestVerifier_RejectsUnknownHMACKID(t *testing.T) {
	v := NewVerifier([]byte(vSecret), nil, nil, vIssuer, vAudience, vHMACKID)
	tok := vSignHS(t, vSecret, "some-other-kid", "", vClaims(time.Hour))
	if _, err := v.Validate(tok); err == nil {
		t.Error("expected rejection of an unrecognized HS256 kid")
	}
}

func TestVerifier_RejectsWrongSecret(t *testing.T) {
	v := NewVerifier([]byte(vSecret), nil, nil, vIssuer, vAudience, vHMACKID)
	tok := vSignHS(t, "a-different-32-byte-secret-value!!!", vHMACKID, "", vClaims(time.Hour))
	if _, err := v.Validate(tok); err == nil {
		t.Error("expected rejection of a token signed with the wrong secret")
	}
}

func TestVerifier_RejectsWrongIssuer(t *testing.T) {
	v := NewVerifier([]byte(vSecret), nil, nil, "other-issuer", vAudience, vHMACKID)
	tok := vSignHS(t, vSecret, vHMACKID, "", vClaims(time.Hour))
	if _, err := v.Validate(tok); err == nil {
		t.Error("expected rejection when iss does not match the configured issuer")
	}
}

func TestVerifier_RejectsExpired(t *testing.T) {
	v := NewVerifier([]byte(vSecret), nil, nil, vIssuer, vAudience, vHMACKID)
	tok := vSignHS(t, vSecret, vHMACKID, "", vClaims(-time.Hour))
	if _, err := v.Validate(tok); err == nil {
		t.Error("expected rejection of an expired token")
	}
}

// TestVerifier_RejectsNoneAlg pins the WithValidMethods allowlist — the gap the
// gateway's former Validate lacked. A forged alg=none token is rejected before
// any key func runs.
func TestVerifier_RejectsNoneAlg(t *testing.T) {
	v := NewVerifier([]byte(vSecret), nil, nil, vIssuer, vAudience, vHMACKID)
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, vClaims(time.Hour))
	tok.Header["kid"] = vHMACKID
	s, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	if _, err := v.Validate(s); err == nil {
		t.Error("expected rejection of an alg=none token")
	}
}

// TestVerifier_ES256Disabled confirms fail-closed: with no keyByKID, an ES256
// token is rejected rather than panicking.
func TestVerifier_ES256Disabled(t *testing.T) {
	priv := newP256(t)
	v := NewVerifier([]byte(vSecret), nil, nil, vIssuer, vAudience, vHMACKID)
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, vClaims(time.Hour))
	tok.Header["kid"] = "es256-1"
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign es256: %v", err)
	}
	if _, err := v.Validate(s); err == nil {
		t.Error("expected ES256 to fail closed when no key set is configured")
	}
}

// TestVerifier_ES256Accepts confirms an ES256 token verifies when the key set
// resolves its kid.
func TestVerifier_ES256Accepts(t *testing.T) {
	priv := newP256(t)
	keyByKID := func(kid string) (*ecdsa.PublicKey, bool) {
		if kid == "es256-1" {
			return &priv.PublicKey, true
		}
		return nil, false
	}
	v := NewVerifier([]byte(vSecret), nil, keyByKID, vIssuer, vAudience, vHMACKID)
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, vClaims(time.Hour))
	tok.Header["kid"] = "es256-1"
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign es256: %v", err)
	}
	if _, err := v.Validate(s); err != nil {
		t.Fatalf("valid ES256 rejected: %v", err)
	}
}

func TestVerifierRequiresExpiration(t *testing.T) {
	claims := jwt.MapClaims{
		"iss": vIssuer, "aud": vAudience, "sub": "42", "kid": vHMACKID,
		"iat": jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		// no exp on purpose
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = vHMACKID
	signed, err := tok.SignedString([]byte(vSecret))
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier([]byte(vSecret), nil, nil, vIssuer, vAudience, vHMACKID)
	if _, err := v.Validate(signed); err == nil {
		t.Fatal("exp-less token accepted; exp must be required at the shared verify path")
	}
}

func TestNewVerifierFailsClosedOnDegenerateConfig(t *testing.T) {
	if v := NewVerifier(nil, nil, nil, vIssuer, vAudience, vHMACKID); v != nil {
		if _, err := v.Validate("anything"); err == nil {
			t.Fatal("empty-secret verifier accepted a token")
		}
	}
	if v := NewVerifier([]byte(vSecret), nil, nil, "", vAudience, vHMACKID); v != nil {
		if _, err := v.Validate("anything"); err == nil {
			t.Fatal("empty-issuer verifier accepted a token")
		}
	}
	if v := NewVerifier(nil, nil, nil, "", vAudience, vHMACKID); v != nil {
		if _, err := v.Validate("anything"); err == nil {
			t.Fatal("empty-secret+empty-issuer verifier accepted a token")
		}
	}
}
