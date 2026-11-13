package auth

import (
	"crypto/ecdsa"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"setjoin.com/shared/jwtutil"
)

// stubJWKS is a minimal es256Verifier backed by a static kid→key map — the test
// stand-in for the real JWKSClient (no network).
type stubJWKS struct {
	keys map[string]*ecdsa.PublicKey
}

func (s stubJWKS) KeyByKID(kid string) (*ecdsa.PublicKey, bool) {
	k, ok := s.keys[kid]
	return k, ok && k != nil
}

// mintES256 mints an ES256 token with the given private key + kid carrying a
// realistic first-party access Claims, EXACTLY as authserver's sign() would.
func mintES256(t *testing.T, priv *ecdsa.PrivateKey, kid string, mutate func(*jwtutil.Claims, *jwt.Token)) string {
	t.Helper()
	now := time.Now()
	claims := &jwtutil.Claims{
		UserID: 7,
		Email:  "carol@example.com",
		Type:   jwtutil.TypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    testIssuer,
			Audience:  jwt.ClaimStrings{audience},
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = kid
	if mutate != nil {
		mutate(claims, tok)
	}
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign ES256: %v", err)
	}
	return signed
}

// providerWithES256 builds a JWTProvider in HS256 standard mode (the production
// dual-verify shape) and wires the given JWKS verifier.
func providerWithES256(verifier es256Verifier) *JWTProvider {
	p := NewJWTProvider(testSecret, nil, testIssuer)
	p.SetES256Verifier(verifier)
	return p
}

// TestES256CrossEndContract is the load-bearing contract test: a token minted by
// the authserver shape (ES256 + the KeySet kid) MUST verify at the gateway, and
// every tamper/confusion/scope variant MUST be rejected.
func TestES256CrossEndContract(t *testing.T) {
	priv := newP256(t)
	kid := es256KID(t, &priv.PublicKey)
	verifier := stubJWKS{keys: map[string]*ecdsa.PublicKey{kid: &priv.PublicKey}}
	p := providerWithES256(verifier)

	t.Run("accepts a valid ES256 access token", func(t *testing.T) {
		tok := mintES256(t, priv, kid, nil)
		claims, err := p.Validate(tok)
		if err != nil {
			t.Fatalf("expected acceptance, got error: %v", err)
		}
		if claims.UserID != 7 || claims.Email != "carol@example.com" {
			t.Errorf("wrong claims: %+v", claims)
		}
		if claims.Type != TypeAccess {
			t.Errorf("expected access type, got %s", claims.Type)
		}
	})

	t.Run("rejects unknown kid", func(t *testing.T) {
		tok := mintES256(t, priv, "es256-0000000000000000", nil)
		if _, err := p.Validate(tok); err == nil {
			t.Error("expected rejection for unknown kid")
		}
	})

	t.Run("rejects tampered signature", func(t *testing.T) {
		tok := mintES256(t, priv, kid, nil)
		// Mutate a char inside the signature segment (after the last '.'). Pick a
		// position well inside the segment and swap it to a different base64url
		// char so the decoded signature bytes definitely change.
		dot := strings.LastIndex(tok, ".")
		sig := []byte(tok)
		pos := dot + 1 + (len(tok)-dot-1)/2 // middle of the signature
		if sig[pos] == 'a' {
			sig[pos] = 'b'
		} else {
			sig[pos] = 'a'
		}
		if _, err := p.Validate(string(sig)); err == nil {
			t.Error("expected rejection for tampered signature")
		}
	})

	t.Run("rejects HS256 token whose kid names the EC key (alg confusion)", func(t *testing.T) {
		// Forge an HS256 token using the EC public key bytes as the HMAC secret,
		// labelled with the EC key's kid — the classic alg-confusion attack.
		now := time.Now()
		claims := &jwtutil.Claims{
			UserID: 7, Email: "carol@example.com", Type: jwtutil.TypeAccess,
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer: testIssuer, Audience: jwt.ClaimStrings{audience},
				NotBefore: jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(now),
			},
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tok.Header["kid"] = kid
		// Use the marshalled public key (SPKI DER) as the "secret".
		pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			t.Fatalf("marshal pub: %v", err)
		}
		forged, err := tok.SignedString(pubBytes)
		if err != nil {
			t.Fatalf("sign forged HS256: %v", err)
		}
		// The forged token carries kid = the EC kid but alg=HS256. The gateway
		// must NOT route it to the ES256 branch (alg dispatch) and the HS256
		// branch rejects the unexpected kid — either way: rejected.
		if _, err := p.Validate(forged); err == nil {
			t.Error("expected rejection of HS256-token-named-with-EC-kid (alg confusion)")
		}
	})

	t.Run("rejects wrong issuer", func(t *testing.T) {
		tok := mintES256(t, priv, kid, func(c *jwtutil.Claims, _ *jwt.Token) {
			c.Issuer = "evil-issuer"
		})
		if _, err := p.Validate(tok); err == nil {
			t.Error("expected rejection for wrong issuer")
		}
	})

	t.Run("rejects wrong audience", func(t *testing.T) {
		tok := mintES256(t, priv, kid, func(c *jwtutil.Claims, _ *jwt.Token) {
			c.Audience = jwt.ClaimStrings{"some-other-service"}
		})
		if _, err := p.Validate(tok); err == nil {
			t.Error("expected rejection for wrong audience")
		}
	})

	t.Run("rejects expired token", func(t *testing.T) {
		tok := mintES256(t, priv, kid, func(c *jwtutil.Claims, _ *jwt.Token) {
			c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
		})
		if _, err := p.Validate(tok); err == nil {
			t.Error("expected rejection for expired token")
		}
	})

	t.Run("rejects ES256 when no JWKS verifier configured (HS256-only mode)", func(t *testing.T) {
		hsOnly := NewJWTProvider(testSecret, nil, testIssuer)
		tok := mintES256(t, priv, kid, nil)
		if _, err := hsOnly.Validate(tok); err == nil {
			t.Error("expected ES256 to fail closed when no JWKS verifier is set")
		}
	})
}

// TestDualVerify asserts the SAME provider instance verifies BOTH a legacy HS256
// token (signed with the shared secret) AND an ES256 token (via JWKS) — the
// never-a-flag-day migration invariant.
func TestDualVerify(t *testing.T) {
	priv := newP256(t)
	kid := es256KID(t, &priv.PublicKey)
	p := providerWithES256(stubJWKS{keys: map[string]*ecdsa.PublicKey{kid: &priv.PublicKey}})

	// 1. A legacy HS256 token (authserver-issued shape) still verifies.
	hsTok := mintHS256(t, testSecret, testClaims(99, "dave@example.com", false, TypeAccess, time.Hour))
	hsClaims, err := p.Validate(hsTok)
	if err != nil {
		t.Fatalf("expected HS256 token to verify, got: %v", err)
	}
	if hsClaims.UserID != 99 {
		t.Errorf("HS256 wrong uid: %d", hsClaims.UserID)
	}

	// 2. ES256 token verifies on the SAME provider.
	esTok := mintES256(t, priv, kid, nil)
	esClaims, err := p.Validate(esTok)
	if err != nil {
		t.Fatalf("expected ES256 token to verify on the same provider, got: %v", err)
	}
	if esClaims.UserID != 7 {
		t.Errorf("ES256 wrong uid: %d", esClaims.UserID)
	}
}
