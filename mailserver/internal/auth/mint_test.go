package auth

import (
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/jwtutil"
)

// testIssuer is the iss the gateway expects; the authserver's jwt.issuer default.
const testIssuer = "mailserver"

// The gateway is verify-only, so tests can no longer round-trip through a gateway
// Issue* method — these helpers mint tokens the way the AUTHSERVER does (the real
// production shape: HS256/SM2 signed with the authserver's kids), which the
// gateway then validates.

// testClaims builds a minimal valid claim set (correct iss/aud/exp) for a token
// the gateway should accept. A negative ttl yields an already-expired token.
func testClaims(userID int64, email string, isAdmin bool, typ jwtutil.TokenType, ttl time.Duration) *jwtutil.Claims {
	now := time.Now()
	return &jwtutil.Claims{
		UserID:  userID,
		Email:   email,
		IsAdmin: isAdmin,
		Type:    typ,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    testIssuer,
			Audience:  jwt.ClaimStrings{audience},
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
}

// mintHS256 signs claims as the authserver's HS256 path does (kid=authserver-hmac-1).
func mintHS256(t *testing.T, secret string, claims *jwtutil.Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = kidHMAC
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("mintHS256: %v", err)
	}
	return s
}

// mintSM2 signs claims as the authserver's SM2 path does (kid=authserver-sm2-1).
func mintSM2(t *testing.T, key *ecdsa.PrivateKey, claims *jwtutil.Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(&cryptokey.SigningMethodSM2{}, claims)
	tok.Header["kid"] = "authserver-sm2-1"
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("mintSM2: %v", err)
	}
	return s
}
