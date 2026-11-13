package jwtutil

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Algorithm names accepted on first-party tokens. ES256 (ADR-005 asymmetric),
// SM2 (SMx/hybrid profiles), HS256 (the conservative default). "none" and every
// other alg are rejected by the WithValidMethods allowlist below.
const (
	algES256 = "ES256"
	algSM2   = "SM2"
	algHS256 = "HS256"

	// kidSM2 is the single kid every SM2 token is stamped with; both services
	// issue/verify SM2 under this one key id.
	kidSM2 = "authserver-sm2-1"
)

// Verifier is the SINGLE first-party JWT verification path, shared by the
// authserver (which also issues) and the mailserver gateway (verify-only). It
// dual-verifies ES256 (by kid, against a caller-supplied key set), SM2, and
// HS256 in one keyfunc dispatch, so a crypto-migration window never rejects a
// freshly issued token (ADR-005). The alg-confusion closure (RFC 8725) is
// structural: WithValidMethods caps the parser to the three known algs before
// the keyfunc runs, and each branch re-asserts its concrete signing method — a
// public key can never be coerced into use as an HMAC secret, and "none" never
// reaches a key.
//
// This REPLACES the two hand-maintained JWTProvider.Validate bodies that had
// drifted (the gateway's was missing the WithValidMethods allowlist and
// hard-coded its issuer). Do NOT reintroduce a per-service verify copy — extend
// this type instead, so the two services can never diverge by hand again.
//
// Verifier does NOT check revocation or token type; callers layer those on top
// (the authserver/gateway authenticators gate on Claims.Type).
type Verifier struct {
	secret   []byte                                    // HS256 shared secret (required)
	sm2Pub   *ecdsa.PublicKey                          // SM2 verify key; nil ⇒ SM2 tokens rejected
	keyByKID func(kid string) (*ecdsa.PublicKey, bool) // ES256 kid→pubkey; nil ⇒ ES256 disabled (HS256/SM2-only)
	issuer   string
	audience string
	hmacKIDs map[string]bool // kids accepted for HS256 (the issuing service's HMAC kid)

	// invalidReason is non-empty when construction received a degenerate
	// configuration (empty HS256 secret or empty issuer). The verifier then
	// FAILS CLOSED: every Validate rejects with this reason instead of
	// verifying tokens under an empty HMAC key (HMAC over a zero-length key)
	// or with a vacuous issuer check.
	invalidReason string
}

// NewVerifier builds the shared verifier.
//
//   - secret   — the HS256 shared secret (both services mount the same JWT_SECRET).
//   - sm2Pub   — the SM2 public key, or nil to reject SM2 tokens (standard profile).
//   - keyByKID — resolves an ES256 kid to its public key, or nil to disable ES256
//     (HS256/SM2-only mode). Satisfied by the authserver KeySet and the gateway
//     JWKS client. The token's own jku/x5u/embedded-key headers are never read —
//     only this trusted lookup is consulted.
//   - issuer/audience — the exact iss/aud every accepted token must carry.
//   - hmacKIDs — the kid(s) accepted for HS256 (the ISSUING authserver's kid).
//
// Construction-time fail-closed contract: an empty secret or empty issuer
// cannot produce a usable verifier (HMAC over a zero-length key; WithIssuer("")
// is a vacuous check), so the returned Verifier refuses every token with a
// clear error instead of accepting anything. The empty-audience case already
// fails closed in the parser. Every production caller passes ValidateBase-
// floored secrets and a pinned issuer at wiring time.
func NewVerifier(secret []byte, sm2Pub *ecdsa.PublicKey, keyByKID func(kid string) (*ecdsa.PublicKey, bool), issuer, audience string, hmacKIDs ...string) *Verifier {
	kids := make(map[string]bool, len(hmacKIDs))
	for _, k := range hmacKIDs {
		kids[k] = true
	}
	v := &Verifier{
		secret:   secret,
		sm2Pub:   sm2Pub,
		keyByKID: keyByKID,
		issuer:   issuer,
		audience: audience,
		hmacKIDs: kids,
	}
	switch {
	case len(secret) == 0 && issuer == "":
		v.invalidReason = "jwtutil: verifier built with an empty HS256 secret and an empty issuer; refusing all tokens"
	case len(secret) == 0:
		v.invalidReason = "jwtutil: verifier built with an empty HS256 secret; refusing all tokens"
	case issuer == "":
		v.invalidReason = "jwtutil: verifier built with an empty issuer; refusing all tokens"
	}
	return v
}

// Validate parses and cryptographically verifies tokenStr, returning its Claims.
func (v *Verifier) Validate(tokenStr string) (*Claims, error) {
	if v.invalidReason != "" {
		return nil, errors.New(v.invalidReason)
	}
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		alg, _ := t.Header["alg"].(string)
		kid, _ := t.Header["kid"].(string)

		switch alg {
		case algES256:
			// ADR-005 asymmetric tokens. keyByKID nil ⇒ ES256 not configured.
			// The shared es256KeyFunc re-asserts the concrete ECDSA method,
			// requires a kid, and resolves the key solely via keyByKID.
			if v.keyByKID == nil {
				return nil, errors.New("jwtutil: ES256 token but no key set configured")
			}
			return es256KeyFunc(v.keyByKID)(t)
		case algSM2:
			if kid != kidSM2 {
				return nil, fmt.Errorf("jwtutil: unexpected kid for SM2: %v", t.Header["kid"])
			}
			if v.sm2Pub == nil {
				return nil, errors.New("jwtutil: SM2 token but no SM2 key configured")
			}
			return v.sm2Pub, nil
		case algHS256:
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("jwtutil: unexpected signing method")
			}
			if !v.hmacKIDs[kid] {
				return nil, fmt.Errorf("jwtutil: unexpected kid: %v", t.Header["kid"])
			}
			return v.secret, nil
		default:
			return nil, fmt.Errorf("jwtutil: unsupported alg %q", alg)
		}
	}, jwt.WithValidMethods([]string{algES256, algSM2, algHS256}), jwt.WithIssuer(v.issuer), jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired())
	if err != nil {
		return nil, err
	}
	c, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("jwtutil: invalid token")
	}
	return c, nil
}
