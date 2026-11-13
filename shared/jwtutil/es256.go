package jwtutil

import (
	"crypto/ecdsa"
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

// ErrES256NoKID is returned when an ES256 token carries no (or an empty) `kid`
// header. ADR-005 binds every signing key to one kid, so a kid-less token can
// never be matched to a published JWKS key and is rejected outright.
var ErrES256NoKID = errors.New("jwtutil: ES256 token missing kid header")

// ErrES256UnknownKID is returned when the token's `kid` is not present in the
// caller-supplied key set. The lookup func is the ONLY source of trust — the
// header's own `jku`/`x5u`/embedded-key fields are never consulted (SSRF /
// key-injection closure, RFC 8725 §3.5/§3.8).
var ErrES256UnknownKID = errors.New("jwtutil: ES256 token kid not in key set")

// es256KeyFunc is the ES256 key-resolution closure shared by ParseES256 (the
// pure-ES256 primitive) and Verifier (the unified HS256/SM2/ES256 dispatch), so
// the ES256 rules live in ONE place: assert the concrete *SigningMethodECDSA,
// require a non-empty kid, and resolve the *ecdsa.PublicKey SOLELY via
// keyByKID(kid) — the token's own jku/x5u/jwk header fields are never read
// (SSRF / key-injection closure, RFC 8725 §3.5/§3.8).
func es256KeyFunc(keyByKID func(kid string) (*ecdsa.PublicKey, bool)) jwt.Keyfunc {
	return func(t *jwt.Token) (any, error) {
		// Defense in depth: the parser's WithValidMethods already rejects
		// non-ES256, but assert the concrete method too so a future caller
		// dropping the option can't silently widen the surface.
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok || t.Method.Alg() != "ES256" {
			return nil, errors.New("jwtutil: unexpected signing method (want ES256)")
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, ErrES256NoKID
		}
		pub, ok := keyByKID(kid)
		if !ok || pub == nil {
			return nil, ErrES256UnknownKID
		}
		return pub, nil
	}
}

// ParseES256 is the ES256 verification primitive used by the mailserver gateway's
// JWKS-cached verify path (via Verifier). It parses tokenStr into claims,
// enforcing the alg-confusion closure of ADR-005 / RFC 8725:
//
//   - WithValidMethods restricts acceptance to ES256 ONLY — an HS256 (or any
//     other alg, including "none") token is rejected before the key func runs,
//     so a public key can never be coerced into use as an HMAC secret.
//   - a non-empty `kid` header is required; the *ecdsa.PublicKey is resolved
//     solely via keyByKID(kid) (see es256KeyFunc).
//
// iss / aud / exp / nbf are NOT checked here; callers add jwt.WithIssuer /
// jwt.WithAudience (and exp/nbf are validated by golang-jwt by default). This
// keeps the primitive purely about "is this an ES256 token signed by a key we
// published?", leaving claim-scoping policy to each service.
func ParseES256(tokenStr string, claims jwt.Claims, keyByKID func(kid string) (*ecdsa.PublicKey, bool), opts ...jwt.ParserOption) (*jwt.Token, error) {
	parseOpts := append([]jwt.ParserOption{jwt.WithValidMethods([]string{"ES256"})}, opts...)
	return jwt.ParseWithClaims(tokenStr, claims, es256KeyFunc(keyByKID), parseOpts...)
}
