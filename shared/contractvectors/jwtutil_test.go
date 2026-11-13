package contractvectors

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/golang-jwt/jwt/v5"
	_ "setjoin.com/shared/cryptokey"
	"setjoin.com/shared/jwtutil"
)

func TestRecordJwtutil(t *testing.T) {
	secret := []byte("fixture-signing-secret-not-production")
	domain := int64(9)
	claims := jwtutil.Claims{UserID: 42, Email: "fixture@example.test", IsAdmin: true, Permissions: []string{"mail.read", "mail.write"}, DomainScope: &domain, Type: jwtutil.TypeAccess, JTI: "fixture-jti", ACR: "aal2", AMR: []string{"pwd", "otp", "mfa"}, RegisteredClaims: jwt.RegisteredClaims{Issuer: "fixture-issuer", Audience: jwt.ClaimStrings{"fixture-audience"}, ExpiresAt: jwt.NewNumericDate(time.Unix(4102444800, 0)), IssuedAt: jwt.NewNumericDate(time.Unix(1700000000, 0))}}
	sign := func(c jwtutil.Claims, kid string) string {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
		token.Header["kid"] = kid
		s, err := token.SignedString(secret)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	expired := claims
	expired.ExpiresAt = jwt.NewNumericDate(time.Unix(946684800, 0))
	wrongIssuer := claims
	wrongIssuer.Issuer = "other"
	none := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	noneToken, err := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	// Captured from golang-jwt's ES256 signer with the fixture private scalar 1;
	// retaining the signature makes replay independent of ECDSA randomness.
	const es256Token = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImZpeHR1cmUtZXMyNTYiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsiZml4dHVyZS1hdWRpZW5jZSJdLCJlbWFpbCI6ImZpeHR1cmVAZXhhbXBsZS50ZXN0IiwiZXhwIjo0MTAyNDQ0ODAwLCJpc3MiOiJmaXh0dXJlLWlzc3VlciIsInR5cCI6ImFjY2VzcyIsInVpZCI6NDJ9.ull8eddwevnKY9ZnS8I0EYd5S8syhkKR03rBg9tdufl-7eBK3GPJ29sU4zLDkDAPdZbauoQGaPLQBE0L0SPn9A"
	// A fixed private key and deterministic nonce make a repeatable valid input.
	// The actual verdict and claims are produced by the shared Go verifier.
	sm2Key, err := sm2.NewPrivateKeyFromInt(big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	sm2Payload := b64([]byte(`{"alg":"SM2","kid":"authserver-sm2-1","typ":"JWT"}`)) + "." + b64([]byte(`{"uid":42,"email":"fixture@example.test","typ":"access","iss":"fixture-issuer","aud":["fixture-audience"],"exp":4102444800}`))
	digest := sm3.Sum([]byte(sm2Payload))
	signature, err := sm2.SignDeterministic(sm2Key, digest[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	sm2Token := sm2Payload + "." + b64(signature)
	inputs := []struct{ name, token string }{
		{"valid_hs256_claims", sign(claims, "fixture-kid")},
		{"valid_es256_claims", es256Token},
		{"valid_sm2_claims", sm2Token},
		{"invalid_sm2_signature", sm2Token[:len(sm2Token)-2] + "AA"},
		{"invalid_es256_signature", es256Token[:len(es256Token)-2] + "AA"},
		{"expired", sign(expired, "fixture-kid")},
		{"wrong_issuer", sign(wrongIssuer, "fixture-kid")},
		{"unknown_kid", sign(claims, "other-kid")},
		{"none_algorithm", noneToken},
		{"malformed_token", "not-a-token"},
	}
	x, y := elliptic.P256().ScalarBaseMult([]byte{1})
	publicKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	keyByKID := func(kid string) (*ecdsa.PublicKey, bool) { return publicKey, kid == "fixture-es256" }
	verifier := jwtutil.NewVerifier(secret, &sm2Key.PublicKey, keyByKID, "fixture-issuer", "fixture-audience", "fixture-kid")
	var cases []vectorCase
	for _, in := range inputs {
		got, err := verifier.Validate(in.token)
		output := map[string]any{"valid": err == nil}
		if err == nil {
			encoded, e := json.Marshal(got)
			if e != nil {
				t.Fatal(e)
			}
			output["claims_json"] = string(encoded)
		} else {
			output["error"] = err.Error()
		}
		cases = append(cases, vectorCase{Name: in.name, Input: map[string]any{"token": in.token, "secret": "fixture-signing-secret-not-production", "issuer": "fixture-issuer", "audience": "fixture-audience", "kid": "fixture-kid", "es256_public_x": x.Text(16), "es256_public_y": y.Text(16), "es256_kid": "fixture-es256", "sm2_public_x": sm2Key.X.Text(16), "sm2_public_y": sm2Key.Y.Text(16)}, Output: output})
	}
	writeVectors(t, "jwtutil", cases)
}
