package handlers

// possession_session_token_test.go — the per-tab DPoP admission-recovery read
// (r3; GET /auth/session/token): the session cookie is shared across browser
// tabs but the RFC 9449 ath source is per-tab, so a fresh tab (no token
// string) and a stale tab (another tab's refresh rotated the cookie) mint
// inadmissible proofs with no way back. The read reveals the PRESENTED string
// through the recovery funnel — everything the regular funnel enforces EXCEPT
// ath, so a cnf-bound token still requires a DPoP proof bound to its cnf.jkt
// (shared/threat.VerifyDPoP's documented ath-less caller class).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/threat"
)

const sessionTokenHTU = "http://example.com/auth/session/token"

// recoveryKeyPair is a proof key with its embedded JWK and jkt.
type recoveryKeyPair struct {
	key *ecdsa.PrivateKey
	jwk map[string]any
	jkt string
}

func newRecoveryKeyPair(t *testing.T) recoveryKeyPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("proof key: %v", err)
	}
	jwk := map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes()),
		"y": base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes()),
	}
	jkt, err := threat.JKTFromJWK(jwk)
	if err != nil {
		t.Fatalf("jkt: %v", err)
	}
	return recoveryKeyPair{key: key, jwk: jwk, jkt: jkt}
}

// signRecoveryProof signs the ath-LESS proof the recovery call presents —
// the caller cannot compute ath; that is what it is here for.
func (kp recoveryKeyPair) signRecoveryProof(t *testing.T) string {
	t.Helper()
	claims := jwt.MapClaims{
		"htm": "GET",
		"htu": sessionTokenHTU,
		"jti": "recovery-proof-" + strconv.FormatInt(time.Now().UnixNano(), 10),
		"iat": time.Now().Unix(),
		// Deliberately NO ath.
	}
	proof := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	proof.Header["typ"] = "dpop+jwt"
	proof.Header["jwk"] = kp.jwk
	signed, err := proof.SignedString(kp.key)
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	return signed
}

// mintBoundAccess issues a cnf-bound access token carrying kp's jkt.
func mintBoundAccess(t *testing.T, h *AuthHandler, userID int64, email string, jkt string) string {
	t.Helper()
	bound, err := h.jwt.IssueAccessCA(userID, email, false, nil, nil, nil, nil,
		token.AuthContext{}, &jwtutil.ConfirmationClaim{JKT: jkt}, nil, "")
	if err != nil {
		t.Fatalf("issue bound access: %v", err)
	}
	return bound
}

func postSessionToken(tokCookie, proof string) (*http.Request, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodGet, "/auth/session/token", nil)
	if tokCookie != "" {
		req.AddCookie(&http.Cookie{Name: "access_token", Value: tokCookie})
	}
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	return req, httptest.NewRecorder()
}

// TestSessionTokenAdmissionRecovery pins the read's admission contract: the
// revealed string never outruns the proof-of-possession the caller supplied.
func TestSessionTokenAdmissionRecovery(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUserWithEmail(t, h, "sess-recovery", false)

	t.Run("bound token + matching ath-less proof: the shared token is revealed", func(t *testing.T) {
		kp := newRecoveryKeyPair(t)
		bound := mintBoundAccess(t, h, userID, claims.Email, kp.jkt)
		req, rr := postSessionToken(bound, kp.signRecoveryProof(t))
		h.SessionToken(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d body %s, want 200", rr.Code, rr.Body.String())
		}
		var body struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body.AccessToken == "" {
			t.Fatalf("body %s (%v)", rr.Body.String(), err)
		}
		if body.AccessToken != bound {
			t.Fatal("recovery revealed a different string than the presented token")
		}
	})

	t.Run("bound token + wrong-key proof: 401 (the reveal never bypasses the binding)", func(t *testing.T) {
		owner := newRecoveryKeyPair(t)
		stranger := newRecoveryKeyPair(t)
		bound := mintBoundAccess(t, h, userID, claims.Email, owner.jkt)
		req, rr := postSessionToken(bound, stranger.signRecoveryProof(t))
		h.SessionToken(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("stranger proof: status = %d body %s, want 401 (jkt mismatch)", rr.Code, rr.Body.String())
		}
	})

	t.Run("bound token without any proof: 401", func(t *testing.T) {
		kp := newRecoveryKeyPair(t)
		bound := mintBoundAccess(t, h, userID, claims.Email, kp.jkt)
		req, rr := postSessionToken(bound, "")
		h.SessionToken(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("no-proof bound token: status = %d body %s, want 401", rr.Code, rr.Body.String())
		}
	})

	t.Run("unbound token without proof: revealed (nothing to bind)", func(t *testing.T) {
		plain, err := h.jwt.IssueAccess(userID, claims.Email, false)
		if err != nil {
			t.Fatalf("issue unbound: %v", err)
		}
		req, rr := postSessionToken(plain, "")
		h.SessionToken(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("unbound token: status = %d body %s, want 200", rr.Code, rr.Body.String())
		}
		if !json.Valid(rr.Body.Bytes()) {
			t.Fatalf("body %s is not JSON", rr.Body.String())
		}
	})

	t.Run("no credentials: 401", func(t *testing.T) {
		req, rr := postSessionToken("", "")
		h.SessionToken(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous: status = %d, want 401", rr.Code)
		}
	})
}
