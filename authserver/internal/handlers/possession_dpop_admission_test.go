package handlers

// possession_dpop_admission_test.go — the dual-admission possession
// endpoints' DPoP enforcement (r1 receipt defect 4; scheme v7 §3.2 T1 +
// occ-dpop): the access-token admission modes reuse the shared bearer
// authenticator's session-acceptance funnel, so a cnf-BOUND access token is
// refused without a verifiable RFC 9449 proof binding the token's cnf.jkt to
// THIS request. A stolen bound token can no longer replace ceremonies or
// submit proofs. The mfa_pending member keeps plain validation — the
// specified pending-token fallback (pending tokens carry no cnf).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/threat"
)

// mintBoundAccessAndProof issues a cnf-bound access token and a matching
// DPoP proof (ath-bound to the token, htu bound to the endpoint URL).
func mintBoundAccessAndProof(t *testing.T, h *AuthHandler, userID int64, email, htu string, withProof bool) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("dpop key: %v", err)
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
	bound, err := h.jwt.IssueAccessCA(userID, email, false, nil, nil, nil, nil,
		token.AuthContext{}, &jwtutil.ConfirmationClaim{JKT: jkt}, nil, "")
	if err != nil {
		t.Fatalf("issue bound token: %v", err)
	}
	if !withProof {
		return bound, ""
	}
	claims := jwt.MapClaims{"htm": "POST", "htu": htu, "jti": "proof-jti-" + strconv.FormatInt(time.Now().UnixNano(), 10), "iat": time.Now().Unix()}
	sum := sha256.Sum256([]byte(bound))
	claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	proof := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	proof.Header["typ"] = "dpop+jwt"
	proof.Header["jwk"] = jwk
	signed, err := proof.SignedString(key)
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	return bound, signed
}

// TestPossessionEndpointsRequireDPoPForBoundTokens is the r1 defect 4
// reproduction: begin and finish admit cnf-bound access tokens ONLY with a
// verifiable DPoP proof, in both transport modes (Authorization header and
// ambient cookie).
func TestPossessionEndpointsRequireDPoPForBoundTokens(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUser(t, h, "dpopadm", true)
	htu := "http://example.com/auth/mfa/possession/webauthn/begin"

	newBegin := func(tokHeader, tokCookie, proof string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/auth/mfa/possession/webauthn/begin",
			strings.NewReader(`{"operation":"recovery.regenerate"}`))
		req.Header.Set("Content-Type", "application/json")
		if tokHeader != "" {
			req.Header.Set("Authorization", "Bearer "+tokHeader)
		}
		if tokCookie != "" {
			req.AddCookie(&http.Cookie{Name: "access_token", Value: tokCookie})
		}
		if proof != "" {
			req.Header.Set("DPoP", proof)
		}
		rr := httptest.NewRecorder()
		h.MFAPossessionWebAuthnBegin(rr, req)
		return rr
	}

	t.Run("bound bearer without proof: 401 (the bypass is closed)", func(t *testing.T) {
		bound, _ := mintBoundAccessAndProof(t, h, userID, claims.Email, htu, false)
		rr := newBegin(bound, "", "")
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d body %s, want 401 — a cnf-bound token must not authenticate without its DPoP proof", rr.Code, rr.Body.String())
		}
		var n int
		if err := h.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM webauthn_ceremonies WHERE user_id = $1`, userID,
		).Scan(&n); err != nil || n != 0 {
			t.Fatalf("refused bound token created ceremonies: %d (%v)", n, err)
		}
	})

	t.Run("bound bearer with a valid proof: admitted (session scope)", func(t *testing.T) {
		bound, proof := mintBoundAccessAndProof(t, h, userID, claims.Email, htu, true)
		rr := newBegin(bound, "", proof)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d body %s, want 200 (proof-of-possession satisfied)", rr.Code, rr.Body.String())
		}
		var n int
		if err := h.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM webauthn_ceremonies WHERE user_id = $1 AND token_scope = 'session'`, userID,
		).Scan(&n); err != nil || n != 1 {
			t.Fatalf("ceremony rows = %d (%v), want the admitted ceremony", n, err)
		}
	})

	t.Run("bound cookie without proof: 401; with proof: admitted", func(t *testing.T) {
		bound, proof := mintBoundAccessAndProof(t, h, userID, claims.Email, htu, true)
		rr := newBegin("", bound, "")
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("cookie mode without proof: status = %d, want 401", rr.Code)
		}
		// A second minted pair: the first proof's jti was consumed by (t.Run
		// "with a valid proof")'s cache only if admitted — mint fresh here.
		bound2, proof2 := mintBoundAccessAndProof(t, h, userID, claims.Email, htu, true)
		rr = newBegin("", bound2, proof2)
		if rr.Code != http.StatusOK {
			t.Fatalf("cookie mode with proof: status = %d body %s, want 200", rr.Code, rr.Body.String())
		}
		_ = bound
		_ = proof
	})

	t.Run("pending-token fallback unchanged (no cnf, no proof needed)", func(t *testing.T) {
		pending, err := h.jwt.IssueMFAPending(userID, claims.Email)
		if err != nil {
			t.Fatalf("issue pending: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/auth/mfa/possession/webauthn/begin",
			strings.NewReader(`{"operation":"bootstrap.totp.enroll","mfa_token":"`+pending+`"}`))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.MFAPossessionWebAuthnBegin(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d body %s, want 200 (the specified Mode B fallback is preserved)", rr.Code, rr.Body.String())
		}
	})
}

// mintBrowserProofVariant mints a cnf-bound access token plus a DPoP proof in
// the BROWSER transport shape. withAth=true is the CORRECTED transport (r2
// defect 1): the proof carries ath = base64url(SHA-256(token)) exactly as
// VerifyDPoPForToken demands. withAth=false is the historical browser shape
// (htm/htu/iat/jti only) that the verifier must refuse.
func mintBrowserProofVariant(t *testing.T, h *AuthHandler, userID int64, email, htu string, withAth bool) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("dpop key: %v", err)
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
	bound, err := h.jwt.IssueAccessCA(userID, email, false, nil, nil, nil, nil,
		token.AuthContext{}, &jwtutil.ConfirmationClaim{JKT: jkt}, nil, "")
	if err != nil {
		t.Fatalf("issue bound token: %v", err)
	}
	claims := jwt.MapClaims{"htm": "POST", "htu": htu, "jti": "browser-jti-" + strconv.FormatInt(time.Now().UnixNano(), 10), "iat": time.Now().Unix()}
	if withAth {
		sum := sha256.Sum256([]byte(bound))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	proof := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	proof.Header["typ"] = "dpop+jwt"
	proof.Header["jwk"] = jwk
	signed, err := proof.SignedString(key)
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	return bound, signed
}

// TestBrowserCookieSessionPossessionAthBinding is the r2 defect 1 regression:
// the webmail SPA presents its cnf-bound access token ONLY as the ambient
// HttpOnly cookie, so the possession begin/finish admission runs
// VerifyDPoPForToken against a cookie-carried token. The browser proof MUST
// therefore carry the ath binding the verifier enforces — proofs in the
// historical ath-less browser shape are refused 401 (DPoP enforcement is
// preserved), and the corrected ath-bound browser transport is admitted on
// begin AND passes the gate on finish, both over a pure cookie session.
func TestBrowserCookieSessionPossessionAthBinding(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUser(t, h, "dpopath", true)
	beginHTU := "http://example.com/auth/mfa/possession/webauthn/begin"
	finishHTU := "http://example.com/auth/mfa/possession/webauthn/finish"

	cookieBegin := func(tok, proof string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/auth/mfa/possession/webauthn/begin",
			strings.NewReader(`{"operation":"recovery.regenerate"}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "access_token", Value: tok})
		if proof != "" {
			req.Header.Set("DPoP", proof)
		}
		rr := httptest.NewRecorder()
		h.MFAPossessionWebAuthnBegin(rr, req)
		return rr
	}

	t.Run("historical ath-less browser proof over the cookie: 401 (enforcement preserved)", func(t *testing.T) {
		bound, proof := mintBrowserProofVariant(t, h, userID, claims.Email, beginHTU, false)
		rr := cookieBegin(bound, proof)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d body %s, want 401 — a proof without the ath binding never satisfies VerifyDPoPForToken", rr.Code, rr.Body.String())
		}
		var n int
		if err := h.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM webauthn_ceremonies WHERE user_id = $1`, userID,
		).Scan(&n); err != nil || n != 0 {
			t.Fatalf("refused ath-less proof created ceremonies: %d (%v)", n, err)
		}
	})

	t.Run("corrected ath-bound browser proof over the cookie: begin 200 (the aligned transport)", func(t *testing.T) {
		bound, proof := mintBrowserProofVariant(t, h, userID, claims.Email, beginHTU, true)
		rr := cookieBegin(bound, proof)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d body %s, want 200 — a legitimate cookie session MUST be able to satisfy the admission contract", rr.Code, rr.Body.String())
		}
		var n int
		if err := h.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM webauthn_ceremonies WHERE user_id = $1 AND kind = 'management_assertion'`, userID,
		).Scan(&n); err != nil || n != 1 {
			t.Fatalf("management_assertion rows = %d (%v), want 1", n, err)
		}
	})

	t.Run("finish over the cookie: ath-less proof 401", func(t *testing.T) {
		bound, proof := mintBrowserProofVariant(t, h, userID, claims.Email, finishHTU, false)
		_ = bound
		body := `{"id":"dGVzdA","rawId":"dGVzdA","type":"public-key",` +
			`"response":{"authenticatorData":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJ3cm9uZyJ9","signature":"AA","userHandle":null},` +
			`"operation":"recovery.regenerate"}`
		req := httptest.NewRequest(http.MethodPost, "/auth/mfa/possession/webauthn/finish", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "access_token", Value: bound})
		req.Header.Set("DPoP", proof)
		rr := httptest.NewRecorder()
		h.MFAPossessionWebAuthnFinish(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("finish status = %d body %s, want 401 — the gate runs before any ceremony logic", rr.Code, rr.Body.String())
		}
	})

	t.Run("finish over the cookie: ath-bound proof passes the DPoP gate (403 on the assertion, never 401)", func(t *testing.T) {
		// A fresh ath-bound session whose begin minted its own ceremony, so
		// the finish reaches the assertion check past every admission gate.
		bound, beginProof := mintBrowserProofVariant(t, h, userID, claims.Email, beginHTU, true)
		if rr := cookieBegin(bound, beginProof); rr.Code != http.StatusOK {
			t.Fatalf("begin status = %d body %s, want 200", rr.Code, rr.Body.String())
		}
		finBound, finProof := mintBrowserProofVariant(t, h, userID, claims.Email, finishHTU, true)
		req := httptest.NewRequest(http.MethodPost, "/auth/mfa/possession/webauthn/finish",
			strings.NewReader(`{"operation":"recovery.regenerate","id":"dGVzdA","rawId":"dGVzdA","type":"public-key","response":{"authenticatorData":"AA","clientDataJSON":"e30","signature":"AA","userHandle":null}}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "access_token", Value: finBound})
		req.Header.Set("DPoP", finProof)
		rr := httptest.NewRecorder()
		h.MFAPossessionWebAuthnFinish(rr, req)
		if rr.Code == http.StatusUnauthorized {
			t.Fatalf("finish status = 401 body %s — an ath-bound browser proof must pass the cookie-session DPoP gate", rr.Body.String())
		}
		if rr.Code != http.StatusForbidden {
			t.Fatalf("finish status = %d body %s, want 403 (admission OK, invalid assertion)", rr.Code, rr.Body.String())
		}
	})
}
