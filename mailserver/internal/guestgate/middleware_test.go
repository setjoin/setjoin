// middleware_test.go — Task 6 review follow-up: guestgate.Middleware must
// SKIP ch.AuthenticateRequest for requests that carry neither a Bearer
// Authorization header nor an access_token cookie (CalDAV/CardDAV Basic-auth
// clients, unauthenticated probes) — otherwise every DAV request re-runs the
// full auth chain a second time on top of d.requireAuth's own
// AuthenticateRequest (2x bcrypt, 2x threat-score record, 2x audit row,
// doubled tarpit sleep). A guest principal is JWT-borne only, so this can
// never let a guest slip past the allowlist.
package guestgate

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/jwtutil"
)

const (
	mwTestSecret = "guestgate-middleware-test-secret-32b!"
	mwTestIssuer = "mailserver"
	mwTestAud    = "mailserver-gateway"
	mwTestKid    = "authserver-hmac-1"
)

func mwMintToken(t *testing.T, guest bool) string {
	t.Helper()
	now := time.Now()
	claims := &jwtutil.Claims{
		UserID: 1,
		Email:  "u@example.com",
		Type:   jwtutil.TypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    mwTestIssuer,
			Audience:  jwt.ClaimStrings{mwTestAud},
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
	if guest {
		claims.AccountType = jwtutil.AccountTypeGuest
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = mwTestKid
	s, err := tok.SignedString([]byte(mwTestSecret))
	if err != nil {
		t.Fatalf("mwMintToken: %v", err)
	}
	return s
}

func TestMiddleware_NonJWTRequestsSkipTheChain(t *testing.T) {
	const stamp = "X-Handler"
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(stamp, "next")
		w.WriteHeader(http.StatusTeapot) // a distinctive, un-confusable status
	})

	prov := auth.NewJWTProvider(mwTestSecret, nil, mwTestIssuer)
	chain := auth.NewChainWithJWT(prov)
	guestToken := mwMintToken(t, true)
	memberToken := mwMintToken(t, false)

	h := Middleware(chain, next)

	cases := []struct {
		name       string
		setup      func(r *http.Request)
		wantStatus int
		wantStamp  string
	}{
		{
			name:       "no credentials at all passes straight through",
			setup:      func(r *http.Request) {},
			wantStatus: http.StatusTeapot,
			wantStamp:  "next",
		},
		{
			name: "Basic auth (DAV client) passes straight through, chain not consulted",
			setup: func(r *http.Request) {
				r.SetBasicAuth("carol", "hunter2")
			},
			wantStatus: http.StatusTeapot,
			wantStamp:  "next",
		},
		{
			name: "Bearer guest token on a non-allowlisted path still gates (404)",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer "+guestToken)
			},
			wantStatus: http.StatusNotFound,
			wantStamp:  "",
		},
		{
			name: "Bearer member token still gates (passes through, narrows only guests)",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer "+memberToken)
			},
			wantStatus: http.StatusTeapot,
			wantStamp:  "next",
		},
		{
			name: "access_token cookie carrying a guest token still gates (404)",
			setup: func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: "access_token", Value: guestToken})
			},
			wantStatus: http.StatusNotFound,
			wantStamp:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/user/profile", nil) // NOT allowlisted
			tc.setup(req)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rr.Code, tc.wantStatus)
			}
			if got := rr.Header().Get(stamp); got != tc.wantStamp {
				t.Fatalf("stamp = %q, want %q", got, tc.wantStamp)
			}
		})
	}
}

// TestGateSkipDrift_ChecksEveryChainCredentialSource pins the gate/chain
// agreement invariant (D-MAILSERVER-INTERNAL-GUESTGATE-001): for every
// credential shape the auth chain can act on, the gate's skip predicate must
// be FALSE (the chain gets consulted and a guest narrows); for every shape the
// gate SKIPS, the chain must refuse the request outright (no guest claim can
// hide behind the skip). Together with the source-scan cookie-name guard in
// TestGateSkipDrift_CookieNameMatchesChainSource this encodes the JWT-only
// assumption instead of leaving it uncoded.
func TestGateSkipDrift_ChecksEveryChainCredentialSource(t *testing.T) {
	prov := auth.NewJWTProvider(mwTestSecret, nil, mwTestIssuer)
	chain := auth.NewChainWithJWT(prov)
	guestToken := mwMintToken(t, true)

	// (a) Every chain-recognized credential source is DETECTED by the gate.
	detected := []struct {
		name string
		mk   func(r *http.Request)
	}{
		{"Bearer header", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+guestToken)
		}},
		{"access_token cookie", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: accessTokenCookieName, Value: guestToken})
		}},
		{"cookie variant with the chain's literal name", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "access_token", Value: guestToken})
		}},
	}
	for _, tc := range detected {
		r := httptest.NewRequest(http.MethodGet, "/api/x", nil)
		tc.mk(r)
		if !carriesJWTCredential(r) {
			t.Errorf("%s: gate must DETECT this credential (skip would hide a guest)", tc.name)
		}
	}

	// (b) Every skipped shape is refused by the chain — no guest can ride it.
	skipped := []struct {
		name string
		mk   func(r *http.Request)
	}{
		{"no credentials", func(r *http.Request) {}},
		{"Basic auth", func(r *http.Request) {
			r.SetBasicAuth("carol", "hunter2")
		}},
		{"empty Bearer", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer")
		}},
		{"non-JWT cookie shape", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "other_cookie", Value: "x"})
		}},
		{"empty access_token cookie", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: accessTokenCookieName, Value: ""})
		}},
	}
	for _, tc := range skipped {
		r := httptest.NewRequest(http.MethodGet, "/api/x", nil)
		tc.mk(r)
		if carriesJWTCredential(r) {
			t.Errorf("%s: gate must SKIP this shape (it is not a JWT credential)", tc.name)
		}
		if _, err := chain.AuthenticateRequest(r); err == nil {
			t.Errorf("%s: chain must REFUSE a skipped shape — the skip could never hide a guest", tc.name)
		}
	}
}

// TestGateSkipDrift_CookieNameMatchesChainSource guards the one hand-mirrored
// literal at the source level: internal/auth/chain.go's unexported
// accessTokenCookie constant must still be exactly the cookie name the gate's
// accessTokenCookieName literal mirrors. If the chain's cookie credential
// source ever moves (rename, additional cookie, header-only), this test turns
// RED and forces the single-source refactor instead of silently drifting.
func TestGateSkipDrift_CookieNameMatchesChainSource(t *testing.T) {
	src, err := os.ReadFile("../auth/chain.go")
	if err != nil {
		t.Fatalf("read chain source: %v", err)
	}
	const wantConst = `const accessTokenCookie = "access_token"`
	if !strings.Contains(string(src), wantConst) {
		t.Errorf("auth/chain.go no longer declares %q — the guestgate mirror (accessTokenCookieName=%q) has drifted; export a shared credential-detection primitive instead of updating the copy",
			wantConst, accessTokenCookieName)
	}
	// The jwt method must still read that cookie as its (only) cookie source.
	if !strings.Contains(string(src), "r.Cookie(accessTokenCookie)") {
		t.Error("auth/chain.go's jwt method no longer reads the access_token cookie — re-audit the gate's JWT-only skip assumption")
	}
	// The gate's mirror literal must match the chain constant's value.
	if accessTokenCookieName != "access_token" {
		t.Errorf("gate mirror literal = %q, want the chain's cookie name", accessTokenCookieName)
	}
}
