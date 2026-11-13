// guest_dispatch_test.go — Guest G0 Task 6 (review-fold E-B1/E-M1): the
// containment proof against the REAL dispatch composition. A guest token must
// be denied at POST /jmap (the BARE pinned root — the hole a /api-only wrap
// leaves), denied on non-allowlisted /api routes, and allowed through the
// exact session/live-rail/chat routes — all through buildRootDispatch, not a
// synthetic middleware chain. Members and unauthenticated callers pass
// through everywhere (the gate only narrows).
package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/toggle"
)

// dispatchTest{Secret,Issuer,Audience,Kid} mirror the authserver's real minting
// shape (internal/auth's unexported audience/kidHMAC constants + mint_test.go's
// mintHS256 pattern) so tokens minted here validate through the production
// JWTProvider/Verifier path exactly like a real authserver-issued token would.
const (
	dispatchTestSecret = "guest-dispatch-test-secret-32-bytes!!"
	dispatchTestIssuer = "mailserver"
	dispatchTestAud    = "mailserver-gateway"
	dispatchTestKid    = "authserver-hmac-1"
)

// newDispatchTestChain builds a REAL auth.Chain — jwt_bearer wired via
// auth.NewChainWithJWT, no guest pool (claim-only belt enforcement, the same
// pool-nil seam guest_belt_test.go exercises) — plus a really-minted guest and
// member access token signed exactly as the authserver mints them, so
// chain.AuthenticateRequest validates them through the real verify path.
func newDispatchTestChain(t *testing.T) (chain *auth.Chain, guestToken, memberToken string) {
	t.Helper()
	prov := auth.NewJWTProvider(dispatchTestSecret, nil, dispatchTestIssuer)
	chain = auth.NewChainWithJWT(prov)
	guestToken = mintDispatchToken(t, true)
	memberToken = mintDispatchToken(t, false)
	return chain, guestToken, memberToken
}

func mintDispatchToken(t *testing.T, guest bool) string {
	t.Helper()
	now := time.Now()
	claims := &jwtutil.Claims{
		UserID: 1,
		Email:  "u@example.com",
		Type:   jwtutil.TypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    dispatchTestIssuer,
			Audience:  jwt.ClaimStrings{dispatchTestAud},
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
	if guest {
		claims.AccountType = jwtutil.AccountTypeGuest
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = dispatchTestKid
	s, err := tok.SignedString([]byte(dispatchTestSecret))
	if err != nil {
		t.Fatalf("mintDispatchToken: %v", err)
	}
	return s
}

func TestGuestDispatch_RealRootMux(t *testing.T) {
	const stamp = "X-Handler"
	leaf := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(stamp, "leaf")
		w.WriteHeader(http.StatusOK)
	})

	// Register the REAL patterns exactly as the register*Routes functions do.
	apiMux := http.NewServeMux()
	for _, pat := range []string{
		"POST /jmap", "POST /jmap/upload/{accountId}",
		"GET /jmap/download/{accountId}/{blobId}/{name}",
		"GET /jmap/ws", "GET /jmap/eventsource",
		"GET /.well-known/jmap", "GET /auth/me", "POST /auth/refresh",
		"POST /auth/logout", "GET /auth/me/org-chart", "POST /user/profile",
		"/chat/", "/meet/", "/public/meet/", "GET /rtc", "GET /rtc/",
		"POST /drive/spaces", "POST /drive/native-token",
	} {
		apiMux.Handle(pat, leaf)
	}

	chain, guestToken, memberToken := newDispatchTestChain(t)

	spa := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(stamp, "spa")
		w.WriteHeader(http.StatusOK)
	})
	root := http.NewServeMux()
	guestFlags := toggle.NewTestFlags(map[string]bool{toggle.FeatureGuestAccounts: true})
	buildRootDispatch(root, apiMux, chain, guestFlags, spa)

	cases := []struct {
		name, method, path, token string
		wantStatus                int
		wantStamp                 string
	}{
		// THE E-B1 hole, closed: bare pinned root.
		{"guest POST /jmap denied at bare root", "POST", "/jmap", guestToken, 404, ""},
		{"guest upload denied at bare root", "POST", "/jmap/upload/1", guestToken, 404, ""},
		{"guest POST /api/jmap denied via mount", "POST", "/api/jmap", guestToken, 404, ""},
		{"guest non-allowlisted /api denied", "POST", "/api/user/profile", guestToken, 404, ""},
		{"guest drive blanket", "POST", "/api/drive/spaces", guestToken, 404, ""},
		{"guest native-token denied", "POST", "/api/drive/native-token", guestToken, 404, ""},
		{"guest org-chart denied (exact /auth/me only)", "GET", "/auth/me/org-chart", guestToken, 404, ""},
		// G3: current Meet shapes reach the reducer-scoped handler, while an
		// unenumerated future suffix stays indistinguishable from missing.
		{"guest scoped meet metadata", "GET", "/api/meet/1", guestToken, 200, "leaf"},
		{"guest unenumerated meet route denied", "POST", "/api/meet/1/future", guestToken, 404, ""},
		// Authenticated knock completes over the public secret-bound GET poll;
		// public POST stays denied so the account cannot shed its u: identity.
		{"guest authenticated-knock poll", "GET", "/api/public/meet/slug/join-request/2", guestToken, 200, "leaf"},
		{"guest public anonymous create denied", "POST", "/api/public/meet/slug/join-request", guestToken, 404, ""},
		// The browser signal WS carries the guest cookie plus the reducer-minted
		// LiveKit token, so both exact and slash-suffixed mounts pass the gate.
		{"guest rtc exact", "GET", "/rtc", guestToken, 200, "leaf"},
		{"guest rtc signal suffix", "GET", "/rtc/rtc/v1", guestToken, 200, "leaf"},
		// C-7: the legacy non-GET 308 alias is behind the gate — a guest
		// probing a bare legacy path gets the indistinguishable 404, never a
		// route-existence-revealing redirect; members/unauth keep the 308.
		{"guest bare legacy POST is 404 not 308", "POST", "/drive/spaces", guestToken, 404, ""},
		{"member bare legacy POST still 308s", "POST", "/drive/spaces", memberToken, 308, ""},
		{"unauth bare legacy POST still 308s", "POST", "/drive/spaces", "", 308, ""},
		// The allowlisted surfaces reach their handlers.
		{"guest session doc", "GET", "/.well-known/jmap", guestToken, 200, "leaf"},
		{"guest auth/me", "GET", "/auth/me", guestToken, 200, "leaf"},
		{"guest refresh", "POST", "/auth/refresh", guestToken, 200, "leaf"},
		{"guest chat", "GET", "/api/chat/conversations", guestToken, 200, "leaf"},
		{"guest ws", "GET", "/jmap/ws", guestToken, 200, "leaf"},
		{"guest eventsource", "GET", "/jmap/eventsource", guestToken, 200, "leaf"},
		// The gate only narrows.
		{"member POST /jmap passes", "POST", "/jmap", memberToken, 200, "leaf"},
		{"member profile passes", "POST", "/api/user/profile", memberToken, 200, "leaf"},
		{"unauthenticated passes through to handler auth", "POST", "/jmap", "", 200, "leaf"},
		// Non-API + legacy behavior preserved.
		{"SPA fallthrough", "GET", "/inbox", "", 200, "spa"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			rr := httptest.NewRecorder()
			root.ServeHTTP(rr, req)
			if rr.Code != tc.wantStatus {
				t.Fatalf("%s %s: status %d, want %d", tc.method, tc.path, rr.Code, tc.wantStatus)
			}
			if got := rr.Header().Get(stamp); got != tc.wantStamp {
				t.Fatalf("%s %s: stamp %q, want %q", tc.method, tc.path, got, tc.wantStamp)
			}
		})
	}
}

func TestGuestDispatch_FeatureOffMakesExistingGuestRuntimeInert(t *testing.T) {
	const stamp = "X-Handler"
	leaf := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(stamp, "leaf")
		w.WriteHeader(http.StatusOK)
	})
	apiMux := http.NewServeMux()
	apiMux.Handle("GET /jmap/eventsource", leaf)
	apiMux.Handle("GET /auth/me", leaf)
	apiMux.Handle("GET /auth/guest-invite/accept", leaf)

	chain, guestToken, memberToken := newDispatchTestChain(t)
	root := http.NewServeMux()
	guestFlags := toggle.NewTestFlags(map[string]bool{toggle.FeatureGuestAccounts: false})
	buildRootDispatch(root, apiMux, chain, guestFlags, http.NotFoundHandler())

	for _, tc := range []struct {
		name, path, token string
		wantStatus        int
		wantStamp         string
	}{
		{"guest eventsource is hidden", "/jmap/eventsource", guestToken, http.StatusNotFound, ""},
		{"guest session is hidden", "/auth/me", guestToken, http.StatusNotFound, ""},
		{"member behavior is unchanged", "/auth/me", memberToken, http.StatusOK, "leaf"},
		{"pre-auth invite acceptance remains reachable", "/auth/guest-invite/accept", "", http.StatusOK, "leaf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			rr := httptest.NewRecorder()
			root.ServeHTTP(rr, req)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status=%d, want %d (body=%s)", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if got := rr.Header().Get(stamp); got != tc.wantStamp {
				t.Fatalf("handler stamp=%q, want %q", got, tc.wantStamp)
			}
		})
	}
}
