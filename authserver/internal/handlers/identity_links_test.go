package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

func identityLinkTestFlags(enabled bool) *toggle.FeatureFlags {
	return toggle.NewTestFlags(map[string]bool{
		toggle.FeatureIdentityModelV2: enabled,
	})
}

func TestBeginIdentityLinkRequiresFreshAAL2(t *testing.T) {
	h := &loginHandler{&deps{cookieKey: make([]byte, 32)}}
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/link", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "opaque"})
	rec := httptest.NewRecorder()

	if h.beginIdentityLink(rec, req, "oidc", "oidc:workforce") {
		t.Fatal("link flow started without authenticated fresh AAL2")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestBeginIdentityLinkSealsPersonSessionProviderAndExpiry(t *testing.T) {
	h := &loginHandler{&deps{cookieKey: []byte("0123456789abcdef0123456789abcdef")}}
	h.identityLinkElevationBegin = func(
		context.Context, identityLinkFlow, []byte,
	) error {
		return nil
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/link", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "session-token"})
	claims := &token.Claims{
		UserID: 42,
		ACR:    jwtutil.ACRAAL2,
		JTI:    "session-jti",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	}
	req = req.WithContext(ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()

	if !h.beginIdentityLink(rec, req, "oidc", "oidc:workforce") {
		t.Fatalf("link flow rejected: %d %s", rec.Code, rec.Body.String())
	}
	res := rec.Result()
	defer res.Body.Close()
	var flowCookie *http.Cookie
	for _, cookie := range res.Cookies() {
		if cookie.Name == identityLinkFlowCookie {
			flowCookie = cookie
			break
		}
	}
	if flowCookie == nil || !flowCookie.HttpOnly ||
		flowCookie.SameSite != http.SameSiteStrictMode || flowCookie.MaxAge != 600 {
		t.Fatalf("flow cookie = %#v", flowCookie)
	}
	raw, err := h.decryptCookieValue(flowCookie.Value)
	if err != nil {
		t.Fatalf("decrypt flow: %v", err)
	}
	var flow identityLinkFlow
	if err := json.Unmarshal(raw, &flow); err != nil {
		t.Fatalf("decode flow: %v", err)
	}
	if flow.UserID != 42 || flow.Kind != "oidc" ||
		flow.ProviderKey != "oidc:workforce" || flow.FlowID == "" ||
		flow.SessionJTI != "session-jti" || flow.SessionHash == "" ||
		flow.ExpiresAt <= time.Now().Unix() {
		t.Fatalf("unexpected bound flow: %#v", flow)
	}
}

func TestIdentityLinkCookieClear_DeletesRootPathCookieInCookieJar(t *testing.T) {
	h := &loginHandler{&deps{cookieKey: []byte("0123456789abcdef0123456789abcdef")}}
	h.identityLinkElevationBegin = func(context.Context, identityLinkFlow, []byte) error {
		return nil
	}
	claims := &token.Claims{
		UserID: 42,
		ACR:    jwtutil.ACRAAL2,
		JTI:    "session-jti",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	}
	flowURL, err := url.Parse("https://auth.example/auth/oidc/link")
	if err != nil {
		t.Fatal(err)
	}
	startReq := httptest.NewRequest(http.MethodGet, flowURL.String(), nil)
	startReq.AddCookie(&http.Cookie{Name: "access_token", Value: "session-token"})
	startReq = startReq.WithContext(ContextWithUser(startReq.Context(), claims))
	startRec := httptest.NewRecorder()
	if !h.beginIdentityLink(startRec, startReq, "oidc", "oidc:workforce") {
		t.Fatalf("link flow rejected: %d %s", startRec.Code, startRec.Body.String())
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("new cookie jar: %v", err)
	}
	jar.SetCookies(flowURL, startRec.Result().Cookies())
	if !cookieJarContains(jar, flowURL, identityLinkFlowCookie) {
		t.Fatal("identity-link flow cookie was not stored at Path=/")
	}

	callbackURL, err := url.Parse("https://auth.example/auth/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	clearReq := httptest.NewRequest(http.MethodGet, callbackURL.String(), nil)
	for _, cookie := range jar.Cookies(callbackURL) {
		clearReq.AddCookie(cookie)
	}
	clearRec := httptest.NewRecorder()
	if _, handled, valid := h.consumeIdentityLink(clearRec, clearReq, "oidc", "oidc:workforce"); !handled || valid {
		t.Fatalf("malformed identity-link flow handled=%v valid=%v, want true/false", handled, valid)
	}
	jar.SetCookies(callbackURL, clearRec.Result().Cookies())
	if cookieJarContains(jar, flowURL, identityLinkFlowCookie) {
		t.Fatal("identity-link flow cookie survived its deletion descriptor")
	}
}

func cookieJarContains(jar http.CookieJar, target *url.URL, name string) bool {
	for _, cookie := range jar.Cookies(target) {
		if cookie.Name == name {
			return true
		}
	}
	return false
}

func TestIdentityLinksRequiresAuthentication(t *testing.T) {
	h := &loginHandler{&deps{toggles: identityLinkTestFlags(true)}}
	rec := httptest.NewRecorder()
	h.IdentityLinks(rec, httptest.NewRequest(http.MethodGet, "/auth/identity-links", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestIdentityUnlinkRequiresFreshAAL2BeforeParsingTarget(t *testing.T) {
	h := &loginHandler{&deps{toggles: identityLinkTestFlags(true)}}
	req := httptest.NewRequest(http.MethodDelete, "/auth/identity-links/1",
		strings.NewReader(`{"reason":"retired provider"}`))
	rec := httptest.NewRecorder()
	h.IdentityUnlink(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestIdentityLinkSurfaceIsAbsentWhileMasterFlagOff(t *testing.T) {
	h := &loginHandler{&deps{toggles: identityLinkTestFlags(false)}}
	for _, tc := range []struct {
		name   string
		method string
		path   string
		call   func(http.ResponseWriter, *http.Request)
	}{
		{"oidc start", http.MethodPost, "/auth/oidc/link", h.OIDCLink},
		{"saml start", http.MethodPost, "/auth/saml/workforce/link", h.SAMLLink},
		{"inventory", http.MethodGet, "/auth/identity-links", h.IdentityLinks},
		{"unlink", http.MethodDelete, "/auth/identity-links/1", h.IdentityUnlink},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.call(rec, httptest.NewRequest(tc.method, tc.path, nil))
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404 while identity model is off",
					rec.Code)
			}
		})
	}
}

func TestFederatedCallbackClearsPendingLinkWhenMasterFlagTurnsOff(t *testing.T) {
	h := &loginHandler{&deps{
		toggles:   identityLinkTestFlags(false),
		cookieKey: []byte("0123456789abcdef0123456789abcdef"),
	}}
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)
	req.AddCookie(&http.Cookie{
		Name: identityLinkFlowCookie, Value: "previously-authorized-flow",
	})
	rec := httptest.NewRecorder()
	if !h.handleFederatedIdentityLink(rec, req, federatedIdentityLink{
		kind: "oidc", providerKey: "oidc:workforce",
	}) {
		t.Fatal("disabled pending link was not treated as a terminal attempt")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var cleared bool
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == identityLinkFlowCookie && cookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("disabled pending identity-link cookie was not cleared")
	}
}

func TestIdentityLinkStartsRejectUnknownProvidersAndUnavailableElevation(t *testing.T) {
	h := &loginHandler{&deps{
		toggles:   identityLinkTestFlags(true),
		cookieKey: []byte("0123456789abcdef0123456789abcdef"),
	}}
	oidcRec := httptest.NewRecorder()
	h.OIDCLink(oidcRec,
		httptest.NewRequest(http.MethodPost, "/auth/oidc/link?provider=missing", nil))
	if oidcRec.Code != http.StatusBadRequest {
		t.Fatalf("unknown OIDC provider status=%d body=%s",
			oidcRec.Code, oidcRec.Body.String())
	}
	samlReq := httptest.NewRequest(http.MethodPost, "/auth/saml/missing/link", nil)
	samlReq.SetPathValue("idp", "missing")
	samlRec := httptest.NewRecorder()
	h.SAMLLink(samlRec, samlReq)
	if samlRec.Code != http.StatusNotFound {
		t.Fatalf("unknown SAML registration status=%d body=%s",
			samlRec.Code, samlRec.Body.String())
	}

	h.identityLinkElevationBegin = func(
		context.Context, identityLinkFlow, []byte,
	) error {
		return context.Canceled
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/link", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "session-token"})
	req = req.WithContext(ContextWithUser(req.Context(), &token.Claims{
		UserID: 42,
		ACR:    jwtutil.ACRAAL2,
		JTI:    "session-jti",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	}))
	rec := httptest.NewRecorder()
	if h.beginIdentityLink(rec, req, "oidc", "oidc:workforce") {
		t.Fatal("link flow started after elevation persistence failed")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable elevation status=%d body=%s",
			rec.Code, rec.Body.String())
	}
}

func TestBeginIdentityLinkFailsClosedWhenFlowCookieCannotBeEncrypted(t *testing.T) {
	h := &loginHandler{&deps{cookieKey: []byte("short")}}
	h.identityLinkElevationBegin = func(
		context.Context, identityLinkFlow, []byte,
	) error {
		return nil
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/link", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "session-token"})
	req = req.WithContext(ContextWithUser(req.Context(), &token.Claims{
		UserID: 42,
		ACR:    jwtutil.ACRAAL2,
		JTI:    "session-jti",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	}))
	rec := httptest.NewRecorder()
	if h.beginIdentityLink(rec, req, "oidc", "oidc:workforce") {
		t.Fatal("link flow started without an encryptable flow cookie")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestConsumeIdentityLinkRejectsChangedTokenBeforeDatabaseAccess(t *testing.T) {
	jwtProvider := newTestJWT()
	h := &loginHandler{&deps{
		cookieKey: []byte("0123456789abcdef0123456789abcdef"),
		jwt:       jwtProvider,
	}}
	seal := func(flow identityLinkFlow) string {
		t.Helper()
		raw, err := json.Marshal(flow)
		if err != nil {
			t.Fatal(err)
		}
		value, err := h.encryptCookieValue(raw)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	access, err := jwtProvider.IssueAccess(42, "person@example.test", false)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(access))
	flow := identityLinkFlow{
		UserID: 42, Kind: "oidc", ProviderKey: "oidc:workforce",
		FlowID: "flow", SessionJTI: "session",
		SessionHash: hex.EncodeToString(sum[:]),
		ExpiresAt:   time.Now().Add(time.Minute).Unix(),
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)
	req.AddCookie(&http.Cookie{Name: identityLinkFlowCookie, Value: seal(flow)})
	req.AddCookie(&http.Cookie{Name: "access_token", Value: access})
	rec := httptest.NewRecorder()
	if _, attempted, valid := h.consumeIdentityLink(
		rec, req, "oidc", "oidc:workforce",
	); !attempted || valid || rec.Code != http.StatusForbidden {
		t.Fatalf("AAL1 flow attempted=%v valid=%v status=%d body=%s",
			attempted, valid, rec.Code, rec.Body.String())
	}

	flow.SessionHash = strings.Repeat("0", 64)
	req = httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)
	req.AddCookie(&http.Cookie{Name: identityLinkFlowCookie, Value: seal(flow)})
	req.AddCookie(&http.Cookie{Name: "access_token", Value: access})
	rec = httptest.NewRecorder()
	if _, attempted, valid := h.consumeIdentityLink(
		rec, req, "oidc", "oidc:workforce",
	); !attempted || valid || rec.Code != http.StatusForbidden {
		t.Fatalf("changed-token flow attempted=%v valid=%v status=%d body=%s",
			attempted, valid, rec.Code, rec.Body.String())
	}
}

func TestConsumeIdentityLinkCookieAndSessionFences(t *testing.T) {
	h := &loginHandler{&deps{
		cookieKey: []byte("0123456789abcdef0123456789abcdef"),
	}}
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)
	rec := httptest.NewRecorder()
	if _, attempted, valid := h.consumeIdentityLink(
		rec, req, "oidc", "oidc:workforce",
	); attempted || valid {
		t.Fatal("missing link cookie was treated as an attempted flow")
	}

	seal := func(flow identityLinkFlow) string {
		t.Helper()
		raw, err := json.Marshal(flow)
		if err != nil {
			t.Fatal(err)
		}
		value, err := h.encryptCookieValue(raw)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	validFlow := identityLinkFlow{
		UserID: 42, Kind: "oidc", ProviderKey: "oidc:workforce",
		FlowID: "flow", SessionJTI: "session",
		SessionHash: strings.Repeat("a", 64),
		ExpiresAt:   time.Now().Add(time.Minute).Unix(),
	}
	for name, flow := range map[string]identityLinkFlow{
		"kind mismatch": func() identityLinkFlow {
			value := validFlow
			value.Kind = "saml"
			return value
		}(),
		"expired": func() identityLinkFlow {
			value := validFlow
			value.ExpiresAt = time.Now().Add(-time.Minute).Unix()
			return value
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)
			req.AddCookie(&http.Cookie{
				Name: identityLinkFlowCookie, Value: seal(flow),
			})
			rec := httptest.NewRecorder()
			if _, attempted, valid := h.consumeIdentityLink(
				rec, req, "oidc", "oidc:workforce",
			); !attempted || valid || rec.Code != http.StatusBadRequest {
				t.Fatalf("flow fence attempted=%v valid=%v status=%d body=%s",
					attempted, valid, rec.Code, rec.Body.String())
			}
		})
	}

	req = httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)
	req.AddCookie(&http.Cookie{
		Name: identityLinkFlowCookie, Value: seal(validFlow),
	})
	rec = httptest.NewRecorder()
	if _, attempted, valid := h.consumeIdentityLink(
		rec, req, "oidc", "oidc:workforce",
	); !attempted || valid || rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing access token attempted=%v valid=%v status=%d body=%s",
			attempted, valid, rec.Code, rec.Body.String())
	}
}

func TestIdentityLinkInventoryAndUnlinkInputFailures(t *testing.T) {
	pool := openHandlerPool(t)
	pool.Close()
	h := &loginHandler{&deps{
		workerPool: pgxutil.WorkerPool{Pool: pool},
		toggles:    identityLinkTestFlags(true),
	}}
	claims := &token.Claims{
		UserID: 42,
		ACR:    jwtutil.ACRAAL2,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	}
	listReq := httptest.NewRequest(http.MethodGet, "/auth/identity-links", nil)
	listReq = listReq.WithContext(ContextWithUser(listReq.Context(), claims))
	listRec := httptest.NewRecorder()
	h.IdentityLinks(listRec, listReq)
	if listRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable identity link inventory status=%d body=%s",
			listRec.Code, listRec.Body.String())
	}

	unlinkReq := httptest.NewRequest(http.MethodDelete,
		"/auth/identity-links/not-an-id",
		strings.NewReader(`{"reason":"remove provider"}`))
	unlinkReq.SetPathValue("id", "not-an-id")
	unlinkReq = unlinkReq.WithContext(ContextWithUser(unlinkReq.Context(), claims))
	unlinkRec := httptest.NewRecorder()
	h.IdentityUnlink(unlinkRec, unlinkReq)
	if unlinkRec.Code != http.StatusBadRequest {
		t.Fatalf("invalid identity unlink status=%d body=%s",
			unlinkRec.Code, unlinkRec.Body.String())
	}
}

func TestIdentityUnlinkReturnsBoundedReducerFailureForMissingLink(t *testing.T) {
	pool := openHandlerPool(t)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
		Toggles: identityLinkTestFlags(true),
	})
	claims := &token.Claims{
		UserID: 9223372036854775807,
		ACR:    jwtutil.ACRAAL2,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	}
	req := httptest.NewRequest(http.MethodDelete, "/auth/identity-links/1",
		strings.NewReader(`{"reason":"remove retired provider"}`))
	req.SetPathValue("id", "1")
	req = req.WithContext(ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.IdentityUnlink(rec, req)
	if rec.Code < http.StatusBadRequest || rec.Code >= http.StatusInternalServerError {
		t.Fatalf("missing unlink status=%d body=%s",
			rec.Code, rec.Body.String())
	}
}
