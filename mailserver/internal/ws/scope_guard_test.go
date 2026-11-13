package ws

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/jwtutil"
)

// scopeGuardSecret/Issuer mint AND validate through the same provider, so only
// internal consistency matters (mirrors the auth package's test values).
const (
	scopeGuardSecret = "super-secret-32-byte-key-for-tests!"
	scopeGuardIssuer = "mailserver"
)

// mintScopedDriveToken returns a valid HS256 access token carrying Scp:"drive"
// (the Drive P1 native-token bridge) plus the provider that validates it.
func mintScopedDriveToken(t *testing.T) (token string, chain *auth.Chain) {
	t.Helper()
	prov := auth.NewJWTProvider(scopeGuardSecret, nil, scopeGuardIssuer)
	base := &jwtutil.Claims{UserID: 7, Email: "u@example.com", JTI: "j1", FamilyID: "f1"}
	tok, _, err := prov.IssueDriveNativeToken(base, "drive", time.Hour)
	if err != nil {
		t.Fatalf("IssueDriveNativeToken: %v", err)
	}
	return tok, auth.NewChainWithJWT(prov)
}

// A drive-scoped mirror token must NOT open a mailbox push stream: EventSource
// validates the JWT directly (bypassing chain.AuthenticateRequest's scope
// guard), so it re-enforces the guard itself. Without the fix a leaked 12h
// on-disk drive token would authenticate a full JMAP StateChange feed.
func TestEventSource_RejectsScopedDriveToken(t *testing.T) {
	tok, chain := mintScopedDriveToken(t)
	h := NewHandler(nil, chain, nil, slog.Default(), false)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/jmap/eventsource", nil)
	req.Header.Set("Authorization", "Bearer "+tok) // Bearer path skips the origin pin
	h.EventSource(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("scoped drive token on EventSource = %d, want 401", rec.Code)
	}
}

// Same containment on the WebSocket handshake: Upgrade validates the cookie
// token directly, so it must reject a scoped token before the upgrade — else a
// drive token opens full JMAP read/write over WS.
func TestWSUpgrade_RejectsScopedDriveToken(t *testing.T) {
	tok, chain := mintScopedDriveToken(t)
	h := NewHandler(nil, chain, nil, slog.Default(), false)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/jmap/ws", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: tok})
	h.Upgrade(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("scoped drive token on WS Upgrade = %d, want 401", rec.Code)
	}
}
