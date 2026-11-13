package ws

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/threat"
)

func mintPushAccessToken(t *testing.T, userID int64, jti, familyID string) (string, time.Time) {
	t.Helper()
	now := time.Now().UTC().Add(-time.Second)
	claims := &jwtutil.Claims{
		UserID:   userID,
		Email:    "push@example.com",
		Type:     jwtutil.TypeAccess,
		JTI:      jti,
		FamilyID: familyID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    scopeGuardIssuer,
			Audience:  jwt.ClaimStrings{"mailserver-gateway"},
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = "authserver-hmac-1"
	signed, err := token.SignedString([]byte(scopeGuardSecret))
	if err != nil {
		t.Fatalf("sign push access token: %v", err)
	}
	return signed, now
}

func TestPushHandshakesRejectRevokedAccessToken(t *testing.T) {
	t.Parallel()
	const (
		userID   = int64(71)
		jti      = "push-jti"
		familyID = "push-family"
	)
	token, issuedAt := mintPushAccessToken(t, userID, jti, familyID)

	tests := []struct {
		name string
		row  threat.RevocationRow
	}{
		{
			name: "all",
			row: threat.RevocationRow{
				UserID: userID, Scope: threat.ScopeAll, NotBefore: issuedAt.Add(time.Second),
			},
		},
		{
			name: "jti",
			row: threat.RevocationRow{
				UserID: userID, Scope: threat.ScopeJTI, JTI: jti, NotBefore: issuedAt.Add(time.Second),
			},
		},
		{
			name: "family",
			row: threat.RevocationRow{
				UserID: userID, Scope: threat.ScopeFamily, FamilyID: familyID, NotBefore: issuedAt.Add(time.Second),
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			denylist := threat.NewSessionDenylist(nil, slog.Default())
			denylist.Apply(tc.row)

			handler := NewHandler(nil, auth.NewChainWithJWT(
				auth.NewJWTProvider(scopeGuardSecret, nil, scopeGuardIssuer),
			), nil, slog.Default(), false)
			handler.SetDenylist(denylist)
			handler.SetSessionRegistry(threat.NewProtocolSessionRegistry())

			t.Run("websocket", func(t *testing.T) {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "/jmap/ws", nil)
				req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
				handler.Upgrade(rec, req)
				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("revoked WS handshake status = %d, want 401", rec.Code)
				}
			})

			t.Run("eventsource", func(t *testing.T) {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "/jmap/eventsource", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				handler.EventSource(rec, req)
				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("revoked SSE handshake status = %d, want 401", rec.Code)
				}
			})
		})
	}
}

func TestPushDenylistAllowsUnrevokedAccessToken(t *testing.T) {
	t.Parallel()
	_, issuedAt := mintPushAccessToken(t, 81, "clean-jti", "clean-family")
	claims := &jwtutil.Claims{
		UserID:   81,
		JTI:      "clean-jti",
		FamilyID: "clean-family",
	}
	claims.IssuedAt = jwt.NewNumericDate(issuedAt)

	denylist := threat.NewSessionDenylist(func(context.Context) ([]threat.RevocationRow, error) {
		return []threat.RevocationRow{{
			UserID: 82, Scope: threat.ScopeAll, NotBefore: issuedAt.Add(time.Second),
		}}, nil
	}, slog.Default())
	if err := denylist.Refresh(context.Background()); err != nil {
		t.Fatalf("load denylist: %v", err)
	}
	if deny, shouldClose := denylistDecision(denylist, claims); deny || shouldClose {
		t.Fatalf("unrevoked access token denied: deny=%v shouldClose=%v", deny, shouldClose)
	}
}
