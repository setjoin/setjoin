package drive_test

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/drive"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/toggle"
)

// TestMintNativeToken covers the mint + sliding-renewal shape (batch-3 item
// 6): the drive package's own responsibility is "authenticated request in,
// scoped JWT with the SAME jti/family out" — the auth chain's own decode/
// accept behavior (cookie vs Bearer, the scope-containment guard) is proven
// separately in internal/auth/chain_test.go
// (TestAuthenticateRequestAcceptsScopedTokenOnItsSurface /
// TestAuthenticateRequestRejectsScopedTokenOffSurface), so this test starts
// from an already-authenticated context exactly like requireAuth would leave
// it, regardless of which credential produced it.
func TestMintNativeToken(t *testing.T) {
	jwtProv := auth.NewJWTProvider("test-secret-32-bytes-long-enough!!", nil, "mailserver")
	h := drive.NewHandler(nil, nil, nil, "", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), slog.Default())
	h.SetJWTProvider(jwtProv)

	// Simulate an authenticated web session (cookie or Bearer — indistinguishable
	// by the time requireAuth has resolved Claims).
	session := &auth.Claims{UserID: 42, JTI: "session-jti-abc", FamilyID: "family-xyz"}
	req := httptest.NewRequest(http.MethodPost, "/drive/native-token", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), session))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("mint: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expiresAt"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || out.Token == "" || out.ExpiresAt == "" {
		t.Fatalf("decode mint response: err=%v body=%s", err, rr.Body.String())
	}

	minted, err := jwtProv.Validate(out.Token)
	if err != nil {
		t.Fatalf("the gateway must validate its own minted drive-native token: %v", err)
	}
	if minted.UserID != 42 {
		t.Errorf("UserID = %d, want 42", minted.UserID)
	}
	if minted.Scp != "drive" {
		t.Errorf("Scp = %q, want drive", minted.Scp)
	}
	if minted.JTI != session.JTI || minted.FamilyID != session.FamilyID {
		t.Errorf("jti/family = %q/%q, want carried forward from the session (%q/%q) — revocation-with-session",
			minted.JTI, minted.FamilyID, session.JTI, session.FamilyID)
	}
	if minted.Cnf != nil {
		t.Error("a minted drive-native token must stay unbound (no cnf) — skips the DPoP branch")
	}

	// Sliding renewal: re-POST using the FIRST minted token's OWN decoded
	// claims as the caller (exactly what the auth chain leaves in context for
	// a Bearer request carrying that token) — jti/family must propagate
	// UNCHANGED again, never re-derived from the renewal request itself, so a
	// chain of renewals never outlives the original session's revocation.
	req2 := httptest.NewRequest(http.MethodPost, "/drive/native-token", nil)
	req2 = req2.WithContext(auth.ContextWithUser(req2.Context(), minted))
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("renew: want 200, got %d: %s", rr2.Code, rr2.Body.String())
	}
	var out2 struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rr2.Body.Bytes(), &out2); err != nil {
		t.Fatalf("decode renew response: %v", err)
	}
	renewed, err := jwtProv.Validate(out2.Token)
	if err != nil {
		t.Fatalf("validate renewed token: %v", err)
	}
	if renewed.JTI != session.JTI || renewed.FamilyID != session.FamilyID {
		t.Errorf("renewal jti/family = %q/%q, want unchanged from the original session (%q/%q)",
			renewed.JTI, renewed.FamilyID, session.JTI, session.FamilyID)
	}
}

// TestMintNativeTokenCapsExpiryAtSourceSession (er5-s11, sealed anchor
// cand-drive-token-renewal): a derived mirror must never outlive its source
// session. A session with 30 minutes of policy-limited life left gets a
// mirror that dies WITH the session — not a fresh 12h credential. JTI/Family
// still propagate (revocation-with-session unchanged).
func TestMintNativeTokenCapsExpiryAtSourceSession(t *testing.T) {
	jwtProv := auth.NewJWTProvider("test-secret-32-bytes-long-enough!!", nil, "mailserver")
	h := drive.NewHandler(nil, nil, nil, "", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), slog.Default())
	h.SetJWTProvider(jwtProv)

	session := &auth.Claims{
		UserID: 7, JTI: "short-session-jti", FamilyID: "short-session-family",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/drive/native-token", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), session))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("mint: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expiresAt"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode mint response: %v", err)
	}
	minted, err := jwtProv.Validate(out.Token)
	if err != nil {
		t.Fatalf("validate minted token: %v", err)
	}
	if minted.ExpiresAt == nil {
		t.Fatal("minted token carries no expiry")
	}
	if !minted.ExpiresAt.Time.Before(time.Now().Add(12 * time.Hour)) {
		t.Errorf("minted mirror outlives the 12h TTL ceiling: %v", minted.ExpiresAt.Time)
	}
	if minted.ExpiresAt.Time.After(session.ExpiresAt.Time.Add(5 * time.Second)) {
		t.Errorf("minted mirror expires %v, after the source session's expiry %v — the clamp failed",
			minted.ExpiresAt.Time, session.ExpiresAt.Time)
	}
	if minted.JTI != session.JTI || minted.FamilyID != session.FamilyID {
		t.Errorf("clamped mint must still carry the source jti/family, got %q/%q", minted.JTI, minted.FamilyID)
	}

	// A long-lived source session (no near expiry) still gets the full TTL —
	// the clamp only shortens, never extends.
	longSession := &auth.Claims{
		UserID: 7, JTI: "long-session-jti", FamilyID: "long-session-family",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
		},
	}
	req2 := httptest.NewRequest(http.MethodPost, "/drive/native-token", nil)
	req2 = req2.WithContext(auth.ContextWithUser(req2.Context(), longSession))
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("mint (long session): want 200, got %d", rr2.Code)
	}
	var out2 struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rr2.Body.Bytes(), &out2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	long, err := jwtProv.Validate(out2.Token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if long.ExpiresAt == nil || !long.ExpiresAt.Time.After(time.Now().Add(11*time.Hour+50*time.Minute)) {
		t.Errorf("long-lived session should get ~the full 12h TTL, got %v", long.ExpiresAt)
	}
}

// TestMintNativeTokenRefusesDeviceBoundSession (er5-s11): IssueDriveNativeToken
// drops the Device claim, so a device-bound (MAM) session minting a mirror
// would shed its device constraint onto a /drive/* credential. The mint must
// fail closed (403, no token), not mint the uncontained credential.
func TestMintNativeTokenRefusesDeviceBoundSession(t *testing.T) {
	jwtProv := auth.NewJWTProvider("test-secret-32-bytes-long-enough!!", nil, "mailserver")
	h := drive.NewHandler(nil, nil, nil, "", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), slog.Default())
	h.SetJWTProvider(jwtProv)

	session := &auth.Claims{
		UserID: 9, JTI: "mam-session-jti", FamilyID: "mam-session-family",
		Device: &jwtutil.DeviceClaim{ID: "device-fingerprint", Platform: "desktop"},
	}
	req := httptest.NewRequest(http.MethodPost, "/drive/native-token", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), session))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("device-bound mint: want 403, got %d: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `"token"`) {
		t.Errorf("refusal must not carry a token, got %s", rr.Body.String())
	}
}

// TestMintNativeTokenToggleOff pins G5: feature.drive OFF -> 404, same as
// every other drive route (never a distinct code path for this endpoint).
func TestMintNativeTokenToggleOff(t *testing.T) {
	h := drive.NewHandler(nil, nil, nil, "", toggle.NewTestFlags(map[string]bool{"feature.drive": false}), slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/drive/native-token", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("want 404 while feature.drive OFF, got %d", rr.Code)
	}
}

// TestMintNativeTokenRequiresAuth pins that an unauthenticated POST 401s
// before ever reaching the JWT provider (same G5-then-auth gate as every
// other drive route — ServeHTTP's ordering, not a per-route special case).
func TestMintNativeTokenRequiresAuth(t *testing.T) {
	h := drive.NewHandler(nil, nil, nil, "", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/drive/native-token", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("want 401 without claims, got %d", rr.Code)
	}
}

// TestMintNativeTokenNoProviderConfigured pins the defensive 500 (not a
// panic) when SetJWTProvider was never called.
func TestMintNativeTokenNoProviderConfigured(t *testing.T) {
	h := drive.NewHandler(nil, nil, nil, "", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/drive/native-token", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("want 500 when no JWTProvider is wired, got %d", rr.Code)
	}
}
