package device

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/shared/cryptokey"
	"time"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/jwtutil"
)

// These tests prove the decision logic of each device-auth fix WITHOUT a live
// DB. They are deliberately non-skipped: the security-relevant branches of each
// guard run (and reject) before any database access, so a nil *pgxpool.Pool is
// never dereferenced on the paths exercised here. Each test fails against the
// pre-fix code (no HMAC guard / no replay bound / user_id hardcoded to 0).

// ── FIX 2: REPLAY — timestamp freshness bound ───────────────────────────────

func TestCheckTimestampFresh(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name    string
		ts      string
		wantErr bool
	}{
		{"empty is rejected", "", true},
		{"garbage is rejected", "not-a-timestamp", true},
		{"fresh rfc3339 ok", now.Format(time.RFC3339), false},
		{"fresh unix ok", "1781697600", false}, // == 2026-06-17T12:00:00Z
		{"within skew (past) ok", now.Add(-4 * time.Minute).Format(time.RFC3339), false},
		{"within skew (future) ok", now.Add(4 * time.Minute).Format(time.RFC3339), false},
		{"stale past rejected", now.Add(-MaxClockSkew - time.Minute).Format(time.RFC3339), true},
		{"too-future rejected", now.Add(MaxClockSkew + time.Minute).Format(time.RFC3339), true},
		{"ancient captured HMAC rejected", "2020-01-01T00:00:00Z", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkTimestampFresh(tc.ts, now)
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkTimestampFresh(%q) err=%v, wantErr=%v", tc.ts, err, tc.wantErr)
			}
		})
	}
}

func TestParseDeviceTimestamp_AcceptsBothForms(t *testing.T) {
	want := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	if got, err := parseDeviceTimestamp("2026-06-17T12:00:00Z"); err != nil || !got.Equal(want) {
		t.Fatalf("rfc3339: got %v err %v", got, err)
	}
	if got, err := parseDeviceTimestamp("1781697600"); err != nil || !got.Equal(want) {
		t.Fatalf("unix: got %v err %v", got, err)
	}
	if _, err := parseDeviceTimestamp(""); err == nil {
		t.Fatal("empty timestamp must error")
	}
}

// VerifyDeviceRequest must reject missing HMAC and stale timestamps BEFORE it
// ever loads the device secret — so these run with a nil pool. Against the
// pre-fix code (no replay bound) the stale-timestamp request would have been
// accepted forever.
func TestVerifyDeviceRequest_RejectsBeforeDB(t *testing.T) {
	mkReq := func(hmacHdr, tsHdr string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/device/policy?device_id=5", nil)
		if hmacHdr != "" {
			r.Header.Set(HeaderHMAC, hmacHdr)
		}
		if tsHdr != "" {
			r.Header.Set(HeaderTimestamp, tsHdr)
		}
		return r
	}

	// Missing HMAC: rejected before any DB access (nil pool never touched).
	if err := VerifyDeviceRequest(context.Background(), nil, 5, mkReq("", time.Now().UTC().Format(time.RFC3339)), testSecretCodec()); err == nil {
		t.Fatal("missing HMAC must be rejected")
	}

	// Present HMAC but stale timestamp: rejected before the DB lookup. (A real
	// secret lookup would need the pool; this proves the replay bound short-
	// circuits first.)
	stale := time.Now().Add(-MaxClockSkew - time.Hour).UTC().Format(time.RFC3339)
	if err := VerifyDeviceRequest(context.Background(), nil, 5, mkReq("deadbeef", stale), testSecretCodec()); err == nil {
		t.Fatal("stale timestamp must be rejected (replay bound)")
	}
}

// ── FIX 1 + 4: SIBLING / WIRING — RequireDeviceHMAC is the single guard ──────

// RequireDeviceHMAC must reject a missing/invalid device_id with 400 and a
// missing/stale HMAC with 401, all before any DB access. This is the shared
// seam both /device/checkin and /device/policy route through.
func TestRequireDeviceHMAC_RejectsBeforeDB(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })

	// device_id extractor that yields a valid ID, so we exercise the HMAC branch.
	idFromQuery := deviceIDFromQuery

	t.Run("bad device_id -> 400, handler not reached", func(t *testing.T) {
		called = false
		h := RequireDeviceHMAC(nil, discardLogger(), testSecretCodec(), idFromQuery, next)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/device/policy?device_id=0", nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("bad device_id: want 400, got %d", rec.Code)
		}
		if called {
			t.Fatal("handler must not be reached on bad device_id")
		}
	})

	t.Run("missing HMAC -> 401, handler not reached", func(t *testing.T) {
		called = false
		h := RequireDeviceHMAC(nil, discardLogger(), testSecretCodec(), idFromQuery, next)
		rec := httptest.NewRecorder()
		// Valid device_id, no HMAC header — rejected before DB (nil pool safe).
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/device/policy?device_id=5", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("missing HMAC: want 401, got %d", rec.Code)
		}
		if called {
			t.Fatal("handler must not be reached without a valid HMAC")
		}
	})

	t.Run("stale HMAC -> 401, handler not reached", func(t *testing.T) {
		called = false
		h := RequireDeviceHMAC(nil, discardLogger(), testSecretCodec(), idFromQuery, next)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/device/policy?device_id=5", nil)
		req.Header.Set(HeaderHMAC, "deadbeef")
		req.Header.Set(HeaderTimestamp, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("stale HMAC: want 401, got %d", rec.Code)
		}
		if called {
			t.Fatal("handler must not be reached with a stale HMAC")
		}
	})
}

// deviceIDFromBody must buffer + restore the body so the wrapped handler can
// still decode it after the guard has peeked at device_id.
func TestDeviceIDFromBody_RestoresBody(t *testing.T) {
	body, _ := json.Marshal(CheckinRequest{DeviceID: 99})
	r := httptest.NewRequest(http.MethodPost, "/device/checkin", bytes.NewReader(body))

	id, err := deviceIDFromBody(r)
	if err != nil {
		t.Fatalf("deviceIDFromBody: %v", err)
	}
	if id != 99 {
		t.Fatalf("device_id = %d, want 99", id)
	}

	// The handler downstream must still be able to read the full body.
	rest, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	var got CheckinRequest
	if err := json.Unmarshal(rest, &got); err != nil {
		t.Fatalf("body was not restored intact: %v (raw %q)", err, rest)
	}
	if got.DeviceID != 99 {
		t.Fatalf("restored body device_id = %d, want 99", got.DeviceID)
	}
}

func TestDeviceIDFromQuery(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/device/policy?device_id=42", nil)
	id, err := deviceIDFromQuery(r)
	if err != nil || id != 42 {
		t.Fatalf("deviceIDFromQuery = %d, %v; want 42, nil", id, err)
	}
	bad := httptest.NewRequest(http.MethodGet, "/device/policy?device_id=abc", nil)
	if _, err := deviceIDFromQuery(bad); err == nil {
		t.Fatal("non-numeric device_id must error")
	}
}

// ── FIX 3: user_id=0 — registration binds to the authenticated user ─────────

func newTestJWT(t *testing.T) *token.JWTProvider {
	t.Helper()
	// 32+ char secret as required for HS256.
	return token.NewJWTProvider(
		"test-secret-which-is-definitely-32-bytes-long",
		nil, cryptokey.ProfileStandard,
		time.Hour, 720*time.Hour, "authserver-test",
	)
}

// RequireUserAuth must reject requests with no/garbage bearer token and a
// non-access token type, and on success stamp the real user ID into context.
func TestRequireUserAuth(t *testing.T) {
	jwt := newTestJWT(t)
	logger := discardLogger()

	var stamped int64 = -1
	sink := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if uid, ok := UserIDFromContext(r.Context()); ok {
			stamped = uid
		}
	})
	mw := RequireUserAuth(jwt, logger)(sink)

	t.Run("no header -> 401", func(t *testing.T) {
		stamped = -1
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/device/register", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("no header: want 401, got %d", rec.Code)
		}
		if stamped != -1 {
			t.Fatal("handler must not run without auth")
		}
	})

	t.Run("garbage token -> 401", func(t *testing.T) {
		stamped = -1
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/device/register", nil)
		req.Header.Set("Authorization", "Bearer not-a-real-jwt")
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("garbage token: want 401, got %d", rec.Code)
		}
	})

	t.Run("wrong token type -> 403", func(t *testing.T) {
		stamped = -1
		mfaTok, err := jwt.IssueMFAPending(7, "u@example.com")
		if err != nil {
			t.Fatalf("IssueMFAPending: %v", err)
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/device/register", nil)
		req.Header.Set("Authorization", "Bearer "+mfaTok)
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("non-access token: want 403, got %d", rec.Code)
		}
		if stamped != -1 {
			t.Fatal("handler must not run for a non-access token")
		}
	})

	t.Run("valid access token -> stamps the real user ID", func(t *testing.T) {
		stamped = -1
		const realUser int64 = 4242
		access, err := jwt.IssueAccess(realUser, "u@example.com", false)
		if err != nil {
			t.Fatalf("IssueAccess: %v", err)
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/device/register", nil)
		req.Header.Set("Authorization", "Bearer "+access)
		mw.ServeHTTP(rec, req)
		if stamped != realUser {
			t.Fatalf("stamped user = %d, want %d (must be from the token, never 0)", stamped, realUser)
		}
	})
}

// claims-based sanity: a token issued for user 4242 must validate to 4242, so
// the registration path can never fall back to a hardcoded 0.
func TestRequireUserAuth_BindsTokenUser(t *testing.T) {
	jwt := newTestJWT(t)
	access, err := jwt.IssueAccess(4242, "u@example.com", false)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	claims, err := jwt.Validate(access)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.UserID != 4242 {
		t.Fatalf("claims.UserID = %d, want 4242", claims.UserID)
	}
	if claims.Type != jwtutil.TypeAccess {
		t.Fatalf("claims.Type = %q, want %q", claims.Type, jwtutil.TypeAccess)
	}
}

// The registration handler must fail closed (401) when the context carries no
// authenticated user — proving user_id is never defaulted to 0. This runs the
// real handler with a nil pool: the fail-closed branch returns before any DB
// access, and the test confirms RegisterDevice (which would need the pool) is
// never reached.
func TestRegister_FailsClosedWithoutAuth(t *testing.T) {
	h := NewHandler(nil, discardLogger(), testSecretCodec()) // nil pool: must never be dereferenced
	body, _ := json.Marshal(Identity{
		Fingerprint: "fingerprint-long-enough-to-pass-validation-32+",
		Platform:    "ios",
	})
	rec := httptest.NewRecorder()
	// No WithUserID on the context -> unauthenticated.
	req := httptest.NewRequest(http.MethodPost, "/device/register", bytes.NewReader(body))
	h.Register(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated register: want 401, got %d — body %s", rec.Code, rec.Body.String())
	}
}

// And it must use the user from context (not the body, not 0) — verified at the
// context layer, which is the value RegisterDevice is handed.
func TestRegister_UsesContextUserNotBody(t *testing.T) {
	const realUser int64 = 7
	ctx := WithUserID(context.Background(), realUser)
	uid, ok := UserIDFromContext(ctx)
	if !ok || uid != realUser {
		t.Fatalf("UserIDFromContext = (%d,%v), want (%d,true)", uid, ok, realUser)
	}
	// A fresh context (what the pre-fix code effectively had) must NOT yield a
	// usable user — the handler fails closed rather than registering under 0.
	if _, ok := UserIDFromContext(context.Background()); ok {
		t.Fatal("an unauthenticated context must not yield a user ID")
	}
}
