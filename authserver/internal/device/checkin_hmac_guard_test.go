package device

// Non-owner-pairing and mounted-route guards for the live HMAC check-in
// endpoint (D-MAILSERVER-INTERNAL-MDM-002 retirement acceptance).
//
// checkin_auth_test.go proves the handler-level HMAC primitives (missing /
// wrong / cross-challenge HMAC, and the valid-HMAC 200 regression). This file
// closes the two remaining acceptance rows for the retirement:
//
//   - TestHandleCheckin_RejectsValidHMACFromNonOwnerDevice: an HMAC that is
//     itself cryptographically VALID — signed with the real secret of another
//     registered device owned by a DIFFERENT user — must not authenticate a
//     check-in for this device. Possession of any one device secret proves
//     only that device; the canonical challenge binds device_id, so a
//     non-owner device/user pairing cannot be transplanted (401).
//   - TestRegisterRoutes_CheckinRequiresDeviceHMAC: the route AS MOUNTED
//     (RegisterRoutes → RequireDeviceHMAC → HandleCheckin, auth.go:170)
//     rejects an unauthenticated check-in with 401 and admits a validly
//     signed one with 200 — the live POST /device/checkin regression.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"setjoin.com/shared/cryptokey"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/authserver/internal/token"
)

// registerOtherUserDevice inserts a device owned by a DIFFERENT user than
// notUserID and returns its ID and per-device HMAC secret. Cleans up at test
// end. Mirrors registerTestDevice (checkin_auth_test.go) with a second-user
// lookup so the non-owner pairing is a real cross-user pairing.
func registerOtherUserDevice(t *testing.T, pool *pgxpool.Pool, notUserID int64) (int64, string) {
	t.Helper()
	ctx := context.Background()

	var userID int64
	if err := pool.QueryRow(ctx,
		`SELECT MIN(id) FROM users WHERE id > $1`, notUserID,
	).Scan(&userID); err != nil || userID == 0 {
		t.Skip("no second user in test DB — skipping non-owner-pairing test")
	}

	fp := fmt.Sprintf("fp-checkin-hmac-guard-%d-%020d", userID, os.Getpid())
	reg, err := RegisterDevice(ctx, pool, userID, Identity{
		Fingerprint: fp,
		Platform:    "ios",
		OSVersion:   "17.0",
		AppVersion:  "1.0.0",
		DeviceName:  "checkin-hmac-guard-other-user",
	}, testSecretCodec())
	if err != nil {
		t.Fatalf("RegisterDevice (other user): %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM devices WHERE id = $1`, reg.ID)
	})
	if reg.HMACSecret == "" {
		t.Fatal("RegisterDevice returned an empty HMAC secret for the other-user device")
	}
	return reg.ID, reg.HMACSecret
}

// TestHandleCheckin_RejectsValidHMACFromNonOwnerDevice proves the non-owner
// pairing rejection: device B (owned by a different user) presents a CORRECTLY
// signed HMAC — B's real secret over the canonical challenge for device A —
// and device A's check-in still rejects it with 401. A valid HMAC from a
// device you own proves nothing about any other device.
func TestHandleCheckin_RejectsValidHMACFromNonOwnerDevice(t *testing.T) {
	pool := openDevicePool(t)
	deviceA, _ := registerTestDevice(t, pool)

	// The non-owner device must belong to a DIFFERENT user than device A.
	var ownerA int64
	if err := pool.QueryRow(context.Background(),
		`SELECT user_id FROM devices WHERE id = $1`, deviceA,
	).Scan(&ownerA); err != nil {
		t.Fatalf("load device A owner: %v", err)
	}
	deviceB, secretB := registerOtherUserDevice(t, pool, ownerA)
	if deviceB == deviceA {
		t.Fatal("non-owner device collided with device A — test setup invalid")
	}

	ts := time.Now().UTC().Format(time.RFC3339) // fresh: VerifyDeviceRequest enforces ±5min skew
	// Cryptographically valid HMAC — but from device B's secret over device A's
	// canonical request challenge: a non-owner device/user pairing.
	nonOwnerReq := checkinRequest(t, deviceA, "", "")
	signRequestProof(t, nonOwnerReq, secretB, deviceA, ts, "nonce-non-owner-pairing")

	h := HandleCheckin(pool, discardLogger(), testSecretCodec())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, nonOwnerReq)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("non-owner pairing: expected 401, got %d — body: %s", rec.Code, rec.Body.String())
	}
}

// TestRegisterRoutes_CheckinRequiresDeviceHMAC is the live-route regression:
// the endpoint exactly as mounted in production (RegisterRoutes, auth.go:170 —
// RequireDeviceHMAC in front of HandleCheckin) returns 401 without a device
// HMAC and 200 with a valid one. csrf is nil because the per-device HMAC
// routes are not cookie-authenticated (see RegisterRoutes doc).
func TestRegisterRoutes_CheckinRequiresDeviceHMAC(t *testing.T) {
	pool := openDevicePool(t)
	deviceID, secret := registerTestDevice(t, pool)

	jwt := newRouteGuardJWTProvider(t)
	mux := http.NewServeMux()
	RegisterRoutes(mux, pool, jwt, discardLogger(), testSecretCodec(), nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Without any HMAC headers → 401 from RequireDeviceHMAC.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/device/checkin",
		bytes.NewReader([]byte(fmt.Sprintf(`{"device_id":%d,"policy_version":0}`, deviceID))))
	req.Header.Set("Content-Type", "application/json")
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /device/checkin (no HMAC): %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("mounted route without HMAC: expected 401, got %d", res.StatusCode)
	}

	// With a valid per-device HMAC over a fresh full request challenge → 200
	// (the mounted RequireDeviceHMAC guard now also consumes the single-use
	// nonce deployment-wide, med-shard2-006).
	ts := time.Now().UTC().Format(time.RFC3339)
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/device/checkin",
		bytes.NewReader([]byte(fmt.Sprintf(`{"device_id":%d,"policy_version":0}`, deviceID))))
	req.Header.Set("Content-Type", "application/json")
	guardBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read guard body: %v", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(guardBody))
	guardSum := sha256.Sum256(guardBody)
	guardBodyHash := hex.EncodeToString(guardSum[:])
	guardNonce := fmt.Sprintf("nonce-route-guard-%d-%d", os.Getpid(), time.Now().UnixNano())
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderNonce, guardNonce)
	req.Header.Set(HeaderBodyHash, guardBodyHash)
	req.Header.Set(HeaderHMAC, signChallenge(secret,
		challengeForRequest(deviceID, ts, req.Method, req.URL.RequestURI(), guardBodyHash, guardNonce)))
	res, err = srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /device/checkin (valid HMAC): %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("mounted route with valid HMAC: expected 200, got %d", res.StatusCode)
	}
}

// newRouteGuardJWTProvider builds the provider RegisterRoutes needs for its
// /device/register bootstrap route. The checkin route under test never
// validates a bearer token, but RegisterRoutes requires a non-nil provider
// (RequireUserAuth closes over it when mounting the route).
func newRouteGuardJWTProvider(t *testing.T) *token.JWTProvider {
	t.Helper()
	return token.NewJWTProvider(
		"device-route-guard-test-secret-ok",
		nil,
		cryptokey.ProfileStandard,
		time.Hour,
		720*time.Hour,
		"device-route-guard-test-issuer",
	)
}
