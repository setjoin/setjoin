package device

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"setjoin.com/shared/cryptokey"
	shareddevice "setjoin.com/shared/device"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
)

// signChallenge produces the hex HMAC-SHA256 a real client would send in the
// X-Device-HMAC header for a given device secret + challenge.
func signChallenge(secret, challenge string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(challenge))
	return hex.EncodeToString(mac.Sum(nil))
}

// signRequestProof sets the full device-proof headers on req exactly the way a
// remediated client must (med-shard2-006): X-Device-Timestamp, a fresh
// X-Device-Nonce, the X-Device-Body-SHA256 of the exact body bytes, and
// X-Device-HMAC over the canonical request challenge (deviceID, ts, method,
// request URI, body hash, nonce) keyed with secret. proofDeviceID is the
// device id bound INTO the challenge — normally the request's own device, set
// to a different id to prove a cross-device/cross-challenge proof is rejected.
func signRequestProof(t *testing.T, req *http.Request, secret string, proofDeviceID int64, ts, nonce string) {
	t.Helper()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	sum := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(sum[:])
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderBodyHash, bodyHash)
	req.Header.Set(HeaderHMAC, signChallenge(secret,
		challengeForRequest(proofDeviceID, ts, req.Method, req.URL.RequestURI(), bodyHash, nonce)))
}

// testSecretCodec seals/opens device HMAC secrets for the _enc storage tests
// (med-auth-baseline-secrets-001). Test-only master key material.
func testSecretCodec() *shareddevice.SecretCodec {
	return shareddevice.NewSecretCodec([]byte("device-test-master-secret-key"), cryptokey.ProfileStandard)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ── Pure unit coverage of the HMAC verification primitives (no DB) ──────────

func TestChallengeFor_BindsDeviceAndTimestamp(t *testing.T) {
	// Different device IDs (or timestamps) must produce different challenges so
	// an HMAC captured for one device can't be reused for another.
	if challengeFor(1, "ts") == challengeFor(2, "ts") {
		t.Error("challenge must differ across device IDs")
	}
	if challengeFor(1, "a") == challengeFor(1, "b") {
		t.Error("challenge must differ across timestamps")
	}
	if got, want := challengeFor(42, "2026-06-17T00:00:00Z"), "42:2026-06-17T00:00:00Z"; got != want {
		t.Errorf("challengeFor = %q, want %q", got, want)
	}
}

func TestValidateHMAC_MatchAndMismatch(t *testing.T) {
	secret := "00112233445566778899aabbccddeeff"
	challenge := challengeFor(7, "ts")
	good := signChallenge(secret, challenge)

	if !ValidateHMAC(secret, challenge, good) {
		t.Error("ValidateHMAC should accept a correctly-signed HMAC")
	}
	if ValidateHMAC(secret, challenge, "") {
		t.Error("ValidateHMAC must reject an empty HMAC")
	}
	if ValidateHMAC(secret, challenge, good[:len(good)-1]+"0") {
		t.Error("ValidateHMAC must reject a tampered HMAC")
	}
	if ValidateHMAC("wrong-secret", challenge, good) {
		t.Error("ValidateHMAC must reject an HMAC signed with the wrong secret")
	}
}

// ── DB-backed handler coverage: the actual security hole ────────────────────

// openDevicePool returns a real pool; skips if DB_DSN is not set.
func openDevicePool(t *testing.T) *pgxpool.Pool {
	return testsupport.OpenTestPool(t)
}

// registerTestDevice inserts a device for an existing user and returns its ID
// and per-device HMAC secret. When the test DB has no users at all (freshly
// loaded schema), it seeds one so REQUIRE_DB runs exercise the real handler
// instead of silently skipping — a skip never counts as a pass.
func registerTestDevice(t *testing.T, pool *pgxpool.Pool) (int64, string) {
	t.Helper()
	ctx := context.Background()

	var userID int64
	if err := pool.QueryRow(ctx, `SELECT MIN(id) FROM users`).Scan(&userID); err != nil || userID == 0 {
		seeded, serr := insertTestUser(ctx, pool,
			fmt.Sprintf("checkin-auth-seed-%d-%d@device.test", os.Getpid(), time.Now().UnixNano()))
		if serr != nil {
			t.Fatalf("seed fixture user: %v", serr)
		}
		userID = seeded
		// Registered BEFORE the device cleanup below so LIFO deletes the device
		// row (which references this user) first.
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, seeded)
		})
	}

	// A fingerprint long enough to satisfy ValidateFingerprint (>= 32 chars),
	// made unique so reruns don't collide on UNIQUE(user_id, fingerprint).
	fp := fmt.Sprintf("fp-checkin-auth-test-%d-%020d", userID, os.Getpid())
	reg, err := RegisterDevice(ctx, pool, userID, Identity{
		Fingerprint: fp,
		Platform:    "ios",
		OSVersion:   "17.0",
		AppVersion:  "1.0.0",
		DeviceName:  "checkin-auth-test",
	}, testSecretCodec())
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM devices WHERE id = $1`, reg.ID)
	})
	if reg.HMACSecret == "" {
		t.Fatal("RegisterDevice returned an empty HMAC secret")
	}
	return reg.ID, reg.HMACSecret
}

func checkinRequest(t *testing.T, deviceID int64, hmacHdr, tsHdr string) *http.Request {
	t.Helper()
	body, _ := json.Marshal(CheckinRequest{DeviceID: deviceID})
	req := httptest.NewRequest(http.MethodPost, "/device/checkin", bytes.NewReader(body))
	if hmacHdr != "" {
		req.Header.Set(HeaderHMAC, hmacHdr)
	}
	if tsHdr != "" {
		req.Header.Set(HeaderTimestamp, tsHdr)
	}
	return req
}

// TestHandleCheckin_RejectsMissingHMAC proves the closed hole: a checkin that
// presents NO device HMAC is rejected with 401. (Against the pre-fix code this
// returned 200 — device_id was spoofable.)
func TestHandleCheckin_RejectsMissingHMAC(t *testing.T) {
	pool := openDevicePool(t)
	deviceID, _ := registerTestDevice(t, pool)

	h := HandleCheckin(pool, discardLogger(), testSecretCodec())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, checkinRequest(t, deviceID, "", "ts"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing HMAC: expected 401, got %d — body: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleCheckin_RejectsWrongHMAC proves a forged/incorrect HMAC for a real
// device ID is rejected with 401 (spoofing another device is blocked).
func TestHandleCheckin_RejectsWrongHMAC(t *testing.T) {
	pool := openDevicePool(t)
	deviceID, _ := registerTestDevice(t, pool)

	req := checkinRequest(t, deviceID, "", "")
	// Proof signed with the wrong secret over the full request challenge.
	signRequestProof(t, req, "not-the-device-secret", deviceID,
		time.Now().UTC().Format(time.RFC3339), "nonce-wrong-secret")

	h := HandleCheckin(pool, discardLogger(), testSecretCodec())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong HMAC: expected 401, got %d — body: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleCheckin_RejectsHMACForDifferentDevice proves an HMAC validly signed
// over a *different* device's challenge cannot be replayed for this device.
func TestHandleCheckin_RejectsHMACForDifferentDevice(t *testing.T) {
	pool := openDevicePool(t)
	deviceID, secret := registerTestDevice(t, pool)

	req := checkinRequest(t, deviceID, "", "")
	// Correct secret, but the challenge binds a different device ID — must not match.
	signRequestProof(t, req, secret, deviceID+1,
		time.Now().UTC().Format(time.RFC3339), "nonce-cross-device")

	h := HandleCheckin(pool, discardLogger(), testSecretCodec())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("cross-device HMAC: expected 401, got %d — body: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleCheckin_AcceptsValidHMAC proves a correctly-signed checkin succeeds.
func TestHandleCheckin_AcceptsValidHMAC(t *testing.T) {
	pool := openDevicePool(t)
	deviceID, secret := registerTestDevice(t, pool)

	req := checkinRequest(t, deviceID, "", "")
	signRequestProof(t, req, secret, deviceID,
		time.Now().UTC().Format(time.RFC3339), "nonce-accept-valid")

	h := HandleCheckin(pool, discardLogger(), testSecretCodec())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("valid HMAC: expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}
}
