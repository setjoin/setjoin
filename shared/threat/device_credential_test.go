package threat

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/device"
)

// signedDeviceRequest builds a POST request to target carrying a full
// remediated device proof (med-shard2-006): X-Device-ID, timestamp, a fresh
// single-use nonce, the body hash of the (empty) body, and the HMAC over the
// canonical request challenge keyed with secret.
func signedDeviceRequest(target, secret string, deviceID int64, ts, nonce string) *http.Request {
	r := httptest.NewRequest("POST", target, nil)
	emptyHash := sha256.Sum256(nil)
	bodyHash := hex.EncodeToString(emptyHash[:])
	challenge := device.ChallengeForRequest(deviceID, ts, "POST", target, bodyHash, nonce)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(challenge))
	r.Header.Set("X-Device-ID", strconv.FormatInt(deviceID, 10))
	r.Header.Set("X-Device-Timestamp", ts)
	r.Header.Set("X-Device-Nonce", nonce)
	r.Header.Set("X-Device-Body-SHA256", bodyHash)
	r.Header.Set("X-Device-HMAC", hex.EncodeToString(mac.Sum(nil)))
	return r
}

func TestDeviceCredentialResolver(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	// Close via t.Cleanup FIRST (registered before the fixture cleanup below)
	// so LIFO runs clean() against an OPEN pool and only then closes it — a
	// `defer pool.Close()` would run before clean() and silently skip it.
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	secret := "00112233445566778899aabbccddeeff"

	// Pre-clean any leftovers.
	clean := func() {
		pool.Exec(ctx, `DELETE FROM devices WHERE fingerprint LIKE 'dcr-cred-test%'`)
		pool.Exec(ctx, `DELETE FROM users WHERE email='dcr-cred-test@dcr-device.example'`)
		pool.Exec(ctx, `DELETE FROM domains WHERE name='dcr-device.example'`)
	}
	clean()
	t.Cleanup(clean)

	// Provision an isolated domain + user + device.
	// Use upsert so a leftover domain row (stale fixture from another test suite)
	// doesn't fail the INSERT; we always get the canonical id back.
	var domainID, uid, did int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ('dcr-device.example')
		 ON CONFLICT (name) DO UPDATE SET name=EXCLUDED.name RETURNING id`).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name)
		 VALUES ('dcr', $1, 'dcr-cred-test@dcr-device.example', 'DCR Test') RETURNING id`,
		domainID).Scan(&uid); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO devices (user_id, fingerprint, hmac_secret, enroll_state)
		 VALUES ($1, $2, $3, 'approved') RETURNING id`,
		uid, "dcr-cred-test-fp-pad-to-32chars-xxxx", secret).Scan(&did); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	res := NewDeviceCredentialResolver(pool, testLogger(), device.NewSecretCodec([]byte("device-test-master-secret-key"), cryptokey.ProfileStandard))
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	// valid proof, correct owner -> bound, approved
	bound, gotID, state := res.Resolve(ctx, signedDeviceRequest("/jmap", secret, did, ts, "dcr-nonce-valid"), uid)
	if !bound || gotID != did || state != "approved" {
		t.Fatalf("valid proof: bound=%v id=%d state=%q", bound, gotID, state)
	}

	// cross-user device replay: valid HMAC but wrong userID -> not bound
	// This is the critical security gate: a device registered to uid must not
	// inflate DeviceBound for a different user (uid+1).
	tsc := strconv.FormatInt(time.Now().Unix(), 10)
	if b, _, _ := res.Resolve(ctx, signedDeviceRequest("/jmap", secret, did, tsc, "dcr-nonce-cross"), uid+1); b {
		t.Fatal("cross-user device replay: valid HMAC for wrong user must not be bound")
	}

	// stale timestamp -> not bound
	stale := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	if b, _, _ := res.Resolve(ctx, signedDeviceRequest("/jmap", secret, did, stale, "dcr-nonce-stale"), uid); b {
		t.Fatal("stale ts must not be bound")
	}

	// revoked device -> not bound even with a valid HMAC
	pool.Exec(ctx, `UPDATE devices SET revoked_at = now(), enroll_state='revoked' WHERE id=$1`, did)
	// Rebuild a fresh signed request (same secret, fresh ts) — the HMAC itself is valid;
	// the resolver must still reject it because the device is revoked.
	ts2 := strconv.FormatInt(time.Now().Unix(), 10)
	if b, _, _ := res.Resolve(ctx, signedDeviceRequest("/jmap", secret, did, ts2, "dcr-nonce-revoked"), uid); b {
		t.Fatal("revoked device must not be bound")
	}
}
