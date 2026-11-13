package device

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	shareddevice "setjoin.com/shared/device"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The device HMAC secret is the trust-root. Deep-scan package
// desktop-drive-bridge-unconfined pins the rotation property the client
// confinement work relies on: RE-ENROLLMENT (re-registering the same
// (user_id, fingerprint) — identity.go's ON CONFLICT DO UPDATE, which does NOT
// list hmac_secret) PRESERVES the originally issued secret. It is therefore
// explicitly NOT a rotation mechanism: the old proof secret stays valid across
// re-enrollment, and only a real secret change (or the device-proof gate
// rejecting a wrong secret) invalidates old proofs.
func TestRegisterDeviceReenrollmentPreservesSecretAndIsNotARotation(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set")
	}
	pool, _ := pgxpool.New(context.Background(), dsn)
	defer pool.Close()
	ctx := context.Background()

	uid, err := insertTestUser(ctx, pool, fmt.Sprintf("rot-%d@device.test", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	defer pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, uid)

	id := Identity{Fingerprint: fmt.Sprintf("no-rotate-%030d", time.Now().UnixNano()), Platform: "mac"}

	first, err := RegisterDevice(ctx, pool, uid, id, testSecretCodec())
	if err != nil {
		t.Fatalf("first register: %v", err)
	}
	if first.HMACSecret == "" {
		t.Fatal("first registration must return the HMAC secret")
	}

	// Re-enroll the SAME device fingerprint twice.
	second, err := RegisterDevice(ctx, pool, uid, id, testSecretCodec())
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	third, err := RegisterDevice(ctx, pool, uid, id, testSecretCodec())
	if err != nil {
		t.Fatalf("re-register 2: %v", err)
	}
	if second.ID != first.ID || third.ID != first.ID {
		t.Fatalf("re-enrollment must hit the same device row: %d/%d/%d", first.ID, second.ID, third.ID)
	}
	if second.HMACSecret != "" || third.HMACSecret != "" {
		t.Fatal("re-enrollment must never re-emit the HMAC secret")
	}

	// The STORED trust value must be preserved — re-enrollment is asserted NOT
	// to rotate it. Since med-auth-baseline-secrets-001 the row stores only the
	// AES-256-GCM _enc envelope (hmac_secret is NULL); preservation is checked
	// by opening the envelope and comparing to the issued secret, and by the
	// proof-verification consequence below.
	var stored []byte
	if err := pool.QueryRow(ctx,
		`SELECT hmac_secret_enc FROM devices WHERE id=$1`, first.ID).Scan(&stored); err != nil {
		t.Fatalf("read stored envelope: %v", err)
	}
	if len(stored) == 0 {
		t.Fatal("registration must persist the sealed hmac_secret_enc envelope")
	}
	opened, err := testSecretCodec().Open(stored, shareddevice.SecretKeyIDV1)
	if err != nil {
		t.Fatalf("open stored envelope: %v", err)
	}
	if opened != first.HMACSecret {
		t.Fatal("re-enrollment must PRESERVE the original secret (it is not a rotation mechanism)")
	}

	// Consequence: a proof made with the ORIGINAL (preserved) secret still
	// verifies after re-enrollment, while a WRONG secret is rejected by the
	// canonical verifier. (Astra hold 4: this proves wrong-secret rejection
	// only — the real rotation invalidation is pinned by
	// TestPersistedRotationInvalidatesOldProofsThroughLiveGate below.)
	deviceID := first.ID
	ts := fmt.Sprintf("%d", time.Now().Unix())
	challenge := challengeFor(deviceID, ts)

	mac := hmac.New(sha256.New, []byte(opened))
	mac.Write([]byte(challenge))
	preservedProof := hex.EncodeToString(mac.Sum(nil))
	if !ValidateHMAC(opened, challenge, preservedProof) {
		t.Fatal("the preserved secret must still produce a valid proof after re-enrollment")
	}

	mac = hmac.New(sha256.New, []byte("a-wrong-secret-never-issued"))
	mac.Write([]byte(challenge))
	wrongProof := hex.EncodeToString(mac.Sum(nil))
	if ValidateHMAC(opened, challenge, wrongProof) {
		t.Fatal("a proof made with any secret other than the stored one must be REJECTED")
	}
}

// signedCheckin builds a POST /device/checkin request whose device-proof
// headers are signed with `secret` over the full request challenge, using a
// FRESH single-use nonce. Every VerifyDeviceRequest call in the rotation tests
// below gets its own nonce, so a rejection is attributable to the secret/state
// under test and never to a spent nonce (Astra hold 4: replay rejection must
// not be able to fake a pass).
func signedCheckin(t *testing.T, deviceID int64, secret, nonce string) *http.Request {
	t.Helper()
	req := checkinRequest(t, deviceID, "", "")
	signRequestProof(t, req, secret, deviceID, time.Now().UTC().Format(time.RFC3339), nonce)
	return req
}

// uniqueNonce suffixes a monotonically fresh value so parallel/sequential
// verifications never share a nonce even for the same label.
func uniqueNonce(label string) string {
	return fmt.Sprintf("%s-%d", label, time.Now().UnixNano())
}

// registerRotationFixtureDevice creates a user + device pair self-sufficiently
// (no seed users required) and returns the device id, issued secret, and the
// owner id needed for lifecycle transitions. Rows are cleaned up at test end.
func registerRotationFixtureDevice(t *testing.T, pool *pgxpool.Pool, label string) (int64, string, int64) {
	t.Helper()
	ctx := context.Background()
	uid, err := insertTestUser(ctx, pool, fmt.Sprintf("%s-%d@device.test", label, time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, uid) })

	id := Identity{Fingerprint: fmt.Sprintf("%s-%030d", label, time.Now().UnixNano()), Platform: "mac"}
	reg, err := RegisterDevice(ctx, pool, uid, id, testSecretCodec())
	if err != nil {
		t.Fatalf("register device: %v", err)
	}
	if reg.HMACSecret == "" {
		t.Fatal("registration must return the HMAC secret")
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM devices WHERE id=$1`, reg.ID) })
	return reg.ID, reg.HMACSecret, uid
}

// TestPersistedRotationInvalidatesOldProofsThroughLiveGate is the REAL
// rotation fixture the fabricated comparison in the preservation test could
// never be (Astra hold 4): the device's persisted trust secret is rotated
// IN THE DATABASE — since med-auth-baseline-secrets-001 the persisted form is
// the sealed hmac_secret_enc envelope (SQL cannot seal; the reducer's legacy
// column rotation for _enc rows is the open rotation-semantics decision), so
// the rotation persists a fresh codec-sealed envelope, exactly the atomic
// shape the register/lazy-migration paths use — and every claim is exercised
// through the live HMAC gate (VerifyDeviceRequest — secret lookup, timestamp
// freshness, body binding, nonce claim). After the rotation:
//
//   - a proof signed with the OLD secret is REJECTED (old proofs invalidated),
//   - a proof signed with the NEW persisted secret is ACCEPTED (the gate
//     consults the persisted row — the fabricated in-memory comparison proved
//     nothing about this),
//   - replaying the exact accepted request is REJECTED (its nonce is spent),
//     so none of the acceptances above could have come from replay evasion.
func TestPersistedRotationInvalidatesOldProofsThroughLiveGate(t *testing.T) {
	pool := openDevicePool(t)
	ctx := context.Background()
	deviceID, oldSecret, _ := registerRotationFixtureDevice(t, pool, "rot-live")

	// Pre-rotation: the issued secret verifies through the live gate (fresh nonce).
	if err := VerifyDeviceRequest(ctx, pool, deviceID, signedCheckin(t, deviceID, oldSecret, uniqueNonce("rot-pre")), testSecretCodec()); err != nil {
		t.Fatalf("pre-rotation proof with the issued secret must verify: %v", err)
	}

	// REAL persisted rotation, DB-side: seal a fresh random secret into the
	// envelope and store it in the same atomic shape the register/lazy-migration
	// paths use (envelope + key id in, plaintext out).
	newSecret := "rotated-" + fmt.Sprintf("%064d", time.Now().UnixNano())
	sealed, err := testSecretCodec().Seal(newSecret)
	if err != nil {
		t.Fatalf("seal rotated secret: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE devices SET hmac_secret = NULL, hmac_secret_enc = $2, hmac_secret_key_id = $3
		  WHERE id = $1`, deviceID, sealed, shareddevice.SecretKeyIDV1); err != nil {
		t.Fatalf("persisted rotation: %v", err)
	}
	if newSecret == oldSecret || newSecret == "" {
		t.Fatal("rotation must persist a fresh, different secret")
	}

	// Old-secret proof with a FRESH nonce → rejected (the rotation, not replay,
	// is what invalidates it).
	if err := VerifyDeviceRequest(ctx, pool, deviceID, signedCheckin(t, deviceID, oldSecret, uniqueNonce("rot-old")), testSecretCodec()); err == nil {
		t.Fatal("a proof signed with the pre-rotation secret must be REJECTED after a persisted rotation")
	}

	// New-secret proof with a FRESH nonce → accepted: the live gate reads the
	// persisted row.
	accepted := signedCheckin(t, deviceID, newSecret, uniqueNonce("rot-new"))
	if err := VerifyDeviceRequest(ctx, pool, deviceID, accepted, testSecretCodec()); err != nil {
		t.Fatalf("a proof signed with the rotated secret must be ACCEPTED through the live gate: %v", err)
	}

	// Replay control: the SAME captured request (same nonce) is rejected, so
	// the acceptance above can never be confused with a replay pass.
	if err := VerifyDeviceRequest(ctx, pool, deviceID, accepted, testSecretCodec()); err == nil {
		t.Fatal("replaying the accepted proof must fail (the nonce is single-use)")
	}
}

// TestRevocationRotationInvalidatesOldSecretsThroughLiveGate pins the
// lifecycle rotation/revocation fixture end-to-end in this package: the
// device_enroll_transition reducer ROTATES the persisted secret on revoke
// (revocation is terminal — no revoked->X transition), and the live gate then
// rejects proofs signed with EITHER the originally issued secret or the
// rotated one, because a revoked device loses its trust channel outright.
func TestRevocationRotationInvalidatesOldSecretsThroughLiveGate(t *testing.T) {
	pool := openDevicePool(t)
	ctx := context.Background()
	deviceID, issuedSecret, ownerID := registerRotationFixtureDevice(t, pool, "rot-revoke")

	// unenrolled -> enrolled -> revoked (the reducer's legal path), with the
	// device's owner as the actor (devices.enrolled_by FKs to users).
	if _, err := pool.Exec(ctx, `SELECT device_enroll_transition($1, $2, 'enrolled', 'rotation-fixture')`, ownerID, deviceID); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT device_enroll_transition($1, $2, 'revoked', 'rotation-fixture')`, ownerID, deviceID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// The reducer rotated the persisted secret away from the issued value.
	var stored string
	if err := pool.QueryRow(ctx, `SELECT hmac_secret FROM devices WHERE id = $1`, deviceID).Scan(&stored); err != nil {
		t.Fatalf("read rotated secret: %v", err)
	}
	if stored == issuedSecret {
		t.Fatal("revocation must rotate the persisted hmac_secret away from the issued value")
	}

	// Old-secret proof with a FRESH nonce → rejected: old proofs are invalid
	// after the rotation/revocation.
	if err := VerifyDeviceRequest(ctx, pool, deviceID, signedCheckin(t, deviceID, issuedSecret, uniqueNonce("revoke-old")), testSecretCodec()); err == nil {
		t.Fatal("a proof signed with the pre-revocation secret must be REJECTED after revocation")
	}

	// Even the ROTATED (persisted) secret proves nothing: the revoked device's
	// trust channel is closed before the HMAC is consulted.
	if err := VerifyDeviceRequest(ctx, pool, deviceID, signedCheckin(t, deviceID, stored, uniqueNonce("revoke-rotated")), testSecretCodec()); err == nil {
		t.Fatal("a revoked device must fail verification even with the rotated persisted secret")
	}
}
