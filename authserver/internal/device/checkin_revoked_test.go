package device

// med-shard2-006 (D-AUTHSERVER-INTERNAL-DEVICE-002): a revoked device loses
// the authenticated checkin/policy trust channel entirely — its secret lookup
// fails, so both HMAC endpoints reject the next proof with 401 instead of
// disclosing resolved policy or wipe-flag state to a revoked client.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestHandleCheckin_RevokedDeviceChannelEnds drives the real handler: a valid
// proof authenticates before revocation; after device_enroll_transition
// revokes the device, an equally valid fresh proof is rejected with 401 on
// BOTH the checkin and the policy-read endpoints.
func TestHandleCheckin_RevokedDeviceChannelEnds(t *testing.T) {
	pool := openDevicePool(t)
	deviceID, secret := registerTestDevice(t, pool)
	ctx := context.Background()

	// Baseline: the not-yet-revoked device authenticates (its enroll state is
	// the registration default 'unenrolled' — only REVOKED devices are cut off).
	pre := checkinRequest(t, deviceID, "", "")
	signRequestProof(t, pre, secret, deviceID, time.Now().UTC().Format(time.RFC3339), "nonce-pre-revoke")
	h := HandleCheckin(pool, discardLogger(), testSecretCodec())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, pre)
	if rec.Code != http.StatusOK {
		t.Fatalf("pre-revoke checkin: expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}

	// Revoke via the lifecycle reducer, exactly as admin_device_lockdown does
	// through shared/device.RevokeDevice. The actor is the device's owner (a
	// real user — devices.enrolled_by carries an FK to users).
	var ownerID int64
	if err := pool.QueryRow(ctx,
		`SELECT user_id FROM devices WHERE id = $1`, deviceID).Scan(&ownerID); err != nil {
		t.Fatalf("load device owner: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT device_enroll_transition($1, $2, 'enrolled', 'test enroll')`,
		ownerID, deviceID); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT device_enroll_transition($1, $2, 'revoked', 'test revoke')`,
		ownerID, deviceID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// The checkin channel ends: a proof signed with the secret the client
	// still holds — which the revocation reducer has just rotated away in the
	// database — is rejected 401 (the revoked row is also filtered from the
	// secret lookup outright).
	post := checkinRequest(t, deviceID, "", "")
	signRequestProof(t, post, secret, deviceID, time.Now().UTC().Format(time.RFC3339), "nonce-post-revoke")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, post)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("post-revoke checkin: expected 401, got %d — body: %s", rec.Code, rec.Body.String())
	}

	// The policy-read channel ends the same way (no resolved-policy or
	// wipe-flag disclosure to a revoked device).
	policyReq := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/device/policy?device_id=%d", deviceID), nil)
	signRequestProof(t, policyReq, secret, deviceID, time.Now().UTC().Format(time.RFC3339), "nonce-post-revoke-policy")
	policyRec := httptest.NewRecorder()
	HandleGetDevicePolicy(pool, discardLogger(), testSecretCodec()).ServeHTTP(policyRec, policyReq)
	if policyRec.Code != http.StatusUnauthorized {
		t.Fatalf("post-revoke policy read: expected 401, got %d — body: %s", policyRec.Code, policyRec.Body.String())
	}
}
