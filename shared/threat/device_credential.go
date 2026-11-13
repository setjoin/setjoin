package threat

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/device"
)

// DeviceCredentialResolver turns an inbound request's X-Device-* proof headers
// into a trusted device-bound signal for the policy engine. It is the SINGLE
// place a blocking lockdown decision learns "is this a bound, approved device?"
// — mirroring how device.VerifyDeviceRequest is the sole device-auth seam. A
// blocking decision never rests on the forgeable DeviceFP.
//
// bound is TRUE only when the HMAC verifies AND revoked_at IS NULL (the device
// is not revoked). EnrollState is whatever devices.enroll_state holds at the
// time of the read (callers that need "approved" can check it; this resolver
// does not block on unapproved states — that is a policy-engine concern).
//
// Infra errors (DB blip, parse failure) resolve to (false, 0, "") + a logged
// warning: the resolver fails OPEN at the signal level (no proof = no signal),
// so under lockdown a no-signal request is blocked by the lockdown rule
// (fail-closed at the gate, not here).
//
// ponytail: no cache — the HMAC timestamp bound (±5 min) already limits replay;
// add a per-request TTL cache if latency shows up in profiles.
type DeviceCredentialResolver struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
	codec  *device.SecretCodec
}

// NewDeviceCredentialResolver creates a resolver backed by pool. codec is the
// process SecretCodec that opens the at-rest device HMAC secret
// (med-auth-baseline-secrets-001); nil fails closed at verification.
func NewDeviceCredentialResolver(pool *pgxpool.Pool, logger *slog.Logger, codec *device.SecretCodec) *DeviceCredentialResolver {
	return &DeviceCredentialResolver{pool: pool, logger: logger, codec: codec}
}

// Resolve verifies the device proof headers and reads the device's enrollment
// state. Returns (bound, deviceID, enrollState).
//
// userID is the authenticated user whose session this proof is for. The
// devices row must be owned by userID (devices.user_id = userID); a valid
// HMAC from a device registered to a different user is rejected — cross-user
// device replay is blocked here, not just at the policy gate.
//
// bound is TRUE only when:
//   - X-Device-HMAC verifies (constant-time, fresh timestamp, correct secret), AND
//   - devices.user_id = userID (device belongs to the authenticated user), AND
//   - revoked_at IS NULL on the devices row.
//
// Any error (missing/stale/wrong HMAC, no device row, wrong owner, revoked, DB blip)
// returns (false, 0, "") or (false, deviceID, "revoked") for revoked devices.
func (dcr *DeviceCredentialResolver) Resolve(ctx context.Context, req *http.Request, userID int64) (bool, int64, string) {
	idStr := req.Header.Get(device.HeaderDeviceID)
	if idStr == "" {
		return false, 0, ""
	}
	deviceID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || deviceID <= 0 {
		return false, 0, ""
	}
	// Verify the HMAC proof — this is the single load-bearing security check.
	// Missing header, stale timestamp, wrong HMAC, unknown device → not bound
	// (expected for plain browsers, which never set these headers).
	if err := device.VerifyDeviceRequest(ctx, dcr.pool, deviceID, req, dcr.codec); err != nil {
		// Not a warn: expected path for every plain-browser request.
		return false, 0, ""
	}
	// HMAC verified. Now read enroll_state + revoked_at in one query, gating on
	// user_id so a valid HMAC from device N (owner: user A) cannot be used by
	// user B to inflate DeviceBound in their session (cross-user device replay).
	// ponytail: ownership check — user_id guard is the security gate; ErrNoRows
	// on wrong-owner is indistinguishable from a missing device (fail-closed).
	var state string
	var revoked *string // NULL → not revoked
	err = dcr.pool.QueryRow(ctx,
		`SELECT enroll_state, revoked_at::text FROM devices WHERE id = $1 AND user_id = $2`,
		deviceID, userID).
		Scan(&state, &revoked)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			dcr.logger.WarnContext(ctx, "device credential: enroll_state read failed",
				"device_id", deviceID, "error", err)
		}
		return false, 0, ""
	}
	if revoked != nil {
		// HMAC was valid (device exists + secret matches + correct owner) but the
		// device is revoked — return the state for audit but NOT bound.
		return false, deviceID, state
	}
	return true, deviceID, state
}
