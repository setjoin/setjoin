// Package device — the composed actor-binding secret seam (owner decision D1,
// 2026-09-14: DEVICE-003 / D-SHARED-DEVICE-003).
//
// GetDeviceSecret discloses the plaintext long-lived device HMAC secret to any
// importer of this package, keyed on device id alone. Its signature is
// deliberately unchanged (VerifyDeviceRequest and the lazy at-rest migration
// compose on it internally); containment is recovered by composition: the only
// sanctioned way for a caller outside this package to obtain a secret is this
// wrapper, which binds the requesting actor to the device owner before the
// disclosure happens.
package device

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// GetDeviceSecretForOwner returns the per-device HMAC secret for deviceID only
// when the requesting actor owns the device: the ownership predicate
// (devices.user_id = actorUserID) is enforced IN the lookup query (R1), not
// checked-then-read. actorUserID is the authenticated user's id and must come
// from auth context, never from a request-owned field (R2).
//
// Fail closed with ErrNoSecret — indistinguishable, no oracle — when the
// device does not exist, the actor is not its owner, or the device is revoked
// (the revoked filter is GetDeviceSecret's own, inherited here). This mirrors
// DeviceCredentialResolver's wrong-owner read: a valid secret request for
// another user's device looks exactly like an unknown device.
//
// Composition, not signature change: GetDeviceSecret keeps its signature and
// remains internal-only (VerifyDeviceRequest, the at-rest lazy migration).
// devices.user_id is write-once at registration — no reducer or seam mutates
// it — so the ownership probe and the secret load cannot be split by a
// concurrent mutation; if user_id ever becomes mutable, the ownership
// predicate must move into the secret-loading statement itself.
//
// codec must be the process SecretCodec; nil fails closed (inherited from
// GetDeviceSecret).
func GetDeviceSecretForOwner(ctx context.Context, pool *pgxpool.Pool, actorUserID, deviceID int64, codec *SecretCodec) (string, error) {
	var owned bool
	err := pool.QueryRow(ctx,
		`SELECT true FROM devices
		  WHERE id = $1
		    AND user_id = $2`,
		deviceID, actorUserID).Scan(&owned)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNoSecret
		}
		return "", fmt.Errorf("device: ownership-scoped secret load: %w", err)
	}
	if !owned {
		return "", ErrNoSecret
	}
	return GetDeviceSecret(ctx, pool, deviceID, codec)
}
