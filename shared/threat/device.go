// Device trust resolution for conditional access policy engine.
//
// Resolves device trust tiers: managed > known > unknown > risky.
// Managed = enrolled in managed_devices table with compliant status.
// Known = present in device_registry, last_seen within 90d, auth_count >= 3.
// Unknown = not in registry or auth_count < 3.
// Risky = unknown + VPN/anonymous proxy detected.
//
// Spec: docs/design/security/ (conditional access policies)
package threat

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/jwtutil"
)

// DeviceTrustResolver determines the trust tier for a device.
type DeviceTrustResolver struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewDeviceTrustResolver creates a device trust resolver.
func NewDeviceTrustResolver(pool *pgxpool.Pool, logger *slog.Logger) *DeviceTrustResolver {
	return &DeviceTrustResolver{pool: pool, logger: logger}
}

// Resolve returns the trust tier for a device fingerprint and user.
// Tiers: managed, known, unknown, risky.
func (dtr *DeviceTrustResolver) Resolve(ctx context.Context, deviceFP string, userID int64, isVPN bool) string {
	if deviceFP == "" || dtr.pool == nil {
		return "unknown"
	}

	deviceHash := fmt.Sprintf("%x", sha256.Sum256([]byte(deviceFP)))

	// Check managed_devices first (highest trust)
	if dtr.isManagedDevice(ctx, deviceHash, userID) {
		return "managed"
	}

	// Check device_registry for known/unknown
	if dtr.isKnownDevice(ctx, deviceHash, userID) {
		return "known"
	}

	// Unknown + VPN = risky
	if isVPN {
		return "risky"
	}

	return "unknown"
}

// UpsertTrustTier updates the trust tier in device_registry after auth.
func (dtr *DeviceTrustResolver) UpsertTrustTier(ctx context.Context, deviceFP string, userID int64, tier string) {
	if dtr.pool == nil || deviceFP == "" || userID == 0 {
		return
	}
	deviceHash := fmt.Sprintf("%x", sha256.Sum256([]byte(deviceFP)))
	_, err := dtr.pool.Exec(ctx,
		`UPDATE device_registry SET trust_tier = $1 WHERE user_id = $2 AND device_hash = $3`,
		tier, userID, deviceHash)
	if err != nil {
		dtr.logger.Warn("device trust: failed to update trust tier", "error", err, "user_id", userID)
	}
}

// ── Device-trust enforcement: login-time DeviceClaim production ──
//
// The ONLY login-reachable compliance table is managed_devices, keyed by
// device_hash (= sha256-hex(DeviceFP), as Resolve already derives). Its
// compliance_status ∈ {compliant, non_compliant, unknown}. The richer
// mdm_device_state (which has a 'quarantined' status + a wipe state machine) is
// keyed by a device_id UUID and is NOT reachable from a DeviceFP/device_hash, so
// it cannot drive the login-embedded claim. See the correlation note in the
// device-trust-enforcement plan.

// MapManagedComplianceToClaim maps a managed_devices row to the DeviceClaim the
// gateway gate (shared/middleware.RequireDeviceCompliance) reads. It is the
// single, pure, tested producer→consumer contract.
//
//	compliant     -> TrustTier "compliant"   (passes the gate)
//	non_compliant -> TrustTier "quarantined" (403 at the gate — the block)
//	unknown / not-found / anything else -> nil (a claim-less token; the gate
//	                                       FAILS CLOSED on it while enforcement
//	                                       is enabled — 403
//	                                       device_compliance_unverifiable)
//
// It NEVER fabricates a "quarantined" tier from an absent or unrecognized row —
// a device with no managed_devices entry (or an unknown status) can never be
// locked out BY THIS MAPPING as a quarantine. But the nil it returns for the
// indeterminate legs is no longer a pass: the gate treats a claim-less token as
// unverifiable and blocks it unless an explicitly contracted legacy token class
// (LegacyTokenPolicy) admits it — the device-trust-nil-claim-pass-through
// fail-open (occ_027c0f3d4df0cadcfb74d1a6, D-SHARED-MIDDLEWARE-002) is closed
// at the gate, and this producer deliberately leaves every indeterminate device
// on that fail-closed leg rather than minting a tier it cannot substantiate.
// WipeRequested is always false: no wipe source is reachable by device_hash
// (the mdm_device_state wipe machine is keyed by a device_id UUID we don't
// have at login), so the login-embedded claim never asserts a wipe it can't
// substantiate.
func MapManagedComplianceToClaim(deviceHash, complianceStatus string, found bool) *jwtutil.DeviceClaim {
	if !found {
		return nil
	}
	switch complianceStatus {
	case "compliant":
		return &jwtutil.DeviceClaim{
			ID:               deviceHash,
			TrustTier:        jwtutil.TrustTierCompliant,
			ComplianceStatus: jwtutil.ComplianceOK,
		}
	case "non_compliant":
		return &jwtutil.DeviceClaim{
			ID:        deviceHash,
			TrustTier: jwtutil.TrustTierQuarantined,
		}
	default:
		// "unknown" or any unrecognized value: do NOT populate the claim. This
		// producer never fabricates a quarantine from uncertainty; the
		// claim-less token is then handled by the gate's fail-closed
		// legacy-class policy while enforcement is enabled (see the function
		// contract above) — never silently passed through.
		return nil
	}
}

// ResolveDeviceClaim looks up this device's managed_devices compliance row and
// maps it to a *jwtutil.DeviceClaim for embedding in the access token at login.
//
// FAIL-OPEN AT LOGIN ONLY: any DB error (or nil pool / empty FP) returns nil —
// login itself is never blocked and a quarantine is never fabricated from a
// lookup failure. The returned nil is a CLAIM-LESS token, and enforcement of
// it is NOT this function's job: shared/middleware.RequireDeviceCompliance
// fails a claim-less token closed (403) while
// feature.device_trust_enforcement is enabled, so an unenrolled or lookup-
// failed device cannot ride the token onto a gated route. An unenrolled device
// (no managed_devices row) likewise returns nil.
//
// V254 FORCE-RLS pairing: managed_devices is Posture A (self keyed on
// app.current_user_id). The statement runs inside dbscope.RunUserScoped so the
// GUC is the ONLY scope source here — the in-statement user_id predicate (R1)
// stays; the transaction-scoped set is PgBouncer-safe.
func (dtr *DeviceTrustResolver) ResolveDeviceClaim(ctx context.Context, deviceFP string, userID int64) *jwtutil.DeviceClaim {
	if dtr.pool == nil || deviceFP == "" {
		return nil
	}
	deviceHash := fmt.Sprintf("%x", sha256.Sum256([]byte(deviceFP)))

	var complianceStatus string
	err := dbscope.RunUserScoped(ctx, dtr.pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT compliance_status FROM managed_devices WHERE device_hash = $1 AND user_id = $2`,
			deviceHash, userID,
		).Scan(&complianceStatus)
	})
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) && dtr.logger != nil {
			// A real DB error: log and fail open (treat as unenrolled). pgx.ErrNoRows
			// is the normal unenrolled path and is not worth a warn.
			dtr.logger.Warn("device trust: compliance lookup failed, failing open",
				"error", err, "user_id", userID)
		}
		return nil
	}
	return MapManagedComplianceToClaim(deviceHash, complianceStatus, true)
}

// isManagedDevice checks if a device is enrolled and compliant FOR THIS USER.
// device_hash (= sha256(userAgent | /24-masked-IP)) is NOT user-unique, so the
// user_id scope is load-bearing: without it, two users behind the same NAT with
// the same UA collide and the second inherits the first's 'managed' tier — a
// cross-tenant trust escalation. Scoped exactly like its siblings
// ResolveDeviceClaim/isKnownDevice (R1: SELECT filters by user_id from auth ctx).
//
// V254 FORCE-RLS pairing: the managed_devices self arm reads
// app.current_user_id — paired transaction-locally by dbscope.RunUserScoped.
func (dtr *DeviceTrustResolver) isManagedDevice(ctx context.Context, deviceHash string, userID int64) bool {
	var compliant bool
	err := dbscope.RunUserScoped(ctx, dtr.pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT compliance_status = 'compliant' FROM managed_devices WHERE device_hash = $1 AND user_id = $2`,
			deviceHash, userID,
		).Scan(&compliant)
	})
	return err == nil && compliant
}

// isKnownDevice checks if a device is known (last_seen within 90d and auth_count >= 3).
//
// V254 FORCE-RLS pairing: the device_registry self arm reads
// app.current_user_id — paired transaction-locally by dbscope.RunUserScoped.
func (dtr *DeviceTrustResolver) isKnownDevice(ctx context.Context, deviceHash string, userID int64) bool {
	var known bool
	err := dbscope.RunUserScoped(ctx, dtr.pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS(
				SELECT 1 FROM device_registry
				WHERE user_id = $1 AND device_hash = $2
				  AND last_seen > now() - INTERVAL '90 days'
				  AND auth_count >= 3
			)`,
			userID, deviceHash,
		).Scan(&known)
	})
	return err == nil && known
}
