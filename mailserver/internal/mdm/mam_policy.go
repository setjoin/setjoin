package mdm

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

// MAMPolicy is the resolved effective policy for a device, covering all
// MAM dimensions beyond basic MDM passcode/compliance checks.
type MAMPolicy struct {
	Policies map[string]string `json:"policies"`
	Version  int64             `json:"version"`
}

// NotificationProfile controls how the device receives real-time updates.
type NotificationProfile struct {
	Profile                string `json:"profile"`                  // "push_only", "websocket_only", "hybrid"
	WebsocketKeepaliveSecs int    `json:"websocket_keepalive_secs"` // 0 = default (30s)
}

// ResolveMAMPolicy resolves the full MAM policy for a device by merging
// three layers: global defaults → group policies → per-device overrides.
// groupIDs is a map of group_type → group_id (e.g. {"department": 5, "role": 2}).
//
// FAIL-CLOSED: any group-load, query, rows-scan or iteration error ABORTS the
// whole resolution — the caller gets (nil, error) and the affected
// enforcement/check-in fails closed. A restrictive layer is never skipped and
// an empty map is never substituted for a failed load: returning a
// weaker-but-successful policy on a database error would silently drop
// restrictions the operator configured. The slog.Warn on the abort path is
// explicitly UNOBSERVABLE best-effort telemetry (slog cannot report its own
// failure; no persistence is promised) — the binding contract is the
// (nil, error) return itself, regardless of any logging outcome.
//
// OWNERSHIP (retained-code guard): deviceID must be the server-side device
// identity (an authoritative devices row resolved under an authority gate —
// devices.id), never a raw request-owned field. ResolveMAMPolicy currently
// has NO production caller (retained without an established live caller; see
// the package retirement note and TestRetainedCheckinPath_NoLiveCaller) — the
// next caller inherits this fail-closed behavior and the ownership duty.
func ResolveMAMPolicy(ctx context.Context, pool *pgxpool.Pool, deviceID int64, groupIDs map[string]int64) (*MAMPolicy, error) {
	logger := slog.Default()

	// Layer 1: Global defaults (device_id IS NULL)
	global, err := loadPolicyLayer(ctx, pool, nil, nil)
	if err != nil {
		logger.Warn("mam: policy resolution aborted loading global policies", "device_id", deviceID, "error", err)
		return nil, err
	}

	// Layer 2: Group policies — an error ABORTS the resolution (fail-closed).
	// `continue` here would silently drop every group restriction and return
	// a weaker-but-successful policy.
	group := make(map[string]string)
	for groupType, groupID := range groupIDs {
		gt := groupType
		gid := groupID
		groupPolicies, err := loadPolicyLayer(ctx, pool, &gt, &gid)
		if err != nil {
			logger.Warn("mam: policy resolution aborted loading group policies", "group_type", groupType, "group_id", groupID, "error", err)
			return nil, err
		}
		for k, v := range groupPolicies {
			group[k] = v
		}
	}

	// Layer 3: Per-device overrides — an error ABORTS (fail-closed); an empty
	// map is never substituted for a failed per-device load.
	perDevice, err := loadPolicyLayer(ctx, pool, nil, nil, deviceID)
	if err != nil {
		logger.Warn("mam: policy resolution aborted loading per-device policies", "device_id", deviceID, "error", err)
		return nil, err
	}

	// Merge layers: later layers override earlier ones
	merged := mergePolicies(global, group, perDevice)

	// Compute policy version (max of updated_at timestamps as simple version)
	version := computePolicyVersion(global, group, perDevice)

	return &MAMPolicy{
		Policies: merged,
		Version:  version,
	}, nil
}

// loadPolicyLayer loads one layer of policies from the database.
// If deviceID is provided, loads per-device policies. If groupType+groupID provided,
// loads group policies. Otherwise loads global defaults (device_id IS NULL).
//
// DETERMINISTIC RESOLUTION (D-MAILSERVER-INTERNAL-MDM-011): the writer-side
// NULL-device_id upsert can append duplicate rows for the same key (a plain
// UNIQUE never matches NULLs), so each layer deduplicates per policy_key with
// DISTINCT ON and a total order (updated_at DESC, id DESC): the most recently
// updated row for a key wins deterministically — never scan-order
// last-write-wins.
func loadPolicyLayer(ctx context.Context, pool *pgxpool.Pool, groupType *string, groupID *int64, deviceID ...int64) (map[string]string, error) {
	result := make(map[string]string)

	if len(deviceID) > 0 && deviceID[0] > 0 {
		// Per-device policies
		rows, err := pool.Query(ctx,
			`SELECT DISTINCT ON (policy_key) policy_key, policy_value
			   FROM device_policy
			  WHERE device_id = $1
			  ORDER BY policy_key, updated_at DESC, id DESC`,
			deviceID[0],
		)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var key, value string
			if err := rows.Scan(&key, &value); err != nil {
				return nil, err
			}
			result[key] = value
		}
		return result, rows.Err()
	}

	if groupType != nil && groupID != nil {
		// Group policies
		rows, err := pool.Query(ctx,
			`SELECT DISTINCT ON (policy_key) policy_key, policy_value
			   FROM device_policy_groups
			  WHERE group_type = $1 AND group_id = $2
			  ORDER BY policy_key, updated_at DESC, id DESC`,
			*groupType, *groupID,
		)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var key, value string
			if err := rows.Scan(&key, &value); err != nil {
				return nil, err
			}
			result[key] = value
		}
		return result, rows.Err()
	}

	// Global defaults
	rows, err := pool.Query(ctx,
		`SELECT DISTINCT ON (policy_key) policy_key, policy_value
		   FROM device_policy
		  WHERE device_id IS NULL
		  ORDER BY policy_key, updated_at DESC, id DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		result[key] = value
	}
	return result, rows.Err()
}

// mergePolicies merges policy layers. Later layers override earlier ones.
func mergePolicies(global, group, perDevice map[string]string) map[string]string {
	merged := make(map[string]string)

	for k, v := range global {
		merged[k] = v
	}
	for k, v := range group {
		merged[k] = v
	}
	for k, v := range perDevice {
		merged[k] = v
	}

	return merged
}

// computePolicyVersion produces a simple version number from the policy maps.
// Uses the count of policies as a basic versioning scheme — incremented on any change.
func computePolicyVersion(layers ...map[string]string) int64 {
	var total int
	for _, layer := range layers {
		total += len(layer)
	}
	return int64(total)
}
