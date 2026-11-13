package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/toggle"
)

// revocationLoader returns the current denied-device hash set:
//
//	key = lowercase-hex sha256(device fingerprint string) [matches user_devices.fingerprint_hash].
//
// Production queries the pool; tests inject a fake.
type revocationLoader func(context.Context) (map[string]bool, error)

// revocationCacheTTL bounds staleness of the in-process denied set. Short so a
// revoke takes effect quickly; pg_notify refresh (Task 5) is the primary trigger,
// this TTL-tick is the fallback.
// ponytail: var (not const) so tests can set to 0 to force expiry without sleeping.
var revocationCacheTTL = 5 * time.Second

// DeviceRevocationChecker is the in-process denylist for revoked/wiped devices.
// Shared between the HTTP DeviceRevocationGate middleware and the WS JMAP path so
// both paths consult the same loaded cache — no duplicate DB round-trips or
// independent cache staleness windows.
//
// IsRevoked is fail-CLOSED: when the set has never loaded (first DB error), it
// returns true for any enrolled device — matching the HTTP gate's posture.
type DeviceRevocationChecker struct {
	load       revocationLoader
	isEnforced func() bool // runtime toggle check — bound at construction
	logger     *slog.Logger
	mu         sync.Mutex
	cached     map[string]bool
	cachedAt   time.Time
}

// Loaded reports whether the denylist has successfully loaded at least once.
func (c *DeviceRevocationChecker) Loaded() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cached != nil
}

// IsRevoked reports whether the device fingerprint (raw string, not pre-hashed) is
// in the revoked set. Returns false (pass) when the feature toggle is off or when
// deviceFP is empty (legacy/unenrolled device). Returns true (deny) when the cache
// has never loaded (fail-CLOSED to match the HTTP gate).
func (c *DeviceRevocationChecker) IsRevoked(ctx context.Context, deviceFP string) bool {
	if c.isEnforced != nil && !c.isEnforced() {
		return false // toggle off — pure pass-through
	}
	if deviceFP == "" {
		return false // legacy/unenrolled device — pass
	}
	set := c.get(ctx)
	if set == nil {
		return true // fail-CLOSED: denylist never loaded
	}
	sum := sha256.Sum256([]byte(deviceFP))
	key := hex.EncodeToString(sum[:])
	return set[key]
}

func (c *DeviceRevocationChecker) get(ctx context.Context) map[string]bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cached != nil && time.Since(c.cachedAt) < revocationCacheTTL {
		return c.cached
	}
	set, err := c.load(ctx)
	if err != nil {
		if c.cached == nil {
			c.logger.Warn("device revocation: first-load failed — failing CLOSED until DB reachable", "error", err)
		} else {
			c.logger.Warn("device revocation: reload failed — using stale cache", "error", err)
		}
		// nil on first-load (guard will fail CLOSED); stale set on refresh failure.
		return c.cached
	}
	c.cached, c.cachedAt = set, time.Now()
	return c.cached
}

// newDeviceRevocationGate builds the middleware from a loader (injectable for tests).
// Returns the HTTP middleware and the underlying DeviceRevocationChecker so the WS
// JMAP path can share the same loaded cache (offline #2b fix).
func newDeviceRevocationGate(load revocationLoader, toggles toggleChecker, logger *slog.Logger) (func(http.Handler) http.Handler, *DeviceRevocationChecker) {
	checker := &DeviceRevocationChecker{
		load:   load,
		logger: logger,
		isEnforced: func() bool {
			return toggles != nil && toggles.IsEnabled(toggle.FeatureDeviceTrustEnforcement)
		},
	}

	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := auth.UserFromContext(r.Context())
			if claims == nil || claims.Device == nil || claims.Device.ID == "" {
				next.ServeHTTP(w, r) // nil/legacy device — pass (same posture as compliance gate)
				return
			}
			if checker.IsRevoked(r.Context(), claims.Device.ID) {
				sum := sha256.Sum256([]byte(claims.Device.ID))
				key := hex.EncodeToString(sum[:])
				logger.Warn("device revocation: device blocked",
					"user_id", claims.UserID, "device_fp_hash", key, "denylist_loaded", checker.Loaded())
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"title":  "Forbidden",
					"detail": "This device's access has been revoked. Contact your administrator.",
					"status": http.StatusForbidden,
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	return mw, checker
}

// DeviceRevocationGate is the production constructor: a pool-backed loader over
// user_devices (offline_approval='revoked' OR wipe_requested=true).
// Returns the HTTP middleware (consumed by main.go withDeviceTrust) and the shared
// DeviceRevocationChecker for the WS path (offline #2b).
func DeviceRevocationGate(pool *pgxpool.Pool, toggles toggleChecker, logger *slog.Logger) (func(http.Handler) http.Handler, *DeviceRevocationChecker) {
	load := func(ctx context.Context) (map[string]bool, error) {
		if pool == nil {
			return map[string]bool{}, nil
		}
		rows, err := pool.Query(ctx, `
			SELECT encode(fingerprint_hash, 'hex')
			  FROM user_devices
			 WHERE fingerprint_hash IS NOT NULL
			   AND (wipe_requested = TRUE OR offline_approval = 'revoked')`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		set := map[string]bool{}
		for rows.Next() {
			var h string
			if err := rows.Scan(&h); err != nil {
				return nil, err
			}
			set[h] = true
		}
		return set, rows.Err()
	}
	return newDeviceRevocationGate(load, toggles, logger)
}
