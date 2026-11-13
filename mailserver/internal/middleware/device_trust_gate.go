package middleware

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/jwtutil"
	sharedmw "setjoin.com/shared/middleware"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
)

// toggleChecker is the minimal feature-flag surface the device-trust gate needs.
// *toggle.FeatureFlags satisfies it; tests inject a static map.
type toggleChecker interface {
	IsEnabled(key string) bool
}

// DeviceTrustGate wraps the shared RequireDeviceCompliance gate behind the
// feature.device_trust_enforcement toggle (DEFAULT OFF — this is auth; a bug
// locks users out). When the toggle is OFF the gate is a PURE PASS-THROUGH
// no-op: the request goes straight to the next handler with no claim inspection.
// When ON, it delegates to RequireDeviceCompliance, which 403s a quarantined or
// wipe-requested device and passes a nil-Device (unenrolled/legacy) claim
// through.
//
// An unseeded toggle row stays OFF: IsEnabled resolves the key through the
// toggle registry, where feature.device_trust_enforcement defaults false.
//
// This is intended to wrap the authenticated route chain right after RequireAuth
// (which populates the claims this gate reads), so no individual route can
// forget it.
func DeviceTrustGate(toggles toggleChecker, logger *slog.Logger) func(http.Handler) http.Handler {
	claimsFn := func(r *http.Request) *jwtutil.Claims {
		// auth.Claims is a type alias for jwtutil.Claims, so this is the same type.
		return auth.UserFromContext(r.Context())
	}
	compliance := sharedmw.RequireDeviceCompliance(claimsFn, logger)

	return func(next http.Handler) http.Handler {
		gated := compliance(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if toggles == nil || !toggles.IsEnabled(toggle.FeatureDeviceTrustEnforcement) {
				// Inert until deliberately flipped: straight pass-through.
				next.ServeHTTP(w, r)
				return
			}
			gated.ServeHTTP(w, r)
		})
	}
}

// resolveFn is the device-proof seam the lockdown gate calls; production passes
// DeviceCredentialResolver.Resolve (with userID from context), tests pass a stub.
type resolveFn func(ctx context.Context, r *http.Request) (bound bool, deviceID int64, state string)

// deviceLockdownGate is the strict CA-2 gate. It blocks unenrolled/unbound
// devices when both feature.conditional_access AND feature.device_lockdown are
// on (BZ095 403).
//
// Build-gate (locked decision 9): it hard-refuses to enforce — short-circuiting
// to pass-through with a loud warn — unless the CA-0a break-glass exclude list
// is present and non-empty, so a global lockdown can NEVER lock out every admin.
//
// Gate logic (spec §12 table):
//   - either toggle OFF → pass-through.
//   - both ON but checkBreakGlass returns setPresent=false → pass-through + WARN (Decision 9).
//   - both ON + set present + user ∈ break-glass → pass-through (break-glass exempt).
//   - both ON + set present + user ∉ break-glass: bound+approved → 200; else → 403 BZ095.
func deviceLockdownGate(toggles toggleChecker, resolve resolveFn, checkBreakGlass func(context.Context, int64) (setPresent bool, member bool), logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if toggles == nil ||
				!toggles.IsEnabled(toggle.FeatureConditionalAccess) ||
				!toggles.IsEnabled(toggle.FeatureDeviceLockdown) {
				next.ServeHTTP(w, r)
				return
			}
			var userID int64
			if c := auth.UserFromContext(r.Context()); c != nil {
				userID = c.UserID
			}
			setPresent, isMember := checkBreakGlass(r.Context(), userID)
			// Build-gate (Decision 9): refuse to enforce if break-glass set absent/empty.
			if !setPresent {
				logger.Warn("device lockdown ON but break-glass exclude list absent — refusing to enforce (pass-through)")
				next.ServeHTTP(w, r)
				return
			}
			// Break-glass exemption: authenticated break-glass admin bypasses lockdown.
			if isMember {
				next.ServeHTTP(w, r)
				return
			}
			bound, deviceID, state := resolve(r.Context(), r)
			if bound && state == "approved" {
				next.ServeHTTP(w, r)
				return
			}
			logger.Warn("device lockdown: blocked unenrolled/unbound device",
				"device_id", deviceID, "state", state)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"title":  "Forbidden",
				"status": http.StatusForbidden,
				"code":   "BZ095",
				"detail": "device not enrolled — contact your administrator",
			})
		})
	}
}

// DeviceLockdownGate is the exported strict CA-2 gate for use in main.go.
// It layers AFTER DeviceTrustGate (quarantine/wipe) on the authenticated chain.
// Both feature.conditional_access AND feature.device_lockdown must be ON (both
// registry-default OFF) to enforce; this middleware checks both, ensuring
// device_lockdown cannot enforce while conditional_access is off.
//
// checkBreakGlass is a per-request membership probe returning (setPresent, member).
// setPresent=false when the CA-0a break-glass list is absent/empty (Decision 9:
// refuse to enforce). member=true when the authenticated user is in the set
// (break-glass exempt from lockdown). Typically:
//
//	func(ctx context.Context, userID int64) (bool, bool) {
//	    var raw []byte
//	    if err := pool.QueryRow(ctx,
//	        `SELECT value FROM system_config
//	          WHERE key = 'ca_break_glass_user_ids'`).Scan(&raw); err != nil || len(raw) == 0 {
//	        return false, false
//	    }
//	    var ids []int64
//	    if json.Unmarshal(raw, &ids) != nil || len(ids) == 0 { return false, false }
//	    for _, id := range ids { if id == userID { return true, true } }
//	    return true, false
//	}
func DeviceLockdownGate(toggles toggleChecker, resolver *threat.DeviceCredentialResolver, checkBreakGlass func(context.Context, int64) (bool, bool), logger *slog.Logger) func(http.Handler) http.Handler {
	// Close over resolver.Resolve, adapting the 3-arg signature to resolveFn by
	// reading userID from the request context (set by RequireAuth upstream).
	// ponytail: if no claims in context (unauthenticated path), userID is 0 →
	// device ownership check in Resolve returns false → fails closed (403).
	resolve := func(ctx context.Context, r *http.Request) (bool, int64, string) {
		var userID int64
		if c := auth.UserFromContext(ctx); c != nil {
			userID = c.UserID
		}
		return resolver.Resolve(ctx, r, userID)
	}
	return deviceLockdownGate(toggles, resolve, checkBreakGlass, logger)
}
