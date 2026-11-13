package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"setjoin.com/shared/jwtutil"
)

// ClaimsFunc extracts JWT claims from the request. The caller provides
// the function — typically auth.UserFromContext in mailserver or the
// equivalent in authserver.
type ClaimsFunc func(r *http.Request) *jwtutil.Claims

// LegacyTokenClass is one explicitly inventoried class of claim-less
// (pre-device-claim) tokens that the device-compliance gate tolerates only
// until its contracted retirement cutoff.
//
// The class inventory and each cutoff value are an explicitly PROPOSED
// rollout/product contract — no documented retirement deadline exists in the
// record. This type is the enforcement mechanism, not the decision: a class
// enters enforcement only when an operator names it here with a cutoff.
type LegacyTokenClass struct {
	// Name identifies the class in logs and tests (e.g.
	// "pre-enrollment-access"). Purely diagnostic.
	Name string
	// Match reports whether a claim-less token belongs to this class. It is
	// called only with non-nil claims whose Device claim is nil, so it can
	// classify on any remaining claim surface (token type, issuer, ACR, …).
	Match func(claims *jwtutil.Claims) bool
	// Cutoff is the contracted retirement deadline. At and after Cutoff the
	// class no longer passes the gate and requests fail closed (403); the
	// boundary is inclusive (Cutoff itself is retired). A zero Cutoff means
	// the class is never allowed — a class without an explicit deadline is
	// misconfigured and fails closed.
	Cutoff time.Time
}

// LegacyTokenPolicy is the explicit token-class/cutoff contract governing
// claim-less (nil Device) tokens at RequireDeviceCompliance.
//
// Fail-closed contract:
//   - nil policy, no matching class, or a zero-cutoff class → 403
//   - matching class whose Cutoff is in the future → pass (the residual
//     window the class contract explicitly accepts; claim-less tokens carry
//     no verifiable wipe/quarantine state inside it)
//   - matching class at/after its Cutoff → 403
//
// Legacy refresh rotation alone NEVER establishes retirement: no rotation
// signal (fresh IssuedAt, refresh-family id, …) grants passage or exemption.
// Only an explicit Cutoff removes a class from enforcement, so a class stays
// blocked at its deadline even for tokens freshly rotated after it.
type LegacyTokenPolicy struct {
	Classes []LegacyTokenClass
	// Now is the clock seam used to evaluate Cutoff. Nil means time.Now.
	// Tests inject a fixed clock to simulate across the cutoff boundary.
	Now func() time.Time
}

// now resolves the policy clock; safe on a nil policy.
func (p *LegacyTokenPolicy) now() time.Time {
	if p == nil || p.Now == nil {
		return time.Now()
	}
	return p.Now()
}

// classify returns the first inventoried class whose Match accepts the
// claim-less token, or nil when the token belongs to no class (fail closed).
func (p *LegacyTokenPolicy) classify(claims *jwtutil.Claims) *LegacyTokenClass {
	if p == nil {
		return nil
	}
	for i := range p.Classes {
		if p.Classes[i].Match != nil && p.Classes[i].Match(claims) {
			return &p.Classes[i]
		}
	}
	return nil
}

// RequireDeviceCompliance gates requests on device trust tier and wipe state.
// Reads claims from the provided ClaimsFunc. If claims are nil, returns 401.
// If the device is quarantined or has been wiped, returns 403.
//
// A token without a Device claim carries no verifiable wipe/quarantine state,
// so it FAILS CLOSED with 403 unless it belongs to an explicitly inventoried
// legacy token class whose contracted cutoff has not passed. Use
// RequireDeviceComplianceWithLegacyPolicy to admit such classes; the bare
// constructor runs with an empty policy (every claim-less token blocked).
//
// No database call, no network call — the JWT claims are the single source
// of truth for device compliance state at request time.
func RequireDeviceCompliance(claimsFn ClaimsFunc, logger *slog.Logger) func(http.Handler) http.Handler {
	return RequireDeviceComplianceWithLegacyPolicy(claimsFn, nil, logger)
}

// RequireDeviceComplianceWithLegacyPolicy is RequireDeviceCompliance with an
// explicit LegacyTokenPolicy: claim-less tokens matching an inventoried class
// pass only while that class's contracted cutoff is in the future; everything
// else fails closed exactly as the bare constructor does.
func RequireDeviceComplianceWithLegacyPolicy(claimsFn ClaimsFunc, policy *LegacyTokenPolicy, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := claimsFn(r)
			if claims == nil {
				denyJSON(w, http.StatusUnauthorized, "Unauthorized", "Authentication required.")
				return
			}

			// Fail closed: a claim-less token cannot prove compliance (no
			// wipe/quarantine state to read), so it passes only inside an
			// explicitly contracted legacy-class window. No rotation signal
			// can exempt it — only the class cutoff governs.
			if claims.Device == nil {
				class := policy.classify(claims)
				if class == nil || !policy.now().Before(class.Cutoff) {
					logger.Warn("device compliance: claim-less token blocked (no in-window legacy class)",
						"user_id", claims.UserID,
						"token_type", claims.Type,
					)
					denyJSON(w, http.StatusForbidden, "device_compliance_unverifiable",
						"Device compliance could not be verified from this token. Sign in again from your device.")
					return
				}
				logger.Info("device compliance: legacy claim-less token class allowed until cutoff",
					"legacy_class", class.Name,
					"cutoff", class.Cutoff.Format(time.RFC3339),
					"user_id", claims.UserID,
					"token_type", claims.Type,
				)
				next.ServeHTTP(w, r)
				return
			}

			if claims.Device.WipeRequested {
				logger.Warn("device compliance: device has been wiped",
					"device_id", claims.Device.ID,
					"user_id", claims.UserID,
				)
				denyJSON(w, http.StatusForbidden, "Forbidden", "Device has been wiped. Contact your administrator.")
				return
			}

			if claims.Device.TrustTier == jwtutil.TrustTierQuarantined {
				logger.Warn("device compliance: device is quarantined",
					"device_id", claims.Device.ID,
					"user_id", claims.UserID,
					"compliance_status", claims.Device.ComplianceStatus,
				)
				denyJSON(w, http.StatusForbidden, "Forbidden", "Device is quarantined. Check compliance status in device settings.")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
