package middleware

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"setjoin.com/shared/clientip"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
)

// RuntimeAccessDeps are the collaborators for the per-request runtime spine.
type RuntimeAccessDeps struct {
	Claims   ClaimsFunc
	Denylist *threat.SessionDenylist
	Engine   *threat.PolicyEngine
	Toggles  *toggle.FeatureFlags
	Replay   *threat.DPoPReplayCache
	Logger   *slog.Logger
	// ContextWithLimitedWeb, when non-nil, is called to inject a limited_web
	// projection into the request context (capability cut: no attachment download /
	// no external auto-forward). Optional; absence is a no-op.
	ContextWithLimitedWeb func(context.Context, bool) context.Context

	// GroupResolver, if non-nil, resolves the directory group IDs for a user
	// (used to populate PolicyEvalContext.GroupIDs for group-scoped CA policies).
	// Wire with a closure over threat.ResolveUserGroups in production; nil = skip.
	GroupResolver func(ctx context.Context, userID int64) []int64
	// RoleGroupResolver, if non-nil, resolves admin role-group IDs for a user
	// (used to populate PolicyEvalContext.RoleGroupIDs for role-scoped CA policies).
	// Wire with a closure over threat.ResolveRoleGroups in production; nil = skip.
	RoleGroupResolver func(ctx context.Context, userID int64) []int64
	// CountryFunc, if non-nil, resolves the ISO-3166-1 alpha-2 country code for
	// a client IP (used to populate PolicyEvalContext.Country for geo-scoped policies).
	// Wire with a closure over geoip2.Reader in production; nil = empty country.
	CountryFunc func(ip string) string
	// TermsPendingResolver, if non-nil, checks whether a user has an unaccepted
	// enabled ToU at the given touID. Returns (touID, pending=true) when acceptance
	// is still required. Used to allow require_terms blocks only when the ToU is
	// genuinely pending (so a user who has already accepted is not blocked again).
	// nil dep => fail-closed (treat as pending, i.e. block).
	TermsPendingResolver func(ctx context.Context, userID int64, touID int64) (pending bool)
}

func denyJSON(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "about:blank", "title": code, "detail": detail, "status": status})
}

// denyJSONAdmission writes a 401 whose body carries the machine-readable
// problem `code` marking a DPoP/token-binding ADMISSION refusal
// (threat.DPoPAdmissionCode). The webmail client's per-tab recovery keys on
// this member — and on it alone — to decide a proof-signed replay is safe;
// every other deny shape (revocation, sign-in-frequency, step-up) stays
// marker-free so an application-level refusal never replays.
func denyJSONAdmission(w http.ResponseWriter, code, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": "about:blank", "title": code, "detail": detail,
		"status": http.StatusUnauthorized, "code": threat.DPoPAdmissionCode,
	})
}

// denyJSONRemediation writes a 403 with CA-3b remediation fields so the SPA
// can act on the block rather than showing a dead-end error screen.
func denyJSONRemediation(w http.ResponseWriter, detail, remediation string, touID int64) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusForbidden)
	body := map[string]any{"type": "about:blank", "title": "access_blocked", "detail": detail, "status": http.StatusForbidden, "remediation": remediation}
	if touID != 0 {
		body["remediation_tou_id"] = touID
	}
	_ = json.NewEncoder(w).Encode(body)
}

// RequireRuntimeAccess re-evaluates conditional access per request: denylist →
// token-binding → sign-in-frequency → fresh policy re-eval → limited_web.
//
// Constructor contract (fail loud at wiring time, never mid-request):
//   - nil Claims function is a wiring defect → panics here, at construction
//     (every request would otherwise nil-deref inside the handler);
//   - nil Logger falls back to slog.Default() instead of nil-deref;
//   - nil Replay with token binding ON fails CLOSED per request (401), never
//     a nil deref inside VerifyDPoP.
//
// Positive durable session-revocation matches are authoritative even before
// the first full reconcile and while feature.cae_runtime is OFF. Loaded state
// is needed only to trust a negative lookup. This makes live security/lifecycle
// revocations effective during staged CAE rollout and a degraded cold start.
// The toggle still controls fail-closed denylist availability, token binding,
// session controls, policy re-evaluation, and limited_web projection.
// Fail-closed contract:
//   - nil denylist → 401 (cannot verify revocation state)
//   - denylist not yet loaded (cold-start) → 401
//   - known-revoked session → 401
//   - nil Replay with DPoP binding active → 401 (cannot verify single-use jti)
//   - unverifiable DPoP proof (when binding on) → 401
//   - sif/idle exceeded → 401 + WWW-Authenticate: reauth
//   - SignInFreq-bearing token with NO temporal anchor (neither auth_time nor
//     iat) → 401 + WWW-Authenticate: reauth (fail closed; a timer that cannot
//     be evaluated must not silently pass)
//   - policy re-eval block/step-up → 403/401 (nil engine = fail-open; engine error = fail-open)
//   - require_terms block with no tou_id (RemediationTermsID==0) → 403 (a malformed
//     terms policy must DENY, never resolve/allow — the resolver(uid,0) fail-open)
//
// Break-glass / exclude principals are exempted from policy re-eval (the engine
// short-circuits before any fail-closed branch; isBreakGlass is internal to PolicyEngine).
func RequireRuntimeAccess(deps RuntimeAccessDeps) func(http.Handler) http.Handler {
	if deps.Claims == nil {
		panic("middleware: RequireRuntimeAccess requires a non-nil Claims function (every request must resolve its auth claims)")
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			caeEnabled := deps.Toggles != nil &&
				deps.Toggles.IsEnabled(toggle.FeatureCAERuntime)
			claims := deps.Claims(r)
			if claims == nil && caeEnabled {
				denyJSON(w, http.StatusUnauthorized, "Unauthorized", "Authentication required.")
				return
			}

			// 1. Denylist. A positive lookup is authoritative even when the
			// denylist is not yet complete: Apply may already have delivered a
			// live revocation after a failed startup refresh. Loaded only governs
			// whether a negative lookup can be trusted.
			if claims != nil && deps.Denylist != nil {
				iat := time.Time{}
				if claims.IssuedAt != nil {
					iat = claims.IssuedAt.Time
				}
				if deps.Denylist.IsRevoked(claims.UserID, claims.JTI, claims.RefreshFamilyID(), iat) {
					deps.Logger.Info("runtime access: session revoked",
						"user_id", claims.UserID, "jti", claims.JTI)
					denyJSON(w, http.StatusUnauthorized, "session_revoked", "Session has been revoked. Sign in again.")
					return
				}
			}
			if !caeEnabled {
				next.ServeHTTP(w, r)
				return
			}

			// With CAE enabled, nil/unloaded denylist state also fails closed.
			// ponytail: nil Denylist is fail-closed (not skip) — the feature is on,
			// we cannot verify revocation state, so we must deny.
			if deps.Denylist == nil {
				deps.Logger.Warn("runtime access: nil denylist — denying (fail-closed)", "user_id", claims.UserID)
				denyJSON(w, http.StatusUnauthorized, "session_revoked", "Session verification unavailable — re-authenticate.")
				return
			}
			if !deps.Denylist.Loaded() {
				// Cold-start safety: we cannot prove there are no revocations.
				deps.Logger.Warn("runtime access: denylist not yet loaded — denying (cold-start fail-closed)",
					"user_id", claims.UserID)
				denyJSON(w, http.StatusUnauthorized, "session_revoked", "Session verification unavailable — re-authenticate.")
				return
			}
			// 2. Token binding (only when token is bound + feature on).
			if claims.Cnf != nil && claims.Cnf.JKT != "" &&
				deps.Toggles.IsEnabled(toggle.FeatureTokenBinding) {
				// Fail closed on a miswired replay cache: a nil Replay would
				// nil-deref inside VerifyDPoP (jti single-use check) — a
				// 500-amplifier on an attacker-influenced header. Without the
				// cache the proof's single-use property cannot be verified,
				// so the bound request is denied.
				if deps.Replay == nil {
					deps.Logger.Warn("runtime access: DPoP binding active but replay cache not wired — denying (fail-closed)",
						"user_id", claims.UserID)
					denyJSONAdmission(w, "token_binding_failed", "Token binding verification failed.")
					return
				}
				proof := r.Header.Get("DPoP")
				htu := "https://" + r.Host + dpopExternalPath(r)
				if err := threat.VerifyDPoP(proof, r.Method, htu, claims.Cnf.JKT, time.Now(), deps.Replay); err != nil {
					deps.Logger.Warn("runtime access: DPoP proof failed",
						"user_id", claims.UserID, "error", err)
					denyJSONAdmission(w, "token_binding_failed", "Token binding verification failed.")
					return
				}
			}

			// 3. Sign-in frequency / idle.
			if claims.SignInFreq != nil {
				var authenticatedAt time.Time
				if claims.SessionAuthTime != nil {
					authenticatedAt = time.Unix(*claims.SessionAuthTime, 0)
				} else if claims.IssuedAt != nil {
					// Rolling-upgrade compatibility for access tokens minted
					// before auth_time existed.
					authenticatedAt = claims.IssuedAt.Time
				}
				if authenticatedAt.IsZero() {
					// Fail closed: a SignInFreq-bearing token with NEITHER
					// auth_time nor iat carries no temporal anchor, so the
					// sign-in-frequency timer cannot be evaluated. This
					// inverts the fail-open a zero anchor previously produced
					// (timer silently skipped) and matches the package's
					// zero-iat denylist convention. Tokens are signed, so a
					// client cannot strip the claims; an anchor-less token
					// can only come from an issuer defect — re-auth fixes it.
					deps.Logger.Warn("runtime access: sign-in-frequency token has no auth_time or iat — denying (fail-closed)",
						"user_id", claims.UserID)
					w.Header().Set("WWW-Authenticate", "reauth")
					denyJSON(w, http.StatusUnauthorized, "sign_in_frequency", "Session expired — re-authenticate.")
					return
				}
				if time.Since(authenticatedAt) > time.Duration(*claims.SignInFreq)*time.Second {
					w.Header().Set("WWW-Authenticate", "reauth")
					denyJSON(w, http.StatusUnauthorized, "sign_in_frequency", "Session expired — re-authenticate.")
					return
				}
			}

			// 4. Fresh policy re-eval (nil engine = fail-open; engine errors = fail-open via Engine internals).
			if deps.Engine != nil {
				clientIP := runtimeClientIP(r)
				// Thread the real auth method from the token; fall back to "jwt_bearer" for
				// pre-CA tokens that predate the auth_method claim (omitempty).
				am := claims.AuthMethod
				if am == "" {
					am = "jwt_bearer"
				}
				pectx := threat.PolicyEvalContext{
					UserID: claims.UserID,
					// Mailserver auth.Chain.applyGuestBelt has already re-derived
					// AccountType from guest_accounts for this request. This is an
					// authoritative post-belt claim, not raw token trust.
					IsGuest:             claims.IsGuest(),
					SourceIP:            clientIP,
					AuthMethod:          am,
					Protocol:            threat.ProtocolHTTP,
					UserAgent:           r.UserAgent(),
					RequestTime:         time.Now(),
					CurrentACR:          claims.ACR,
					RevocationSensitive: true, // skip the decision cache (CA-3a must not serve stale revocation verdicts)
					DeviceFP:            threat.MakeDeviceFP(r.UserAgent(), clientIP),
				}
				// Populate RiskLevel from the JWT Risk claim so require_risk_remediation
				// can compare against the user's actual risk band rather than always blocking.
				if claims.Risk != nil {
					pectx.RiskLevel = claims.Risk.Level
				}
				if deps.GroupResolver != nil {
					pectx.GroupIDs = deps.GroupResolver(r.Context(), claims.UserID)
				}
				if deps.RoleGroupResolver != nil {
					pectx.RoleGroupIDs = deps.RoleGroupResolver(r.Context(), claims.UserID)
				}
				if deps.CountryFunc != nil {
					pectx.Country = deps.CountryFunc(clientIP)
				}
				result, satisfied := deps.Engine.EvaluateTokenACR(r.Context(), pectx)
				if !satisfied {
					if result.Decision == threat.DecisionBlock {
						if result.Remediation == "terms" {
							// Fail-CLOSED on a malformed require_terms decision: a terms block
							// whose policy carries no tou_id arrives with RemediationTermsID==0.
							// Calling TermsPendingResolver(uid, 0) matches no terms_of_use row,
							// so pending resolves false and EVERY request is let through — the
							// fail-OPEN this guard closes. The runtime gate is require_terms's
							// SOLE enforcement point (login defers it here), so deny here; never
							// resolve/allow on a tou_id-less terms block.
							if result.RemediationTermsID == 0 {
								denyJSONRemediation(w, result.Reason, result.Remediation, 0)
								return
							}
							// Check whether the caller has already accepted this ToU.
							// nil resolver → fail-closed (treat as pending → block).
							pending := true
							if deps.TermsPendingResolver != nil {
								pending = deps.TermsPendingResolver(r.Context(), claims.UserID, result.RemediationTermsID)
							}
							if !pending {
								// Accepted → allow this request; the policy is cleared.
								next.ServeHTTP(w, r)
								return
							}
							denyJSONRemediation(w, result.Reason, result.Remediation, result.RemediationTermsID)
							return
						}
						denyJSONRemediation(w, result.Reason, result.Remediation, 0)
						return
					}
					// step_up or other non-allow → force re-auth.
					w.Header().Set("WWW-Authenticate", "reauth")
					denyJSON(w, http.StatusUnauthorized, "step_up_required", result.Reason)
					return
				}
				// 5. limited_web capability projection.
				if result.LimitedWeb && deps.ContextWithLimitedWeb != nil {
					r = r.WithContext(deps.ContextWithLimitedWeb(r.Context(), true))
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// dpopExternalPath returns the path the client actually signed. Mounts such as
// http.StripPrefix mutate URL.Path before inner middleware runs, while
// RequestURI retains the original externally visible target.
func dpopExternalPath(r *http.Request) string {
	if r.RequestURI != "" {
		if target, err := url.ParseRequestURI(r.RequestURI); err == nil && target.Path != "" {
			return target.EscapedPath()
		}
	}
	return r.URL.EscapedPath()
}

// runtimeClientIP extracts the source IP for policy evaluation via the shared
// clientip leaf package — the same X-Forwarded-For trust boundary as
// httputil.ClientIP and threatClientIP (was inlined here to dodge the
// httputil↔middleware import cycle; the leaf package resolves it).
func runtimeClientIP(r *http.Request) string {
	return clientip.Extract(r)
}
