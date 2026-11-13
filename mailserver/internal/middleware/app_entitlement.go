package middleware

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// appEntitlementChecker is the interface RequireApp uses to check per-app access.
// Implementations must be safe for concurrent use.
// userID is the authenticated user's ID from JWT claims.
// Returns true when the user may access the app, false to block with 403.
type appEntitlementChecker interface {
	Allowed(ctx context.Context, userID int64, app string) bool
}

// entitlementAuditor is an optional interface that appEntitlementChecker
// implementations may also satisfy.  When the checker implements it, RequireApp
// calls WriteBlockedAudit after writing the 403 response so the denial is
// recorded in admin_audit_log (action='app_blocked', target_type='app', notes=app).
type entitlementAuditor interface {
	WriteBlockedAudit(ctx context.Context, userID int64, ip, app string)
}

// RequireApp returns HTTP middleware that enforces per-app entitlement.
// When the caller's entitlement is denied the middleware writes an RFC 9457
// Problem (403 Forbidden) and does NOT call the next handler.
// When denied, the block is also written to the admin audit log if the checker
// implements entitlementAuditor (PoolEntitlementChecker always does).
//
// The middleware expects auth.UserFromContext to be populated (i.e. RequireAuth
// must run first on the same route). If no user is found in context the
// middleware returns 401.
func RequireApp(checker appEntitlementChecker, logger *slog.Logger, app string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := auth.UserFromContext(r.Context())
			if claims == nil {
				httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			if !checker.Allowed(r.Context(), claims.UserID, app) {
				logger.Info("app entitlement blocked",
					"user_id", claims.UserID,
					"app", app,
					"path", r.URL.Path,
				)
				httputil.WriteProblem(w, r, httputil.NewForbiddenProblem(
					"Access to this application is not permitted for your account.",
				))
				// Write audit log if the checker supports it (PoolEntitlementChecker does).
				if auditor, ok := checker.(entitlementAuditor); ok {
					auditor.WriteBlockedAudit(r.Context(), claims.UserID, httputil.ClientIP(r), app)
				}
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type appFeatureToggle interface {
	IsEnabled(string) bool
}

// RequireAppFeatureFirst preserves the app handlers' toggle-OFF 404 contract
// while inserting RequireApp before route dispatch.
func RequireAppFeatureFirst(toggles appFeatureToggle, feature string, checker appEntitlementChecker, logger *slog.Logger, app string) func(http.Handler) http.Handler {
	requireApp := RequireApp(checker, logger, app)
	return func(next http.Handler) http.Handler {
		entitled := requireApp(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !toggles.IsEnabled(feature) {
				httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
				return
			}
			entitled.ServeHTTP(w, r)
		})
	}
}

// PoolEntitlementChecker implements appEntitlementChecker using the PostgreSQL
// user-id entitlement reducer, including for mailbox-less guests.
type PoolEntitlementChecker struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewPoolEntitlementChecker creates a PoolEntitlementChecker backed by the given pool.
func NewPoolEntitlementChecker(pool *pgxpool.Pool, logger *slog.Logger) *PoolEntitlementChecker {
	return &PoolEntitlementChecker{pool: pool, logger: logger}
}

// Allowed calls check_user_app_entitlement directly with the authenticated user id.
// Returns false (fail-closed / 403) on any DB error — pool exhaustion, timeout,
// or network blip — to prevent an attacker from bypassing entitlement checks by
// causing DB unavailability.
func (c *PoolEntitlementChecker) Allowed(ctx context.Context, userID int64, app string) bool {
	var allowed bool
	if err := c.pool.QueryRow(ctx,
		`SELECT check_user_app_entitlement($1, $2)`, userID, app,
	).Scan(&allowed); err != nil {
		c.logger.Warn("app entitlement: reducer error, fail-closed",
			"user_id", userID, "app", app, "error", err)
		return false
	}
	return allowed
}

// WriteBlockedAudit implements entitlementAuditor.  It writes one row to
// admin_audit_log recording the 403 denial so administrators can audit which
// users are being blocked from which apps.
//
//	action      = 'app_blocked'
//	target_type = 'app'
//	notes       = <app name>
//
// Errors are logged at Warn level and ignored (audit is best-effort).
// ponytail: tier=routine — app_blocked is informational; suppressed at lean.
func (c *PoolEntitlementChecker) WriteBlockedAudit(ctx context.Context, userID int64, ip, app string) {
	if err := audit.Write(ctx, c.pool, audit.Entry{
		Actor: userID, Action: "app_blocked", TargetType: "app",
		Notes: app, IP: ip, Tier: audit.TierForAction("app_blocked"),
	}); err != nil {
		c.logger.Warn("app entitlement: failed to write audit log",
			"user_id", userID, "app", app, "error", err)
	}
}
