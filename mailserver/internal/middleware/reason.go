// Package middleware — reason.go enforces the X-Audit-Reason header for
// sensitive write operations whose area is in audit_policy.reason_required_areas.
//
// RequireReason wraps a handler: for a permission whose area
// (strings.SplitN(perm,".",2)[0]) is in the policy's required list, a missing
// or empty X-Audit-Reason header → 400 + a core "sensitive_action.reason_missing"
// audit row (always committed, never lost).  A present reason is placed in the
// request context for the downstream handler via ReasonFromContext.
package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// ctxKeyReason is the unexported context key for the audit reason string.
type ctxKeyReason struct{}

// ReasonFromContext returns the X-Audit-Reason value placed by RequireReason,
// or "" if the middleware was not applied or the area was out-of-scope.
func ReasonFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyReason{}).(string)
	return v
}

// RequireReason returns middleware that enforces an X-Audit-Reason header for
// any permission whose area (the dot-prefix) is listed in
// audit_policy.reason_required_areas (id=1).
//
// On missing reason: writes a core "sensitive_action.reason_missing" row via
// WriteAutonomous (committed independently) and returns 400.
// On present reason: puts it in the request context and calls next.
// Out-of-scope areas: passed through unconditionally, no DB side-effect.
//
// The policy row is fetched once per request (single lightweight query).
// ponytail: no cache — singleton-by-PK query is trivial; admin writes are low-frequency.
func RequireReason(perm string, pool *pgxpool.Pool) func(http.Handler) http.Handler {
	area := strings.SplitN(perm, ".", 2)[0]
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Load the required-areas list fresh each request so policy changes
			// take effect without a restart.
			var areas []string
			if err := pool.QueryRow(r.Context(),
				`SELECT reason_required_areas FROM audit_policy WHERE id=1`,
			).Scan(&areas); err != nil {
				// DB error: fail open (don't block every admin write on a transient blip).
				next.ServeHTTP(w, r)
				return
			}

			required := false
			for _, a := range areas {
				if a == area {
					required = true
					break
				}
			}
			if !required {
				next.ServeHTTP(w, r)
				return
			}

			reason := r.Header.Get("X-Audit-Reason")
			if reason == "" {
				// Write a core audit row — denied-for-missing-reason must leave a
				// durable trace. WriteAutonomous commits independently of any tx.
				claims := auth.UserFromContext(r.Context())
				var actor int64
				if claims != nil {
					actor = claims.UserID
				}
				_ = audit.WriteAutonomous(r.Context(), pool, audit.Entry{
					Actor:  actor,
					Action: "sensitive_action.reason_missing",
					IP:     httputil.ClientIP(r),
					Notes:  perm,
					Tier:   "core",
				})
				httputil.WriteProblemStatus(w, http.StatusBadRequest, "reason_required")
				return
			}

			// Attach reason to context for the downstream handler.
			ctx := context.WithValue(r.Context(), ctxKeyReason{}, reason)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
