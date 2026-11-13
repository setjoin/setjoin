// Package auth defines the shared authentication contract consumed by middleware
// and implemented by each service's concrete auth chain. This is the seam that
// lets RequireAuth (the authn-only wrapper; authorization is solely via
// RequirePermAudited on each route — the enum-role RequireAdmin/RequireRole
// wrappers were removed in the RBAC cut-over) work across authserver, mailserver,
// and future services without importing any service-specific code.
package auth

import (
	"context"
	"net/http"

	"setjoin.com/shared/jwtutil"
)

// Authenticator validates an HTTP request and returns the resolved Claims.
// Each service supplies its own implementation (JWT + Kerberos in mailserver,
// JWT only in authserver, etc.). The shared middleware depends on this
// interface, not on any concrete chain type.
type Authenticator interface {
	Authenticate(ctx context.Context, r *http.Request) (*jwtutil.Claims, error)
}
