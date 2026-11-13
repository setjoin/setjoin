package auth

import (
	"net/http"

	"setjoin.com/shared/httputil"
)

// RequireUser returns the authenticated Claims from the request context, or
// writes a 401 problem+json response and returns nil if none is present.
// Handlers use it to fold the auth-gate nil-check into two lines:
//
//	claims := auth.RequireUser(w, r)
//	if claims == nil {
//		return
//	}
func RequireUser(w http.ResponseWriter, r *http.Request) *Claims {
	claims := UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return nil
	}
	return claims
}
