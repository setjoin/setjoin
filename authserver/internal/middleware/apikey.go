package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"setjoin.com/shared/httputil"
)

// RequireAPIKey returns middleware that validates requests carry a
// Bearer token matching the configured INTERNAL_API_KEY.
func RequireAPIKey(apiKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if apiKey == "" {
				httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal API key not configured")
				return
			}
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				httputil.WriteProblemStatus(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			token := strings.TrimPrefix(auth, "Bearer ")
			if subtle.ConstantTimeCompare([]byte(token), []byte(apiKey)) != 1 {
				httputil.WriteProblemStatus(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
