package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

// LogSlowRequests returns middleware that logs a warning for any request
// exceeding the threshold. The request_id from the context is included in
// the log line so all related logs can be correlated with grep.
func LogSlowRequests(logger *slog.Logger, threshold time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next.ServeHTTP(w, r)
			if d := time.Since(start); d > threshold {
				logger.Warn("slow request",
					"path", r.URL.Path,
					"method", r.Method,
					"duration_ms", d.Milliseconds(),
					"request_id", GetRequestID(r.Context()),
				)
			}
		})
	}
}
