// Package middleware provides shared HTTP middleware consumed by both servers.
package middleware

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
)

type requestIDKey struct{}

// maxRequestID is the maximum length accepted for an inbound X-Request-ID.
const maxRequestID = 64

// RequestID is an HTTP middleware that propagates X-Request-ID headers.
// Inbound X-Request-ID values are validated: they must be at most 64
// characters and contain only printable, non-whitespace characters.
// Values that fail validation are discarded and a fresh UUID v4 is
// generated instead, preventing trace poisoning and log-volume abuse.
// The ID is set on the response header and stored in the context.
// Additionally, a child *slog.Logger with "request_id" pre-attached is
// placed into the context so every downstream log line automatically
// carries the request ID.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = uuid.NewString()
		} else if !isValidRequestID(id) {
			// Reject spoofed / non-conforming IDs: regenerate.
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), requestIDKey{}, id)
		logger := slog.Default().With("request_id", id)
		ctx = context.WithValue(ctx, ctxKeyLogger, logger)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// isValidRequestID returns true if s is a safe request ID:
// at most maxRequestID bytes, no control characters, no whitespace.
func isValidRequestID(s string) bool {
	if len(s) > maxRequestID {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b <= 32 || b == 127 {
			return false
		}
	}
	return true
}

type loggerKey struct{}

var ctxKeyLogger = loggerKey{}

// GetRequestID extracts the request ID from a context. Returns empty string
// if no RequestID middleware was applied to this request.
func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey{}).(string); ok {
		return id
	}
	return ""
}

// LoggerFromContext returns a *slog.Logger with "request_id" pre-attached.
// Returns slog.Default() if the context lacks a logger (e.g. background
// tasks or startup code before the HTTP server is running).
func LoggerFromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(ctxKeyLogger).(*slog.Logger); ok {
		return logger
	}
	return slog.Default()
}
