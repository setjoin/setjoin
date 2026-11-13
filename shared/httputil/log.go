package httputil

import (
	"context"
	"log/slog"
	"strings"

	"setjoin.com/shared/middleware"
)

// LogAttrs returns the standard log attributes for an authenticated or
// anonymous request. Use with slog.*Context calls to ensure every log
// line carries request_id and user_id.
//
//	slog.ErrorContext(ctx, "msg", LogAttrs(ctx, userID, "error", err)...)
func LogAttrs(ctx context.Context, userID string, extra ...any) []any {
	out := make([]any, 0, 4+len(extra))
	out = append(out, "request_id", middleware.GetRequestID(ctx))
	if userID == "" {
		userID = "anon"
	}
	out = append(out, "user_id", userID)
	out = append(out, extra...)
	return out
}

// LogError is a shorthand for slog.ErrorContext with standard attrs.
func LogError(ctx context.Context, msg string, userID string, attrs ...any) {
	slog.ErrorContext(ctx, msg, LogAttrs(ctx, userID, attrs...)...)
}

// LogWarn is a shorthand for slog.WarnContext with standard attrs.
func LogWarn(ctx context.Context, msg string, userID string, attrs ...any) {
	slog.WarnContext(ctx, msg, LogAttrs(ctx, userID, attrs...)...)
}

// LogInfo is a shorthand for slog.InfoContext with standard attrs.
func LogInfo(ctx context.Context, msg string, userID string, attrs ...any) {
	slog.InfoContext(ctx, msg, LogAttrs(ctx, userID, attrs...)...)
}

// RedactEmail truncates an email address to u***@domain for safe logging.
// Example: "user@example.com" becomes "u***@example.com".
func RedactEmail(email string) string {
	if email == "" {
		return ""
	}
	at := strings.IndexByte(email, '@')
	if at <= 0 {
		return "***"
	}
	local := email[:at]
	domain := email[at:]
	if len(local) == 1 {
		return local + "***" + domain
	}
	return local[:1] + "***" + domain
}

// RedactedString is a slog.LogValuer that masks its value in logs.
// Use it when passing sensitive data (passwords, tokens, secrets) as
// log attributes.
//
//	slog.Info("request", "token", httputil.RedactedString(token))
type RedactedString string

// LogValue returns a redacted slog.Value to prevent sensitive data from
// appearing in log output.
func (RedactedString) LogValue() slog.Value {
	return slog.StringValue("***REDACTED***")
}
