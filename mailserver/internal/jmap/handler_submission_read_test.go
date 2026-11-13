package jmap

import (
	"context"
	"encoding/json"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/pgxutil"
)

func TestEmailSubmissionGetQueryRegistered(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	for _, m := range []string{"EmailSubmission/get", "EmailSubmission/query"} {
		if _, ok := h.methods[m]; !ok {
			t.Errorf("%s not registered", m)
		}
	}
}

// With a nil pool, get/query must still validate accountId and fail cleanly
// rather than panic — table-driven over the argument-validation paths.
func TestEmailSubmissionReadArgValidation(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	user := &auth.Claims{UserID: 1, Email: "test@example.com"}

	tests := []struct {
		name   string
		method func(context.Context, *auth.Claims, json.RawMessage) (string, json.RawMessage)
		args   string
	}{
		{"get missing accountId", h.emailSubmissionGet, `{}`},
		{"get mismatched accountId", h.emailSubmissionGet, `{"accountId":"999"}`},
		{"query missing accountId", h.emailSubmissionQuery, `{}`},
		{"query mismatched accountId", h.emailSubmissionQuery, `{"accountId":"999"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name, result := tc.method(context.Background(), user, json.RawMessage(tc.args))
			if name != "error" {
				t.Fatalf("expected error, got name=%q result=%s", name, string(result))
			}
			var e Error
			if err := json.Unmarshal(result, &e); err != nil || e.Type == "" {
				t.Errorf("expected a populated error type, got %s", string(result))
			}
		})
	}
}
