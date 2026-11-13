package scim

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// levelCaptureHandler is a minimal slog.Handler that records the level of the
// single record written through it, so a test can assert logReducerError logs a
// client-actionable business error at Info and an internal/unknown error at
// Error (the LogLevel() projection), not always Error.
type levelCaptureHandler struct{ level slog.Level }

func (h *levelCaptureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *levelCaptureHandler) Handle(_ context.Context, r slog.Record) error {
	h.level = r.Level
	return nil
}
func (h *levelCaptureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *levelCaptureHandler) WithGroup(string) slog.Handler      { return h }

// TestReducerStatus_Projection is the headline T9 SCIM behavior-change case.
// Before the shared internal/reducererr projection, every reducer error on a
// SCIM Users/Groups write (scim_upsert_user, scim_delete_user, scim_disable_user,
// scim_upsert_group, scim_apply_group_members) collapsed to 500 Internal Server
// Error — so a duplicate/conflict, forbidden, not-found, over-quota, or
// bad-input reducer failure all wrongly surfaced as 500. reducerStatus now
// classifies the BZ code through reducererr.Classify and returns the matching
// HTTP status: 507 over-quota, 403 forbidden, 404 not-found, 409 stale-state
// conflict, 400 invalid — with 500 kept ONLY for genuinely-unrecognized errors
// (transport blip, internal code). The pgErr shapes mirror what the reducers
// raise (docs/reducer-error-codes.md). The SCIM error JSON shape (WriteSCIMError
// detail/scimType) and the existing log line are untouched; only the status
// code moves for classified BZ errors.
func TestReducerStatus_Projection(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{
			name:       "BZ001 over_quota -> 507 (was 500)",
			err:        &pgconn.PgError{Code: "BZ001", Message: "Mailbox over quota", Hint: `{"type":"over_quota","mailbox_id":42}`},
			wantStatus: 507,
		},
		{
			name:       "BZ009 domain_over_quota -> 507 (was 500)",
			err:        &pgconn.PgError{Code: "BZ009", Message: "Domain over quota", Hint: `{"type":"domain_over_quota","domain_id":1}`},
			wantStatus: 507,
		},
		{
			name:       "BZ002 forbidden -> 403 (was 500)",
			err:        &pgconn.PgError{Code: "BZ002", Message: "Access denied", Hint: `{"type":"forbidden","user_id":7}`},
			wantStatus: 403,
		},
		{
			name:       "BZ005 dlp_blocked -> 403 (was 500)",
			err:        &pgconn.PgError{Code: "BZ005", Message: "Blocked by DLP", Hint: `{"type":"dlp_blocked","policy_id":3}`},
			wantStatus: 403,
		},
		{
			name:       "BZ007 no_mailbox -> 404 (was 500)",
			err:        &pgconn.PgError{Code: "BZ007", Message: "No mailbox", Hint: `{"type":"no_mailbox","rcpt_addr":"a@b"}`},
			wantStatus: 404,
		},
		{
			name:       "BZ011 cannotCalculateChanges -> 409 (was 500)",
			err:        &pgconn.PgError{Code: "BZ011", Message: "Cannot calculate changes", Hint: `{"type":"cannotCalculateChanges"}`},
			wantStatus: 409,
		},
		{
			name:       "BZ001 dual-use non-over_quota slug -> 500 (not mis-mapped to 507)",
			err:        &pgconn.PgError{Code: "BZ001", Message: "Not found", Hint: `{"type":"notFound"}`},
			wantStatus: 500,
		},
		{
			name:       "unregistered BZ code -> 500 (fallback preserved)",
			err:        &pgconn.PgError{Code: "BZ997", Message: "novel failure"},
			wantStatus: 500,
		},
		{
			name:       "non-pg transport error -> 500 (fallback preserved)",
			err:        errors.New("connection reset by peer"),
			wantStatus: 500,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := reducerStatus(tc.err); got != tc.wantStatus {
				t.Errorf("reducerStatus = %d, want %d", got, tc.wantStatus)
			}
		})
	}
}

// TestLogReducerError_LevelAndStatus pins that the scim write-path helper logs a
// client-actionable business error (409/403/404/507) at Info and an
// internal/unknown error (the 500 fallback) at Error — the LogLevel() projection,
// not the hard-coded Error the sites used before — while still returning the same
// HTTP status reducerStatus does (the response shape is unchanged).
func TestLogReducerError_LevelAndStatus(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantLevel  slog.Level
	}{
		{"BZ001 over_quota -> 507 Info", &pgconn.PgError{Code: "BZ001", Hint: `{"type":"over_quota"}`}, 507, slog.LevelInfo},
		{"BZ002 forbidden -> 403 Info", &pgconn.PgError{Code: "BZ002", Hint: `{"type":"forbidden"}`}, 403, slog.LevelInfo},
		{"BZ007 no_mailbox -> 404 Info", &pgconn.PgError{Code: "BZ007", Hint: `{"type":"no_mailbox"}`}, 404, slog.LevelInfo},
		{"BZ011 conflict -> 409 Info", &pgconn.PgError{Code: "BZ011"}, 409, slog.LevelInfo},
		{"unregistered BZ -> 500 Error", &pgconn.PgError{Code: "BZ997"}, 500, slog.LevelError},
		{"non-pg -> 500 Error", errors.New("boom"), 500, slog.LevelError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cap := &levelCaptureHandler{level: slog.LevelDebug}
			s := &Server{logger: slog.New(cap)}
			if got := s.logReducerError("scim test failed", tc.err); got != tc.wantStatus {
				t.Errorf("status = %d, want %d", got, tc.wantStatus)
			}
			if cap.level != tc.wantLevel {
				t.Errorf("log level = %v, want %v", cap.level, tc.wantLevel)
			}
		})
	}
}
