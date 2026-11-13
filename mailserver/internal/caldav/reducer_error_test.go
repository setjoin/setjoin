package caldav

import (
	"context"
	"errors"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"setjoin.com/shared/reducererr"
)

// levelCaptureHandler is a minimal slog.Handler that records the level of the
// single record written through it, so a test can assert writeReducerError logs
// a client-actionable business error at Info and an internal/unknown error at
// Error (the LogLevel() projection), not always Error.
type levelCaptureHandler struct{ level slog.Level }

func (h *levelCaptureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *levelCaptureHandler) Handle(_ context.Context, r slog.Record) error {
	h.level = r.Level
	return nil
}
func (h *levelCaptureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *levelCaptureHandler) WithGroup(string) slog.Handler      { return h }

// TestWriteReducerError_StatusProjection is the headline T9 CalDAV behavior-
// change case. Before the shared internal/reducererr projection, every reducer
// error on a CalDAV PUT/DELETE returned 500 Internal Server Error — so an
// over-quota, forbidden, or not-found event write all wrongly surfaced as 500.
// writeReducerError now classifies the BZ code through reducererr.Classify and
// writes the matching WebDAV status: 507 over-quota, 403 forbidden, 404
// not-found, 409 stale-state conflict, with 500 kept ONLY for genuinely
// unrecognized errors (transport blip, internal code). The pgErr shapes mirror
// what the calendar reducers actually raise (docs/reducer-error-codes.md).
func TestWriteReducerError_StatusProjection(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantLevel  slog.Level
	}{
		{
			name:       "BZ001 over_quota -> 507 (was 500)",
			err:        &pgconn.PgError{Code: "BZ001", Message: "Mailbox over quota", Hint: `{"type":"over_quota","mailbox_id":42}`},
			wantStatus: 507,
			wantLevel:  slog.LevelInfo,
		},
		{
			name:       "BZ009 domain_over_quota -> 507 (was 500)",
			err:        &pgconn.PgError{Code: "BZ009", Message: "Domain over quota", Hint: `{"type":"domain_over_quota","domain_id":1}`},
			wantStatus: 507,
			wantLevel:  slog.LevelInfo,
		},
		{
			name:       "BZ002 forbidden -> 403 (was 500)",
			err:        &pgconn.PgError{Code: "BZ002", Message: "Access denied", Hint: `{"type":"forbidden","user_id":7}`},
			wantStatus: 403,
			wantLevel:  slog.LevelInfo,
		},
		{
			name:       "BZ005 dlp_blocked -> 403 (was 500)",
			err:        &pgconn.PgError{Code: "BZ005", Message: "Blocked by DLP", Hint: `{"type":"dlp_blocked","policy_id":3}`},
			wantStatus: 403,
			wantLevel:  slog.LevelInfo,
		},
		{
			name:       "BZ007 no_mailbox -> 404 (was 500)",
			err:        &pgconn.PgError{Code: "BZ007", Message: "No mailbox", Hint: `{"type":"no_mailbox","rcpt_addr":"a@b"}`},
			wantStatus: 404,
			wantLevel:  slog.LevelInfo,
		},
		{
			name:       "BZ011 cannotCalculateChanges -> 409 (was 500)",
			err:        &pgconn.PgError{Code: "BZ011", Message: "Cannot calculate changes", Hint: `{"type":"cannotCalculateChanges"}`},
			wantStatus: 409,
			wantLevel:  slog.LevelInfo,
		},
		{
			name:       "BZ001 calendar dual-use non-over_quota slug -> 500 (not mis-mapped to 507)",
			err:        &pgconn.PgError{Code: "BZ001", Message: "Event not found", Hint: `{"type":"notFound"}`},
			wantStatus: 500,
			wantLevel:  slog.LevelError,
		},
		{
			name:       "unregistered BZ code -> 500 (fallback preserved)",
			err:        &pgconn.PgError{Code: "BZ997", Message: "novel failure"},
			wantStatus: 500,
			wantLevel:  slog.LevelError,
		},
		{
			name:       "non-pg transport error -> 500 (fallback preserved)",
			err:        errors.New("connection reset by peer"),
			wantStatus: 500,
			wantLevel:  slog.LevelError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cap := &levelCaptureHandler{level: slog.LevelDebug}
			h := &Handler{pool: nil, logger: slog.New(cap)}
			rec := httptest.NewRecorder()
			reducererr.WriteHTTPError(context.Background(), rec, h.logger, "test reducer error", tc.err)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if cap.level != tc.wantLevel {
				t.Errorf("log level = %v, want %v", cap.level, tc.wantLevel)
			}
			// The reducer's human message must never leak into the response body.
			var pgErr *pgconn.PgError
			if errors.As(tc.err, &pgErr) && pgErr.Message != "" {
				if body := rec.Body.String(); body != "" {
					t.Errorf("response body %q must be empty (no reducer message leak)", body)
				}
			}
		})
	}
}
