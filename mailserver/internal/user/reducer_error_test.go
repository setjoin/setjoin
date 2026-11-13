package user

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"setjoin.com/shared/httputil"
)

// TestReducerErrorStatus_Projection is the headline T9 user-package behavior
// change. Before routing reducer errors through internal/reducererr, every BZ
// business error from a user reducer (recall_message, undo_send, set_vacation,
// get_vacation, set_signature_default) returned a blanket 500 — so an over-quota
// / forbidden / not-found / conflict failure all wrongly surfaced as 500.
// reducerErrorStatus now classifies the BZ code through reducererr.Classify and
// returns the matching HTTP status: 507 over-quota, 403 forbidden, 404
// not-found, 409 stale-state conflict, with 500 kept ONLY for genuinely
// unrecognized errors (transport blip, internal/non-business code). The pgErr
// shapes mirror what the reducers actually raise (docs/reducer-error-codes.md).
func TestReducerErrorStatus_Projection(t *testing.T) {
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
			name:       "BZ004 sending_quota_exceeded -> 507 (was 500)",
			err:        &pgconn.PgError{Code: "BZ004", Message: "Sending quota reached", Hint: `{"type":"sending_quota_exceeded"}`},
			wantStatus: 507,
		},
		{
			name:       "BZ002 forbidden -> 403 (was 500)",
			err:        &pgconn.PgError{Code: "BZ002", Message: "Access denied", Hint: `{"type":"forbidden","user_id":7}`},
			wantStatus: 403,
		},
		{
			name:       "BZ003 send_as_unauthorized -> 403 (was 500)",
			err:        &pgconn.PgError{Code: "BZ003", Message: "Send-as not authorized", Hint: `{"type":"send_as_unauthorized"}`},
			wantStatus: 403,
		},
		{
			name:       "BZ005 dlp_blocked -> 403 (was 500)",
			err:        &pgconn.PgError{Code: "BZ005", Message: "Blocked by DLP", Hint: `{"type":"dlp_blocked","policy_id":3}`},
			wantStatus: 403,
		},
		{
			name:       "BZ007 no_mailbox -> 404 (was 500)",
			err:        &pgconn.PgError{Code: "BZ007", Message: "No mailbox", Hint: `{"type":"no_mailbox"}`},
			wantStatus: 404,
		},
		{
			name:       "BZ011 cannotCalculateChanges -> 409 (was 500)",
			err:        &pgconn.PgError{Code: "BZ011", Message: "Cannot calculate changes", Hint: `{"type":"cannotCalculateChanges"}`},
			wantStatus: 409,
		},
		{
			name:       "BZ001 dual-use non-over_quota slug -> 500 (not mis-mapped to 507)",
			err:        &pgconn.PgError{Code: "BZ001", Message: "Calendar not found", Hint: `{"type":"notFound"}`},
			wantStatus: 500,
		},
		{
			name:       "BZ008 missing_inbox (transient/internal) -> 500 (must not leak)",
			err:        &pgconn.PgError{Code: "BZ008", Message: "Missing inbox", Hint: `{"type":"missing_inbox"}`},
			wantStatus: 500,
		},
		{
			name:       "unregistered BZ code -> 500 (fallback preserved)",
			err:        &pgconn.PgError{Code: "BZ997", Message: "novel failure"},
			wantStatus: 500,
		},
		{
			name:       "undo-specific BZ021 message-not-found -> 404 (now classified, was 500)",
			err:        &pgconn.PgError{Code: "BZ021", Message: "undo not found"},
			wantStatus: 404,
		},
		{
			name:       "non-pg transport error -> 500 (fallback preserved)",
			err:        errors.New("connection reset by peer"),
			wantStatus: 500,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := reducerErrorStatus(tc.err); got != tc.wantStatus {
				t.Errorf("reducerErrorStatus = %d, want %d", got, tc.wantStatus)
			}
		})
	}
}

// TestReducerErrorStatus_WrittenStatus pins the end-to-end shape every user
// reducer site uses: the classified status drives httputil.WriteError /
// WriteJSON so the HTTP response carries the corrected status (409/403/404/507),
// NOT 500. This mirrors the carddav/caldav reducer_error_test.go httptest style
// without needing a database — the status code is the entire behavior change.
func TestReducerErrorStatus_WrittenStatus(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		writeJSON  bool // true → WriteJSON (auto_reply style); false → WriteError
		wantStatus int
	}{
		{"forbidden via WriteError -> 403", &pgconn.PgError{Code: "BZ002", Hint: `{"type":"forbidden"}`}, false, 403},
		{"not-found via WriteError -> 404", &pgconn.PgError{Code: "BZ007", Hint: `{"type":"no_mailbox"}`}, false, 404},
		{"over-quota via WriteJSON -> 507", &pgconn.PgError{Code: "BZ001", Hint: `{"type":"over_quota"}`}, true, 507},
		{"conflict via WriteJSON -> 409", &pgconn.PgError{Code: "BZ011"}, true, 409},
		{"unknown via WriteError -> 500", errors.New("boom"), false, 500},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			status := reducerErrorStatus(tc.err)
			if tc.writeJSON {
				httputil.WriteJSON(rec, status, map[string]string{"error": "database error"})
			} else {
				httputil.WriteError(rec, status, "database error")
			}
			if rec.Code != tc.wantStatus {
				t.Errorf("written status = %d, want %d", rec.Code, tc.wantStatus)
			}
			// The reducer's raw human message must never leak into the body.
			var pgErr *pgconn.PgError
			if errors.As(tc.err, &pgErr) && pgErr.Message != "" {
				if body := rec.Body.String(); body != "" && containsMsg(body, pgErr.Message) {
					t.Errorf("response body %q leaks reducer message %q", body, pgErr.Message)
				}
			}
		})
	}
}

// containsMsg reports whether haystack contains needle (small dependency-free
// substring check so the leak assertion needs no extra import).
func containsMsg(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
