package smtp

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// TestClassifyReducerReply_PermanentVsTransient is the headline T9 SMTP case:
// a quota BZ must surface as a 5xx (no retry — the sending MTA must stop
// retrying a permanent failure forever), a transient/infra BZ stays 451 (may
// retry), and a non-BZ infra error is NOT classified (ok=false → caller keeps
// its existing safe default). The reply text is a fixed generic line per class —
// the reducer's human message is never leaked. Codes cited against
// docs/reducer-error-codes.md.
func TestClassifyReducerReply_PermanentVsTransient(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		wantOK    bool
		wantCode  int
		wantEnh   string // RFC 3463 enhanced status the reply line must start with
		permanent bool   // 5xx => permanent (no retry); 4xx => transient (may retry)
	}{
		{
			name:      "BZ001 over_quota -> 552 5.2.2 (permanent, no retry)",
			err:       &pgconn.PgError{Code: "BZ001", Message: "Mailbox over quota", Hint: `{"type":"over_quota","mailbox_id":42}`},
			wantOK:    true,
			wantCode:  552,
			wantEnh:   "5.2.2",
			permanent: true,
		},
		{
			name:      "BZ009 domain_over_quota -> 552 5.2.2 (permanent)",
			err:       &pgconn.PgError{Code: "BZ009", Message: "Domain over quota", Hint: `{"type":"domain_over_quota","domain_id":1}`},
			wantOK:    true,
			wantCode:  552,
			wantEnh:   "5.2.2",
			permanent: true,
		},
		{
			name:      "BZ004 sending_quota_exceeded -> 552 5.2.2 (permanent)",
			err:       &pgconn.PgError{Code: "BZ004", Message: "Daily sending quota reached", Hint: `{"type":"sending_quota_exceeded","mailbox_id":42}`},
			wantOK:    true,
			wantCode:  552,
			wantEnh:   "5.2.2",
			permanent: true,
		},
		{
			name:      "BZ002 forbidden -> 550 5.7.1 (permanent, policy)",
			err:       &pgconn.PgError{Code: "BZ002", Message: "Access denied", Hint: `{"type":"forbidden"}`},
			wantOK:    true,
			wantCode:  550,
			wantEnh:   "5.7.1",
			permanent: true,
		},
		{
			name:      "BZ003 send_as_unauthorized -> 550 5.7.1 (permanent, policy)",
			err:       &pgconn.PgError{Code: "BZ003", Message: "Not authorized to send from this address", Hint: `{"type":"send_as_unauthorized","from_addr":"x@y"}`},
			wantOK:    true,
			wantCode:  550,
			wantEnh:   "5.7.1",
			permanent: true,
		},
		{
			name:      "BZ005 dlp_blocked -> 550 5.7.1 (permanent, policy)",
			err:       &pgconn.PgError{Code: "BZ005", Message: "Message blocked by DLP policy", Hint: `{"type":"dlp_blocked","policy_id":3}`},
			wantOK:    true,
			wantCode:  550,
			wantEnh:   "5.7.1",
			permanent: true,
		},
		{
			name:      "BZ007 no_mailbox -> 550 5.1.1 (permanent, unknown recipient)",
			err:       &pgconn.PgError{Code: "BZ007", Message: "No mailbox for recipient", Hint: `{"type":"no_mailbox","rcpt_addr":"a@b"}`},
			wantOK:    true,
			wantCode:  550,
			wantEnh:   "5.1.1",
			permanent: true,
		},
		{
			name:      "BZ008 missing_inbox -> 451 4.3.0 (transient, may retry)",
			err:       &pgconn.PgError{Code: "BZ008", Message: "Mailbox has no Inbox tag", Hint: `{"type":"missing_inbox","mailbox_id":42}`},
			wantOK:    true,
			wantCode:  451,
			wantEnh:   "4.3.0",
			permanent: false,
		},
		{
			name:   "BZ010 invalid_side (internal) -> not classified (ok=false, caller keeps default)",
			err:    &pgconn.PgError{Code: "BZ010", Message: "Invalid rule evaluation side", Hint: `{"type":"invalid_side"}`},
			wantOK: false,
		},
		{
			name:   "non-pg infra error -> not classified (ok=false → caller's transient default stands)",
			err:    errors.New("connection reset by peer"),
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reply, ok := classifyReducerReply(tc.err)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if reply.code != tc.wantCode {
				t.Errorf("code = %d, want %d", reply.code, tc.wantCode)
			}
			if !strings.HasPrefix(reply.msg, tc.wantEnh+" ") {
				t.Errorf("msg = %q, want enhanced-status prefix %q", reply.msg, tc.wantEnh)
			}
			// Permanent classes are 5xx (sender must NOT retry); transient is 4xx.
			isPermanent := reply.code >= 500
			if isPermanent != tc.permanent {
				t.Errorf("code %d permanent=%v, want permanent=%v", reply.code, isPermanent, tc.permanent)
			}
			// The reducer's human message must never leak into the reply line.
			var pgErr *pgconn.PgError
			if errors.As(tc.err, &pgErr) && pgErr.Message != "" {
				if strings.Contains(reply.msg, pgErr.Message) {
					t.Errorf("reply %q leaks reducer message %q", reply.msg, pgErr.Message)
				}
			}
		})
	}
}
