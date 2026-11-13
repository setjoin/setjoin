package contractvectors

import (
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"setjoin.com/shared/reducererr"
)

func TestRecordReducererr(t *testing.T) {
	type input struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Hint    string `json:"hint"`
	}
	tests := []struct {
		name string
		in   input
	}{
		{"forbidden", input{Code: "BZ002", Message: "private database detail"}},
		{"quota_hint", input{Code: "BZ001", Message: "disk full", Hint: `{"type":"over_quota","mailbox_id":42}`}},
		{"quota_wrong_slug", input{Code: "BZ001", Message: "private database detail", Hint: `{"type":"not_found"}`}},
		{"quota_malformed_hint", input{Code: "BZ001", Message: "private database detail", Hint: `{`}},
		{"last_global", input{Code: "BZ099", Message: "cannot delete last global policy", Hint: `{"type":"last_global"}`}},
		{"transient", input{Code: "BZ008", Message: "internal config"}},
		{"unknown_code", input{Code: "ZZ999", Message: "private database detail"}},
	}
	cases := make([]map[string]any, 0, len(tests))
	for _, tc := range tests {
		err := &pgconn.PgError{Code: tc.in.Code, Message: tc.in.Message, Hint: tc.in.Hint}
		class := reducererr.Classify(err)
		smtpCode, smtpMessage, smtpOK := class.SMTPReply()
		out := map[string]any{"http_status": class.HTTPStatus(), "webdav_status": class.WebDAVStatus(), "jmap_error": class.JMAPError(), "detail": reducererr.Detail(err), "smtp_code": smtpCode, "smtp_message": smtpMessage, "smtp_ok": smtpOK}
		parsed, parseErr := reducererr.ParseReducerError(err)
		if parseErr != nil {
			out["parse_error"] = parseErr.Error()
		} else {
			out["parsed"] = parsed
		}
		cases = append(cases, map[string]any{"name": tc.name, "input": tc.in, "output": out})
	}
	writeVectors(t, "reducererr", cases)
}
