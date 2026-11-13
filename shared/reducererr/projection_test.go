package reducererr

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// TestClassify_BZCodeToClass pins the BZ-code → ReplyClass projection: the
// single classification every gateway protocol now routes through. It covers
// the client-actionable codes from docs/reducer-error-codes.md plus the dual-use
// BZ001 slug disambiguation (only `over_quota` is the storage-quota meaning; a
// calendar BZ001 slug is ClassUnknown so it is never mislabeled over-quota) and
// the non-business fallthrough.
func TestClassify_BZCodeToClass(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want ReplyClass
	}{
		{"BZ001 over_quota", &pgconn.PgError{Code: "BZ001", Hint: `{"type":"over_quota"}`}, ClassOverQuota},
		{"BZ001 calendar slug (notFound)", &pgconn.PgError{Code: "BZ001", Hint: `{"type":"notFound"}`}, ClassUnknown},
		{"BZ001 no hint", &pgconn.PgError{Code: "BZ001"}, ClassUnknown},
		{"BZ009 domain_over_quota", &pgconn.PgError{Code: "BZ009", Hint: `{"type":"domain_over_quota"}`}, ClassOverQuota},
		{"BZ004 sending_quota_exceeded", &pgconn.PgError{Code: "BZ004", Hint: `{"type":"sending_quota_exceeded"}`}, ClassSendQuota},
		{"BZ002 forbidden", &pgconn.PgError{Code: "BZ002", Hint: `{"type":"forbidden"}`}, ClassForbidden},
		{"BZ003 send_as_unauthorized", &pgconn.PgError{Code: "BZ003", Hint: `{"type":"send_as_unauthorized"}`}, ClassForbidden},
		{"BZ005 dlp_blocked", &pgconn.PgError{Code: "BZ005", Hint: `{"type":"dlp_blocked"}`}, ClassForbidden},
		{"BZ007 no_mailbox", &pgconn.PgError{Code: "BZ007", Hint: `{"type":"no_mailbox"}`}, ClassNotFound},
		{"BZ006 accountNotFound", &pgconn.PgError{Code: "BZ006"}, ClassAccountNotFound},
		{"BZ011 cannotCalculateChanges", &pgconn.PgError{Code: "BZ011"}, ClassCannotCalc},
		{"BZ008 missing_inbox", &pgconn.PgError{Code: "BZ008", Hint: `{"type":"missing_inbox"}`}, ClassTransient},
		{"BZ010 invalid_side (intentional 500)", &pgconn.PgError{Code: "BZ010"}, ClassUnknown},
		{"BZ040 invalidArguments", &pgconn.PgError{Code: "BZ040", Hint: `{"type":"invalidArguments"}`}, ClassInvalidArguments},
		{"BZ041 invalidArguments", &pgconn.PgError{Code: "BZ041", Hint: `{"type":"invalidArguments"}`}, ClassInvalidArguments},
		{"BZ099 offline policy not found", &pgconn.PgError{Code: "BZ099"}, ClassNotFound},
		{"BZ048 illegal migration transition", &pgconn.PgError{Code: "BZ048"}, ClassConflict},
		{"BZ081 CA entity not found (no bad_outcome)", &pgconn.PgError{Code: "BZ081"}, ClassNotFound},
		{"BZ081 queue bad_outcome", &pgconn.PgError{Code: "BZ081", Hint: `{"type":"bad_outcome","outcome":"nope"}`}, ClassInvalidArguments},
		{"unregistered BZ code", &pgconn.PgError{Code: "BZ997"}, ClassUnknown},
		{"non-pg error", errors.New("boom"), ClassUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.err); got != tc.want {
				t.Errorf("Classify = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestReplyClass_Projections pins the per-protocol projection of each class: the
// HTTP/WebDAV status, the JMAP method-level error type ("" = fall back to
// serverFail), and the SMTP reply (ok=false = caller keeps its safe default).
// This is the cross-protocol map the four hand-rolled per-protocol mappings
// collapse into.
func TestReplyClass_Projections(t *testing.T) {
	cases := []struct {
		class    ReplyClass
		http     int
		webdav   int
		jmap     string
		smtpCode int
		smtpOK   bool
	}{
		{ClassOverQuota, 507, 507, "overQuota", 552, true},
		{ClassSendQuota, 507, 507, "overQuota", 552, true},
		{ClassForbidden, 403, 403, "forbidden", 550, true},
		{ClassNotFound, 404, 404, "notFound", 550, true},
		{ClassAccountNotFound, 404, 404, "accountNotFound", 0, false},
		{ClassCannotCalc, 409, 409, "cannotCalculateChanges", 0, false},
		{ClassConflict, 409, 409, "", 0, false},
		{ClassTransient, 500, 500, "", 451, true},
		{ClassInvalidArguments, 400, 400, "invalidArguments", 0, false},
		{ClassUnknown, 500, 500, "", 0, false},
	}
	for _, tc := range cases {
		if got := tc.class.HTTPStatus(); got != tc.http {
			t.Errorf("class %d HTTPStatus = %d, want %d", tc.class, got, tc.http)
		}
		if got := tc.class.WebDAVStatus(); got != tc.webdav {
			t.Errorf("class %d WebDAVStatus = %d, want %d", tc.class, got, tc.webdav)
		}
		if got := tc.class.JMAPError(); got != tc.jmap {
			t.Errorf("class %d JMAPError = %q, want %q", tc.class, got, tc.jmap)
		}
		code, _, ok := tc.class.SMTPReply()
		if ok != tc.smtpOK {
			t.Errorf("class %d SMTPReply ok = %v, want %v", tc.class, ok, tc.smtpOK)
		}
		if ok && code != tc.smtpCode {
			t.Errorf("class %d SMTPReply code = %d, want %d", tc.class, code, tc.smtpCode)
		}
	}
}

// TestReplyClass_LogLevel pins the log-severity projection: a client-actionable
// business error (the caller did something the protocol can report back) logs at
// Info — it is an expected, recoverable condition, not a server fault — while
// ClassUnknown (an unrecognized/internal error that surfaces as 500/serverFail)
// and ClassTransient (an infra/config fault that must not leak) log at Error.
// This is the single source of truth for the Info-vs-Error split every gateway
// protocol's reducer-error logger now shares, instead of always logging Error.
func TestReplyClass_LogLevel(t *testing.T) {
	cases := []struct {
		class ReplyClass
		want  slog.Level
	}{
		{ClassOverQuota, slog.LevelInfo},
		{ClassSendQuota, slog.LevelInfo},
		{ClassForbidden, slog.LevelInfo},
		{ClassNotFound, slog.LevelInfo},
		{ClassAccountNotFound, slog.LevelInfo},
		{ClassCannotCalc, slog.LevelInfo},
		{ClassConflict, slog.LevelInfo},
		{ClassTransient, slog.LevelError},
		{ClassUnknown, slog.LevelError},
	}
	for _, tc := range cases {
		if got := tc.class.LogLevel(); got != tc.want {
			t.Errorf("class %d LogLevel = %v, want %v", tc.class, got, tc.want)
		}
	}
}

// TestSMTPReply_DistinctQuotaLines guards that ClassOverQuota (mailbox/domain
// full) and ClassSendQuota (sender daily quota) — which share the 552 5.2.2
// projection on code but carry distinct reply text — emit the two distinct lines
// SMTP has always sent, so splitting them into two classes is byte-faithful.
func TestSMTPReply_DistinctQuotaLines(t *testing.T) {
	_, fullMsg, _ := ClassOverQuota.SMTPReply()
	_, sendMsg, _ := ClassSendQuota.SMTPReply()
	if fullMsg == sendMsg {
		t.Fatalf("ClassOverQuota and ClassSendQuota share reply text %q — must stay distinct", fullMsg)
	}
	if fullMsg != "5.2.2 Mailbox full" {
		t.Errorf("ClassOverQuota msg = %q, want %q", fullMsg, "5.2.2 Mailbox full")
	}
	if sendMsg != "5.2.2 Sending quota exceeded" {
		t.Errorf("ClassSendQuota msg = %q, want %q", sendMsg, "5.2.2 Sending quota exceeded")
	}
}
