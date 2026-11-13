package jmap

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// discardLogger returns a no-op slog.Logger so the mapped/serverFail log lines
// don't pollute test output while still exercising the logging branch.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestMapReducerErr_DirectMapping drives the shared helper directly: each
// stable BZ code (with the HINT the reducer actually raises) maps to the right
// RFC 8620 method-level error type, and an unrecognized error collapses to
// serverFail/"database error" (today's behavior, preserved by the default arm).
func TestMapReducerErr_DirectMapping(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		wantType  string
		wantDesc  string // "" = don't assert description (mapped descs are generic)
		assertDsc bool
	}{
		{
			name:     "BZ011 -> cannotCalculateChanges (RFC 8620 §5.2 resync)",
			err:      &pgconn.PgError{Code: "BZ011", Message: "Cannot calculate changes", Hint: `{"type":"cannotCalculateChanges"}`},
			wantType: "cannotCalculateChanges",
		},
		{
			name:     "BZ006 -> accountNotFound",
			err:      &pgconn.PgError{Code: "BZ006", Message: "Account not found", Hint: `{"type":"accountNotFound"}`},
			wantType: "accountNotFound",
		},
		{
			name:     "BZ002 (forbidden HINT.type) -> forbidden",
			err:      &pgconn.PgError{Code: "BZ002", Message: "Access denied", Hint: `{"type":"forbidden","user_id":7}`},
			wantType: "forbidden",
		},
		// T9: client-actionable codes from docs/reducer-error-codes.md.
		{
			name:     "BZ003 send_as_unauthorized -> forbidden",
			err:      &pgconn.PgError{Code: "BZ003", Message: "not authorized", Hint: `{"type":"send_as_unauthorized","from_addr":"x@y"}`},
			wantType: "forbidden",
		},
		{
			name:     "BZ005 dlp_blocked -> forbidden",
			err:      &pgconn.PgError{Code: "BZ005", Message: "blocked by DLP", Hint: `{"type":"dlp_blocked","policy_id":3}`},
			wantType: "forbidden",
		},
		{
			name:     "BZ001 over_quota (mail) -> overQuota",
			err:      &pgconn.PgError{Code: "BZ001", Message: "quota exceeded", Hint: `{"type":"over_quota","mailbox_id":42}`},
			wantType: "overQuota",
		},
		{
			name:     "BZ004 sending_quota_exceeded -> overQuota",
			err:      &pgconn.PgError{Code: "BZ004", Message: "daily quota", Hint: `{"type":"sending_quota_exceeded","mailbox_id":42}`},
			wantType: "overQuota",
		},
		{
			name:     "BZ009 domain_over_quota -> overQuota",
			err:      &pgconn.PgError{Code: "BZ009", Message: "domain over quota", Hint: `{"type":"domain_over_quota","domain_id":1}`},
			wantType: "overQuota",
		},
		{
			name:     "BZ007 no_mailbox -> notFound",
			err:      &pgconn.PgError{Code: "BZ007", Message: "no mailbox", Hint: `{"type":"no_mailbox","rcpt_addr":"a@b"}`},
			wantType: "notFound",
		},
		{
			name:      "BZ001 NON-over_quota slug (calendar dual-use) -> serverFail (not mis-mapped to overQuota)",
			err:       &pgconn.PgError{Code: "BZ001", Message: "Calendar not found", Hint: `{"type":"notFound"}`},
			wantType:  "serverFail",
			wantDesc:  "database error",
			assertDsc: true,
		},
		{
			name:      "BZ008 missing_inbox (internal) -> serverFail (no leak)",
			err:       &pgconn.PgError{Code: "BZ008", Message: "no inbox tag", Hint: `{"type":"missing_inbox","mailbox_id":42}`},
			wantType:  "serverFail",
			wantDesc:  "database error",
			assertDsc: true,
		},
		{
			name:      "unregistered BZ code -> serverFail (default arm preserved)",
			err:       &pgconn.PgError{Code: "BZ997", Message: "novel failure"},
			wantType:  "serverFail",
			wantDesc:  "database error",
			assertDsc: true,
		},
		{
			name:      "non-pg transport error -> serverFail",
			err:       errors.New("connection reset by peer"),
			wantType:  "serverFail",
			wantDesc:  "database error",
			assertDsc: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := mapReducerErr(tc.err, discardLogger(), "testMethod")
			var e Error
			if err := json.Unmarshal(raw, &e); err != nil {
				t.Fatalf("unmarshal helper result: %v", err)
			}
			if e.Type != tc.wantType {
				t.Errorf("type = %q, want %q", e.Type, tc.wantType)
			}
			if tc.assertDsc && e.Description != tc.wantDesc {
				t.Errorf("description = %q, want %q", e.Description, tc.wantDesc)
			}
		})
	}
}

// TestNullIfZero guards the nullIfZero helper: 0 must return nil (so the reducer
// DEFAULT NULL applies when the client omits maxChanges), and a positive value
// must pass through as int (so the reducer enforces hasMoreChanges).
func TestNullIfZero(t *testing.T) {
	if nullIfZero(0) != nil {
		t.Fatal("nullIfZero(0) must be nil so the reducer DEFAULT applies")
	}
	if v, ok := nullIfZero(50).(int); !ok || v != 50 {
		t.Fatalf("nullIfZero(50) = %v, want int 50", nullIfZero(50))
	}
}

// TestEmailChangesMaxChangesPlumbing verifies that maxChanges from the client is
// passed as the 3rd arg to jmap_email_changes, and omitted (nil) when the client
// sends 0 so the reducer's DEFAULT NULL applies.
func TestEmailChangesMaxChangesPlumbing(t *testing.T) {
	cases := []struct {
		name       string
		maxChanges int
		wantArg    any // nil or int
	}{
		{"omitted (0) → nil", 0, nil},
		{"explicit 50 → 50", 50, 50},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeCaller{returnRaw: json.RawMessage(`{}`)}
			h := newFakeHandler(fake)
			user := testClaims(7)
			args, _ := json.Marshal(map[string]any{"accountId": "7", "sinceState": "1", "maxChanges": tc.maxChanges})
			name, _ := h.emailChanges(context.Background(), user, args)
			if name != "Email/changes" {
				t.Fatalf("emailChanges returned %q, want Email/changes", name)
			}
			if len(fake.gotArgs) != 3 {
				t.Fatalf("jmap_email_changes got %d args, want 3: %v", len(fake.gotArgs), fake.gotArgs)
			}
			if fake.gotArgs[2] != tc.wantArg {
				t.Errorf("arg[2] (maxChanges) = %v (%T), want %v (%T)", fake.gotArgs[2], fake.gotArgs[2], tc.wantArg, tc.wantArg)
			}
		})
	}
}

// TestEmailChangesBZ011SurfacesAsCannotCalculateChanges is the headline T4 case:
// jmap_email_changes raises BZ011 (RFC 8620 §5.2 — the client's sinceState is
// too old to delta from, forcing a full resync). The handler must surface that
// to the client as cannotCalculateChanges, NOT as the old catch-all serverFail
// (which the client could not act on). Driven through the fakeCaller seam, no DB.
func TestEmailChangesBZ011SurfacesAsCannotCalculateChanges(t *testing.T) {
	fake := &fakeCaller{returnErr: &pgconn.PgError{
		Code: "BZ011", Message: "Cannot calculate changes", Hint: `{"type":"cannotCalculateChanges"}`,
	}}
	h := newFakeHandler(fake)
	user := testClaims(7)

	args, _ := json.Marshal(map[string]any{"accountId": "7", "sinceState": "1"})
	name, result := h.emailChanges(context.Background(), user, args)
	if name != "error" {
		t.Fatalf("emailChanges on BZ011 returned %q, want error", name)
	}
	// The seam must have actually been reached (not a pre-pool guard short-circuit).
	if fake.gotFn != "jmap_email_changes" {
		t.Fatalf("caller fn = %q, want jmap_email_changes (the seam was not reached)", fake.gotFn)
	}
	var e Error
	if err := json.Unmarshal(result, &e); err != nil {
		t.Fatalf("unmarshal error response: %v", err)
	}
	if e.Type != "cannotCalculateChanges" {
		t.Errorf("BZ011 surfaced as %q, want cannotCalculateChanges", e.Type)
	}
	// Sanity: cannotCalculateChanges is a 400 (client must resync), not a 500.
	if got := errorStatus(e.Type); got != 400 {
		t.Errorf("errorStatus(cannotCalculateChanges) = %d, want 400", got)
	}
}

// TestEmailChangesErrorMappingThroughHandler proves the remaining arms through
// the real emailChanges handler: BZ006 -> accountNotFound, BZ002 -> forbidden,
// and an unknown error -> serverFail (the preserved default).
func TestEmailChangesErrorMappingThroughHandler(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantType string
	}{
		{"BZ006 -> accountNotFound", &pgconn.PgError{Code: "BZ006", Hint: `{"type":"accountNotFound"}`}, "accountNotFound"},
		{"BZ002 -> forbidden", &pgconn.PgError{Code: "BZ002", Hint: `{"type":"forbidden"}`}, "forbidden"},
		{"unknown -> serverFail", errors.New("i/o timeout"), "serverFail"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeCaller{returnErr: tc.err}
			h := newFakeHandler(fake)
			user := testClaims(7)

			args, _ := json.Marshal(map[string]any{"accountId": "7", "sinceState": "1"})
			name, result := h.emailChanges(context.Background(), user, args)
			if name != "error" {
				t.Fatalf("emailChanges returned %q, want error", name)
			}
			var e Error
			if err := json.Unmarshal(result, &e); err != nil {
				t.Fatalf("unmarshal error response: %v", err)
			}
			if e.Type != tc.wantType {
				t.Errorf("error type = %q, want %q", e.Type, tc.wantType)
			}
		})
	}
}
