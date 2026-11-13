package caldav

// Coverage-gap tests for the iMIP/iTIP error and edge arms in itip.go:
//   - ParseITIP duplicate-METHOD rejection (RFC 5545 §3.7.1);
//   - dnsEvidenceAuthenticated's empty-role fail-closed arm;
//   - signerEmailDomain's malformed-input arms;
//   - smimeValidForCancel's signer-mismatch arm;
//   - processCancel's affected-copy resolution failure, its empty-affected
//     (nothing to cancel) arm, and the reducer-failure firstErr surfacing.
//
// The DB-backed processCancel arms are exercised against tiny SCRATCH SCHEMAS
// (created + dropped by each test) reached through a pool whose search_path is
// pinned to the scratch schema. The production tables cannot produce these
// states — FK integrity guarantees that an event visible to the organizer
// lookup also joins to a mailbox domain — so the scratch schemas simulate the
// failure shapes deterministically: a missing `domains` relation (resolution
// error), an event whose calendar join yields no rows (nothing to cancel), and
// a calendar_process_itip_cancel stub that raises (reducer failure).

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestParseITIPRejectsDuplicateMethod: RFC 5545 §3.7.1 — METHOD MUST NOT occur
// more than once; the object is rejected instead of letting a second METHOD
// reinterpret the message (e.g. an appended "METHOD:CANCEL" under a signed
// "METHOD:REQUEST").
func TestParseITIPRejectsDuplicateMethod(t *testing.T) {
	msg, err := ParseITIP("METHOD:REQUEST\nBEGIN:VEVENT\nUID:dup-1\nEND:VEVENT\nMETHOD:CANCEL\n")
	if err == nil {
		t.Fatalf("duplicate METHOD accepted: %+v", msg)
	}
	if !strings.Contains(err.Error(), "duplicate METHOD") {
		t.Errorf("error = %v, want duplicate-METHOD rejection", err)
	}
}

// TestITIPDNSEvidenceEmptyRoleFailsClosed: an empty role address never
// authenticates, even when the identity itself carries strong evidence.
func TestITIPDNSEvidenceEmptyRoleFailsClosed(t *testing.T) {
	id := ITIPTransportIdentity{
		EnvelopeFrom: "organizer@itip.test",
		FromHeader:   "organizer@itip.test",
		DkimAligned:  true,
		SpfPass:      true,
	}
	for _, role := range []string{"", "   ", "<>", "  <>  "} {
		if id.dnsEvidenceAuthenticated(role) {
			t.Errorf("dnsEvidenceAuthenticated(%q) = true, want fail-closed false", role)
		}
	}
}

// TestSignerEmailDomainMalformedInput: malformed addr-specs yield an empty
// domain — never a wildcard.
func TestSignerEmailDomainMalformedInput(t *testing.T) {
	cases := map[string]string{
		"no-at-sign": "",
		"user@":      "", // trailing @: no domain part
		"@":          "",
		"":           "",
		"<x@ ":       "", // whitespace-only domain
	}
	for in, want := range cases {
		if got := signerEmailDomain(in); got != want {
			t.Errorf("signerEmailDomain(%q) = %q, want %q", in, got, want)
		}
	}
	// Sanity: a well-formed address still extracts its lower-cased domain.
	if got := signerEmailDomain("<User@Example.COM>"); got != "example.com" {
		t.Errorf("signerEmailDomain well-formed = %q, want example.com", got)
	}
}

// TestSmimeValidForCancelSignerMismatch: rule (a) at the identity level fails
// closed when the signer email does not equal the cancel role, and when the
// validated anchor is unattributable (SmimeTrustNone) even on an email match.
func TestSmimeValidForCancelSignerMismatch(t *testing.T) {
	const organizer = "organizer@itip.test"
	if (ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: "someone@else.test", SmimeTrust: SmimeTrustUnrestricted}).smimeValidForCancel(organizer) {
		t.Error("signer email differing from the organizer authenticated the cancel")
	}
	if (ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: organizer, SmimeTrust: SmimeTrustNone}).smimeValidForCancel(organizer) {
		t.Error("SmimeTrustNone (unattributable anchor) authenticated the cancel")
	}
	if !(ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: organizer, SmimeTrust: SmimeTrustUnrestricted}).smimeValidForCancel(organizer) {
		t.Error("valid S/MIME with matching signer + attributable anchor rejected (sanity)")
	}
}

// itipGapScratchSchema creates the named scratch schema, runs ddl inside it,
// and returns a scratch pool whose search_path is pinned to the schema.
// Cleanup (pool close + DROP SCHEMA ... CASCADE) is registered on t.
func itipGapScratchSchema(t *testing.T, schema string, ddl []string) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping DB integration test")
	}
	ctx := context.Background()
	base, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	t.Cleanup(base.Close)
	if _, err := base.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create scratch schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = base.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	})
	for _, stmt := range ddl {
		if _, err := base.Exec(ctx, stmt); err != nil {
			t.Fatalf("scratch DDL: %v", err)
		}
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse DSN: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	scratch, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect scratch pool: %v", err)
	}
	t.Cleanup(scratch.Close)
	return scratch
}

// itipGapScratchTables is the minimal relation shape the CANCEL queries need.
func itipGapScratchTables(schema string) []string {
	return []string{
		`CREATE TABLE ` + schema + `.calendar_events (id BIGSERIAL PRIMARY KEY, uid TEXT, organizer_email TEXT, status TEXT, calendar_id BIGINT)`,
		`CREATE TABLE ` + schema + `.calendars (id BIGSERIAL PRIMARY KEY, mailbox_id BIGINT)`,
		`CREATE TABLE ` + schema + `.mailboxes (id BIGSERIAL PRIMARY KEY, domain_id BIGINT)`,
		`CREATE TABLE ` + schema + `.domains (id BIGSERIAL PRIMARY KEY, name TEXT)`,
	}
}

func itipGapCancelEvent() (*CalendarEvent, ITIPTransportIdentity) {
	const organizer = "organizer@itip.test"
	ev := &CalendarEvent{UID: "gap-uid-1", Organizer: Attendee{Email: organizer}}
	// Rule (c) transport evidence: envelope MAIL FROM == organizer + SPF pass.
	return ev, ITIPTransportIdentity{EnvelopeFrom: organizer, SpfPass: true}
}

// TestProcessCancelAffectedCopyResolutionFailure: when the affected-copy
// enumeration query fails, the failure is logged and returned — it must NOT be
// swallowed into "nothing to cancel".
func TestProcessCancelAffectedCopyResolutionFailure(t *testing.T) {
	// Scratch schema deliberately LACKS the domains relation: the organizer
	// lookup (calendar_events only) succeeds, the sweep query fails at prepare.
	const schema = "itip_gap_missing_domains"
	scratch := itipGapScratchSchema(t, schema, []string{
		`CREATE TABLE ` + schema + `.calendar_events (id BIGSERIAL PRIMARY KEY, uid TEXT, organizer_email TEXT, status TEXT, calendar_id BIGINT)`,
		`INSERT INTO ` + schema + `.calendar_events (uid, organizer_email, status) VALUES ('gap-uid-1','organizer@itip.test','confirmed')`,
	})
	ev, identity := itipGapCancelEvent()

	err := processCancel(context.Background(), scratch, slog.Default(), ev, 0, identity)
	if err == nil {
		t.Fatal("affected-copy resolution failure returned nil")
	}
	if errors.Is(err, ErrITIPUnauthenticated) {
		t.Errorf("infrastructure failure misclassified as unauthenticated: %v", err)
	}
}

// TestProcessCancelNoLocalCopiesIsNoop: an authenticated CANCEL for a
// uid+organizer with no local (joinable) copy cancels nothing and succeeds.
func TestProcessCancelNoLocalCopiesIsNoop(t *testing.T) {
	const schema = "itip_gap_no_copies"
	// The calendar_events row satisfies the organizer lookup, but the EMPTY
	// calendars table makes the join-based sweep resolve zero affected domains.
	scratch := itipGapScratchSchema(t, schema, []string{
		`CREATE TABLE ` + schema + `.calendar_events (id BIGSERIAL PRIMARY KEY, uid TEXT, organizer_email TEXT, status TEXT, calendar_id BIGINT)`,
		`CREATE TABLE ` + schema + `.calendars (id BIGSERIAL PRIMARY KEY, mailbox_id BIGINT)`,
		`CREATE TABLE ` + schema + `.mailboxes (id BIGSERIAL PRIMARY KEY, domain_id BIGINT)`,
		`CREATE TABLE ` + schema + `.domains (id BIGSERIAL PRIMARY KEY, name TEXT)`,
		`INSERT INTO ` + schema + `.calendar_events (uid, organizer_email, status) VALUES ('gap-uid-1','organizer@itip.test','confirmed')`,
	})
	ev, identity := itipGapCancelEvent()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	if err := processCancel(context.Background(), scratch, logger, ev, 0, identity); err != nil {
		t.Fatalf("no-local-copies CANCEL returned error: %v", err)
	}
	if !strings.Contains(logBuf.String(), "no local copies for uid+organizer") {
		t.Errorf("expected the no-local-copies log, got:\n%s", logBuf.String())
	}
}

// TestProcessCancelReducerFailureSurfacesFirstErr: when the per-domain reducer
// invocation fails for an accepted domain, the first error is logged and
// returned, never swallowed as a success.
func TestProcessCancelReducerFailureSurfacesFirstErr(t *testing.T) {
	const schema = "itip_gap_reducer_fails"
	scratch := itipGapScratchSchema(t, schema, append(itipGapScratchTables(schema), []string{
		`INSERT INTO ` + schema + `.domains (name) VALUES ('gapdom.test')`,
		`INSERT INTO ` + schema + `.mailboxes (domain_id) VALUES (1)`,
		`INSERT INTO ` + schema + `.calendars (mailbox_id) VALUES (1)`,
		`INSERT INTO ` + schema + `.calendar_events (uid, organizer_email, status, calendar_id) VALUES ('gap-uid-1','organizer@itip.test','confirmed',1)`,
		`CREATE FUNCTION ` + schema + `.calendar_process_itip_cancel(text, text, text, text) RETURNS bytea LANGUAGE plpgsql
		 AS $$ BEGIN RAISE EXCEPTION 'injected reducer failure for coverage'; END $$`,
	}...))
	ev, identity := itipGapCancelEvent()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	err := processCancel(context.Background(), scratch, logger, ev, 0, identity)
	if err == nil {
		t.Fatal("reducer failure returned nil")
	}
	if !strings.Contains(err.Error(), "injected reducer failure") {
		t.Errorf("error = %v, want the injected reducer failure", err)
	}
	if errors.Is(err, ErrITIPUnauthenticated) {
		t.Errorf("reducer failure misclassified as unauthenticated: %v", err)
	}
	if !strings.Contains(logBuf.String(), "itip cancel processing failed") {
		t.Errorf("expected the reducer-failure log, got:\n%s", logBuf.String())
	}
}
