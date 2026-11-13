package caldav

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// setupITIPTestAccount mk_accounts a recipient mailbox and returns its user
// email (the address the inbound iTIP message addresses as an attendee).
// Skips without TEST_DB_DSN.
func setupITIPTestAccount(t *testing.T, label string) (pool *pgxpool.Pool, mbID, userID int64, email string, cleanup func()) {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping DB integration test")
	}
	ctx := context.Background()
	p, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	if err := p.QueryRow(ctx, `SELECT mk_account($1)`, label).Scan(&mbID); err != nil {
		p.Close()
		t.Fatalf("mk_account: %v", err)
	}
	if err := p.QueryRow(ctx, `SELECT user_id, email FROM mailboxes WHERE id=$1`, mbID).Scan(&userID, &email); err != nil {
		p.Close()
		t.Fatalf("resolve user/email: %v", err)
	}
	cleanup = func() {
		teardownAccount(ctx, p, mbID, userID)
		p.Close()
	}
	return p, mbID, userID, email, cleanup
}

// TestProcessRequest_Create: a plain (non-recurring, non-occurrence) inbound
// METHOD:REQUEST creates a tentative local copy. Pins THREE compounding bugs
// found here while wiring Task 10 (occurrence-scoped inbound iTIP), all with
// zero prior test coverage:
//  1. jmap_calendar_event_set_create was called with 2 args for a 4-param
//     reducer (p_mailbox_id, p_actor_id, p_actor_email, p_creates) — a raw
//     "function does not exist" error on every inbound REQUEST.
//  2. rate_limit_check's p_window_min is INTEGER minutes, not an interval
//     literal — the '1 hour' string made the call error, and the error was
//     silently discarded (bare .Scan, no err check).
//  3. The SQL wrapped rate_limit_check (TRUE-means-allowed) in NOT, inverting
//     it — combined with bug 2's swallowed-error zero-value the two bugs
//     canceled into "always blocked" for ordinary traffic.
//
// Together: EVERY inbound calendar invite over email was silently dropped.
func TestProcessRequest_Create(t *testing.T) {
	pool, mbID, _, email, cleanup := setupITIPTestAccount(t, "itipreq")
	defer cleanup()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO calendars (mailbox_id, name, is_default) VALUES ($1,'Default',TRUE)`, mbID); err != nil {
		t.Fatalf("insert default calendar: %v", err)
	}

	ev := &CalendarEvent{
		UID:   "itip-req-plain-1",
		Title: "Standup",
		Start: time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 8, 3, 10, 30, 0, 0, time.UTC),
		Attendees: []Attendee{
			{Email: email, Status: "needs-action"},
		},
	}
	if err := processRequest(ctx, pool, slog.Default(), ev); err != nil {
		t.Fatalf("processRequest: %v", err)
	}

	var title, status string
	var gotMbID int64
	err := pool.QueryRow(ctx,
		`SELECT ce.title, ce.status, c.mailbox_id FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id WHERE ce.uid=$1`,
		ev.UID,
	).Scan(&title, &status, &gotMbID)
	if err != nil {
		t.Fatalf("event not persisted: %v", err)
	}
	if title != "Standup" || status != "tentative" || gotMbID != mbID {
		t.Errorf("persisted wrong: title=%q status=%q mbID=%d (want %d)", title, status, gotMbID, mbID)
	}
}

// TestProcessRequest_OccurrenceApply: an inbound REQUEST carrying RECURRENCE-ID
// for a UID that already exists LOCALLY as a recurring master must NOT hit the
// "already exists, skipping" dedup — it applies as an occurrence override
// (Task 10).
func TestProcessRequest_OccurrenceApply(t *testing.T) {
	pool, mbID, _, email, cleanup := setupITIPTestAccount(t, "itipocc")
	defer cleanup()
	ctx := context.Background()
	const uid = "itip-req-series-1"

	var calID int64
	if err := pool.QueryRow(ctx, `INSERT INTO calendars (mailbox_id, name) VALUES ($1,'ITIP Occ') RETURNING id`, mbID).Scan(&calID); err != nil {
		t.Fatalf("insert calendar: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, rrule, etag)
		 VALUES ($1,$2,'Standup','2026-08-03 10:00:00+00','2026-08-03 10:30:00+00','FREQ=WEEKLY','m0')`,
		calID, uid); err != nil {
		t.Fatalf("insert master: %v", err)
	}

	ev := &CalendarEvent{
		UID:              uid,
		Title:            "Standup (moved)",
		RecurrenceIDTime: time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC),
		Start:            time.Date(2026, 8, 10, 14, 0, 0, 0, time.UTC),
		End:              time.Date(2026, 8, 10, 14, 30, 0, 0, time.UTC),
		Attendees:        []Attendee{{Email: email, Status: "needs-action"}},
	}
	if err := processRequest(ctx, pool, slog.Default(), ev); err != nil {
		t.Fatalf("processRequest: %v", err)
	}

	var overrideTitle string
	err := pool.QueryRow(ctx,
		`SELECT title FROM calendar_events WHERE uid=$1 AND recurrence_override='2026-08-10 10:00:00+00'::timestamptz`, uid,
	).Scan(&overrideTitle)
	if err != nil {
		t.Fatalf("expected an override row for the occurrence, got none: %v", err)
	}
	if overrideTitle != "Standup (moved)" {
		t.Errorf("override title = %q, want %q", overrideTitle, "Standup (moved)")
	}
	// The dedup path must NOT also have created a second whole-series copy.
	var seriesCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM calendar_events WHERE uid=$1 AND recurrence_override IS NULL`, uid,
	).Scan(&seriesCount); err != nil {
		t.Fatalf("count masters: %v", err)
	}
	if seriesCount != 1 {
		t.Errorf("expected exactly 1 master row (no dedup-skip duplicate), got %d", seriesCount)
	}
}

// TestProcessCancel_OccurrenceExcludesOnlyThatInstance: an inbound CANCEL
// carrying RECURRENCE-ID excludes JUST that occurrence on the recipient's
// local copy — the series (and its other occurrences) survives (Task 10).
func TestProcessCancel_OccurrenceExcludesOnlyThatInstance(t *testing.T) {
	pool, mbID, _, _, cleanup := setupITIPTestAccount(t, "itipcxl")
	defer cleanup()
	ctx := context.Background()
	const uid = "itip-cancel-series-1"
	const organizer = "organizer@itip.test"

	var calID int64
	if err := pool.QueryRow(ctx, `INSERT INTO calendars (mailbox_id, name) VALUES ($1,'ITIP Cancel') RETURNING id`, mbID).Scan(&calID); err != nil {
		t.Fatalf("insert calendar: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, rrule, organizer_email, status, etag)
		 VALUES ($1,$2,'Standup','2026-08-03 10:00:00+00','2026-08-03 10:30:00+00','FREQ=WEEKLY',$3,'confirmed','m0')`,
		calID, uid, organizer); err != nil {
		t.Fatalf("insert master: %v", err)
	}

	ev := &CalendarEvent{
		UID:              uid,
		RecurrenceIDTime: time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC),
		Organizer:        Attendee{Email: organizer},
	}
	// processCancel is invoked per-recipient by the SMTP delivery loop, with
	// accountID resolved from that recipient's mailbox (smtp/inbound.go) and
	// the transport identity threaded from the SMTP connection — here the
	// authenticated organizer (envelope match + SPF pass, contract rule (c)),
	// so the occurrence-exclude path still processes.
	if err := processCancel(ctx, pool, slog.Default(), ev, mbID, ITIPTransportIdentity{EnvelopeFrom: organizer, SpfPass: true}); err != nil {
		t.Fatalf("processCancel: %v", err)
	}

	var status string
	if err := pool.QueryRow(ctx,
		`SELECT status FROM calendar_events WHERE uid=$1 AND recurrence_override IS NULL`, uid,
	).Scan(&status); err != nil {
		t.Fatalf("master row missing: %v", err)
	}
	if status == "cancelled" {
		t.Error("occurrence CANCEL must not cancel the whole series")
	}
	var hasExdate bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM calendar_events ce, unnest(ce.exdate) x
		 WHERE ce.uid=$1 AND ce.recurrence_override IS NULL AND x='2026-08-10 10:00:00+00'::timestamptz)`, uid,
	).Scan(&hasExdate); err != nil {
		t.Fatalf("check exdate: %v", err)
	}
	if !hasExdate {
		t.Error("expected the cancelled occurrence to be excluded via exdate")
	}
}
