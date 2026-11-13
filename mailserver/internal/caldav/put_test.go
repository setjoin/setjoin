package caldav

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/reducercall"
)

// TestHandlePut_DivergentMailboxID_Create: mk_account gives a user_id that
// differs from its mailbox_id (ADR-003 divergent-ids pattern — the norm, not
// the exception). handlePut's create branch called jmap_calendar_event_set_create
// with (user.UserID, creates) — 2 args for a 4-param reducer (p_mailbox_id,
// p_actor_id, p_actor_email, p_creates), a hard signature mismatch that made
// EVERY CalDAV PUT-create of a new resource fail with a raw Postgres error.
// Fixed by passing (cal.MailboxID, user.UserID, user.Email, creates).
// Skips without TEST_DB_DSN (matches sync_collection_test.go).
func TestHandlePut_DivergentMailboxID_Create(t *testing.T) {
	h, pool, mbID, userID, calID, cleanup := setupPutTestAccount(t, "put_create")
	defer cleanup()
	_ = pool

	ics := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:put-create-1\r\n" +
		"SUMMARY:New Event\r\nDTSTART:20260803T100000Z\r\nDTEND:20260803T103000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"

	rec := doPut(h, calID, userID, "put-create-1", ics, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("PUT create: want 201, got %d\n%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("ETag") == `""` || rec.Header().Get("ETag") == "" {
		t.Errorf("PUT create: expected a non-empty ETag header, got %q", rec.Header().Get("ETag"))
	}

	var title string
	var gotMbID int64
	ctx := context.Background()
	err := h.pool.QueryRow(ctx,
		`SELECT ce.title, c.mailbox_id FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id WHERE ce.uid='put-create-1'`,
	).Scan(&title, &gotMbID)
	if err != nil {
		t.Fatalf("event not persisted: %v", err)
	}
	if title != "New Event" {
		t.Errorf("persisted title: got %q", title)
	}
	if gotMbID != mbID {
		t.Errorf("persisted under wrong mailbox: got %d, want %d", gotMbID, mbID)
	}
}

// TestHandlePutRecurring_ExceptionReconciliation drives the full PUT lifecycle
// of a recurring resource through Apple/Google's "master + exception VEVENTs
// in one body" shape (Task 7):
//  1. PUT a master alone → master row created.
//  2. PUT master + an exception VEVENT (RECURRENCE-ID) → an override row is
//     created/patched (jmap_calendar_event_set_occurrence 'this'), not lost to
//     parseICal's single-struct field-overwrite.
//  3. PUT master alone again (exception VEVENT dropped from the wire) → the
//     override row is reconciled away (RFC 4791 PUT is a full-replace).
//  4. PUT master + a bare EXDATE (no exception VEVENT) → the occurrence is
//     excluded (exdate recorded, no override row).
func TestHandlePutRecurring_ExceptionReconciliation(t *testing.T) {
	h, _, _, userID, calID, cleanup := setupPutTestAccount(t, "put_rec")
	defer cleanup()
	ctx := context.Background()
	const uid = "put-rec-1"

	masterOnly := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:" + uid + "\r\n" +
		"SUMMARY:Standup\r\nDTSTART:20260803T100000Z\r\nDTEND:20260803T103000Z\r\n" +
		"RRULE:FREQ=WEEKLY\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"

	// 1. Create the master.
	rec := doPut(h, calID, userID, uid, masterOnly, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("create master: want 201, got %d\n%s", rec.Code, rec.Body.String())
	}
	masterETag := strings.Trim(rec.Header().Get("ETag"), `"`)

	// 2. Add an exception (RECURRENCE-ID 2026-08-10, moved to 14:00).
	withException := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:" + uid + "\r\n" +
		"SUMMARY:Standup\r\nDTSTART:20260803T100000Z\r\nDTEND:20260803T103000Z\r\n" +
		"RRULE:FREQ=WEEKLY\r\nEND:VEVENT\r\n" +
		"BEGIN:VEVENT\r\nUID:" + uid + "\r\nSUMMARY:Standup (moved)\r\n" +
		"RECURRENCE-ID:20260810T100000Z\r\nDTSTART:20260810T140000Z\r\nDTEND:20260810T143000Z\r\n" +
		"END:VEVENT\r\nEND:VCALENDAR\r\n"

	rec = doPut(h, calID, userID, uid, withException, `"`+masterETag+`"`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("add exception: want 204, got %d\n%s", rec.Code, rec.Body.String())
	}

	var overrideTitle string
	err := h.pool.QueryRow(ctx,
		`SELECT title FROM calendar_events WHERE uid=$1 AND recurrence_override='2026-08-10 10:00:00+00'::timestamptz`, uid,
	).Scan(&overrideTitle)
	if err != nil {
		t.Fatalf("expected override row after adding exception: %v", err)
	}
	if overrideTitle != "Standup (moved)" {
		t.Errorf("override title: got %q", overrideTitle)
	}

	// 3. Remove the exception VEVENT from the wire (revert to master-only) —
	// the override row must be reconciled away (dropped, not left orphaned).
	rec = doPut(h, calID, userID, uid, masterOnly, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revert to master-only: want 204, got %d\n%s", rec.Code, rec.Body.String())
	}
	var count int
	if err := h.pool.QueryRow(ctx,
		`SELECT count(*) FROM calendar_events WHERE uid=$1 AND recurrence_override IS NOT NULL`, uid,
	).Scan(&count); err != nil {
		t.Fatalf("count overrides: %v", err)
	}
	if count != 0 {
		t.Errorf("override row survived removal from the wire: count=%d", count)
	}

	// 4. Add a bare EXDATE (no exception VEVENT) — pure exclusion, no override row.
	withExdate := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:" + uid + "\r\n" +
		"SUMMARY:Standup\r\nDTSTART:20260803T100000Z\r\nDTEND:20260803T103000Z\r\n" +
		"RRULE:FREQ=WEEKLY\r\nEXDATE:20260817T100000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	rec = doPut(h, calID, userID, uid, withExdate, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("add exdate: want 204, got %d\n%s", rec.Code, rec.Body.String())
	}

	var hasExdate bool
	if err := h.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM calendar_events ce, unnest(ce.exdate) x
		 WHERE ce.uid=$1 AND ce.recurrence_override IS NULL AND x='2026-08-17 10:00:00+00'::timestamptz)`, uid,
	).Scan(&hasExdate); err != nil {
		t.Fatalf("check exdate: %v", err)
	}
	if !hasExdate {
		t.Error("bare wire EXDATE was not persisted onto the master")
	}
	if err := h.pool.QueryRow(ctx,
		`SELECT count(*) FROM calendar_events WHERE uid=$1 AND recurrence_override IS NOT NULL`, uid,
	).Scan(&count); err != nil {
		t.Fatalf("count overrides: %v", err)
	}
	if count != 0 {
		t.Errorf("bare EXDATE must not create an override row: count=%d", count)
	}
}

// setupPutTestAccount creates a divergent-id account (mk_account) + one
// calendar, wires a Handler against the real pool, and returns everything
// needed to drive handlePut/handleDelete via httptest. Skips without
// TEST_DB_DSN.
func setupPutTestAccount(t *testing.T, label string) (h *Handler, pool *pgxpool.Pool, mbID, userID, calID int64, cleanup func()) {
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
	if err := p.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, mbID).Scan(&userID); err != nil {
		p.Close()
		t.Fatalf("user_id: %v", err)
	}
	if err := p.QueryRow(ctx,
		`INSERT INTO calendars (mailbox_id, name, is_default) VALUES ($1,$2,TRUE) RETURNING id`, mbID, label).Scan(&calID); err != nil {
		p.Close()
		t.Fatalf("insert calendar: %v", err)
	}
	h = &Handler{pool: p, caller: reducercall.New(p), logger: slog.Default()}
	cleanup = func() {
		teardownAccount(ctx, p, mbID, userID)
		p.Close()
	}
	return h, p, mbID, userID, calID, cleanup
}

// doPut issues a PUT request for calID/uid.ics through h.ServeHTTP, as userID,
// optionally with an If-Match header.
func doPut(h *Handler, calID, userID int64, uid, ics, ifMatch string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("PUT", "/"+strconv.FormatInt(calID, 10)+"/"+uid+".ics", strings.NewReader(ics))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID, Email: "putter@mk.test"}))
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
