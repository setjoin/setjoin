package booking_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/booking"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

func newPublicHandler(t *testing.T, enabled bool) *booking.PublicHandler {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	return booking.NewPublicHandler(
		pgxutil.WorkerPool{Pool: pool},
		toggle.NewTestFlags(map[string]bool{"feature.booking_pages": enabled}),
		nil, "", "https://booking.test",
		nil, // sendInvite unused by these routes
		slog.Default(),
	)
}

func readBody(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	b, err := io.ReadAll(rr.Result().Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

func TestPublicRoutes404WhenToggleOff(t *testing.T) {
	h := newPublicHandler(t, false)

	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"meta", http.MethodGet, "/api/public/booking/anything"},
		{"slots", http.MethodGet, "/api/public/booking/anything/slots"},
		{"book", http.MethodPost, "/api/public/booking/anything/book"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}"))
			req.SetPathValue("slug", "anything")
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusNotFound {
				t.Fatalf("%s %s: want 404 when toggle off, got %d", tc.method, tc.path, rr.Code)
			}
		})
	}
}

func TestUnknownSlugMatchesDisabledShape(t *testing.T) {
	offH := newPublicHandler(t, false)
	onH := newPublicHandler(t, true)

	req1 := httptest.NewRequest(http.MethodGet, "/api/public/booking/does-not-exist", nil)
	req1.SetPathValue("slug", "does-not-exist")
	rr1 := httptest.NewRecorder()
	offH.ServeHTTP(rr1, req1)

	req2 := httptest.NewRequest(http.MethodGet, "/api/public/booking/does-not-exist", nil)
	req2.SetPathValue("slug", "does-not-exist")
	rr2 := httptest.NewRecorder()
	onH.ServeHTTP(rr2, req2)

	if rr1.Code != rr2.Code {
		t.Fatalf("status mismatch: toggle-off=%d unknown-slug=%d", rr1.Code, rr2.Code)
	}
	if rr1.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rr1.Code)
	}
	b1, b2 := readBody(t, rr1), readBody(t, rr2)
	if b1 != b2 {
		t.Fatalf("body mismatch (enumeration parity broken):\n  toggle-off:   %s\n  unknown-slug: %s", b1, b2)
	}
}

func TestHoneypotSilentlyDrops(t *testing.T) {
	h := newPublicHandler(t, true)
	body := `{"start":"2099-01-01T00:00:00Z","email":"bot@example.org","website":"http://spam.example"}`
	req := httptest.NewRequest(http.MethodPost, "/api/public/booking/nope/book", strings.NewReader(body))
	req.SetPathValue("slug", "nope")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("honeypot fill: want 200 (pretend success), got %d: %s", rr.Code, readBody(t, rr))
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["ok"] != true {
		t.Fatalf("honeypot response = %v, want {ok:true}", resp)
	}
	// Never reaches booking_create for a slug that does not exist — if it had,
	// the reducer would raise BZ134 and we'd see a 404, not a 200.
}

// TestHoneypotResponseByteIdenticalToSuccess pins the never-tell-the-bot
// property at the byte level (D-MAILSERVER-INTERNAL-BOOKING-002): the
// honeypot path must write exactly the same response body as a genuine
// booking success — a `{"ok":true}` vs `{"ok":true,"verificationSent":true}`
// differential is an observable discrepancy a minimally-parsing bot can read.
func TestHoneypotResponseByteIdenticalToSuccess(t *testing.T) {
	h := newPublicHandler(t, true)
	honeypotBody := `{"start":"2099-01-01T00:00:00Z","email":"bot@example.org","website":"http://spam.example"}`
	req := httptest.NewRequest(http.MethodPost, "/api/public/booking/nope/book", strings.NewReader(honeypotBody))
	req.SetPathValue("slug", "nope")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("honeypot fill: want 200, got %d", rr.Code)
	}
	// booking_test is the external package, so the shared unexported constant is
	// not visible; the literal pins the exact wire bytes both the honeypot path
	// and a genuine success must emit.
	const wantBody = `{"ok":true,"verificationSent":true}`
	if got := rr.Body.String(); got != wantBody {
		t.Errorf("honeypot body = %q, want %q (byte-identical to a genuine success body)", got, wantBody)
	}
}

func TestBookBodyTooLarge(t *testing.T) {
	h := newPublicHandler(t, true)
	huge := `{"email":"` + strings.Repeat("a", 20<<10) + `@example.org"}`
	req := httptest.NewRequest(http.MethodPost, "/api/public/booking/nope/book", strings.NewReader(huge))
	req.SetPathValue("slug", "nope")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413 for an oversized body, got %d: %s", rr.Code, readBody(t, rr))
	}
}

func TestSlotTakenIs409Problem(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	slug := seedPage(t, ctx, pool)

	h := booking.NewPublicHandler(
		pgxutil.WorkerPool{Pool: pool},
		toggle.NewTestFlags(map[string]bool{"feature.booking_pages": true}),
		nil, "", "https://booking.test", nil, slog.Default(),
	)

	// First booking of a fixed future weekday slot succeeds.
	start := nextWeekdaySlot()
	bookBody := fmt.Sprintf(`{"start":%q,"email":"first@example.org","name":"First"}`, start)
	req1 := httptest.NewRequest(http.MethodPost, "/api/public/booking/"+slug+"/book", strings.NewReader(bookBody))
	req1.SetPathValue("slug", slug)
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first booking: want 200, got %d: %s", rr1.Code, readBody(t, rr1))
	}

	// Second booking of the SAME slot must be a 409 problem+json.
	bookBody2 := fmt.Sprintf(`{"start":%q,"email":"second@example.org","name":"Second"}`, start)
	req2 := httptest.NewRequest(http.MethodPost, "/api/public/booking/"+slug+"/book", strings.NewReader(bookBody2))
	req2.SetPathValue("slug", slug)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusConflict {
		t.Fatalf("double-booked slot: want 409, got %d: %s", rr2.Code, readBody(t, rr2))
	}
	if ct := rr2.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("want application/problem+json, got %q", ct)
	}
}

// fixedLimiter is a fake middleware.Limiter that allows exactly n calls total
// then rejects everything after — a HybridRateLimiter needs a live DB pool to
// construct, which isn't the point of this test: it proves main.go's
// middleware.RateLimit(limiter)(publicHandler) wiring rejects with 429 once
// the caller-supplied limiter says no, not that HybridRateLimiter's own
// window math is correct (that's ratelimit_test.go's job).
type fixedLimiter struct{ remaining int }

func (f *fixedLimiter) Allow(string) bool {
	if f.remaining <= 0 {
		return false
	}
	f.remaining--
	return true
}

func TestBookRateLimited(t *testing.T) {
	h := newPublicHandler(t, true)
	limited := middleware.RateLimit(&fixedLimiter{remaining: 5})(h)

	var last *httptest.ResponseRecorder
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/public/booking/nope/book", strings.NewReader(`{}`))
		req.SetPathValue("slug", "nope")
		last = httptest.NewRecorder()
		limited.ServeHTTP(last, req)
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("6th request within the limiter's window: want 429, got %d: %s", last.Code, readBody(t, last))
	}
	if ct := last.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("429 want application/problem+json, got %q", ct)
	}
}

// seedPage inserts a minimal enabled booking page owned by a fresh mailbox and
// returns its slug. Direct SQL (no reducer) is fine here — it is test-fixture
// setup, not the code path under test.
func seedPage(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	var mailboxID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account($1)`, fmt.Sprintf("bkpub-%d", time.Now().UnixNano())).Scan(&mailboxID); err != nil {
		t.Fatalf("mk_account: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO calendars (mailbox_id, name, is_default) VALUES ($1, 'Cal', TRUE) RETURNING id`,
		mailboxID).Scan(new(int64)); err != nil {
		t.Fatalf("insert calendar: %v", err)
	}
	slug := fmt.Sprintf("pub-test-%d", time.Now().UnixNano())
	if err := pool.QueryRow(ctx,
		`SELECT (booking_page_upsert($1, jsonb_build_object('slug',$2::text,'title','Public Test')))->>'id'`,
		mailboxID, slug).Scan(new(string)); err != nil {
		t.Fatalf("seed booking page: %v", err)
	}
	return slug
}

// nextWeekdaySlot returns an RFC3339 instant far enough out (min_notice
// default 120 min, max_advance default 60 days) that lands on a weekday at
// 09:00 UTC — the default availability window (Mon-Fri 09:00-17:00, UTC page
// tz) — so booking_slots always has room regardless of what day the test runs.
func nextWeekdaySlot() string {
	d := time.Now().UTC().AddDate(0, 0, 3)
	for d.Weekday() == time.Saturday || d.Weekday() == time.Sunday {
		d = d.AddDate(0, 0, 1)
	}
	return time.Date(d.Year(), d.Month(), d.Day(), 9, 0, 0, 0, time.UTC).Format(time.RFC3339)
}
