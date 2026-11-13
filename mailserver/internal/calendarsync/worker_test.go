package calendarsync

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// These fetch() tests use an UNGUARDED-DIAL client — same deliberate loopback
// bypass as webhook/dispatcher_test.go, because httptest.NewServer only binds
// loopback addresses, which the production ssrf.SafeHTTPClient would refuse to
// dial at all — but it keeps SafeHTTPClient's OTHER defining behavior:
// CheckRedirect returning http.ErrUseLastResponse so a 3xx is handed back to
// fetch()'s OWN redirect loop instead of Go's default client silently
// following it first. Without this, Go's stdlib client would auto-follow the
// redirect (and enforce its own 10-hop limit) before fetch() ever saw the 3xx
// status — making TestFetch_RedirectToPrivateIPRejected /
// TestFetch_TooManyRedirectsRejected pass for the wrong reason (the stdlib
// client's own behavior, not fetch()'s ssrf.ValidateURL check or maxRedirects).
// fetch()'s explicit ssrf.ValidateURL check on every REDIRECT target (not on
// hop 0, the already-subscribe-time-validated base URL) is what
// TestFetch_RedirectToPrivateIPRejected proves, and that check is a pure
// string/IP decision independent of which http.Client does the dialing — so
// bypassing only the dial guard does not weaken what this test demonstrates.
// shared/ssrf/ssrf_test.go already covers SafeHTTPClient's own dial-time guard.
func newTestWorker() *Worker {
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &Worker{httpClient: client, logger: testsupport.TestLogger()}
}

func TestFetch_200ParsesEvents(t *testing.T) {
	const ics = "BEGIN:VCALENDAR\r\n" +
		"BEGIN:VEVENT\r\nUID:evt-1\r\nDTSTART:20400101T090000Z\r\nDTEND:20400101T093000Z\r\nSUMMARY:Standup\r\nEND:VEVENT\r\n" +
		"END:VCALENDAR\r\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"abc123"`)
		w.Header().Set("Last-Modified", "Wed, 01 Jan 2040 00:00:00 GMT")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(ics))
	}))
	defer srv.Close()

	worker := newTestWorker()
	result, err := worker.fetch(context.Background(), srv.URL, "", "")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if result.notModified {
		t.Fatal("200 response must not report notModified")
	}
	if len(result.events) != 1 || result.events[0].UID != "evt-1" {
		t.Fatalf("expected one parsed event with uid evt-1, got %+v", result.events)
	}
	if result.etag != `"abc123"` {
		t.Errorf("etag = %q, want captured ETag header", result.etag)
	}
	if result.lastModified == "" {
		t.Error("lastModified should be captured from the Last-Modified header")
	}
}

func TestFetch_304NotModifiedSendsConditionalHeaders(t *testing.T) {
	var gotINM, gotIMS string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotINM = r.Header.Get("If-None-Match")
		gotIMS = r.Header.Get("If-Modified-Since")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	worker := newTestWorker()
	result, err := worker.fetch(context.Background(), srv.URL, `"cached-etag"`, "Tue, 01 Jan 2030 00:00:00 GMT")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !result.notModified {
		t.Fatal("304 response must report notModified")
	}
	if gotINM != `"cached-etag"` {
		t.Errorf("If-None-Match sent = %q, want the cached etag", gotINM)
	}
	if gotIMS != "Tue, 01 Jan 2030 00:00:00 GMT" {
		t.Errorf("If-Modified-Since sent = %q, want the cached last-modified", gotIMS)
	}
}

func TestFetch_OversizeRejected(t *testing.T) {
	big := strings.Repeat("A", maxFetchBytes+1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()

	worker := newTestWorker()
	_, err := worker.fetch(context.Background(), srv.URL, "", "")
	if err == nil {
		t.Fatal("expected an error for a feed exceeding the size limit, got nil")
	}
}

// TestFetch_RedirectToPrivateIPRejected proves the SSRF-relevant behavior: a
// feed that redirects to a loopback/private target is refused BEFORE the
// worker ever dials it. Hop 0 reaches the local fixture (plain client, see the
// file doc); the rejection under test is fetch()'s own ssrf.ValidateURL call
// on the resolved redirect target, not the http.Client's dial guard.
func TestFetch_RedirectToPrivateIPRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	worker := newTestWorker()
	_, err := worker.fetch(context.Background(), srv.URL, "", "")
	if err == nil {
		t.Fatal("expected a redirect to a private/link-local target to be rejected, got nil error")
	}
}

// TestResolveRedirect is a pure (no network) check of the URL-resolution logic
// a legitimate redirect hop relies on: RFC 7231 §7.1.2 permits a relative
// Location, and webcal(s):// must normalize the same way hop 0 does. (An
// end-to-end "redirect successfully followed" fetch() test is not achievable
// hermetically: any two local httptest fixtures are BOTH loopback, so the
// redirect target legitimately trips fetch()'s own ssrf.ValidateURL check —
// the exact behavior TestFetch_RedirectToPrivateIPRejected proves. Real
// providers (Google/Outlook webcal endpoints) redirect to a genuine external
// host, where this resolution logic is what makes the follow work.)
func TestResolveRedirect(t *testing.T) {
	cases := []struct{ current, location, want string }{
		{"https://a.test/feed.ics", "https://b.test/feed2.ics", "https://b.test/feed2.ics"},
		{"https://a.test/cal/feed.ics", "/other/feed.ics", "https://a.test/other/feed.ics"},
		{"https://a.test/feed.ics", "webcal://b.test/feed2.ics", "https://b.test/feed2.ics"},
	}
	for _, tc := range cases {
		got, err := resolveRedirect(tc.current, tc.location)
		if err != nil {
			t.Fatalf("resolveRedirect(%q, %q): %v", tc.current, tc.location, err)
		}
		if got != tc.want {
			t.Errorf("resolveRedirect(%q, %q) = %q, want %q", tc.current, tc.location, got, tc.want)
		}
	}
}

// TestFetch_TooManyRedirectsRejected proves an endless redirect chain
// terminates with an error rather than hanging or looping forever. In this
// hermetic fixture (necessarily loopback — see TestResolveRedirect's doc) the
// per-hop ssrf.ValidateURL check trips before the maxRedirects counter would;
// either bound firing is the invariant under test: fetch() always returns.
func TestFetch_TooManyRedirectsRejected(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL, http.StatusFound) // redirects to itself forever
	}))
	defer srv.Close()

	worker := newTestWorker()
	_, err := worker.fetch(context.Background(), srv.URL, "", "")
	if err == nil {
		t.Fatal("expected an infinite redirect loop to be rejected, got nil error")
	}
}

func TestFetch_PartialParseReturnsWhatParsed(t *testing.T) {
	// One well-formed VEVENT + one component with no UID at all (dropped by the
	// diff — see calendar_subscription_refresh.sql's own uid-required skip —
	// but still a valid VEVENT the caldav parser accepts, so this exercises the
	// "some parse, some don't" path via a genuinely malformed block instead).
	const ics = "BEGIN:VCALENDAR\r\n" +
		"BEGIN:VEVENT\r\nUID:evt-ok\r\nDTSTART:20400101T090000Z\r\nDTEND:20400101T093000Z\r\nSUMMARY:Good\r\nEND:VEVENT\r\n" +
		"BEGIN:VEVENT\r\nUID:evt-bad\r\nDTSTART:not-a-date\r\nEND:VEVENT\r\n" +
		"END:VCALENDAR\r\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(ics))
	}))
	defer srv.Close()

	worker := newTestWorker()
	result, err := worker.fetch(context.Background(), srv.URL, "", "")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(result.events) < 1 {
		t.Fatalf("expected at least the well-formed event to parse, got %+v", result.events)
	}
}

func TestNormalizeWebcal(t *testing.T) {
	cases := map[string]string{
		"webcal://example.test/feed.ics":  "https://example.test/feed.ics",
		"webcals://example.test/feed.ics": "https://example.test/feed.ics",
		"https://example.test/feed.ics":   "https://example.test/feed.ics",
		"http://example.test/feed.ics":    "http://example.test/feed.ics",
	}
	for in, want := range cases {
		if got := NormalizeWebcalURL(in); got != want {
			t.Errorf("NormalizeWebcalURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRun_ExitsOnCancel(t *testing.T) {
	w := &Worker{httpClient: &http.Client{}, logger: testsupport.TestLogger()}
	runCtx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		w.Run(runCtx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not exit after ctx cancel within 2s")
	}
}

// TestClaimAndRefresh_DiffAppliedThroughReducer is the DB-backed integration
// test (skips when DB_DSN is unset, per testsupport's fail-closed policy):
// subscribe → claimDue → refreshOne against a real local feed → the reducer
// actually diffed the events into calendar_events, and the bookkeeping columns
// (last_status/etag/last_modified) landed.
func TestClaimAndRefresh_DiffAppliedThroughReducer(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	const ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:worker-evt-1\r\nDTSTART:20400101T090000Z\r\nDTEND:20400101T093000Z\r\nSUMMARY:WorkerSynced\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"w-etag-1"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(ics))
	}))
	defer srv.Close()

	var userID, mailboxID int64
	if _, err := pool.Exec(ctx, `
		INSERT INTO domains (name, is_local) VALUES ('calsync.test', TRUE)
		ON CONFLICT (name) DO NOTHING`); err != nil {
		t.Fatalf("insert test domain: %v", err)
	}
	var domainID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM domains WHERE name = 'calsync.test'`).Scan(&domainID); err != nil {
		t.Fatalf("domain id: %v", err)
	}
	email := fmt.Sprintf("calsyncworker-%d@calsync.test", time.Now().UnixNano())
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (username, domain_id, email, display_name, password_hash)
		VALUES ($1, $2, $1, 'calsync worker test', 'x') RETURNING id`,
		email, domainID).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		VALUES ($1, $2, $3, 'calsync worker test', 'personal', TRUE) RETURNING id`,
		userID, domainID, email).Scan(&mailboxID); err != nil {
		t.Fatalf("insert mailbox: %v", err)
	}
	// Teardown order matters (V085): mailboxes_shared_not_primary CHECKs that a
	// primary mailbox's user_id is never NULL, so deleting the user ALONE
	// (mailboxes.user_id is ON DELETE SET NULL) makes Postgres's own SET NULL
	// action violate that CHECK — and demoting is_primary first is ALSO
	// immediately rejected (a live user must always have a primary). The two
	// deletes must land in ONE transaction: mailboxes' primary-mailbox-exists
	// check on DELETE is a DEFERRED constraint trigger, evaluated at COMMIT —
	// by which point the user row is gone too, so it no-ops. (Several existing
	// tests' bare "DELETE FROM users" cleanup hits this same trap silently,
	// via the swallowed `_, _ = pool.Exec` error — a pre-existing leak this
	// worker's test does not repeat.)
	t.Cleanup(func() {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Logf("cleanup: begin tx: %v", err)
			return
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `DELETE FROM mailboxes WHERE id = $1`, mailboxID); err != nil {
			t.Logf("cleanup: delete mailbox: %v", err)
			return
		}
		if _, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID); err != nil {
			t.Logf("cleanup: delete user: %v", err)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			t.Logf("cleanup: commit: %v", err)
		}
	})

	var calendarID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO calendars (mailbox_id, name, is_default) VALUES ($1, 'Worker sub', FALSE) RETURNING id`,
		mailboxID).Scan(&calendarID); err != nil {
		t.Fatalf("insert calendar: %v", err)
	}

	var subID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO calendar_subscriptions (user_id, calendar_id, url, refresh_interval_minutes)
		VALUES ($1, $2, $3, 0) RETURNING id`, // interval 0 => immediately due
		userID, calendarID, srv.URL).Scan(&subID); err != nil {
		t.Fatalf("insert subscription: %v", err)
	}

	w := &Worker{pool: pgxutil.WorkerPool{Pool: pool}, httpClient: &http.Client{}, logger: testsupport.TestLogger()}
	w.tick(ctx)

	var status string
	var etag *string
	var lastFetchAt *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT last_status, etag, last_fetch_at FROM calendar_subscriptions WHERE id = $1`, subID,
	).Scan(&status, &etag, &lastFetchAt); err != nil {
		t.Fatalf("read back subscription: %v", err)
	}
	if status != "ok" {
		t.Errorf("last_status = %q, want ok", status)
	}
	if etag == nil || *etag != `"w-etag-1"` {
		t.Errorf("etag = %v, want the fetched ETag to be cached", etag)
	}
	if lastFetchAt == nil {
		t.Error("last_fetch_at should be stamped by claimDue")
	}

	var eventCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM calendar_events WHERE calendar_id = $1 AND uid = 'worker-evt-1'`, calendarID,
	).Scan(&eventCount); err != nil {
		t.Fatalf("count synced events: %v", err)
	}
	if eventCount != 1 {
		t.Errorf("expected the fetched event to be diffed into calendar_events, got %d rows", eventCount)
	}
}

// TestSanitizeCacheValidator pins the capture-time validator sanitization
// (D-MAILSERVER-INTERNAL-CALENDARSYNC-002): a hostile feed's ETag/Last-Modified
// carrying header-invalid bytes (CR/LF, controls, non-ASCII) must sanitize to
// "" (persisted as NULL → unconditional GET), never be stored for later
// re-emission as an If-None-Match/If-Modified-Since request header.
func TestSanitizeCacheValidator(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`"abc123"`, `"abc123"`},                                           // normal strong ETag survives
		{"W/\"xyz-1\"", "W/\"xyz-1\""},                                     // weak ETag survives
		{"Sun, 06 Nov 1994 08:49:37 GMT", "Sun, 06 Nov 1994 08:49:37 GMT"}, // HTTP-date survives
		{"evil\r\nX-Injected: 1", ""},                                      // CRLF injection dropped
		{"evil\nETag: x", ""},                                              // bare LF dropped
		{"ctl\x00value", ""},                                               // NUL dropped
		{"ctl\x7fvalue", ""},                                               // DEL dropped
		{"caf\u00e9", "caf\u00e9"},                                         // obs-text is a LEGAL field value (RFC 7230) — survives
		{"", ""},                                                           // absent header stays absent (NULL path)
	}
	for _, tc := range cases {
		if got := sanitizeCacheValidator(tc.in); got != tc.want {
			t.Errorf("sanitizeCacheValidator(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
