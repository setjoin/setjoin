package caldav

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/reducercall"
	"setjoin.com/mailserver/internal/webdav"
)

// TestSyncTokenRoundTrip: the opaque wire token parses back to its counter, and
// an empty token means initial sync (not an error).
func TestSyncTokenRoundTrip(t *testing.T) {
	if got := webdav.BuildSyncToken(42); got != "https://setjoin.invalid/ns/sync/42" {
		t.Fatalf("BuildSyncToken: got %q", got)
	}
	seq, ok := webdav.ParseSyncToken("https://setjoin.invalid/ns/sync/42")
	if !ok || seq != "42" {
		t.Fatalf("ParseSyncToken(uri): got %q ok=%v", seq, ok)
	}
	if seq, ok := webdav.ParseSyncToken(""); !ok || seq != "" {
		t.Fatalf("ParseSyncToken(empty): got %q ok=%v, want initial-sync", seq, ok)
	}
	if _, ok := webdav.ParseSyncToken("not-a-token"); ok {
		t.Fatal("ParseSyncToken(garbage): want ok=false")
	}
}

const syncReportNoToken = `<?xml version="1.0"?>
<D:sync-collection xmlns:D="DAV:">
  <D:sync-token/>
  <D:sync-level>1</D:sync-level>
  <D:prop><D:getetag/></D:prop>
</D:sync-collection>`

func syncReportWithToken(tok string) string {
	return `<?xml version="1.0"?>
<D:sync-collection xmlns:D="DAV:">
  <D:sync-token>` + tok + `</D:sync-token>
  <D:sync-level>1</D:sync-level>
  <D:prop><D:getetag/></D:prop>
</D:sync-collection>`
}

var syncTokenRe = regexp.MustCompile(`<sync-token>([^<]+)</sync-token>`)

// TestSyncCollection_E2E drives the full REPORT path against a real test DB:
// initial sync returns every event + a token; a second REPORT with that token
// returns only the subsequent change; an invalid (future) token returns the
// RFC 6578 DAV:valid-sync-token precondition (403). Skips without TEST_DB_DSN
// (matches scan_db_test.go).
func TestSyncCollection_E2E(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping DB integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	t.Cleanup(pool.Close)

	var mbID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account('caldav_sync_e2e')`).Scan(&mbID); err != nil {
		t.Fatalf("mk_account: %v", err)
	}
	var userID int64
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, mbID).Scan(&userID); err != nil {
		t.Fatalf("user_id: %v", err)
	}
	t.Cleanup(func() { teardownAccount(ctx, pool, mbID, userID) })

	var calID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO calendars (mailbox_id, name) VALUES ($1,'Sync E2E') RETURNING id`, mbID).Scan(&calID); err != nil {
		t.Fatalf("insert calendar: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO calendar_events (calendar_id, uid, title, etag) VALUES ($1,'e2e-1','One','et1'),($1,'e2e-2','Two','et2')`,
		calID); err != nil {
		t.Fatalf("insert events: %v", err)
	}

	h := &Handler{pool: pool, caller: reducercall.New(pool), logger: slog.Default()}

	report := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("REPORT", "/"+strconv.FormatInt(calID, 10)+"/", strings.NewReader(body))
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// 1. Initial sync: both events + a token.
	rec := report(syncReportNoToken)
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("initial sync: want 207, got %d\n%s", rec.Code, rec.Body.String())
	}
	out := rec.Body.String()
	if !strings.Contains(out, "e2e-1.ics") || !strings.Contains(out, "e2e-2.ics") {
		t.Fatalf("initial sync missing events:\n%s", out)
	}
	m := syncTokenRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("initial sync has no sync-token:\n%s", out)
	}
	token1 := m[1]

	// 2. Add a third event, sync from token1 → only the new one.
	if _, err := pool.Exec(ctx,
		`INSERT INTO calendar_events (calendar_id, uid, title, etag) VALUES ($1,'e2e-3','Three','et3')`, calID); err != nil {
		t.Fatalf("insert event 3: %v", err)
	}
	rec = report(syncReportWithToken(token1))
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("incremental sync: want 207, got %d", rec.Code)
	}
	out = rec.Body.String()
	if !strings.Contains(out, "e2e-3.ics") {
		t.Fatalf("incremental sync missing new event:\n%s", out)
	}
	if strings.Contains(out, "e2e-1.ics") || strings.Contains(out, "e2e-2.ics") {
		t.Fatalf("incremental sync leaked unchanged events (should be delta-only):\n%s", out)
	}

	// 3. Invalid (future) token → 403 valid-sync-token precondition.
	rec = report(syncReportWithToken(webdav.BuildSyncToken(999999)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("invalid token: want 403, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "valid-sync-token") {
		t.Fatalf("invalid token: missing valid-sync-token precondition:\n%s", rec.Body.String())
	}
}

// teardownAccount removes an mk_account created for a committed DB test, leaving
// zero residue. Order matters: calendars are deleted first (their AFTER-DELETE
// journal trigger resolves the still-present mailbox fine — a mailbox cascade
// would fire it against the vanishing mailbox row), then the mailbox + user are
// dropped in ONE transaction so the DEFERRED mailbox_primary_enforce_delete
// constraint (BZ013 — "a live user keeps a primary mailbox") sees the user gone
// at commit and passes.
func teardownAccount(ctx context.Context, pool *pgxpool.Pool, mbID, userID int64) {
	_, _ = pool.Exec(ctx, `DELETE FROM calendars WHERE mailbox_id=$1`, mbID)
	_, _ = pool.Exec(ctx, `DELETE FROM addressbooks WHERE mailbox_id=$1`, mbID)
	tx, err := pool.Begin(ctx)
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM mailboxes WHERE id=$1`, mbID); err != nil {
		return
	}
	if _, err := tx.Exec(ctx, `DELETE FROM users WHERE id=$1`, userID); err != nil {
		return
	}
	_ = tx.Commit(ctx)
}
