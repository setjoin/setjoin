package carddav

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/reducercall"
	"setjoin.com/shared/toggle"
)

const galHomePropfindBody = `<?xml version="1.0"?>
<propfind xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <prop>
    <resourcetype/>
    <displayname/>
    <getetag/>
    <supported-report-set/>
  </prop>
</propfind>`

// galFixture is the caller + three colleagues (visible, hidden_from_gal,
// disabled) on the caller's own domain — enough to exercise the visibility
// seam end to end through the GAL bridge.
type galFixture struct {
	mbID, userID                    int64
	visibleID, hiddenID, disabledID int64
}

func setupGalFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool) *galFixture {
	t.Helper()
	var mbID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account('galh_caller')`).Scan(&mbID); err != nil {
		t.Fatalf("mk_account: %v", err)
	}
	var userID, domainID int64
	if err := pool.QueryRow(ctx, `SELECT user_id, domain_id FROM mailboxes WHERE id=$1`, mbID).Scan(&userID, &domainID); err != nil {
		t.Fatalf("caller lookup: %v", err)
	}

	f := &galFixture{mbID: mbID, userID: userID, visibleID: 900010001, hiddenID: 900010002, disabledID: 900010003}
	// Registered before seeding: a t.Fatalf mid-seed (e.g. the second or third
	// colleague) must not leak the ones that already landed. Mailbox + user
	// deletes run in ONE transaction (mirrors teardownAccount): the DEFERRED
	// trg_mailbox_primary_enforce_delete constraint ("a live user keeps a
	// primary mailbox") only clears once the user row is gone too, in the
	// SAME transaction — deleting the mailbox alone in its own auto-commit
	// statement trips it immediately.
	t.Cleanup(func() {
		ids := []int64{f.visibleID, f.hiddenID, f.disabledID}
		tx, err := pool.Begin(ctx)
		if err == nil {
			_, _ = tx.Exec(ctx, `DELETE FROM mailboxes WHERE user_id = ANY($1)`, ids)
			_, _ = tx.Exec(ctx, `DELETE FROM users WHERE id = ANY($1)`, ids)
			_ = tx.Commit(ctx)
		}
		teardownAccount(ctx, pool, mbID, userID)
	})
	seed := func(uid int64, label string, enabled, hidden bool) {
		if _, err := pool.Exec(ctx,
			`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
			 VALUES ($1, $2, $3, $2 || '@galh.e2e.test', $2, $4)`,
			uid, label, domainID, enabled); err != nil {
			t.Fatalf("insert user %s: %v", label, err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO mailboxes (id, user_id, domain_id, email, type, is_primary, display_name, hidden_from_gal)
			 VALUES ($1, $2, $3, $4 || '@galh.e2e.test', 'personal', TRUE, $4, $5)`,
			uid+10_000_000, uid, domainID, label, hidden); err != nil {
			t.Fatalf("insert mailbox %s: %v", label, err)
		}
	}
	seed(f.visibleID, "galh_visible", true, false)
	seed(f.hiddenID, "galh_hidden", true, true)
	seed(f.disabledID, "galh_disabled", false, false)
	return f
}

func galHandler(pool *pgxpool.Pool, on bool) *Handler {
	return &Handler{
		pool:   pool,
		caller: reducercall.New(pool),
		flags:  toggle.NewTestFlags(map[string]bool{toggle.FeatureGalCarddav: on}),
		logger: slog.Default(),
	}
}

func galRequest(h *Handler, method, urlPath string, userID int64, depth, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, urlPath, strings.NewReader(body))
	if depth != "" {
		req.Header.Set("Depth", depth)
	}
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestGal_E2E(t *testing.T) {
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

	f := setupGalFixture(t, ctx, pool)
	h := galHandler(pool, true)

	// 1. PROPFIND / depth 1 → the home listing includes /gal/ with the right props.
	rec := galRequest(h, "PROPFIND", "/", f.userID, "1", galHomePropfindBody)
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("home PROPFIND: want 207, got %d\n%s", rec.Code, rec.Body.String())
	}
	out := rec.Body.String()
	if !strings.Contains(out, "<href>/gal/</href>") {
		t.Fatalf("home PROPFIND missing /gal/ response:\n%s", out)
	}
	if !strings.Contains(out, "Global Address List") {
		t.Fatalf("home PROPFIND /gal/ missing displayname:\n%s", out)
	}
	if !strings.Contains(out, "addressbook-query") || !strings.Contains(out, "addressbook-multiget") || !strings.Contains(out, "sync-collection") {
		t.Fatalf("home PROPFIND /gal/ missing supported-report-set entries:\n%s", out)
	}

	// 2. PROPFIND /gal/ depth 1 → collection + one response per visible user.
	rec = galRequest(h, "PROPFIND", "/gal/", f.userID, "1", galHomePropfindBody)
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("/gal/ PROPFIND: want 207, got %d\n%s", rec.Code, rec.Body.String())
	}
	out = rec.Body.String()
	visibleHref := "/gal/u900010001.vcf"
	hiddenHref := "/gal/u900010002.vcf"
	disabledHref := "/gal/u900010003.vcf"
	if !strings.Contains(out, visibleHref) {
		t.Fatalf("/gal/ PROPFIND missing the visible colleague %s:\n%s", visibleHref, out)
	}
	if !strings.Contains(out, "getetag") {
		t.Fatalf("/gal/ PROPFIND member missing getetag:\n%s", out)
	}
	if strings.Contains(out, hiddenHref) {
		t.Fatalf("/gal/ PROPFIND leaked the hidden_from_gal colleague:\n%s", out)
	}
	if strings.Contains(out, disabledHref) {
		t.Fatalf("/gal/ PROPFIND leaked the disabled colleague:\n%s", out)
	}

	// 3. Toggle OFF → no /gal/ in the home listing, and /gal/ itself 404s.
	hOff := galHandler(pool, false)
	rec = galRequest(hOff, "PROPFIND", "/", f.userID, "1", galHomePropfindBody)
	if strings.Contains(rec.Body.String(), "/gal/") {
		t.Fatalf("toggle OFF: home PROPFIND must not list /gal/:\n%s", rec.Body.String())
	}
	rec = galRequest(hOff, "PROPFIND", "/gal/", f.userID, "1", galHomePropfindBody)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("toggle OFF: /gal/ PROPFIND want 404, got %d", rec.Code)
	}

	// 4. GET /gal/u{id}.vcf → 200, vcard, ETag; unknown/hidden id → 404.
	rec = galRequest(h, http.MethodGet, visibleHref, f.userID, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET visible card: want 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/vcard") {
		t.Fatalf("GET visible card: want text/vcard content-type, got %q", ct)
	}
	if rec.Header().Get("ETag") == "" {
		t.Fatal("GET visible card: missing ETag header")
	}
	if !strings.Contains(rec.Body.String(), "UID:setjoin-gal-u900010001") {
		t.Fatalf("GET visible card: missing UID:\n%s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "galh_visible@galh.e2e.test") {
		t.Fatalf("GET visible card: missing email:\n%s", rec.Body.String())
	}

	rec = galRequest(h, http.MethodGet, "/gal/u999999999.vcf", f.userID, "", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET unknown id: want 404, got %d", rec.Code)
	}

	rec = galRequest(h, http.MethodGet, hiddenHref, f.userID, "", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET hidden_from_gal id: want 404, got %d", rec.Code)
	}

	// 5. A disabled user's card also 404s.
	rec = galRequest(h, http.MethodGet, disabledHref, f.userID, "", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET disabled id: want 404, got %d", rec.Code)
	}
}

const galQueryAllBody = `<?xml version="1.0"?>
<C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <D:prop><D:getetag/><C:address-data/></D:prop>
</C:addressbook-query>`

func galQueryFilterBody(text string) string {
	return `<?xml version="1.0"?>
<C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <D:prop><D:getetag/><C:address-data/></D:prop>
  <C:filter>
    <C:prop-filter name="FN">
      <C:text-match>` + text + `</C:text-match>
    </C:prop-filter>
  </C:filter>
</C:addressbook-query>`
}

func galMultigetBody(hrefs ...string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?>
<C:addressbook-multiget xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <D:prop><D:getetag/><C:address-data/></D:prop>
`)
	for _, href := range hrefs {
		b.WriteString("  <D:href>" + href + "</D:href>\n")
	}
	b.WriteString("</C:addressbook-multiget>")
	return b.String()
}

func TestGal_Report_E2E(t *testing.T) {
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

	f := setupGalFixture(t, ctx, pool)
	h := galHandler(pool, true)
	visibleHref := "/gal/u900010001.vcf"
	callerHref := fmt.Sprintf("/gal/u%d.vcf", f.userID)

	// 1. addressbook-query, no filter → every visible user as address-data vCards.
	rec := galRequest(h, "REPORT", "/gal/", f.userID, "", galQueryAllBody)
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("query all: want 207, got %d\n%s", rec.Code, rec.Body.String())
	}
	out := rec.Body.String()
	if !strings.Contains(out, "BEGIN:VCARD") || !strings.Contains(out, "galh_visible@galh.e2e.test") {
		t.Fatalf("query all missing address-data for the visible colleague:\n%s", out)
	}

	// 2. text-match filter on the fixture's name → only that card; a SQL-injection
	// probe in the filter text must be parameterized (zero rows, no error).
	rec = galRequest(h, "REPORT", "/gal/", f.userID, "", galQueryFilterBody("galh_visible"))
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("query filtered: want 207, got %d\n%s", rec.Code, rec.Body.String())
	}
	out = rec.Body.String()
	if !strings.Contains(out, visibleHref) {
		t.Fatalf("query filtered missing the matched card:\n%s", out)
	}
	if strings.Contains(out, "galh_hidden") || strings.Contains(out, "galh_disabled") {
		t.Fatalf("query filtered over-matched:\n%s", out)
	}
	rec = galRequest(h, "REPORT", "/gal/", f.userID, "", galQueryFilterBody(`%' OR 1=1 --`))
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("SQL-injection probe: want 207, got %d\n%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "BEGIN:VCARD") {
		t.Fatalf("SQL-injection probe must return zero rows, not the whole directory:\n%s", rec.Body.String())
	}

	// 3. addressbook-multiget with two real hrefs → exactly those two.
	rec = galRequest(h, "REPORT", "/gal/", f.userID, "", galMultigetBody(callerHref, visibleHref))
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("multiget: want 207, got %d\n%s", rec.Code, rec.Body.String())
	}
	out = rec.Body.String()
	if !strings.Contains(out, callerHref) || !strings.Contains(out, visibleHref) {
		t.Fatalf("multiget missing a requested href:\n%s", out)
	}
	if strings.Count(out, "<href>") != 2 {
		t.Fatalf("multiget must return exactly the two requested hrefs, got:\n%s", out)
	}
}

func TestGal_SyncCollection_E2E(t *testing.T) {
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

	mkColleague := func(label string) (mbID, userID int64) {
		if err := pool.QueryRow(ctx, `SELECT mk_account($1)`, label).Scan(&mbID); err != nil {
			t.Fatalf("mk_account %s: %v", label, err)
		}
		if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, mbID).Scan(&userID); err != nil {
			t.Fatalf("user_id %s: %v", label, err)
		}
		t.Cleanup(func() { teardownAccount(ctx, pool, mbID, userID) })
		return mbID, userID
	}

	_, callerUser := mkColleague("galsync_caller")
	_, aUser := mkColleague("galsync_a")
	_, bUser := mkColleague("galsync_b")
	_, cUser := mkColleague("galsync_c")

	h := galHandler(pool, true)
	aHref := fmt.Sprintf("/gal/u%d.vcf", aUser)
	bHref := fmt.Sprintf("/gal/u%d.vcf", bUser)

	// Initial sync: every visible colleague + a token.
	rec := galRequest(h, "REPORT", "/gal/", callerUser, "", syncReportNoToken)
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("initial sync: want 207, got %d\n%s", rec.Code, rec.Body.String())
	}
	out := rec.Body.String()
	if !strings.Contains(out, aHref) || !strings.Contains(out, bHref) {
		t.Fatalf("initial sync missing a colleague href:\n%s", out)
	}
	m := syncTokenRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("initial sync has no sync-token:\n%s", out)
	}
	token0 := m[1]

	// Touch A → delta from token0 carries only A, with a fresh etag.
	time.Sleep(2 * time.Millisecond)
	if _, err := pool.Exec(ctx, `UPDATE users SET job_title='CTO', updated_at=clock_timestamp() WHERE id=$1`, aUser); err != nil {
		t.Fatalf("touch A: %v", err)
	}
	rec = galRequest(h, "REPORT", "/gal/", callerUser, "", syncReportWithToken(token0))
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("incremental sync: want 207, got %d\n%s", rec.Code, rec.Body.String())
	}
	out = rec.Body.String()
	if !strings.Contains(out, aHref) {
		t.Fatalf("incremental sync missing touched A:\n%s", out)
	}
	if strings.Contains(out, bHref) {
		t.Fatalf("incremental sync leaked unchanged B:\n%s", out)
	}
	m = syncTokenRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("incremental sync has no sync-token:\n%s", out)
	}
	token1 := m[1]

	// Disable B → next delta lists its href as a top-level 404 (RFC 6578 removed).
	time.Sleep(2 * time.Millisecond)
	if _, err := pool.Exec(ctx, `UPDATE users SET enabled=FALSE, updated_at=clock_timestamp() WHERE id=$1`, bUser); err != nil {
		t.Fatalf("disable B: %v", err)
	}
	rec = galRequest(h, "REPORT", "/gal/", callerUser, "", syncReportWithToken(token1))
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("removal sync: want 207, got %d\n%s", rec.Code, rec.Body.String())
	}
	out = rec.Body.String()
	if !strings.Contains(out, bHref) || !strings.Contains(out, "404 Not Found") {
		t.Fatalf("disabling B must surface it as a removed (404) member:\n%s", out)
	}
	m = syncTokenRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("removal sync has no sync-token:\n%s", out)
	}
	token2 := m[1]

	// Hard-delete C (still visible at token2 issue time) → breaks the count
	// invariant → forced resync (403 valid-sync-token), never a stale delta.
	time.Sleep(2 * time.Millisecond)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin hard-delete tx: %v", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM mailboxes WHERE user_id=$1`, cUser); err != nil {
		t.Fatalf("hard-delete C mailbox: %v", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM users WHERE id=$1`, cUser); err != nil {
		t.Fatalf("hard-delete C user: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit hard-delete: %v", err)
	}
	rec = galRequest(h, "REPORT", "/gal/", callerUser, "", syncReportWithToken(token2))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("hard-delete breaks the count invariant: want 403, got %d\n%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "valid-sync-token") {
		t.Fatalf("hard-delete resync missing valid-sync-token precondition:\n%s", rec.Body.String())
	}

	// Malformed token → 403 valid-sync-token.
	rec = galRequest(h, "REPORT", "/gal/", callerUser, "", syncReportWithToken("not-a-token"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("malformed token: want 403, got %d", rec.Code)
	}
}

const galPutBody = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:test-put\r\nFN:Should Be Rejected\r\nEND:VCARD\r\n"

// galDisclosedRe matches the per-member hrefs of a GAL multistatus response.
var galDisclosedRe = regexp.MustCompile(`/gal/u(\d+)\.vcf`)

// galDisclosedIDs extracts the directory member ids a GAL 207 response actually
// disclosed (one /gal/u{id}.vcf href per member).
func galDisclosedIDs(body string) map[int64]bool {
	out := map[int64]bool{}
	for _, m := range galDisclosedRe.FindAllStringSubmatch(body, -1) {
		id, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			continue
		}
		out[id] = true
	}
	return out
}

// TestGal_VisibilityJournal_E2E: the render path journals what it discloses
// (CARDDAV-V-002) and a never-visible member is never reported as a sync
// removal. Journal rows are read directly (the test connection bypasses RLS
// the same way the pgTAP runner does).
//
// The test database is shared: the org-wide visibility seam (ADR-004 — no
// domain filter) makes every enabled non-hidden user other packages' fixtures
// left behind directory-visible to this fixture's caller, so the PROPFIND and
// sync legitimately journal those disclosures under this mailbox too (the
// ldapsync shared-DB snapshot pattern). Every journal assertion below is
// therefore a DELTA against a pre-activity snapshot, and "the disclosed set"
// is read off the actual response instead of assumed to be the fixture's two
// members. Foreign rows are ignored, never deleted.
func TestGal_VisibilityJournal_E2E(t *testing.T) {
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

	f := setupGalFixture(t, ctx, pool)
	h := galHandler(pool, true)
	visibleHref := "/gal/u900010001.vcf"
	hiddenHref := "/gal/u900010002.vcf"

	journaled := func() map[int64]bool {
		t.Helper()
		rows, err := pool.Query(ctx,
			`SELECT user_id FROM gal_visibility_journal WHERE mailbox_id = $1`, f.mbID)
		if err != nil {
			t.Fatalf("read journal: %v", err)
		}
		defer rows.Close()
		out := map[int64]bool{}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				t.Fatalf("scan journal: %v", err)
			}
			out[id] = true
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("journal rows: %v", err)
		}
		return out
	}

	// Snapshot the pre-existing journal membership; the helpers below assert
	// only what THIS test's activity added (ids now present minus the
	// snapshot), so rows the shared database already carried cannot fail the
	// test — and this test must not touch them.
	before := journaled()
	journalDelta := func() map[int64]bool {
		t.Helper()
		delta := map[int64]bool{}
		for id := range journaled() {
			if !before[id] {
				delta[id] = true
			}
		}
		return delta
	}

	// 1. PROPFIND /gal/ depth 1 discloses the caller + the visible colleague —
	//    exactly the disclosed set is journaled; hidden/disabled stay out.
	rec := galRequest(h, "PROPFIND", "/gal/", f.userID, "1", galHomePropfindBody)
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("PROPFIND /gal/: want 207, got %d\n%s", rec.Code, rec.Body.String())
	}
	disclosed := galDisclosedIDs(rec.Body.String())
	if !disclosed[f.userID] || !disclosed[f.visibleID] {
		t.Fatalf("PROPFIND must disclose the fixture members (caller+visible), disclosed %v", disclosed)
	}
	got := journalDelta()
	if !maps.Equal(got, disclosed) {
		t.Fatalf("PROPFIND must journal exactly the disclosed set, delta %v want %v", got, disclosed)
	}
	if got[f.hiddenID] || got[f.disabledID] {
		t.Fatalf("never-visible members must not be journaled, delta %v", got)
	}

	// 2. GET the hidden card 404s and journals nothing; GET the visible card
	//    200s and is already journaled (idempotent re-record). A single-card
	//    PROPFIND discloses too — same journaling, still nothing new. The
	//    delta against the original snapshot must stay exactly the disclosed
	//    set (on a clean database that is precisely caller+visible).
	if rec := galRequest(h, http.MethodGet, hiddenHref, f.userID, "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("GET hidden card: want 404, got %d", rec.Code)
	}
	if rec := galRequest(h, http.MethodGet, visibleHref, f.userID, "", ""); rec.Code != http.StatusOK {
		t.Fatalf("GET visible card: want 200, got %d", rec.Code)
	}
	if rec := galRequest(h, "PROPFIND", visibleHref, f.userID, "0", galHomePropfindBody); rec.Code != http.StatusMultiStatus {
		t.Fatalf("PROPFIND visible card: want 207, got %d", rec.Code)
	}
	got = journalDelta()
	if !maps.Equal(got, disclosed) {
		t.Fatalf("GET must not change the journal beyond the disclosed set, delta %v want %v", got, disclosed)
	}

	// 3. Initial sync — the reducer journals its changed set in-DB.
	rec = galRequest(h, "REPORT", "/gal/", f.userID, "", syncReportNoToken)
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("initial sync: want 207, got %d\n%s", rec.Code, rec.Body.String())
	}
	m := syncTokenRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("initial sync has no sync-token:\n%s", rec.Body.String())
	}
	token0 := m[1]

	// 4. The never-visible member's row is touched (enabled flip) inside the
	//    token window — the pre-V261 removed-set would have rendered its href
	//    as a 404 removal. It was never journaled, so the delta must carry
	//    neither the href nor any other removal.
	time.Sleep(2 * time.Millisecond)
	if _, err := pool.Exec(ctx,
		`UPDATE users SET enabled = FALSE, updated_at = clock_timestamp() WHERE id = $1`, f.hiddenID); err != nil {
		t.Fatalf("touch hidden member: %v", err)
	}
	rec = galRequest(h, "REPORT", "/gal/", f.userID, "", syncReportWithToken(token0))
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("delta after never-visible touch: want 207, got %d\n%s", rec.Code, rec.Body.String())
	}
	out := rec.Body.String()
	if strings.Contains(out, hiddenHref) {
		t.Fatalf("never-visible member must never be reported as removed:\n%s", out)
	}
	if strings.Contains(out, "404 Not Found") {
		t.Fatalf("delta must carry no removals at all here:\n%s", out)
	}
}

func TestGal_ReadOnly_E2E(t *testing.T) {
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

	f := setupGalFixture(t, ctx, pool)
	h := galHandler(pool, true)
	visibleHref := "/gal/u900010001.vcf"

	// PUT to an existing GAL card → 403 read-only.
	rec := galRequest(h, http.MethodPut, visibleHref, f.userID, "", galPutBody)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("PUT existing gal card: want 403, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "read-only") {
		t.Fatalf("PUT rejection body must mention read-only:\n%s", rec.Body.String())
	}

	// PUT a brand-new resource under /gal/ → 403 too (can't create a directory entry).
	rec = galRequest(h, http.MethodPut, "/gal/newperson.vcf", f.userID, "", galPutBody)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("PUT new gal resource: want 403, got %d", rec.Code)
	}

	// DELETE → 403 read-only.
	rec = galRequest(h, http.MethodDelete, visibleHref, f.userID, "", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("DELETE gal card: want 403, got %d", rec.Code)
	}

	// OPTIONS /gal/ → reduced Allow list (no PUT/DELETE on the GAL).
	rec = galRequest(h, http.MethodOptions, "/gal/", f.userID, "", "")
	if allow := rec.Header().Get("Allow"); allow != "OPTIONS, GET, PROPFIND, REPORT" {
		t.Fatalf("OPTIONS /gal/: want reduced Allow list, got %q", allow)
	}

	// Control: PUT to a personal addressbook must be unaffected (no regression).
	var abID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO addressbooks (mailbox_id, name) VALUES ($1, 'Gal RO Control') RETURNING id`, f.mbID).Scan(&abID); err != nil {
		t.Fatalf("insert control addressbook: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM addressbooks WHERE id=$1`, abID) })
	controlPath := fmt.Sprintf("/%d/x.vcf", abID)
	rec = galRequest(h, http.MethodPut, controlPath, f.userID, "", galPutBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("control PUT to personal addressbook: want 201, got %d\n%s", rec.Code, rec.Body.String())
	}
}
