package admin

// Coverage suite for the changed eDiscovery handler lines the export/case
// suites do not reach: executeSearch's plain-query arm (predicate building,
// atomic count + case-bound result binding + status flip), the defensive
// invalid-query-payload arm, ExportSelected's caseId validation, the export
// binding-check failure arm, and the export audit-refusal arm.
//
// executeSearch is invoked directly (the production goroutine's body) so the
// outcomes are deterministic. Failure injection reuses the package's
// shadow-schema pool helper.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

// seedEDiscoveryCovMailbox seeds one domain/user/mailbox/folder/message
// fixture (9615x id range, disjoint from the 9600 export fixture) and
// registers FK-safe cleanup.
func seedEDiscoveryCovMailbox(t *testing.T, pool *pgxpool.Pool) (mailboxID, msgID int64) {
	t.Helper()
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed ediscovery cov: %v: %v", sql, err)
		}
	}
	exec(`INSERT INTO domains (id, name, is_local) OVERRIDING SYSTEM VALUE VALUES (96150,'ediscov-cov.test',TRUE) ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name, enabled) OVERRIDING SYSTEM VALUE VALUES
		(96151,'ediscov_cov',96150,'u@ediscov-cov.test','U',TRUE) ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, type, is_primary) OVERRIDING SYSTEM VALUE VALUES
		(9615,96151,96150,'u@ediscov-cov.test','U','personal',TRUE) ON CONFLICT DO NOTHING`)
	t.Cleanup(func() {
		c := context.Background()
		del := func(step, sql string, args ...any) {
			if _, err := pool.Exec(c, sql, args...); err != nil {
				t.Errorf("ediscovery cov cleanup, %s: %v", step, err)
			}
		}
		del("messages", `DELETE FROM messages WHERE mailbox_id = 9615`)
		del("ediscovery results", `DELETE FROM ediscovery_search_results WHERE search_id IN (SELECT id FROM ediscovery_searches WHERE created_by = 96151)`)
		del("ediscovery searches", `DELETE FROM ediscovery_searches WHERE created_by = 96151`)
		del("folders", `DELETE FROM folders WHERE mailbox_id = 9615`)
		del("mailbox_lifecycle", `DELETE FROM mailbox_lifecycle WHERE mailbox_id = 9615`)
		del("mailbox_address_claims", `DELETE FROM mailbox_address_claims WHERE mailbox_id = 9615`)
		del("mailboxes.disable-triggers", `ALTER TABLE mailboxes DISABLE TRIGGER ALL`)
		del("mailboxes", `DELETE FROM mailboxes WHERE id = 9615`)
		del("mailboxes.enable-triggers", `ALTER TABLE mailboxes ENABLE TRIGGER ALL`)
		del("users", `DELETE FROM users WHERE id = 96151`)
		del("domains", `DELETE FROM domains WHERE id = 96150`)
	})

	var folderID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO folders (mailbox_id, name, role, path) VALUES (9615, 'Inbox', 'inbox', 'Inbox')
		 RETURNING id`,
	).Scan(&folderID); err != nil {
		t.Fatalf("insert folder: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO messages (mailbox_id, folder_id, message_id, subject, from_addr, from_name,
		 to_addrs, cc_addrs, bcc_addrs, thread_id, raw_ref, received_at, is_read)
		 VALUES (9615, $1, '<ediscov-cov-1@ediscov-cov.test>', 'ediscovery cov haystack', 'ext@outside.example', 'Ext',
		 '[]'::JSONB, '[]'::JSONB, '[]'::JSONB, 'thread-ediscov-cov', 'inbound/cov', now(), TRUE)
		 RETURNING id`, folderID,
	).Scan(&msgID); err != nil {
		t.Fatalf("insert message: %v", err)
	}
	return 9615, msgID
}

// ediscoveryCovInsertSearch inserts one search row and returns its id.
func ediscoveryCovInsertSearch(t *testing.T, pool *pgxpool.Pool, query string) int64 {
	t.Helper()
	var id int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO ediscovery_searches (name, created_by, query, status)
		 VALUES ('ediscov-cov-search', 96151, $1::JSONB, 'pending') RETURNING id`, query,
	).Scan(&id); err != nil {
		t.Fatalf("insert search: %v", err)
	}
	return id
}

// ediscoveryCovStatus reads a search row's (status, result_count).
func ediscoveryCovStatus(t *testing.T, pool *pgxpool.Pool, id int64) (string, int) {
	t.Helper()
	var status string
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT status, COALESCE(result_count, 0) FROM ediscovery_searches WHERE id = $1`, id,
	).Scan(&status, &count); err != nil {
		t.Fatalf("read search status: %v", err)
	}
	return status, count
}

// TestEDiscoveryExecuteSearch_PlainQuery_BindsResults covers the plain
// keywords arm of executeSearch: the predicate is built with every optional
// filter (fromAddr, dateFrom, dateTo, mailboxIds), and count + case-bound
// result binding + status flip commit ATOMICALLY — result_count always equals
// the persisted binding size.
func TestEDiscoveryExecuteSearch_PlainQuery_BindsResults(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	mailboxID, _ := seedEDiscoveryCovMailbox(t, pool)

	searchID := ediscoveryCovInsertSearch(t, pool, fmt.Sprintf(
		`{"keywords":"haystack","kql":"","fromAddr":"outside.example","dateFrom":"2000-01-01","dateTo":"2100-01-01","mailboxIds":[%d]}`, mailboxID))

	h := &EDiscoveryHandler{pool: pool, logger: testsupport.TestLogger()}
	h.executeSearch(context.Background(), searchID)

	status, count := ediscoveryCovStatus(t, pool, searchID)
	if status != "complete" {
		t.Fatalf("executeSearch status = %q, want complete", status)
	}
	var bound int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM ediscovery_search_results WHERE search_id = $1`, searchID).Scan(&bound); err != nil {
		t.Fatalf("count bound results: %v", err)
	}
	if bound != count {
		t.Fatalf("result_count = %d but persisted binding has %d rows — the reported set and the bound set diverged", count, bound)
	}
}

// TestEDiscoveryExecuteSearch_ReexecutionRebinds proves re-execution clears
// stale bindings before re-binding, so the bound set always reflects the
// latest completion.
func TestEDiscoveryExecuteSearch_ReexecutionRebinds(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	mailboxID, _ := seedEDiscoveryCovMailbox(t, pool)

	searchID := ediscoveryCovInsertSearch(t, pool, fmt.Sprintf(
		`{"keywords":"nonexistent-token-cov","kql":"","fromAddr":"","dateFrom":"","dateTo":"","mailboxIds":[%d]}`, mailboxID))

	h := &EDiscoveryHandler{pool: pool, logger: testsupport.TestLogger()}
	h.executeSearch(context.Background(), searchID)
	h.executeSearch(context.Background(), searchID)

	status, count := ediscoveryCovStatus(t, pool, searchID)
	if status != "complete" || count != 0 {
		t.Fatalf("re-executed search = (%q, %d), want (complete, 0)", status, count)
	}
	var bound int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM ediscovery_search_results WHERE search_id = $1`, searchID).Scan(&bound); err != nil {
		t.Fatalf("count bound results: %v", err)
	}
	if bound != 0 {
		t.Fatalf("re-execution left %d stale bound rows, want 0", bound)
	}
}

// TestEDiscoveryExecuteSearch_InvalidQueryPayload_Failed covers the defensive
// arm: a stored query payload that is valid JSON but not an object fails the
// unmarshal and the search is marked failed — never silently completed.
// (The production table's jsonb_typeof='object' CHECK keeps this payload out;
// the shadow fixture omits the check to exercise the guard itself.)
func TestEDiscoveryExecuteSearch_InvalidQueryPayload_Failed(t *testing.T) {
	shadowPool := openMAMListFixturePool(t, `
		CREATE TABLE __SCHEMA__.ediscovery_searches(
			id bigserial PRIMARY KEY, name text NOT NULL, created_by bigint NOT NULL,
			query jsonb NOT NULL, status text NOT NULL DEFAULT 'pending', result_count int,
			started_at timestamptz, completed_at timestamptz, created_at timestamptz DEFAULT now(),
			case_id bigint);
		INSERT INTO __SCHEMA__.ediscovery_searches (name, created_by, query, status)
		VALUES ('ediscov-cov-bad', 96151, '[1,2,3]', 'pending');`)
	var id int64
	if err := shadowPool.QueryRow(context.Background(),
		`SELECT id FROM ediscovery_searches`).Scan(&id); err != nil {
		t.Fatalf("read seeded search id: %v", err)
	}

	h := &EDiscoveryHandler{pool: shadowPool, logger: testsupport.TestLogger()}
	h.executeSearch(context.Background(), id)

	var status string
	if err := shadowPool.QueryRow(context.Background(),
		`SELECT status FROM ediscovery_searches WHERE id = $1`, id).Scan(&status); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if status != "failed" {
		t.Fatalf("invalid-payload search status = %q, want failed", status)
	}
}

// ediscoveryCovExportReq builds a mail.export-carrying export request.
func ediscoveryCovExportReq(t *testing.T, ids, caseID string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/admin/ediscovery/export?ids="+ids+"&caseId="+caseID, nil)
	return req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: 96151, IsAdmin: true, Permissions: []string{permissions.PermMailExport},
	}))
}

// TestEDiscoveryExport_InvalidCaseId_400 covers ExportSelected's caseId
// validation arms: unparseable and non-positive case ids are refused with a
// bounded 400 before any case lookup.
func TestEDiscoveryExport_InvalidCaseId_400(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := &EDiscoveryHandler{pool: pool, logger: testsupport.TestLogger()}

	for _, caseID := range []string{"abc", "0", "-5"} {
		rec := httptest.NewRecorder()
		h.ExportSelected(rec, ediscoveryCovExportReq(t, "1", caseID))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("export caseId=%q: want 400, got %d (body=%s)", caseID, rec.Code, rec.Body.String())
		}
	}
}

// ediscoveryCovCaseFixture is the shadow case-authorization surface shared by
// the export failure tests: an active case holding one completed search.
const ediscoveryCovCaseFixture = `
	CREATE TABLE __SCHEMA__.ediscovery_cases(
		id bigint PRIMARY KEY, name text, status text, created_by bigint,
		created_at timestamptz DEFAULT now());
	CREATE TABLE __SCHEMA__.ediscovery_searches(
		id bigserial PRIMARY KEY, name text, created_by bigint, query jsonb,
		status text, result_count int, export_ref text, started_at timestamptz,
		completed_at timestamptz, created_at timestamptz DEFAULT now(), case_id bigint);
	INSERT INTO __SCHEMA__.ediscovery_cases (id, name, status, created_by)
	VALUES (96160, 'cov case', 'active', 96151);
	INSERT INTO __SCHEMA__.ediscovery_searches (name, created_by, query, status, case_id)
	VALUES ('cov search', 96151, '{"keywords":"x"}'::jsonb, 'complete', 96160);`

// TestEDiscoveryExport_BindingCheckFailure_500 proves the case-bound ids
// precheck is checked: a failing binding query (shadow results table with
// mismatched column types) answers 5xx — the export never streams over an
// unverifiable binding.
func TestEDiscoveryExport_BindingCheckFailure_500(t *testing.T) {
	shadowPool := openMAMListFixturePool(t, ediscoveryCovCaseFixture+`
		CREATE TABLE __SCHEMA__.ediscovery_search_results(search_id bigint, message_id text);`)
	h := &EDiscoveryHandler{pool: shadowPool, logger: testsupport.TestLogger()}

	rec := httptest.NewRecorder()
	h.ExportSelected(rec, ediscoveryCovExportReq(t, "7", "96160"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("binding check failure: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestEDiscoveryExport_AuditRefused_NoStream_500 proves the audit-refusal arm:
// when the export audit cannot be persisted (planted failing audit_write),
// NOTHING streams — the response is a 5xx with no MBOX body.
func TestEDiscoveryExport_AuditRefused_NoStream_500(t *testing.T) {
	shadowPool := openMAMListFixturePool(t, ediscoveryCovCaseFixture+`
		CREATE TABLE __SCHEMA__.ediscovery_search_results(search_id bigint, message_id bigint);
		CREATE FUNCTION __SCHEMA__.audit_write(
			p_actor bigint, p_action text, p_target_type text, p_target_id bigint,
			p_before jsonb, p_after jsonb, p_ip inet, p_notes text, p_tier text
		) RETURNS void LANGUAGE plpgsql AS $fn$ BEGIN
		  RAISE EXCEPTION 'planted audit failure';
		END $fn$;`)
	h := &EDiscoveryHandler{pool: shadowPool, logger: testsupport.TestLogger()}

	// Unparseable ids: msgIDs is empty, the binding precheck is skipped, and
	// the request reaches the audit precondition — which refuses.
	rec := httptest.NewRecorder()
	h.ExportSelected(rec, ediscoveryCovExportReq(t, "not-a-number", "96160"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("audit refused: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct == "application/mbox" {
		t.Fatalf("audit refused but MBOX headers were written: %q", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not problem-JSON: %v (%s)", err, rec.Body.String())
	}
}

// ediscoveryCovShadowPool is a shadow-schema pool with headroom for the
// concurrent connections executeSearch needs (the tx plus the fail() status
// write must not share one connection). Search path resolves the shadow
// schema before pg_catalog/public.
func ediscoveryCovShadowPool(t *testing.T, setupSQL string) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is unset but REQUIRE_DB is set")
		}
		t.Skip("DB_DSN not set")
	}
	adminPool := testsupport.OpenTestPool(t)
	schema := fmt.Sprintf("ediscov_cov_%d", time.Now().UnixNano())
	if _, err := adminPool.Exec(context.Background(), `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create shadow schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = adminPool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	})
	if _, err := adminPool.Exec(context.Background(), strings.ReplaceAll(setupSQL, "__SCHEMA__", schema)); err != nil {
		t.Fatalf("shadow setup: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse DB_DSN: %v", err)
	}
	cfg.MaxConns = 4
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `SET search_path=`+schema+`,pg_catalog,public`)
		return err
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open shadow pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// ediscoveryCovSearchShadow is the full-shape shadow ediscovery_searches for
// the executeSearch failure-branch tests (messages intentionally absent so
// the count/bind statements fall through to the public table).
const ediscoveryCovSearchShadow = `
	CREATE TABLE __SCHEMA__.ediscovery_searches(
		id bigserial PRIMARY KEY, name text NOT NULL, created_by bigint NOT NULL,
		query jsonb NOT NULL, status text NOT NULL DEFAULT 'pending', result_count int,
		started_at timestamptz, completed_at timestamptz, created_at timestamptz DEFAULT now(),
		case_id bigint);
	INSERT INTO __SCHEMA__.ediscovery_searches (name, created_by, query, status)
	VALUES ('ediscov-cov-fail', 96151, '{"keywords":"haystack"}'::jsonb, 'pending');`

// ediscoveryCovRunShadow executes executeSearch against a shadow pool for the
// seeded search row and returns the resulting status.
func ediscoveryCovRunShadow(t *testing.T, shadowPool *pgxpool.Pool) string {
	t.Helper()
	var id int64
	if err := shadowPool.QueryRow(context.Background(),
		`SELECT id FROM ediscovery_searches`).Scan(&id); err != nil {
		t.Fatalf("read seeded search id: %v", err)
	}
	h := &EDiscoveryHandler{pool: shadowPool, logger: testsupport.TestLogger()}
	h.executeSearch(context.Background(), id)
	var status string
	if err := shadowPool.QueryRow(context.Background(),
		`SELECT status FROM ediscovery_searches WHERE id = $1`, id).Scan(&status); err != nil {
		t.Fatalf("read status: %v", err)
	}
	return status
}

// TestEDiscoveryExecuteSearch_KQLPath_Completes covers the KQL arm: a valid
// stored KQL query is parsed, built into the shared predicate, and the search
// completes with its binding (252 arm).
func TestEDiscoveryExecuteSearch_KQLPath_Completes(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	_, _ = seedEDiscoveryCovMailbox(t, pool)

	searchID := ediscoveryCovInsertSearch(t, pool, `{"keywords":"","kql":"haystack"}`)

	h := &EDiscoveryHandler{pool: pool, logger: testsupport.TestLogger()}
	h.executeSearch(context.Background(), searchID)

	if status, _ := ediscoveryCovStatus(t, pool, searchID); status != "complete" {
		t.Fatalf("kql search status = %q, want complete", status)
	}
}

// TestEDiscoveryExecuteSearch_CountFailure proves the checked count: a shadow
// messages table lacking the tsvector columns fails the count and the search
// is marked failed (never silently completed).
func TestEDiscoveryExecuteSearch_CountFailure(t *testing.T) {
	shadowPool := ediscoveryCovShadowPool(t, ediscoveryCovSearchShadow+`
		CREATE TABLE __SCHEMA__.messages(id bigint);`)
	if status := ediscoveryCovRunShadow(t, shadowPool); status != "failed" {
		t.Fatalf("count failure status = %q, want failed", status)
	}
}

// TestEDiscoveryExecuteSearch_UnbindFailure proves the checked stale-binding
// clear: a shadow results table without the search_id column fails the DELETE
// and the search is marked failed.
func TestEDiscoveryExecuteSearch_UnbindFailure(t *testing.T) {
	shadowPool := ediscoveryCovShadowPool(t, ediscoveryCovSearchShadow+`
		CREATE TABLE __SCHEMA__.ediscovery_search_results(message_id bigint);`)
	if status := ediscoveryCovRunShadow(t, shadowPool); status != "failed" {
		t.Fatalf("unbind failure status = %q, want failed", status)
	}
}

// TestEDiscoveryExecuteSearch_BindFailure proves the checked result binding:
// a shadow results table without the message_id column fails the INSERT..SELECT
// and the search is marked failed — a completion without its binding can never
// be observed.
func TestEDiscoveryExecuteSearch_BindFailure(t *testing.T) {
	shadowPool := ediscoveryCovShadowPool(t, ediscoveryCovSearchShadow+`
		CREATE TABLE __SCHEMA__.ediscovery_search_results(search_id bigint);`)
	if status := ediscoveryCovRunShadow(t, shadowPool); status != "failed" {
		t.Fatalf("bind failure status = %q, want failed", status)
	}
}

// TestEDiscoveryExecuteSearch_CompleteFailure proves the checked status flip:
// a shadow searches table missing result_count fails the completion UPDATE
// and the search ends failed — never 'complete' without a result_count.
func TestEDiscoveryExecuteSearch_CompleteFailure(t *testing.T) {
	shadowPool := ediscoveryCovShadowPool(t, `
		CREATE TABLE __SCHEMA__.ediscovery_searches(
			id bigserial PRIMARY KEY, name text NOT NULL, created_by bigint NOT NULL,
			query jsonb NOT NULL, status text NOT NULL DEFAULT 'pending',
			started_at timestamptz, completed_at timestamptz, created_at timestamptz DEFAULT now(),
			case_id bigint);
		CREATE TABLE __SCHEMA__.ediscovery_search_results(search_id bigint, message_id bigint);
		INSERT INTO __SCHEMA__.ediscovery_searches (name, created_by, query, status)
		VALUES ('ediscov-cov-complete-fail', 96151, '{"keywords":"haystack"}'::jsonb, 'pending');`)
	if status := ediscoveryCovRunShadow(t, shadowPool); status != "failed" {
		t.Fatalf("complete failure status = %q, want failed", status)
	}
}

// TestEDiscoveryExecuteSearch_CommitFailure proves the atomic-completion
// contract: a deferred trigger on the shadow results table raises at COMMIT,
// the transaction (binding AND completion flip) rolls back, and the search is
// marked failed — the count, the binding and the status flip commit or fall
// together.
func TestEDiscoveryExecuteSearch_CommitFailure(t *testing.T) {
	shadowPool := ediscoveryCovShadowPool(t, ediscoveryCovSearchShadow+`
		CREATE TABLE __SCHEMA__.ediscovery_search_results(search_id bigint, message_id bigint);
		CREATE VIEW __SCHEMA__.messages AS
		  SELECT 1::bigint AS id,
		         to_tsvector('simple', 'haystack') AS body_tsv,
		         to_tsvector('simple', 'haystack') AS subject_tsv,
		         to_tsvector('simple', 'haystack') AS from_tsv,
		         'x@y'::text AS from_addr,
		         now() AS received_at,
		         1::bigint AS mailbox_id;
		CREATE FUNCTION __SCHEMA__.ediscovery_commit_fail() RETURNS trigger
		LANGUAGE plpgsql AS $fn$ BEGIN
		  RAISE EXCEPTION 'planted deferred commit failure';
		END $fn$;
		CREATE CONSTRAINT TRIGGER ediscovery_commit_fail_trg
		AFTER INSERT ON __SCHEMA__.ediscovery_search_results
		DEFERRABLE INITIALLY DEFERRED
		FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.ediscovery_commit_fail();`)
	if status := ediscoveryCovRunShadow(t, shadowPool); status != "failed" {
		t.Fatalf("commit failure status = %q, want failed", status)
	}
}
