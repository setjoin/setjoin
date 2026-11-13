package admin

// med-shard3-007 (F-003): GetSearch and ExportSelected are scoped behind the
// dedicated mail.export grant (content export never rides Mail-console read
// scopes), and the MBOX export is bound to an authorized case: caseId is
// required, the case must be active with completed-search coverage, and —
// Astra waves34 HOLD 3 — every exported id must be in the case's PERSISTED
// result set (ediscovery_search_results, V244): cross-case or never-matched
// ids are refused. GetSearch likewise serves results only for case-bound
// completed searches, read from the persisted binding. All refusals happen
// before any MBOX byte is written, so an unauthorized request never produces
// a custody chain.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// Fixed fixture ids (distinct range: 9642x, not used by any other fixture in
// this package).
const (
	edGrantDomain = int64(96420)
	edGrantUser   = int64(96421)
)

// seedEdGrantFixtures seeds the domain + user row the search/case FKs want,
// and registers FK-safe cleanup.
func seedEdGrantFixtures(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`INSERT INTO domains (id, name, is_local) VALUES ($1, 'edgrant.test', TRUE)
		 ON CONFLICT (id) DO NOTHING`, edGrantDomain); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		 VALUES ($1, 'edgrant_u', $2, 'edgrant_u@edgrant.test', 'E', TRUE)
		 ON CONFLICT (id) DO NOTHING`, edGrantUser, edGrantDomain); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM ediscovery_searches WHERE created_by = $1`, edGrantUser)                                  //nolint:errcheck
		pool.Exec(c, `DELETE FROM ediscovery_cases WHERE created_by = $1`, edGrantUser)                                     //nolint:errcheck
		pool.Exec(c, `DELETE FROM messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $1)`, edGrantUser) //nolint:errcheck
		// The primary-mailbox trigger blocks plain deletes (see
		// admin_users_test.go) — the DISABLE-TRIGGER teardown pattern. With RI
		// triggers disabled, children must be deleted explicitly first: the
		// mailbox insert trigger mints a mailbox_lifecycle row, default
		// folders, and a mailbox_address_claims row; orphaned folders or
		// claims would collide with the next seed.
		pool.Exec(c, `DELETE FROM folders WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $1)`, edGrantUser)                //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailbox_lifecycle WHERE bound_user_id = $1`, edGrantUser)                                               //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailbox_address_claims WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $1)`, edGrantUser) //nolint:errcheck
		pool.Exec(c, `ALTER TABLE mailboxes DISABLE TRIGGER ALL`)                                                                         //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailboxes WHERE user_id = $1`, edGrantUser)                                                             //nolint:errcheck
		pool.Exec(c, `ALTER TABLE mailboxes ENABLE TRIGGER ALL`)                                                                          //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, edGrantUser)                                                                      //nolint:errcheck
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, edGrantDomain)                                                                  //nolint:errcheck
	})
}

// edGrantHandler builds the handler under test (s3 nil — every fixture message
// carries an empty raw_ref, so the S3 leg is never exercised here).
func edGrantHandler(t *testing.T, pool *pgxpool.Pool) *EDiscoveryHandler {
	t.Helper()
	return NewEDiscoveryHandler(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger(), nil, "", nil)
}

// edGrantClaims returns claims carrying exactly the given permissions.
func edGrantClaims(perms ...string) *auth.Claims {
	return &auth.Claims{UserID: edGrantUser, IsAdmin: true, Permissions: perms}
}

// edGrantInsertCase inserts an ediscovery_cases row and registers cleanup.
func edGrantInsertCase(t *testing.T, pool *pgxpool.Pool, name, status string) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO ediscovery_cases (name, status, created_by) VALUES ($1, $2, $3) RETURNING id`,
		name, status, edGrantUser).Scan(&id); err != nil {
		t.Fatalf("insert case %q: %v", name, err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM ediscovery_cases WHERE id = $1`, id) //nolint:errcheck
	})
	return id
}

// edGrantInsertSearch inserts an ediscovery_searches row and registers cleanup.
func edGrantInsertSearch(t *testing.T, pool *pgxpool.Pool, name, status string, caseID *int64) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO ediscovery_searches (name, created_by, query, status, case_id)
		 VALUES ($1, $2, $3::JSONB, $4, $5) RETURNING id`,
		name, edGrantUser,
		// Key shape mirrors StartSearch's persisted query map: GetSearch scans
		// query->>'kql'/fromAddr/dateFrom/dateTo into strings, so those keys
		// must exist (empty string, not SQL NULL).
		`{"keywords":"custody","kql":"","fromAddr":"","dateFrom":"","dateTo":"","mailboxIds":[]}`,
		status, caseID).Scan(&id); err != nil {
		t.Fatalf("insert search %q: %v", name, err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM ediscovery_searches WHERE id = $1`, id) //nolint:errcheck
	})
	return id
}

// edGrantInsertMessage seeds a bare message row with an empty raw_ref (no S3
// leg) and registers cleanup. Returns the message id.
func edGrantInsertMessage(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, type, is_primary)
		 VALUES (9640, $1, $2, 'edgrant_u@edgrant.test', 'E', 'personal', TRUE)
		 ON CONFLICT (id) DO NOTHING`, edGrantUser, edGrantDomain); err != nil {
		t.Fatalf("seed mailbox: %v", err)
	}
	var folderID int64
	// The fixed fixture mailbox 9640 is shared by every message a test seeds;
	// a second edGrantInsertMessage call in one test must reuse the Inbox
	// folder, not collide with its unique (mailbox_id, path).
	if err := pool.QueryRow(ctx,
		`INSERT INTO folders (mailbox_id, name, role, path) VALUES (9640, 'Inbox', 'inbox', 'Inbox')
		 ON CONFLICT (mailbox_id, path) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`).Scan(&folderID); err != nil {
		t.Fatalf("insert folder: %v", err)
	}
	var msgID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO messages (mailbox_id, folder_id, message_id, subject, from_addr, from_name,
		   to_addrs, cc_addrs, bcc_addrs, thread_id, raw_ref, received_at, is_read)
		 VALUES (9640, $1, '<edgrant-1@edgrant.test>', 'custody export', 'ext@outside.example', 'Ext',
		   '[]'::JSONB, '[]'::JSONB, '[]'::JSONB, 'thread-edgrant', '', now(), TRUE)
		 RETURNING id`, folderID).Scan(&msgID); err != nil {
		t.Fatalf("insert message: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		// The primary-mailbox trigger blocks plain deletes (see
		// admin_users_test.go) — the DISABLE-TRIGGER teardown pattern. With RI
		// triggers disabled, children must be deleted explicitly first: the
		// mailbox insert trigger mints a mailbox_lifecycle row, default
		// folders, and a mailbox_address_claims row; orphaned folders or
		// claims would collide with the next seed.
		pool.Exec(c, `DELETE FROM messages WHERE mailbox_id = 9640`)               //nolint:errcheck
		pool.Exec(c, `DELETE FROM folders WHERE mailbox_id = 9640`)                //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailbox_lifecycle WHERE mailbox_id = 9640`)      //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailbox_address_claims WHERE mailbox_id = 9640`) //nolint:errcheck
		pool.Exec(c, `ALTER TABLE mailboxes DISABLE TRIGGER ALL`)                  //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailboxes WHERE id = 9640`)                      //nolint:errcheck
		pool.Exec(c, `ALTER TABLE mailboxes ENABLE TRIGGER ALL`)                   //nolint:errcheck
	})
	return msgID
}

// edGrantGetSearchCall invokes GetSearch with the given claims.
func edGrantGetSearchCall(t *testing.T, h *EDiscoveryHandler, searchID int64, claims *auth.Claims) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/ediscovery/%d", searchID), nil)
	req.SetPathValue("id", fmt.Sprintf("%d", searchID))
	if claims != nil {
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	}
	rec := httptest.NewRecorder()
	h.GetSearch(rec, req)
	return rec
}

// edGrantExportCall invokes ExportSelected with the given query and claims.
func edGrantExportCall(h *EDiscoveryHandler, query string, claims *auth.Claims) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/admin/ediscovery/export"+query, nil)
	if claims != nil {
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	}
	rec := httptest.NewRecorder()
	h.ExportSelected(rec, req)
	return rec
}

// TestEDiscoveryGetSearch_RequiresMailExportGrant proves the dedicated-grant
// gate on the search read: a compliance.write holder WITHOUT mail.export is
// refused (403), while a mail.export holder reads the same search (200). The
// compliance.write-only refusal is the permission-collapse fix — completed
// search results are message content.
func TestEDiscoveryGetSearch_RequiresMailExportGrant(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedEdGrantFixtures(t, pool)
	h := edGrantHandler(t, pool)
	searchID := edGrantInsertSearch(t, pool, "grant-gate-search", "pending", nil)

	withoutGrant := edGrantGetSearchCall(t, h, searchID, edGrantClaims(permissions.PermComplianceWrite))
	if withoutGrant.Code != http.StatusForbidden {
		t.Fatalf("GetSearch without mail.export: got %d body=%s, want 403", withoutGrant.Code, withoutGrant.Body.String())
	}

	withGrant := edGrantGetSearchCall(t, h, searchID, edGrantClaims(permissions.PermMailExport))
	if withGrant.Code != http.StatusOK {
		t.Fatalf("GetSearch with mail.export: got %d body=%s, want 200", withGrant.Code, withGrant.Body.String())
	}
}

// TestEDiscoveryExport_RequiresMailExportGrant proves the dedicated-grant gate
// on the export stream: without mail.export the export is refused before any
// MBOX byte (no custody chain) is written; an unauthenticated request 401s.
func TestEDiscoveryExport_RequiresMailExportGrant(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedEdGrantFixtures(t, pool)
	h := edGrantHandler(t, pool)
	msgID := edGrantInsertMessage(t, pool)
	query := fmt.Sprintf("?ids=%d&caseId=1", msgID)

	noClaims := edGrantExportCall(h, query, nil)
	if noClaims.Code != http.StatusUnauthorized {
		t.Fatalf("export unauthenticated: got %d, want 401", noClaims.Code)
	}

	withoutGrant := edGrantExportCall(h, query, edGrantClaims(permissions.PermComplianceWrite))
	if withoutGrant.Code != http.StatusForbidden {
		t.Fatalf("export without mail.export: got %d body=%s, want 403", withoutGrant.Code, withoutGrant.Body.String())
	}
	if strings.Contains(withoutGrant.Body.String(), "X-Custody") {
		t.Fatalf("denied export leaked custody-chain bytes: %q", withoutGrant.Body.String())
	}
}

// edGrantBindResult persists a case-bound result row (the V244 binding the
// case-confinement fence reads). Registered cleanup rides the search delete.
func edGrantBindResult(t *testing.T, pool *pgxpool.Pool, searchID, msgID int64) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO ediscovery_search_results (search_id, message_id) VALUES ($1, $2)`,
		searchID, msgID); err != nil {
		t.Fatalf("bind result (search %d, message %d): %v", searchID, msgID, err)
	}
}

// TestEDiscoveryExport_CaseBindingAndCustodyChain proves the case arm of the
// export contract: caseId is required and must reference an ACTIVE case with
// at least one COMPLETED search; authorized cases get an MBOX whose custody
// chain carries the case binding and the exported id set; unauthorized ones
// (missing, no-coverage, closed) are refused with no custody chain.
func TestEDiscoveryExport_CaseBindingAndCustodyChain(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedEdGrantFixtures(t, pool)
	h := edGrantHandler(t, pool)
	msgID := edGrantInsertMessage(t, pool)

	activeWithCoverage := edGrantInsertCase(t, pool, "grant-gate-active", "active")
	searchA := edGrantInsertSearch(t, pool, "grant-gate-search-a", "complete", &activeWithCoverage)
	edGrantBindResult(t, pool, searchA, msgID)
	noCoverage := edGrantInsertCase(t, pool, "grant-gate-nocoverage", "active")
	closed := edGrantInsertCase(t, pool, "grant-gate-closed", "closed")
	edGrantInsertSearch(t, pool, "grant-gate-search-c", "complete", &closed)

	grant := edGrantClaims(permissions.PermMailExport)

	// caseId is required (mirrors the chat eDiscovery export tier).
	rec := edGrantExportCall(h, fmt.Sprintf("?ids=%d", msgID), grant)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("export without caseId: got %d body=%s, want 400", rec.Code, rec.Body.String())
	}

	// Unknown case → 404.
	rec = edGrantExportCall(h, fmt.Sprintf("?ids=%d&caseId=987654321", msgID), grant)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("export with unknown case: got %d body=%s, want 404", rec.Code, rec.Body.String())
	}

	// Active case without completed-search coverage → 403, no custody chain.
	rec = edGrantExportCall(h, fmt.Sprintf("?ids=%d&caseId=%d", msgID, noCoverage), grant)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("export with no-coverage case: got %d body=%s, want 403", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "X-Custody") {
		t.Fatalf("no-coverage export leaked custody-chain bytes: %q", rec.Body.String())
	}

	// Closed case → 403, no custody chain.
	rec = edGrantExportCall(h, fmt.Sprintf("?ids=%d&caseId=%d", msgID, closed), grant)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("export with closed case: got %d body=%s, want 403", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "X-Custody") {
		t.Fatalf("closed-case export leaked custody-chain bytes: %q", rec.Body.String())
	}

	// Authorized case → 200 with a case-bound custody chain.
	rec = edGrantExportCall(h, fmt.Sprintf("?ids=%d&caseId=%d", msgID, activeWithCoverage), grant)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorized export: got %d body=%s, want 200", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		fmt.Sprintf("X-Custody-Case-ID: %d", activeWithCoverage),
		"X-Custody-Checksum: sha256:",
		fmt.Sprintf("X-Custody-Message-IDs: %d", msgID),
		"Subject: custody export",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("authorized export missing custody element %q in:\n%s", want, body)
		}
	}

	// The export act is audited against the authorizing case.
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_audit_log WHERE action = 'ediscovery_export' AND target_id = $1 AND user_id = $2`,
		activeWithCoverage, edGrantUser).Scan(&n); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	if n != 1 {
		t.Fatalf("ediscovery_export audit rows = %d, want 1", n)
	}
}

// TestEDiscoveryExport_RejectsCrossCaseAndUnboundMessageIDs is the Astra
// waves34 HOLD-3 acceptance test: a completed search authorizes its own bound
// results ONLY. A message bound to another case's search (cross-case id) and
// an id bound to no search at all are refused under an otherwise fully
// authorized case — before the audit row and before any custody byte.
func TestEDiscoveryExport_RejectsCrossCaseAndUnboundMessageIDs(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedEdGrantFixtures(t, pool)
	h := edGrantHandler(t, pool)
	msgID := edGrantInsertMessage(t, pool)
	unboundID := edGrantInsertMessage(t, pool)

	caseA := edGrantInsertCase(t, pool, "binding-case-a", "active")
	edGrantInsertSearch(t, pool, "binding-search-a", "complete", &caseA)
	caseB := edGrantInsertCase(t, pool, "binding-case-b", "active")
	searchB := edGrantInsertSearch(t, pool, "binding-search-b", "complete", &caseB)
	edGrantBindResult(t, pool, searchB, msgID)

	grant := edGrantClaims(permissions.PermMailExport)

	// Cross-case id: bound under case B, requested under case A → 403, no
	// custody chain.
	rec := edGrantExportCall(h, fmt.Sprintf("?ids=%d&caseId=%d", msgID, caseA), grant)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-case id export: got %d body=%s, want 403", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "X-Custody") {
		t.Fatalf("cross-case export leaked custody-chain bytes: %q", rec.Body.String())
	}

	// Unbound id: never bound by ANY search, requested under a fully
	// authorized case → 403 too.
	rec = edGrantExportCall(h, fmt.Sprintf("?ids=%d&caseId=%d", unboundID, caseB), grant)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unbound id export: got %d body=%s, want 403", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "X-Custody") {
		t.Fatalf("unbound export leaked custody-chain bytes: %q", rec.Body.String())
	}

	// The refused attempts audited nothing for this test's cases: the export
	// audit fires only after the binding check passes.
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_audit_log
		  WHERE action = 'ediscovery_export' AND target_id IN ($1, $2)`,
		caseA, caseB).Scan(&n); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	if n != 0 {
		t.Fatalf("refused exports wrote audit rows: %d", n)
	}

	// Under the authorizing case (B) the bound id exports with its custody chain.
	rec = edGrantExportCall(h, fmt.Sprintf("?ids=%d&caseId=%d", msgID, caseB), grant)
	if rec.Code != http.StatusOK {
		t.Fatalf("case-bound export: got %d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), fmt.Sprintf("X-Custody-Case-ID: %d", caseB)) {
		t.Fatalf("case-bound export missing custody chain:\n%s", rec.Body.String())
	}
}

// edGrantGetSearchResults decodes a GetSearch response body into its results
// array. The confinement assertions inspect the DECODED results, not substring
// matches on the raw body: the search's own `"id":N` field shares the body
// with result ids, and on a fresh database the search id can equal or extend
// the message id's decimal digits, which made a strings.Contains needle on
// `"id":<msgID>` false-positive (the fixture-assertion bug behind the
// "case-unbound search served message results" runner failure).
func edGrantGetSearchResults(t *testing.T, rec *httptest.ResponseRecorder) []map[string]interface{} {
	t.Helper()
	var body struct {
		Results []map[string]interface{} `json:"results"`
		Search  map[string]interface{}   `json:"search"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode GetSearch response: %v (body=%s)", err, rec.Body.String())
	}
	return body.Results
}

// TestEDiscoveryGetSearch_ConfinesResultsToCaseBoundSearches proves the read
// arm of the HOLD-3 contract: GetSearch serves results only for a completed
// search bound to a case, read from the persisted binding. A completed search
// with NO case returns no results even when binding rows exist and
// result_count claims matches; the case-bound search serves exactly its bound
// rows.
func TestEDiscoveryGetSearch_ConfinesResultsToCaseBoundSearches(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedEdGrantFixtures(t, pool)
	h := edGrantHandler(t, pool)
	msgID := edGrantInsertMessage(t, pool)

	caseID := edGrantInsertCase(t, pool, "read-confinement-case", "active")
	boundSearch := edGrantInsertSearch(t, pool, "read-confinement-bound", "complete", &caseID)
	edGrantBindResult(t, pool, boundSearch, msgID)
	unboundSearch := edGrantInsertSearch(t, pool, "read-confinement-unbound", "complete", nil)

	// Both searches claim completed matches; only the bound one may serve them.
	for _, searchID := range []int64{boundSearch, unboundSearch} {
		if _, err := pool.Exec(context.Background(),
			`UPDATE ediscovery_searches SET result_count = 1 WHERE id = $1`, searchID); err != nil {
			t.Fatalf("force result_count on search %d: %v", searchID, err)
		}
	}

	grant := edGrantClaims(permissions.PermMailExport)

	rec := edGrantGetSearchCall(t, h, unboundSearch, grant)
	if rec.Code != http.StatusOK {
		t.Fatalf("GetSearch unbound completed search: got %d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if results := edGrantGetSearchResults(t, rec); len(results) != 0 {
		t.Fatalf("case-unbound search served message results: %+v", results)
	}

	rec = edGrantGetSearchCall(t, h, boundSearch, grant)
	if rec.Code != http.StatusOK {
		t.Fatalf("GetSearch case-bound search: got %d body=%s, want 200", rec.Code, rec.Body.String())
	}
	results := edGrantGetSearchResults(t, rec)
	if len(results) != 1 {
		t.Fatalf("case-bound search served %d results, want exactly its single bound row", len(results))
	}
	if got, ok := results[0]["id"].(float64); !ok || int64(got) != msgID {
		t.Fatalf("case-bound search result id = %v, want its bound message %d", results[0]["id"], msgID)
	}
}
