package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// Shared fixture IDs — large values to avoid collision with pgTAP test data.
// These are inserted once by insertFixtures, cleaned up via t.Cleanup.
const (
	testDomainID      = int64(99990)
	testRequesterID   = int64(99991) // the JIT requester (submitted the approval request)
	testApproverID    = int64(99992) // the designated approver
	testNonApproverID = int64(99993) // an authenticated user with no approver role
	testRoleGroupID   = int64(3)     // Help Desk (pre-seeded in admin_role_groups)
)

// insertFixtures seeds the domain, users, and role assignment the Decide tests
// need. All cleanup is via t.Cleanup so each test just calls this once.
func insertFixtures(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()

	if _, err := pool.Exec(ctx,
		`INSERT INTO domains (id, name, is_local) VALUES ($1, 'approval-test.local', true) ON CONFLICT DO NOTHING`,
		testDomainID,
	); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	for _, u := range []struct {
		id       int64
		username string
		email    string
	}{
		{testRequesterID, "appr_req", "req@approval-test.local"},
		{testApproverID, "appr_apr", "apr@approval-test.local"},
		{testNonApproverID, "appr_other", "other@approval-test.local"},
	} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO users (id, username, domain_id, email, display_name) VALUES ($1,$2,$3,$4,$2) ON CONFLICT DO NOTHING`,
			u.id, u.username, testDomainID, u.email,
		); err != nil {
			t.Fatalf("insert user %d: %v", u.id, err)
		}
	}

	// Role assignment: testRequesterID is eligible for Help Desk (needed by
	// rbac_approval_decide's admin_role_window_open call on the happy path).
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, eligible)
		 VALUES ($1, $2, true) ON CONFLICT DO NOTHING`,
		testRequesterID, testRoleGroupID,
	); err != nil {
		t.Fatalf("insert role assignment: %v", err)
	}

	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM admin_role_assignments WHERE user_id = $1 AND role_group_id = $2`, testRequesterID, testRoleGroupID) //nolint:errcheck
		pool.Exec(ctx, `DELETE FROM users WHERE id IN ($1,$2,$3)`, testRequesterID, testApproverID, testNonApproverID)                   //nolint:errcheck
		pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, testDomainID)                                                                //nolint:errcheck
	})
}

// insertRequest inserts a fresh pending rbac.jit_activation request.
// Returns the request ID. Cleanup deletes the row.
func insertRequest(t *testing.T, pool *pgxpool.Pool, requesterID, approverRef int64) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO approval_requests
		  (consumer_type, requester_user_id, subject, payload, approver_kind, approver_ref, expires_at)
		VALUES (
		  'rbac.jit_activation', $1, 'test activation',
		  '{"role_group_id":"3","duration_minutes":"60"}',
		  'user', $2, now()+interval '1h'
		)
		RETURNING id`,
		requesterID, approverRef,
	).Scan(&id); err != nil {
		t.Fatalf("insert request: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM approval_requests WHERE id = $1`, id) //nolint:errcheck
	})
	return id
}

// decideReq builds a POST /me/approvals/{id}/decide httptest.Request with
// the given actor's claims already in context.
func decideReq(t *testing.T, actorID, requestID int64, decision string) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	return decideBodyReq(t, actorID, requestID, map[string]any{"decision": decision})
}

func decideBodyReq(t *testing.T, actorID, requestID int64, body map[string]any) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/me/approvals/"+strconv64(t, requestID)+"/decide", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: actorID, Type: jwtutil.TypeAccess,
	}))
	req.SetPathValue("id", strconv64(t, requestID))
	return req, httptest.NewRecorder()
}

func insertDriveAccessRequest(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	ctx := context.Background()
	var spaceID, rootID, fileID, approvalPolicyID, drivePolicyID int64
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by)
		VALUES($1,1,$1) ON CONFLICT DO NOTHING`, testApproverID); err != nil {
		t.Fatalf("grant Drive admin role: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT drive_space_create($1,$2,'regular')`,
		testApproverID, "Approval handler Drive access").Scan(&spaceID); err != nil {
		t.Fatalf("create Drive access space: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT drive_member_grant($1,$2,$3,'viewer')`,
		testApproverID, spaceID, testRequesterID); err != nil {
		t.Fatalf("grant Drive viewer: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT drive_node_create($1,$2,NULL,'folder',$3)`,
		testApproverID, spaceID, "Approval root").Scan(&rootID); err != nil {
		t.Fatalf("create Drive root: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT drive_node_create($1,$2,$3,'file',$4)`,
		testApproverID, spaceID, rootID, "Approval target").Scan(&fileID); err != nil {
		t.Fatalf("create Drive target: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE drive_spaces SET acl_mode='acl' WHERE id=$1`, spaceID); err != nil {
		t.Fatalf("enable ACL fixture: %v", err)
	}

	oldFlags := map[string]bool{}
	for _, key := range []string{
		"feature.drive_node_acl_reads", "feature.drive_node_acl_writes", "feature.drive_access_governance",
	} {
		var enabled bool
		if err := pool.QueryRow(ctx, `SELECT enabled FROM feature_toggles WHERE key=$1`, key).Scan(&enabled); err != nil {
			t.Fatalf("read feature toggle %s: %v", key, err)
		}
		oldFlags[key] = enabled
		if _, err := pool.Exec(ctx, `UPDATE feature_toggles SET enabled=true WHERE key=$1`, key); err != nil {
			t.Fatalf("enable feature toggle %s: %v", key, err)
		}
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO approval_policies(
		  consumer_type,name,priority,conditions,requires_approval,approver_spec
		) VALUES('drive.access',$1,10,'{}',true,
		  jsonb_build_object('kind','named','user_id',$2::bigint))
		RETURNING id`, "Approval handler Drive policy", testApproverID).Scan(&approvalPolicyID); err != nil {
		t.Fatalf("create approval policy: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT drive_access_request_policy_set(
		$1,NULL,$2,$3,$4,'user',ARRAY['rename'],'self',60,1,false,true)`,
		testApproverID, approvalPolicyID, spaceID, rootID).Scan(&drivePolicyID); err != nil {
		t.Fatalf("create Drive request policy: %v", err)
	}
	var requestIDText string
	if err := pool.QueryRow(ctx, `SELECT drive_access_request(
		$1,$2,'user',$1,ARRAY['rename'],'self',30,1,false,NULL,
		'Need one approved rename',$3)->>'requestId'`,
		testRequesterID, fileID, "handler-drive-access-0001").Scan(&requestIDText); err != nil {
		t.Fatalf("create Drive access request: %v", err)
	}
	requestID, err := strconv.ParseInt(requestIDText, 10, 64)
	if err != nil {
		t.Fatalf("parse Drive access request id %q: %v", requestIDText, err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM approval_requests WHERE id=$1`, requestID)                                    //nolint:errcheck
		pool.Exec(ctx, `DELETE FROM drive_access_request_policies WHERE id=$1`, drivePolicyID)                    //nolint:errcheck
		pool.Exec(ctx, `DELETE FROM approval_policies WHERE id=$1`, approvalPolicyID)                             //nolint:errcheck
		pool.Exec(ctx, `DELETE FROM drive_spaces WHERE id=$1`, spaceID)                                           //nolint:errcheck
		pool.Exec(ctx, `DELETE FROM admin_role_assignments WHERE user_id=$1 AND role_group_id=1`, testApproverID) //nolint:errcheck
		for key, enabled := range oldFlags {
			pool.Exec(ctx, `UPDATE feature_toggles SET enabled=$2 WHERE key=$1`, key, enabled) //nolint:errcheck
		}
	})
	return requestID
}

func strconv64(t *testing.T, v int64) string {
	t.Helper()
	return strconv.FormatInt(v, 10)
}

// ── Decision validation — no DB required ──────────────────────────────────────

func TestDecide_BadDecision(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	body, _ := json.Marshal(map[string]string{"decision": "maybe"})
	req := httptest.NewRequest(http.MethodPost, "/me/approvals/1/decide", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: testApproverID, Type: jwtutil.TypeAccess,
	}))
	req.SetPathValue("id", "1")
	w := httptest.NewRecorder()

	h.Decide(w, req)

	// 400 must come from Go-level input validation, BEFORE any DB call.
	// (If it reached the reducer, we'd get 409 BZ108 — decision validation
	//  was the Task 2 carry-forward specifically to prevent this confusion.)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad decision: want 400, got %d — %s", w.Code, w.Body.String())
	}
}

func TestDecideDriveAccessValidatesOverridesAndDeniesThroughConsumer(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)
	requestID := insertDriveAccessRequest(t, pool)
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	for _, tt := range []struct {
		name string
		body map[string]any
	}{
		{name: "malformed expiry", body: map[string]any{"decision": "approve", "expiresAt": "tomorrow", "expectedEpoch": "0"}},
		{name: "malformed epoch", body: map[string]any{"decision": "approve", "expectedEpoch": "x"}},
		{name: "negative epoch", body: map[string]any{"decision": "approve", "expectedEpoch": "-1"}},
		{name: "missing epoch after valid expiry", body: map[string]any{"decision": "approve", "expiresAt": time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, w := decideBodyReq(t, testApproverID, requestID, tt.body)
			h.Decide(w, req)
			if w.Code != http.StatusUnprocessableEntity {
				t.Fatalf("Drive override: want 422, got %d body=%s", w.Code, w.Body.String())
			}
		})
	}

	req, w := decideBodyReq(t, testApproverID, requestID, map[string]any{
		"decision": "deny", "comment": "Not required for this task",
	})
	h.Decide(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Drive deny: want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var result map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode Drive deny: %v", err)
	}
	if result["status"] != "denied" {
		t.Fatalf("Drive deny status = %q, want denied", result["status"])
	}
}

// ── DB-backed BZ error map tests ──────────────────────────────────────────────
//
// These run on the superuser `mail` pool (BYPASSRLS active, RLS not enforced).
// That is intentional: we are testing the application-level BZ→HTTP mapping
// (the reducer's business-rule errors), not the DB-level RLS policy.
// The production opaque-stranger behavior (opaque 404 for non-visible rows)
// is proven by dbscope.TestRunUserScoped_RLSLeakProof.

func TestDecide_SoD(t *testing.T) {
	// BZ106 → 409: requester tries to decide their own request.
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)
	reqID := insertRequest(t, pool, testRequesterID, testApproverID)
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	req, w := decideReq(t, testRequesterID, reqID, "approve")
	h.Decide(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("SoD: want 409, got %d — %s", w.Code, w.Body.String())
	}
}

func TestDecide_NonApprover(t *testing.T) {
	// BZ107 → 403: authenticated user who is not the designated approver.
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)
	reqID := insertRequest(t, pool, testRequesterID, testApproverID)
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	req, w := decideReq(t, testNonApproverID, reqID, "approve")
	h.Decide(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("non-approver: want 403, got %d — %s", w.Code, w.Body.String())
	}
}

func TestDecide_Happy(t *testing.T) {
	// Happy path: the designated approver approves → 200 + {"status":"applied"}.
	// rbac_approval_decide opens the window, writes the applied row, and returns
	// 'applied' — the final lifecycle status, consistent with GET /me/approvals.
	// Requires an eligible admin_role_assignments row — inserted by insertFixtures.
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)
	reqID := insertRequest(t, pool, testRequesterID, testApproverID)
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	req, w := decideReq(t, testApproverID, reqID, "approve")
	h.Decide(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("happy approve: want 200, got %d — %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	// rbac_approval_decide opens the window, updates the row to 'applied', and
	// returns 'applied' — the final lifecycle status — so decide and list agree.
	if resp["status"] != "applied" {
		t.Errorf("happy approve: want status=applied, got %q", resp["status"])
	}
}

func TestDecide_DoubleDecide(t *testing.T) {
	// BZ108 → 409: approver tries to decide an already-decided (applied) request.
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)
	reqID := insertRequest(t, pool, testRequesterID, testApproverID)
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	// First decide (approve → applied).
	req1, w1 := decideReq(t, testApproverID, reqID, "approve")
	h.Decide(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("setup: first approve failed %d — %s", w1.Code, w1.Body.String())
	}

	// Second decide on the same request (now status='applied', not 'pending').
	req2, w2 := decideReq(t, testApproverID, reqID, "deny")
	h.Decide(w2, req2)

	if w2.Code != http.StatusConflict {
		t.Errorf("double-decide: want 409, got %d — %s", w2.Code, w2.Body.String())
	}
}

// ── List endpoint ─────────────────────────────────────────────────────────────

func TestListMyApprovals(t *testing.T) {
	// Smoke test: a pending request where the caller is the approver appears in
	// pendingForMe; the caller's own submitted request appears in myRequests.
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)
	// reqID is pending, approver=testApproverID, requester=testRequesterID.
	insertRequest(t, pool, testRequesterID, testApproverID)
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	// Call as the approver (testApproverID).
	req := httptest.NewRequest(http.MethodGet, "/me/approvals", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: testApproverID, Type: jwtutil.TypeAccess,
	}))
	w := httptest.NewRecorder()
	h.ListMyApprovals(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d — %s", w.Code, w.Body.String())
	}
	var resp struct {
		PendingForMe []approvalItem `json:"pendingForMe"`
		MyRequests   []approvalItem `json:"myRequests"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// The test DB is shared and other tests may leave rows around, so we just
	// assert at least one item appears in the right bucket.
	if len(resp.PendingForMe) == 0 {
		t.Error("list as approver: pendingForMe is empty, expected ≥1 pending request")
	}
	// myRequests for the approver should be empty (they submitted nothing).
	if len(resp.MyRequests) != 0 {
		t.Errorf("list as approver: myRequests should be empty, got %d items", len(resp.MyRequests))
	}

	// Call as the requester.
	req2 := httptest.NewRequest(http.MethodGet, "/me/approvals", nil)
	req2 = req2.WithContext(auth.ContextWithUser(req2.Context(), &auth.Claims{
		UserID: testRequesterID, Type: jwtutil.TypeAccess,
	}))
	w2 := httptest.NewRecorder()
	h.ListMyApprovals(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("list as requester: want 200, got %d", w2.Code)
	}
	var resp2 struct {
		PendingForMe []approvalItem `json:"pendingForMe"`
		MyRequests   []approvalItem `json:"myRequests"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp2.MyRequests) == 0 {
		t.Error("list as requester: myRequests is empty, expected ≥1 submitted request")
	}
}

// TestListMyApprovals_GroupModerationNullRequester is a regression test: a
// mail.group_moderation request has a NULL requester_user_id (the sender is an
// external address, not an internal user). The pending-for-me query must use
// `requester_user_id IS DISTINCT FROM $1` — `<> $1` silently drops the row
// (NULL <> $1 is NULL) — and the scan must accept the NULL (RequesterUserID is
// *int64). Together these mean the moderator actually sees the held message.
func TestListMyApprovals_GroupModerationNullRequester(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)
	ctx := context.Background()

	subject := "e2e-null-requester-" + strconv64(t, testApproverID)
	var reqID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO approval_requests
		  (consumer_type, requester_user_id, subject, payload, approver_kind, approver_ref, expires_at)
		VALUES ('mail.group_moderation', NULL, $1, '{}', 'user', $2, now()+interval '1h')
		RETURNING id`,
		subject, testApproverID,
	).Scan(&reqID); err != nil {
		t.Fatalf("insert group_moderation request: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM approval_requests WHERE id = $1`, reqID) }) //nolint:errcheck

	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
	req := httptest.NewRequest(http.MethodGet, "/me/approvals", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: testApproverID, Type: jwtutil.TypeAccess,
	}))
	w := httptest.NewRecorder()
	h.ListMyApprovals(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200 (NULL requester must not crash the scan), got %d — %s", w.Code, w.Body.String())
	}
	var resp struct {
		PendingForMe []approvalItem `json:"pendingForMe"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	found := false
	for _, it := range resp.PendingForMe {
		if it.Subject == subject {
			found = true
			if it.RequesterUserID != nil {
				t.Errorf("group_moderation requesterUserId: want nil, got %d", *it.RequesterUserID)
			}
		}
	}
	if !found {
		t.Error("group_moderation request (NULL requester) is missing from pendingForMe — the moderator cannot see the held message")
	}
}

// TestListMyApprovals_ResponseShapeIsObject pins the ListMyApprovals response
// shape (handler.go:196): a JSON OBJECT with "pendingForMe" and "myRequests"
// array keys, NEVER a bare top-level array (the old shape a caller might have
// shipped if the map wrapper were dropped). freshActorID never requests
// anything, so myRequests is asserted empty; pendingForMe is only asserted to
// be present and array-shaped (the test DB is shared, per the sibling test's
// note above, so other tests' pending rows may legitimately appear — the
// application-level visibility predicate scopes pendingForMe to rows where the
// actor is requester or authorized approver, and this pool additionally runs
// BYPASSRLS).
func TestListMyApprovals_ResponseShapeIsObject(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	const freshActorID = int64(999999901) // no approval_requests row references this id
	req := httptest.NewRequest(http.MethodGet, "/me/approvals", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: freshActorID, Type: jwtutil.TypeAccess,
	}))
	w := httptest.NewRecorder()
	h.ListMyApprovals(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d — %s", w.Code, w.Body.String())
	}

	// Bare top-level array is the exact old-shape regression: catch it before
	// even trying to decode as an object.
	trimmed := bytes.TrimSpace(w.Body.Bytes())
	if len(trimmed) == 0 || trimmed[0] != '{' {
		t.Fatalf(`response must be a JSON OBJECT (starts with "{"), got: %s`, w.Body.String())
	}

	var resp map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal as object: %v (body=%s)", err, w.Body.String())
	}
	pendingRaw, ok := resp["pendingForMe"]
	if !ok {
		t.Fatal(`response missing "pendingForMe" key`)
	}
	myRaw, ok := resp["myRequests"]
	if !ok {
		t.Fatal(`response missing "myRequests" key`)
	}
	var pending, mine []approvalItem
	if err := json.Unmarshal(pendingRaw, &pending); err != nil {
		t.Fatalf("pendingForMe is not a JSON array: %v (%s)", err, pendingRaw)
	}
	if err := json.Unmarshal(myRaw, &mine); err != nil {
		t.Fatalf("myRequests is not a JSON array: %v (%s)", err, myRaw)
	}
	if len(mine) != 0 {
		t.Errorf("myRequests = %d items, want 0 for an actor that submitted nothing", len(mine))
	}
}
