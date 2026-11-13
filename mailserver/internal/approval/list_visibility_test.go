package approval

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// list_visibility_test.go — ListMyApprovals application-level visibility fencing.
//
// The pendingForMe query historically relied on the approval_requests FORCE RLS
// policy alone; on the documented pre-flip runtime RLS is INERT (the DB_DSN role
// is superuser/owner/BYPASSRLS and DB_WORKER_DSN defaults to DB_DSN), so every
// pending request in every domain would land in every authenticated user's
// list. The handler now carries the requester-or-authorized-approver predicate
// in the SAME WHERE as the read. These tests prove the fence on the superuser
// (BYPASSRLS) pool — exactly the posture where RLS cannot help — via the
// repo-wide connect-or-skip helper (testsupport.OpenTestPool).

// Second-tenant fixture IDs — distinct from the shared insertFixtures IDs
// (99990–99993) and from any other package fixture, so a leak is attributable.
const (
	lvDomain2ID    = int64(99995)
	lvRequester2ID = int64(99996)
	lvApprover2ID  = int64(99997)
)

// insertListVisibilityFixtures seeds one pending request per visibility arm on
// top of insertFixtures (domain 99990, users 99991–99993, Help Desk assignment
// for testRequesterID):
//
//   - userApproverReq: requester testRequesterID, approver user testApproverID.
//   - roleGroupReq:    requester testApproverID, approver role_group 3 (Help
//     Desk; testRequesterID holds the eligible assignment — active while the
//     rbac.jit toggle is pinned OFF by the callers).
//   - tenant2Req:      second domain, requester lvRequester2ID, approver user
//     lvApprover2ID — consumer hr.leave, whose payload is on the
//     scanApprovalItem allowlist, so a row-level leak would also leak payload
//     bytes across tenants.
//
// Cleanup is t.Cleanup-registered LIFO-safe: the request rows (registered by
// insertVisibilityRequest during this call) are deleted before the second
// tenant's users/domain (registered here), which are deleted before
// insertFixtures' rows.
func insertListVisibilityFixtures(t *testing.T, pool *pgxpool.Pool) (userApproverReqID, roleGroupReqID, tenant2ReqID int64) {
	t.Helper()
	ctx := context.Background()

	if _, err := pool.Exec(ctx,
		`INSERT INTO domains (id, name, is_local) VALUES ($1, 'approval-lv2.local', true) ON CONFLICT DO NOTHING`,
		lvDomain2ID,
	); err != nil {
		t.Fatalf("insert second-tenant domain: %v", err)
	}
	for _, u := range []struct {
		id       int64
		username string
		email    string
	}{
		{lvRequester2ID, "appr_lv_req2", "req2@approval-lv2.local"},
		{lvApprover2ID, "appr_lv_apr2", "apr2@approval-lv2.local"},
	} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO users (id, username, domain_id, email, display_name) VALUES ($1,$2,$3,$4,$2) ON CONFLICT DO NOTHING`,
			u.id, u.username, lvDomain2ID, u.email,
		); err != nil {
			t.Fatalf("insert second-tenant user %d: %v", u.id, err)
		}
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM users WHERE id IN ($1,$2)`, lvRequester2ID, lvApprover2ID) //nolint:errcheck
		pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, lvDomain2ID)                       //nolint:errcheck
	})

	userApproverReqID = insertVisibilityRequest(t, pool, "rbac.jit_activation",
		testRequesterID, "user", testApproverID,
		`{"role_group_id":"3","duration_minutes":"60"}`, "lv-user-approver")
	roleGroupReqID = insertVisibilityRequest(t, pool, "rbac.jit_activation",
		testApproverID, "role_group", testRoleGroupID,
		`{"role_group_id":"3","duration_minutes":"60"}`, "lv-role-group")
	tenant2ReqID = insertVisibilityRequest(t, pool, "hr.leave",
		lvRequester2ID, "user", lvApprover2ID,
		`{"leave_type":"annual","reason":"lv tenant2"}`, "lv-tenant2")
	return userApproverReqID, roleGroupReqID, tenant2ReqID
}

// insertVisibilityRequest inserts a raw pending approval_requests row of any
// consumer/approver shape (insertRequest pins rbac + user approver, which is
// not enough for the role_group and second-tenant arms).
func insertVisibilityRequest(t *testing.T, pool *pgxpool.Pool, consumerType string, requesterID int64, approverKind string, approverRef int64, payload, subject string) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO approval_requests
		  (consumer_type, requester_user_id, subject, payload, approver_kind, approver_ref, expires_at)
		VALUES ($1, $2, $3, $4::jsonb, $5, $6, now()+interval '1h')
		RETURNING id`,
		consumerType, requesterID, subject, payload, approverKind, approverRef,
	).Scan(&id); err != nil {
		t.Fatalf("insert visibility fixture %q: %v", subject, err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM approval_requests WHERE id = $1`, id) //nolint:errcheck
	})
	return id
}

// listMyApprovalsReq builds a GET /me/approvals request with the actor's
// claims already in context.
func listMyApprovalsReq(t *testing.T, actorID int64) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/me/approvals", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: actorID, Type: jwtutil.TypeAccess,
	}))
	return req, httptest.NewRecorder()
}

// decodeListResponse asserts the 200 + object shape and returns both buckets.
func decodeListResponse(t *testing.T, w *httptest.ResponseRecorder) (pendingForMe, myRequests []approvalItem) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d — %s", w.Code, w.Body.String())
	}
	var resp struct {
		PendingForMe []approvalItem `json:"pendingForMe"`
		MyRequests   []approvalItem `json:"myRequests"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal list response: %v", err)
	}
	return resp.PendingForMe, resp.MyRequests
}

func listContains(items []approvalItem, id int64) bool {
	for _, it := range items {
		if it.ID == id {
			return true
		}
	}
	return false
}

// TestListMyApprovals_RequesterSeesOwnRequests pins the requester arm: the
// submitted request appears in myRequests and never in pendingForMe (a request
// awaiting my own action is not "pending for me" — deciding it is BZ106 SoD).
func TestListMyApprovals_RequesterSeesOwnRequests(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)
	userApproverReqID, _, _ := insertListVisibilityFixtures(t, pool)
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	req, w := listMyApprovalsReq(t, testRequesterID)
	h.ListMyApprovals(w, req)

	pending, mine := decodeListResponse(t, w)
	if !listContains(mine, userApproverReqID) {
		t.Error("requester's own submitted request missing from myRequests")
	}
	if listContains(pending, userApproverReqID) {
		t.Error("requester's own pending request leaked into pendingForMe")
	}
}

// TestListMyApprovals_AuthorizedApproverSeesScopedSet covers the two authorized
// approver arms: a designated user approver and an active member of the
// approver role_group each see exactly their queue entries in pendingForMe.
// Payload handling stays scoped on the visible rows: the rbac payload (not on
// the scanApprovalItem allowlist) is zeroed; the second tenant's hr.leave
// payload (allowlisted) reaches only its own approver, intact.
func TestListMyApprovals_AuthorizedApproverSeesScopedSet(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	// Pin the JIT toggle OFF so the Help Desk assignment's
	// admin_assignment_active gate is deterministically satisfied (same toggle
	// the V073 RLS policy and approval_decide consult).
	testsupport.SetFeatureToggleForTest(t, pool, "rbac.jit", false)
	insertFixtures(t, pool)
	userApproverReqID, roleGroupReqID, tenant2ReqID := insertListVisibilityFixtures(t, pool)
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	// Designated user approver: sees their request, payload withheld (rbac is
	// not an allowlisted consumer), and nothing extra in myRequests.
	req, w := listMyApprovalsReq(t, testApproverID)
	h.ListMyApprovals(w, req)
	pending, mine := decodeListResponse(t, w)
	if !listContains(pending, userApproverReqID) {
		t.Error("designated user approver: request missing from pendingForMe")
	}
	for _, it := range pending {
		if it.ID == userApproverReqID && len(it.Payload) != 0 {
			t.Errorf("rbac.jit_activation payload must stay withheld, got %s", it.Payload)
		}
	}
	if listContains(mine, userApproverReqID) {
		t.Error("approver saw someone else's request in myRequests")
	}
	// The role_group request's requester is testApproverID: it belongs in
	// myRequests, never in pendingForMe.
	if !listContains(mine, roleGroupReqID) {
		t.Error("role_group request missing from its requester's myRequests")
	}
	if listContains(pending, roleGroupReqID) {
		t.Error("requester's own role_group request leaked into pendingForMe")
	}

	// Active role_group member (Help Desk assignment seeded by insertFixtures):
	// the role_group-approver request shows up in their pendingForMe queue.
	req2, w2 := listMyApprovalsReq(t, testRequesterID)
	h.ListMyApprovals(w2, req2)
	pending2, _ := decodeListResponse(t, w2)
	if !listContains(pending2, roleGroupReqID) {
		t.Error("active Help Desk member: role_group approval missing from pendingForMe")
	}

	// Second tenant's authorized approver: sees their own row, with the
	// allowlisted hr.leave payload intact.
	req3, w3 := listMyApprovalsReq(t, lvApprover2ID)
	h.ListMyApprovals(w3, req3)
	pending3, _ := decodeListResponse(t, w3)
	if !listContains(pending3, tenant2ReqID) {
		t.Error("second-tenant approver: hr.leave request missing from pendingForMe")
	}
	for _, it := range pending3 {
		if it.ID == tenant2ReqID && len(it.Payload) == 0 {
			t.Error("hr.leave payload (allowlisted) must reach its authorized approver")
		}
	}
}

// TestListMyApprovals_CrossTenantAndUnauthorizedApproverDenied is the regression
// test for the finding itself: with a second principal's approvals present, an
// unrelated authenticated user — and a first-tenant user/approver pair — see
// none of the foreign rows in either list, even though this pool runs
// BYPASSRLS (RLS inert), which is precisely the pre-flip posture the
// application predicate must fence.
func TestListMyApprovals_CrossTenantAndUnauthorizedApproverDenied(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	testsupport.SetFeatureToggleForTest(t, pool, "rbac.jit", false)
	insertFixtures(t, pool)
	userApproverReqID, roleGroupReqID, tenant2ReqID := insertListVisibilityFixtures(t, pool)
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	foreign := []int64{userApproverReqID, roleGroupReqID, tenant2ReqID}

	t.Run("unrelated authenticated user sees nothing", func(t *testing.T) {
		req, w := listMyApprovalsReq(t, testNonApproverID)
		h.ListMyApprovals(w, req)
		pending, mine := decodeListResponse(t, w)
		for _, id := range foreign {
			if listContains(pending, id) {
				t.Errorf("foreign approval request %d leaked into pendingForMe", id)
			}
			if listContains(mine, id) {
				t.Errorf("foreign approval request %d leaked into myRequests", id)
			}
		}
	})

	t.Run("first-tenant requester does not see second tenant's approvals", func(t *testing.T) {
		req, w := listMyApprovalsReq(t, testRequesterID)
		h.ListMyApprovals(w, req)
		pending, mine := decodeListResponse(t, w)
		if listContains(pending, tenant2ReqID) || listContains(mine, tenant2ReqID) {
			t.Error("cross-tenant leak: second tenant's approval visible to first-tenant user")
		}
	})

	t.Run("first-tenant approver does not see second tenant's approvals", func(t *testing.T) {
		req, w := listMyApprovalsReq(t, testApproverID)
		h.ListMyApprovals(w, req)
		pending, mine := decodeListResponse(t, w)
		if listContains(pending, tenant2ReqID) || listContains(mine, tenant2ReqID) {
			t.Error("cross-tenant leak: second tenant's approval visible to first-tenant approver")
		}
	})
}
