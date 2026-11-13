package approval

import (
	"bytes"
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
	"setjoin.com/shared/toggle"
)

const (
	hrDomainID      = int64(99980)
	hrRequesterID   = int64(99981)
	hrManagerID     = int64(99982)
	hrOtherID       = int64(99983)
	hrPolicyLeavePr = 9500
	hrPolicyExpPr   = 9501
)

// insertHRFixtures seeds a domain, a requester with a manager, and catch-all
// hr.leave/hr.expense approval_policies rows so the happy-path resolves.
func insertHRFixtures(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	exec(`INSERT INTO domains (id, name, is_local) VALUES ($1, 'hr-go-test.local', true) ON CONFLICT DO NOTHING`, hrDomainID)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name) VALUES ($1,'hrg_mgr',$2,'mgr@hr-go-test.local','Mgr') ON CONFLICT DO NOTHING`, hrManagerID, hrDomainID)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name, manager_id) VALUES ($1,'hrg_req',$2,'req@hr-go-test.local','Req',$3) ON CONFLICT DO NOTHING`, hrRequesterID, hrDomainID, hrManagerID)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name) VALUES ($1,'hrg_oth',$2,'oth@hr-go-test.local','Oth') ON CONFLICT DO NOTHING`, hrOtherID, hrDomainID)
	exec(`INSERT INTO approval_policies (consumer_type, name, priority, conditions, approver_spec)
	      VALUES ('hr.leave','hr-go-leave',$1,'{}','{"kind":"manager"}') ON CONFLICT DO NOTHING`, hrPolicyLeavePr)
	exec(`INSERT INTO approval_policies (consumer_type, name, priority, conditions, approver_spec)
	      VALUES ('hr.expense','hr-go-expense',$1,'{}','{"kind":"manager"}') ON CONFLICT DO NOTHING`, hrPolicyExpPr)

	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM approval_requests WHERE requester_user_id = $1`, hrRequesterID)                                                              //nolint:errcheck
		pool.Exec(c, `DELETE FROM approval_policies WHERE priority IN ($1,$2) AND consumer_type IN ('hr.leave','hr.expense')`, hrPolicyLeavePr, hrPolicyExpPr) //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id IN ($1,$2,$3)`, hrRequesterID, hrManagerID, hrOtherID)                                                        //nolint:errcheck
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, hrDomainID)                                                                                          //nolint:errcheck
	})
}

func submitHRReq(t *testing.T, actorID int64, body map[string]any) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/me/approvals/hr", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: actorID, Type: jwtutil.TypeAccess,
	}))
	return req, httptest.NewRecorder()
}

func leaveForm() map[string]any {
	return map[string]any{
		"kind": "hr.leave",
		"form": map[string]any{
			"leave_type": "annual",
			"start_date": "2026-07-10",
			"end_date":   "2026-07-12",
			"days":       3,
			"reason":     "family trip",
		},
	}
}

func TestSubmitHR_ToggleOff(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	insertHRFixtures(t, pool)
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
	h.SetFeatureFlags(toggle.NewTestFlags(map[string]bool{"approval.hr_leave": false}))

	req, w := submitHRReq(t, hrRequesterID, leaveForm())
	h.SubmitHR(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("toggle off: want 404, got %d — %s", w.Code, w.Body.String())
	}
}

func TestSubmitHR_NoToggleStoreConfigured(t *testing.T) {
	// nil toggles (unwired Handler, e.g. a stray call site) must 404, not panic
	// or silently allow — the feature is invisible until explicitly enabled.
	pool := testsupport.OpenTestPool(t)
	insertHRFixtures(t, pool)
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	req, w := submitHRReq(t, hrRequesterID, leaveForm())
	h.SubmitHR(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("nil toggles: want 404, got %d — %s", w.Code, w.Body.String())
	}
}

func TestSubmitHR_LeaveHappy(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	insertHRFixtures(t, pool)
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
	h.SetFeatureFlags(toggle.NewTestFlags(map[string]bool{"approval.hr_leave": true}))

	req, w := submitHRReq(t, hrRequesterID, leaveForm())
	h.SubmitHR(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("leave happy: want 201, got %d — %s", w.Code, w.Body.String())
	}
	var resp map[string]int64
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["id"] == 0 {
		t.Error("leave happy: want a positive request id")
	}
}

func TestSubmitHR_InvalidForm(t *testing.T) {
	// BZ124 → 400, with the reducer's field-level detail passed through.
	pool := testsupport.OpenTestPool(t)
	insertHRFixtures(t, pool)
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
	h.SetFeatureFlags(toggle.NewTestFlags(map[string]bool{"approval.hr_leave": true}))

	body := leaveForm()
	body["form"].(map[string]any)["leave_type"] = "not-a-real-type"
	req, w := submitHRReq(t, hrRequesterID, body)
	h.SubmitHR(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid form: want 400, got %d — %s", w.Code, w.Body.String())
	}
}

func TestSubmitHR_MissingReceipt(t *testing.T) {
	// BZ126 → 400: an expense line item references a receipt blob that doesn't exist.
	pool := testsupport.OpenTestPool(t)
	insertHRFixtures(t, pool)
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
	h.SetFeatureFlags(toggle.NewTestFlags(map[string]bool{"approval.hr_expense": true}))

	req, w := submitHRReq(t, hrRequesterID, map[string]any{
		"kind": "hr.expense",
		"form": map[string]any{
			"currency":    "CNY",
			"total_cents": 1000,
			"line_items": []map[string]any{
				{"description": "x", "amount_cents": 1000, "category": "other", "receipt_sha256": "0000000000000000000000000000000000000000000000000000000000ff"},
			},
		},
	})
	h.SubmitHR(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("missing receipt: want 400, got %d — %s", w.Code, w.Body.String())
	}
}

func TestSubmitHR_NoPolicyMatched_422(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	// A fresh domain/user with NO hr.expense policy configured at all.
	exec := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	const (
		dID = int64(99990)
		uID = int64(99991)
	)
	exec(`INSERT INTO domains (id, name, is_local) VALUES ($1, 'hr-nopolicy-test.local', true) ON CONFLICT DO NOTHING`, dID)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name) VALUES ($1,'hrnp_req',$2,'req@hr-nopolicy-test.local','Req') ON CONFLICT DO NOTHING`, uID, dID)
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM approval_requests WHERE requester_user_id = $1`, uID) //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, uID)                            //nolint:errcheck
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, dID)                          //nolint:errcheck
	})

	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
	h.SetFeatureFlags(toggle.NewTestFlags(map[string]bool{"approval.hr_expense": true}))

	req, w := submitHRReq(t, uID, map[string]any{
		"kind": "hr.expense",
		"form": map[string]any{
			"currency":    "CNY",
			"total_cents": 1000,
			"line_items": []map[string]any{
				{"description": "x", "amount_cents": 1000, "category": "other"},
			},
		},
	})
	h.SubmitHR(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("no policy: want 422, got %d — %s", w.Code, w.Body.String())
	}
}

func TestDecide_HRLeave_RoutesToHRWrapper(t *testing.T) {
	// Decide on an hr.leave request routes to hr_approval_decide and returns 'applied'.
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool) // testRequesterID / testApproverID
	ctx := context.Background()
	var reqID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO approval_requests
		  (consumer_type, requester_user_id, subject, payload, approver_kind, approver_ref, expires_at)
		VALUES ('hr.leave', $1, 'Leave: annual', '{"leave_type":"annual"}'::jsonb, 'user', $2, now()+interval '1h')
		RETURNING id`, testRequesterID, testApproverID,
	).Scan(&reqID); err != nil {
		t.Fatalf("insert hr.leave request: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM approval_requests WHERE id = $1`, reqID) }) //nolint:errcheck

	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
	req, w := decideReq(t, testApproverID, reqID, "approve")
	h.Decide(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("hr.leave decide: want 200, got %d — %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["status"] != "applied" {
		t.Errorf("hr.leave decide: want status=applied, got %q", resp["status"])
	}
}

// TestListMyApprovals_HRPayloadVisible_MailPayloadWithheld pins the deliberate
// exception to "payload is consumer-internal, never returned by the list
// endpoint": hr.leave/hr.expense's payload is the small, user-facing form the
// requester submitted (needed for the evidence renderer), so it rides the
// wire; every other consumer's payload (e.g. rbac.jit_activation's own — small
// but not wired for display — and mail.external_send's, which carries the
// full send() replay args) keeps the existing withheld behavior unchanged.
func TestListMyApprovals_HRPayloadVisible_MailPayloadWithheld(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)
	ctx := context.Background()

	var hrReqID, rbacReqID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO approval_requests
		  (consumer_type, requester_user_id, subject, payload, approver_kind, approver_ref, expires_at)
		VALUES ('hr.leave', $1, 'Leave: annual', '{"leave_type":"annual","reason":"trip"}'::jsonb, 'user', $2, now()+interval '1h')
		RETURNING id`, testRequesterID, testApproverID,
	).Scan(&hrReqID); err != nil {
		t.Fatalf("insert hr.leave request: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM approval_requests WHERE id = $1`, hrReqID) }) //nolint:errcheck

	rbacReqID = insertRequest(t, pool, testRequesterID, testApproverID) // payload {"role_group_id":"3","duration_minutes":"60"}

	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
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
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var sawHR, sawRBAC bool
	for _, it := range resp.PendingForMe {
		if it.ID == hrReqID {
			sawHR = true
			if len(it.Payload) == 0 {
				t.Error("hr.leave: payload should be visible in the list response")
			}
		}
		if it.ID == rbacReqID {
			sawRBAC = true
			if len(it.Payload) != 0 {
				t.Errorf("rbac.jit_activation: payload should stay withheld, got %s", it.Payload)
			}
		}
	}
	if !sawHR || !sawRBAC {
		t.Fatalf("expected both requests in pendingForMe (sawHR=%v sawRBAC=%v)", sawHR, sawRBAC)
	}
}
