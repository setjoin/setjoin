package approval

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// cancelReq builds a POST /me/approvals/{id}/cancel httptest.Request with the
// given actor's claims already in context (mirrors decideReq).
func cancelReq(t *testing.T, actorID, requestID int64) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/me/approvals/"+strconv64(t, requestID)+"/cancel", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: actorID, Type: jwtutil.TypeAccess,
	}))
	req.SetPathValue("id", strconv64(t, requestID))
	return req, httptest.NewRecorder()
}

func TestCancel_Happy(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)
	reqID := insertRequest(t, pool, testRequesterID, testApproverID)
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	req, w := cancelReq(t, testRequesterID, reqID)
	h.Cancel(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("cancel: want 200, got %d — %s", w.Code, w.Body.String())
	}
	if s := approvalStatus(t, reqID); s != "cancelled" {
		t.Errorf("request status = %q, want cancelled", s)
	}
}

func TestCancel_NotRequester(t *testing.T) {
	// The designated APPROVER is not the requester — BZ125 → 404, opaque
	// (no ownership oracle — mirrors Decide's BZ108 posture).
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)
	reqID := insertRequest(t, pool, testRequesterID, testApproverID)
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	req, w := cancelReq(t, testApproverID, reqID)
	h.Cancel(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("non-requester cancel: want 404, got %d — %s", w.Code, w.Body.String())
	}
	if s := approvalStatus(t, reqID); s != "pending" {
		t.Errorf("request status = %q, want still pending after rejected cancel", s)
	}
}

func TestCancel_UnknownID(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	req, w := cancelReq(t, testRequesterID, 999999999)
	h.Cancel(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("unknown id cancel: want 404, got %d — %s", w.Code, w.Body.String())
	}
}

func TestCancel_AlreadyDecided(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	insertFixtures(t, pool)
	reqID := insertRequest(t, pool, testRequesterID, testApproverID)
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	// approve it first, then attempt to cancel
	decideReqObj, decideW := decideReq(t, testApproverID, reqID, "approve")
	h.Decide(decideW, decideReqObj)
	if decideW.Code != http.StatusOK {
		t.Fatalf("setup approve failed: %d — %s", decideW.Code, decideW.Body.String())
	}

	req, w := cancelReq(t, testRequesterID, reqID)
	h.Cancel(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("cancel of decided request: want 404, got %d — %s", w.Code, w.Body.String())
	}
}
