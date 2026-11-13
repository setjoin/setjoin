package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/toggle"
)

func TestDeviceLockdownGate(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })

	// listPresent: set exists, current user not a member.
	listPresent := func(_ context.Context, _ int64) (bool, bool) { return true, false }
	// listAbsent: set missing → Decision 9 pass-through.
	listAbsent := func(_ context.Context, _ int64) (bool, bool) { return false, false }
	// bgMember: set present, user 42 is break-glass.
	bgMember := func(_ context.Context, uid int64) (bool, bool) { return true, uid == 42 }

	// stub resolver via resolveFn; production wires DeviceCredentialResolver.Resolve.
	boundApproved := func(_ context.Context, _ *http.Request) (bool, int64, string) { return true, 1, "approved" }
	unbound := func(_ context.Context, _ *http.Request) (bool, int64, string) { return false, 0, "" }

	plain := httptest.NewRequest("POST", "/jmap", nil)

	cases := []struct {
		name        string
		bothToggles bool // both feature.conditional_access + feature.device_lockdown ON
		checkBG     func(context.Context, int64) (bool, bool)
		resolve     resolveFn
		req         *http.Request
		wantCode    int
	}{
		{"toggle off -> pass", false, listPresent, unbound, plain, 200},
		{"on + exclude present + bound-approved -> 200", true, listPresent, boundApproved, plain, 200},
		{"on + exclude present + unbound -> 403", true, listPresent, unbound, plain, 403},
		// Locked decision 9: both ON but no break-glass exclude list → REFUSE to enforce (pass-through).
		{"on but NO exclude list -> pass-through (build-gate)", true, listAbsent, unbound, plain, 200},
		// Break-glass exemption: member + non-compliant device + lockdown ON → allowed.
		{"break-glass member + unbound + lockdown on -> allowed", true, bgMember, unbound, reqWithClaims(&auth.Claims{UserID: 42}), 200},
		// Non-break-glass user still gets 403.
		{"non-bg user + unbound + lockdown on -> 403", true, bgMember, unbound, reqWithClaims(&auth.Claims{UserID: 99}), 403},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			toggles := staticToggle{}
			if c.bothToggles {
				toggles[toggle.FeatureConditionalAccess] = true
				toggles[toggle.FeatureDeviceLockdown] = true
			}
			gate := deviceLockdownGate(toggles, c.resolve, c.checkBG, gateLogger())
			rec := httptest.NewRecorder()
			gate(ok).ServeHTTP(rec, c.req)
			if rec.Code != c.wantCode {
				t.Fatalf("code=%d want %d", rec.Code, c.wantCode)
			}
		})
	}
}

// TestDeviceLockdownGate_SyntheticBZ095Body pins the SPA deviceBlock wire
// contract (c6): jmap/client.ts branches on status 403 AND body code "BZ095"
// to route the user to /blocked. This body is written SYNTHETICALLY by the
// gate — it is NOT a reducererr projection (BZ095 the pg error classifies to
// 409/ClassConflict on the admin lifecycle path) — so this test is the guard
// that keeps the synthetic 403 surface stable.
func TestDeviceLockdownGate_SyntheticBZ095Body(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	listPresent := func(_ context.Context, _ int64) (bool, bool) { return true, false }
	unbound := func(_ context.Context, _ *http.Request) (bool, int64, string) { return false, 0, "" }

	toggles := staticToggle{
		toggle.FeatureConditionalAccess: true,
		toggle.FeatureDeviceLockdown:    true,
	}
	gate := deviceLockdownGate(toggles, unbound, listPresent, gateLogger())
	rec := httptest.NewRecorder()
	gate(ok).ServeHTTP(rec, httptest.NewRequest("POST", "/jmap", nil))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (SPA deviceBlock branch)", rec.Code)
	}
	var body struct {
		Status int    `json:"status"`
		Code   string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, rec.Body.String())
	}
	if body.Code != "BZ095" || body.Status != http.StatusForbidden {
		t.Fatalf("body = %+v, want code=BZ095 status=403 (jmap/client.ts hard contract)", body)
	}
}
