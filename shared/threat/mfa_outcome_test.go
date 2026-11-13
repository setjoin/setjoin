package threat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

// TestMiddleware_VerifiedNoOutcome_DoesNotTripCaptcha proves the wave-7 fix:
// a login handler that verifies the password correctly but pauses for a
// follow-up step (MFA enrollment / MFA challenge / step-up, all marked via
// WithVerifiedNoOutcome) must NOT feed the CAPTCHA failure counter — so a
// legitimate user re-submitting the same correct password while completing
// MFA never trips CAPTCHA. The contrast case (real wrong-password 401s, no
// marker) must still trip it at the same threshold — the fix must not have
// disabled the control, only corrected what it counts.
func TestMiddleware_VerifiedNoOutcome_DoesNotTripCaptcha(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	ensureCurrentAuthAttemptsPartition(t, ctx, pool)

	const (
		verifiedIP = "203.0.113.50" // TEST-NET-3 — mfa-enrollment/challenge case
		failIP     = "203.0.113.60" // TEST-NET-3 — real wrong-password case
		threshold  = 3
	)

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM auth_attempts WHERE source_ip IN ($1::INET, $2::INET)`,
			verifiedIP, failIP)
	})

	ti := &ThreatInterceptor{
		pool: pool,
		toggles: toggle.NewStatic(map[string]bool{
			toggle.FeatureThreatFeed:  false,
			toggle.FeatureGeoBlock:    false,
			toggle.FeatureSprayDetect: false,
			toggle.FeatureCaptcha:     true,
			toggle.FeatureTarpit:      false,
			toggle.FeatureRateLimit:   false,
		}),
		cfg: ThreatConfig{CaptchaWindowMins: 60, CaptchaThreshold: threshold},
	}

	// post drives one request through the real middleware. next reports whether
	// the wrapped handler was actually reached (false = the middleware itself
	// short-circuited the request, i.e. CAPTCHA fired before the handler ran).
	post := func(srcIP string, status int, verifiedNoOutcome bool) (handlerCalled bool, rec *httptest.ResponseRecorder) {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			if verifiedNoOutcome {
				// Mirrors what Login does for mfa_enrollment_required/mfa_required/
				// force_password_change/CA step-up: mutate *r in place so the
				// Middleware closure's rr.Context() (read after ServeHTTP returns)
				// carries the marker.
				*r = *r.WithContext(WithVerifiedNoOutcome(r.Context()))
			}
			w.WriteHeader(status)
		})
		rec = httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = srcIP + ":54321"
		ti.Middleware(next).ServeHTTP(rec, req)
		return handlerCalled, rec
	}

	// ---- Group A: `threshold` correct-password logins that each pause for MFA
	// (403, marked verified-no-outcome). None may be counted as a failure.
	for i := 0; i < threshold; i++ {
		called, rec := post(verifiedIP, http.StatusForbidden, true)
		if !called {
			t.Fatalf("verified-no-outcome request %d: handler was not reached (status %d) — CAPTCHA fired too early", i, rec.Code)
		}
	}
	// One more request on the same IP: must still proceed straight to the
	// handler — no CAPTCHA challenge, because none of the above were recorded
	// as failures.
	if called, rec := post(verifiedIP, http.StatusForbidden, true); !called {
		t.Fatalf("request %d+1 on verifiedIP: handler was not reached (status %d, X-Threat-Reason=%q) — CAPTCHA incorrectly tripped by mfa-enrollment/challenge responses",
			threshold, rec.Code, rec.Header().Get("X-Threat-Reason"))
	}

	// ---- Group B (contrast): `threshold` real wrong-password logins (401, no
	// marker) on a distinct IP must still trip CAPTCHA on the next request —
	// proving the fix narrows the classification, it doesn't disable the control.
	for i := 0; i < threshold; i++ {
		called, rec := post(failIP, http.StatusUnauthorized, false)
		if !called {
			t.Fatalf("wrong-password request %d: handler was not reached (status %d) unexpectedly", i, rec.Code)
		}
	}
	called, rec := post(failIP, http.StatusUnauthorized, false)
	if called {
		t.Fatalf("request %d+1 on failIP: handler was reached — expected CAPTCHA to fire after %d real failures", threshold, threshold)
	}
	if rec.Code != http.StatusForbidden || rec.Header().Get("X-Threat-Reason") != "captcha" {
		t.Fatalf("expected CAPTCHA response (403, X-Threat-Reason=captcha), got %d, X-Threat-Reason=%q", rec.Code, rec.Header().Get("X-Threat-Reason"))
	}
}
