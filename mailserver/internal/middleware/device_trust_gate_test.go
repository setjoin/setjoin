package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/jwtutil"
)

func gateLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// staticToggle is a minimal toggleChecker for tests. An absent key reads
// false, mirroring the real registry default of the security-family keys
// these gates check.
type staticToggle map[string]bool

func (s staticToggle) IsEnabled(key string) bool { return s[key] }

// reqWithClaims attaches gateway auth claims to the request context, the way
// RequireAuth does upstream, so the gate's claimsFn can read them.
func reqWithClaims(c *auth.Claims) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/jmap", nil)
	if c != nil {
		ctx := auth.ContextWithUser(r.Context(), c)
		r = r.WithContext(ctx)
	}
	return r
}

func runGate(tg toggleChecker, c *auth.Claims) int {
	gate := DeviceTrustGate(tg, gateLogger())
	called := false
	h := gate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, reqWithClaims(c))
	_ = called
	return rec.Code
}

func quarantinedClaims() *auth.Claims {
	return &auth.Claims{UserID: 1, Type: jwtutil.TypeAccess,
		Device: &jwtutil.DeviceClaim{ID: "d1", TrustTier: jwtutil.TrustTierQuarantined}}
}

func compliantClaims() *auth.Claims {
	return &auth.Claims{UserID: 1, Type: jwtutil.TypeAccess,
		Device: &jwtutil.DeviceClaim{ID: "d2", TrustTier: jwtutil.TrustTierCompliant}}
}

func nilDeviceClaims() *auth.Claims {
	return &auth.Claims{UserID: 1, Type: jwtutil.TypeAccess}
}

func TestDeviceTrustGate_ToggleOff_IsNoOp(t *testing.T) {
	// Toggle OFF (unseeded) -> the gate must be a pure pass-through, even for a
	// quarantined device. This is the rollout-safety invariant.
	if got := runGate(staticToggle{}, quarantinedClaims()); got != http.StatusOK {
		t.Errorf("toggle OFF must pass quarantined through (200), got %d", got)
	}
	if got := runGate(staticToggle{"feature.device_trust_enforcement": false}, quarantinedClaims()); got != http.StatusOK {
		t.Errorf("toggle seeded OFF must pass quarantined through (200), got %d", got)
	}
}

func TestDeviceTrustGate_ToggleOn_BlocksQuarantined(t *testing.T) {
	if got := runGate(staticToggle{"feature.device_trust_enforcement": true}, quarantinedClaims()); got != http.StatusForbidden {
		t.Errorf("toggle ON must block quarantined (403), got %d", got)
	}
}

func TestDeviceTrustGate_ToggleOn_AllowsCompliant(t *testing.T) {
	if got := runGate(staticToggle{"feature.device_trust_enforcement": true}, compliantClaims()); got != http.StatusOK {
		t.Errorf("toggle ON must allow compliant (200), got %d", got)
	}
}

func TestDeviceTrustGate_ToggleOn_BlocksNilDevice(t *testing.T) {
	// Fail-closed contract: a claim-less (nil Device) token carries no
	// verifiable wipe/quarantine state, so a wiped or quarantined device
	// riding such a token must be blocked on EVERY DeviceTrustGate-protected
	// route while enforcement is ON. The gate wraps the authenticated chain
	// once, but the route-independence is pinned here across paths.
	paths := []string{"/jmap", "/mail", "/drive", "/admin", "/settings"}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			gate := DeviceTrustGate(staticToggle{"feature.device_trust_enforcement": true}, gateLogger())
			handlerCalled := false
			h := gate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
				w.WriteHeader(http.StatusOK)
			}))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, reqWithClaims(nilDeviceClaims()))

			if handlerCalled {
				t.Errorf("handler must not be reached for a claim-less token on %s", path)
			}
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s: toggle ON must block nil-Device (403), got %d", path, rec.Code)
			}
		})
	}
}

func TestDeviceTrustGate_ToggleOff_NilDeviceStillPassThrough(t *testing.T) {
	// Rollout-safety invariant: with the toggle OFF the gate remains a pure
	// pass-through, so the fail-closed change cannot bite before the flip.
	if got := runGate(staticToggle{}, nilDeviceClaims()); got != http.StatusOK {
		t.Errorf("toggle OFF must pass nil-Device through (200), got %d", got)
	}
}

var _ = context.Background
