package threat_test

// Composed producer→gate contract for the device-trust enforcement closure
// (occ_027c0f3d4df0cadcfb74d1a6, device-trust-nil-claim-pass-through). This is
// an EXTERNAL test package because shared/middleware imports shared/threat
// (runtime_access.go), so an in-package test could not compose the two.
//
// The sealed fail-open: with feature.device_trust_enforcement ON, a nil Device
// claim (what shared/threat.DeviceTrustResolver produces for unenrolled,
// unknown-compliance, or lookup-failed devices) used to pass the gate two lines
// after nil claims failed closed. The gate now fails claim-less tokens closed
// unless an explicitly contracted legacy token class admits them — these tests
// pin that the producer's indeterminate legs land on the fail-closed leg of the
// composed pair, end to end, with no DB.

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/middleware"
	"setjoin.com/shared/threat"
)

// gateLogger keeps the gate's deny-path warnings silent in test output.
var gateLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// gateRequest builds a plain request; the gate's ClaimsFunc is a closure over
// the claims under test, so no context attachment is needed.
func gateRequest() *http.Request {
	return httptest.NewRequest(http.MethodGet, "/gated", nil)
}

// runGate exercises the bare (no legacy classes) enabled gate against claims
// and returns the response code it produces.
func runGate(t *testing.T, claims *jwtutil.Claims) int {
	t.Helper()
	gate := middleware.RequireDeviceCompliance(func(*http.Request) *jwtutil.Claims { return claims }, gateLogger)
	var code int
	handler := gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		code = http.StatusOK
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, gateRequest())
	if code == 0 {
		code = w.Code
	}
	return code
}

// TestNilDeviceClaimFailsClosedAtGate: every indeterminate leg of
// MapManagedComplianceToClaim — the nil the producer returns for an unenrolled
// device, an unknown compliance status, or a lookup failure — is BLOCKED by the
// enabled gate (403 device_compliance_unverifiable). A nil claim can no longer
// ride through device-trust enforcement.
func TestNilDeviceClaimFailsClosedAtGate(t *testing.T) {
	for name, claim := range map[string]*jwtutil.DeviceClaim{
		"unenrolled (no row)":    nil,
		"unknown status":         threat.MapManagedComplianceToClaim("hash", "unknown", true),
		"unrecognized status":    threat.MapManagedComplianceToClaim("hash", "garbage", true),
		"not found":              threat.MapManagedComplianceToClaim("hash", "compliant", false),
		"lookup failure (= nil)": nil,
	} {
		code := runGate(t, &jwtutil.Claims{UserID: 7, Device: claim})
		if code != http.StatusForbidden {
			t.Errorf("%s: gate returned %d for a nil/indeterminate device claim, want 403 (fail closed)", name, code)
		}
	}
}

// TestDeterminateDeviceClaimsAtGate pins the two determinate legs end to end:
// a compliant claim passes the enabled gate; a non_compliant (quarantined)
// claim is blocked.
func TestDeterminateDeviceClaimsAtGate(t *testing.T) {
	compliant := threat.MapManagedComplianceToClaim("hash", "compliant", true)
	if compliant == nil || compliant.TrustTier != jwtutil.TrustTierCompliant {
		t.Fatalf("producer returned %+v, want a compliant claim", compliant)
	}
	if code := runGate(t, &jwtutil.Claims{UserID: 7, Device: compliant}); code != http.StatusOK {
		t.Errorf("compliant claim blocked by the gate: %d", code)
	}

	quarantined := threat.MapManagedComplianceToClaim("hash", "non_compliant", true)
	if quarantined == nil || quarantined.TrustTier != jwtutil.TrustTierQuarantined {
		t.Fatalf("producer returned %+v, want a quarantined claim", quarantined)
	}
	if code := runGate(t, &jwtutil.Claims{UserID: 7, Device: quarantined}); code != http.StatusForbidden {
		t.Errorf("quarantined claim passed the gate: %d", code)
	}
}

// TestNilClaimsAreUnauthorizedAtGate keeps the boundary distinction honest: a
// request with NO claims at all is 401, not 403 — the fail-closed semantics the
// original fail-open sat two lines beneath.
func TestNilClaimsAreUnauthorizedAtGate(t *testing.T) {
	if code := runGate(t, nil); code != http.StatusUnauthorized {
		t.Errorf("gate returned %d for nil claims, want 401", code)
	}
}
