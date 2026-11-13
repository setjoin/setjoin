package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
)

// resolveLoginDeviceClaim is the P1 producer: it embeds a DeviceClaim in the
// access token at login ONLY when device-trust enforcement is wired AND the
// feature toggle is explicitly on. These tests pin the toggle-gating + the
// fail-open / unenrolled pass-through (no DB needed — a nil-pool resolver
// returns nil exactly as a DB error / unenrolled device would).

func req() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	r.Header.Set("User-Agent", "test-agent")
	r.RemoteAddr = "203.0.113.5:1234"
	return r
}

func TestResolveLoginDeviceClaim_NilResolver(t *testing.T) {
	h := &deps{toggles: toggle.NewStatic(map[string]bool{toggle.FeatureDeviceTrustEnforcement: true})}
	if got := h.resolveLoginDeviceClaim(req(), 42); got != nil {
		t.Fatalf("nil deviceTrust must yield nil claim, got %+v", got)
	}
}

func TestResolveLoginDeviceClaim_NilToggles(t *testing.T) {
	h := &deps{deviceTrust: threat.NewDeviceTrustResolver(nil, nil)}
	if got := h.resolveLoginDeviceClaim(req(), 42); got != nil {
		t.Fatalf("nil toggles must yield nil claim, got %+v", got)
	}
}

func TestResolveLoginDeviceClaim_ToggleOff_NoClaim(t *testing.T) {
	// Toggle absent -> the registry default (false) keeps it OFF. No claim is
	// embedded => tokens are byte-for-byte unchanged until a deliberate flip.
	h := &deps{
		deviceTrust: threat.NewDeviceTrustResolver(nil, nil),
		toggles:     toggle.NewStatic(map[string]bool{}),
	}
	if got := h.resolveLoginDeviceClaim(req(), 42); got != nil {
		t.Fatalf("toggle OFF (unseeded) must yield nil claim, got %+v", got)
	}
}

func TestResolveLoginDeviceClaim_ToggleSeededOff_NoClaim(t *testing.T) {
	h := &deps{
		deviceTrust: threat.NewDeviceTrustResolver(nil, nil),
		toggles:     toggle.NewStatic(map[string]bool{toggle.FeatureDeviceTrustEnforcement: false}),
	}
	if got := h.resolveLoginDeviceClaim(req(), 42); got != nil {
		t.Fatalf("toggle seeded OFF must yield nil claim, got %+v", got)
	}
}

func TestResolveLoginDeviceClaim_ToggleOn_FailsOpen(t *testing.T) {
	// Toggle ON but a nil-pool resolver (stand-in for a DB error / unenrolled
	// device) must FAIL OPEN -> nil claim, never a quarantine, never a panic.
	h := &deps{
		deviceTrust: threat.NewDeviceTrustResolver(nil, nil),
		toggles:     toggle.NewStatic(map[string]bool{toggle.FeatureDeviceTrustEnforcement: true}),
	}
	if got := h.resolveLoginDeviceClaim(req(), 42); got != nil {
		t.Fatalf("toggle ON with no DB must fail open to nil claim, got %+v", got)
	}
}

// geoIPCountryCode (P3) threads the resolved ISO country into the policy eval
// context. With no GeoLite2 DB it must degrade to "" (-> geo tier "low"), never
// panic — so the prior behavior is preserved when geo data is absent.
func TestGeoIPCountryCode_NilDBAndBadIP(t *testing.T) {
	h := &deps{} // geoipDB nil
	if got := h.geoIPCountryCode("203.0.113.5"); got != "" {
		t.Errorf("nil geoipDB must yield empty country, got %q", got)
	}
	if got := h.geoIPCountryCode("not-an-ip"); got != "" {
		t.Errorf("unparseable IP must yield empty country, got %q", got)
	}
}
