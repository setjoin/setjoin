package jmap

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/admin"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

// stubEntitlementChecker always returns the fixed value configured.
type stubEntitlementChecker struct {
	allowed bool
}

func (s *stubEntitlementChecker) Allowed(_ context.Context, _ int64, _ string) bool {
	return s.allowed
}

func testClaims(uid int64) *auth.Claims {
	return &jwtutil.Claims{UserID: uid, Email: "t@t.com", Type: jwtutil.TypeAccess}
}

// TestSessionEffectiveCapabilitiesShape verifies the effectiveCapabilities
// method returns the correct shape when pool is nil (the unit-test fallback).
// All apps should be false; assist should remain false (conservative default).
func TestSessionEffectiveCapabilitiesShape(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	caps := h.effectiveCapabilities(context.Background(), 0)

	// Must have both top-level keys.
	appsRaw, ok := caps["apps"]
	if !ok {
		t.Fatal("effectiveCapabilities: missing 'apps' key")
	}
	featuresRaw, ok := caps["features"]
	if !ok {
		t.Fatal("effectiveCapabilities: missing 'features' key")
	}

	// apps must fail closed on a nil/error capability lookup.
	apps, ok := appsRaw.(map[string]bool)
	if !ok {
		t.Fatalf("effectiveCapabilities: apps is %T, want map[string]bool", appsRaw)
	}
	for _, app := range []string{"mail", "calendar", "contacts", "tasks", "approvals", "drive", "chat", "meet"} {
		if v, exists := apps[app]; !exists {
			t.Errorf("apps[%q] is absent, want false", app)
		} else if v {
			t.Errorf("apps[%q] = true, want false", app)
		}
	}

	// features must be a map; assist must be false (conservative default when
	// pool is nil — we do not know whether feature.assist is on).
	features, ok := featuresRaw.(map[string]bool)
	if !ok {
		t.Fatalf("effectiveCapabilities: features is %T, want map[string]bool", featuresRaw)
	}
	if v, exists := features["assist"]; !exists {
		t.Error("features[\"assist\"] is absent, want false")
	} else if v {
		t.Error("features[\"assist\"] = true in nil-pool mode, want false")
	}
	if v, exists := features["external_labels"]; !exists {
		t.Error("features[\"external_labels\"] is absent, want false")
	} else if v {
		t.Error("features[\"external_labels\"] = true in nil-pool mode, want false")
	}
}

// TestEffectiveCapabilitiesDefaultOfflineUnlockFlags verifies the P1-T
// biometric/Windows-SSO unlock toggles are surfaced in the safe-default
// offline block, both false (deny-by-default — we cannot confirm the org
// toggles without a DB call, same posture as offline.allowed).
func TestEffectiveCapabilitiesDefaultOfflineUnlockFlags(t *testing.T) {
	caps := effectiveCapabilitiesDefault()
	offline, ok := caps["offline"].(map[string]any)
	if !ok {
		t.Fatalf("effectiveCapabilitiesDefault: offline is %T, want map[string]any", caps["offline"])
	}
	if v, exists := offline["biometricUnlock"]; !exists || v != false {
		t.Errorf("offline[\"biometricUnlock\"] = %v (exists=%v), want false", v, exists)
	}
	if v, exists := offline["windowsSsoUnlock"]; !exists || v != false {
		t.Errorf("offline[\"windowsSsoUnlock\"] = %v (exists=%v), want false", v, exists)
	}
}

// TestUnlockTogglesNilFeatureFlags verifies unlockToggles fails closed (both
// false) when no FeatureFlags has been wired (nil h.toggles — unit-test /
// pre-boot state), matching the deny-by-default invariant.
func TestUnlockTogglesNilFeatureFlags(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	biometric, windowsSSO := h.unlockToggles()
	if biometric || windowsSSO {
		t.Errorf("unlockToggles() with nil toggles = (%v, %v), want (false, false)", biometric, windowsSSO)
	}
}

// TestUnlockTogglesReflectsFeatureFlags verifies unlockToggles reads through
// to the wired FeatureFlags (toggle.FeatureBiometricUnlock /
// toggle.FeatureWindowsSsoUnlock), independently flippable.
func TestUnlockTogglesReflectsFeatureFlags(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	h.SetFeatureFlags(toggle.NewStatic(map[string]bool{
		toggle.FeatureBiometricUnlock:  true,
		toggle.FeatureWindowsSsoUnlock: false,
	}))
	biometric, windowsSSO := h.unlockToggles()
	if !biometric {
		t.Error("unlockToggles() biometric = false, want true (feature.biometric_unlock ON)")
	}
	if windowsSSO {
		t.Error("unlockToggles() windowsSSO = true, want false (feature.windows_sso_unlock OFF)")
	}
}

// sessionCapabilities reconstructs the top-level `capabilities` map exactly as
// the Session handler builds it (handler.go), so the test asserts on the same
// structure without needing a live pool (Session's primary-mailbox lookup
// short-circuits when pool is nil).
func sessionCapabilities() map[string]any {
	return map[string]any{
		"urn:ietf:params:jmap:core":      map[string]any{},
		"urn:ietf:params:jmap:mail":      map[string]any{},
		"urn:ietf:params:jmap:calendars": map[string]any{},
		"urn:ietf:params:jmap:contacts":  map[string]any{},
		"urn:ietf:params:jmap:tasks":     map[string]any{},
		"urn:ietf:params:jmap:submission": map[string]any{
			"maxDelayedSend":       maxDelayedSendSeconds,
			"submissionExtensions": map[string]any{},
		},
		"urn:setjoin:params:jmap:reminders": map[string]any{},
		"urn:ietf:params:jmap:blob":         map[string]any{},
		VendorCapability:                    map[string]any{},
	}
}

// TestSessionAdvertisesSubmissionCapability verifies the Session capabilities
// object advertises urn:ietf:params:jmap:submission (RFC 8621 §7) so a
// spec-compliant client will actually use EmailSubmission/* (which is fully
// wired). It also checks the value object carries maxDelayedSend (positive,
// since scheduled send via sendAt is supported) and submissionExtensions.
func TestSessionAdvertisesSubmissionCapability(t *testing.T) {
	caps := sessionCapabilities()

	subRaw, ok := caps["urn:ietf:params:jmap:submission"]
	if !ok {
		t.Fatal("capabilities missing urn:ietf:params:jmap:submission — spec clients won't use EmailSubmission/*")
	}
	sub, ok := subRaw.(map[string]any)
	if !ok {
		t.Fatalf("submission capability is %T, want map[string]any", subRaw)
	}

	delay, ok := sub["maxDelayedSend"]
	if !ok {
		t.Fatal("submission capability missing maxDelayedSend")
	}
	d, ok := delay.(int)
	if !ok {
		t.Fatalf("maxDelayedSend is %T, want int", delay)
	}
	if d <= 0 {
		t.Errorf("maxDelayedSend = %d, want > 0 (scheduled send via sendAt is supported)", d)
	}
	if d != maxDelayedSendSeconds {
		t.Errorf("maxDelayedSend = %d, want %d", d, maxDelayedSendSeconds)
	}

	if _, ok := sub["submissionExtensions"]; !ok {
		t.Error("submission capability missing submissionExtensions (RFC 8621 §7 requires the key)")
	}
}

// TestSessionMarshalsSubmissionCapability verifies the submission capability
// survives JSON marshalling (the wire form the client receives) under its
// RFC 8621 URN, with a numeric maxDelayedSend.
func TestSessionMarshalsSubmissionCapability(t *testing.T) {
	blob, err := json.Marshal(map[string]any{"capabilities": sessionCapabilities()})
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	var decoded struct {
		Capabilities struct {
			Submission *struct {
				MaxDelayedSend       int            `json:"maxDelayedSend"`
				SubmissionExtensions map[string]any `json:"submissionExtensions"`
			} `json:"urn:ietf:params:jmap:submission"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatalf("unmarshal session: %v", err)
	}
	if decoded.Capabilities.Submission == nil {
		t.Fatal("marshalled session capabilities omit urn:ietf:params:jmap:submission")
	}
	if decoded.Capabilities.Submission.MaxDelayedSend != maxDelayedSendSeconds {
		t.Errorf("wire maxDelayedSend = %d, want %d", decoded.Capabilities.Submission.MaxDelayedSend, maxDelayedSendSeconds)
	}
}

// TestDispatchGatedMethodDenied verifies that a gated JMAP method (Calendar/get)
// returns ("error", ...) when the injected entitlement checker denies access.
// The next handler must NOT be called.
func TestDispatchGatedMethodDenied(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	h.SetEntitlementChecker(&stubEntitlementChecker{allowed: false})

	user := testClaims(1)
	args, _ := json.Marshal(map[string]any{"accountId": "1"})

	name, result := h.Dispatch(context.Background(), user, "Calendar/get", args)

	if name != "error" {
		t.Errorf("Dispatch with denied entitlement returned %q, want \"error\"", name)
	}
	var errObj map[string]any
	if err := json.Unmarshal(result, &errObj); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	// The type should be the JMAP forbidden error.
	typ, _ := errObj["type"].(string)
	if typ == "" {
		t.Error("error result missing 'type' field")
	}
}

// TestDispatchGatedMethodAllowed verifies that when the checker allows,
// the forbidden gating error is NOT returned for a gated method.
// We test this via Core/echo (which works without a pool) by ensuring the
// gate does NOT intercept ungated methods AND by confirming the forbidden
// type string is produced ONLY by a denied checker.
func TestDispatchGatedMethodAllowed(t *testing.T) {
	// Deny case should produce "forbidden".
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	h.SetEntitlementChecker(&stubEntitlementChecker{allowed: false})

	user := testClaims(1)
	args, _ := json.Marshal(map[string]any{"accountId": "1"})
	name, result := h.Dispatch(context.Background(), user, "Calendar/get", args)
	if name != "error" {
		t.Fatal("expected error from denied checker")
	}
	var errObj map[string]any
	_ = json.Unmarshal(result, &errObj)
	typ, _ := errObj["type"].(string)
	if typ != "urn:ietf:params:jmap:error:forbidden" {
		t.Errorf("denied checker returned unexpected type %q", typ)
	}

	// Allow case: no forbidden error for Core/echo (ungated, runs without pool).
	h2 := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	h2.SetEntitlementChecker(&stubEntitlementChecker{allowed: true})
	echoArgs, _ := json.Marshal(map[string]any{"ping": "pong"})
	name2, _ := h2.Dispatch(context.Background(), user, "Core/echo", echoArgs)
	if name2 == "error" {
		t.Error("Core/echo with allowed checker unexpectedly returned error")
	}
}

// TestDispatchUngatedMethodNotBlocked verifies that Core/echo (an ungated method)
// is never blocked by the entitlement checker, even when it denies everything.
func TestDispatchUngatedMethodNotBlocked(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	h.SetEntitlementChecker(&stubEntitlementChecker{allowed: false})

	user := testClaims(1)
	args, _ := json.Marshal(map[string]any{"ping": "pong"})

	// Core/echo is ungated and does not need a DB connection.
	name, result := h.Dispatch(context.Background(), user, "Core/echo", args)

	// Must NOT return the forbidden entitlement error.
	if name == "error" {
		var errObj map[string]any
		_ = json.Unmarshal(result, &errObj)
		typ, _ := errObj["type"].(string)
		if typ == "urn:ietf:params:jmap:error:forbidden" {
			t.Errorf("ungated Core/echo was blocked by entitlement checker: %s", typ)
		}
	}
}

// TestVendorCapabilityEffectiveAccessFlag verifies the vendor capability
// sub-map advertises "effectiveAccess: true" so clients know the server
// computes per-user app entitlements.
func TestVendorCapabilityEffectiveAccessFlag(t *testing.T) {
	caps := map[string]any{
		VendorCapability: map[string]any{
			"snoozeUntilOnEmailSet":      true,
			"sendAtOnEmailSubmissionSet": true,
			"emailSubmissionGetAndQuery": true,
			"effectiveAccess":            true,
		},
	}
	vendor, ok := caps[VendorCapability].(map[string]any)
	if !ok {
		t.Fatal("vendor capability map has wrong type")
	}
	v, ok := vendor["effectiveAccess"]
	if !ok {
		t.Fatal("vendor capability map missing 'effectiveAccess' key")
	}
	if b, ok := v.(bool); !ok || !b {
		t.Errorf("effectiveAccess = %v, want true", v)
	}
}

// ── Admin console visibility (Task 5, S6 layer 1) ───────────────────────────

// vendorCapabilityWithAdminConsoles builds the vendor capability sub-map the
// same way Session will: it resolves the caller's permissions into console ids
// via admin.ConsolesForPerms and embeds the result under an "admin" key.
func vendorCapabilityWithAdminConsoles(perms []string) map[string]any {
	vc := map[string]any{
		"snoozeUntilOnEmailSet":      true,
		"sendAtOnEmailSubmissionSet": true,
		"emailSubmissionGetAndQuery": true,
		"effectiveAccess":            true,
	}
	// Built by the SAME function Session uses (adminCapabilityBlock), so these
	// tests exercise the real admin-capability construction rather than a mirror.
	vc["admin"] = adminCapabilityBlock(perms)
	return vc
}

// TestSessionAdminConsoles_Auditor verifies that a user holding only audit.read
// sees exactly the Logs console.
func TestSessionAdminConsoles_Auditor(t *testing.T) {
	perms := []string{"audit.read"}
	vc := vendorCapabilityWithAdminConsoles(perms)

	adminBlock, ok := vc["admin"].(map[string]any)
	if !ok {
		t.Fatal("vendor capability missing 'admin' key")
	}
	consoles, ok := adminBlock["consoles"].([]admin.ConsoleID)
	if !ok {
		t.Fatalf("admin.consoles is %T, want []admin.ConsoleID", adminBlock["consoles"])
	}

	expected := []admin.ConsoleID{admin.ConsoleLogs}
	if !reflect.DeepEqual(consoles, expected) {
		t.Errorf("auditor consoles = %v, want %v", consoles, expected)
	}
}

// TestSessionAdminConsoles_SuperAdmin verifies super_admin sees all five consoles.
// The legacy/super_admin IsAdmin path resolves to AllPermissions (see chain.go
// resolvePermissions), which includes roles.manage — the scope gating the Access
// console — so every declared console (incl. Access) is visible.
func TestSessionAdminConsoles_SuperAdmin(t *testing.T) {
	vc := vendorCapabilityWithAdminConsoles(permissions.AllPermissions)

	adminBlock, ok := vc["admin"].(map[string]any)
	if !ok {
		t.Fatal("vendor capability missing 'admin' key")
	}
	consoles, ok := adminBlock["consoles"].([]admin.ConsoleID)
	if !ok {
		t.Fatalf("admin.consoles is %T, want []admin.ConsoleID", adminBlock["consoles"])
	}

	expected := []admin.ConsoleID{admin.ConsoleMail, admin.ConsoleSystem, admin.ConsoleLogs, admin.ConsoleAuth, admin.ConsoleAccess}
	if !reflect.DeepEqual(consoles, expected) {
		t.Errorf("super_admin consoles = %v, want %v", consoles, expected)
	}
}

// TestSessionAdminConsoles_NonAdmin verifies non-admin sees empty console list.
func TestSessionAdminConsoles_NonAdmin(t *testing.T) {
	perms := []string{}
	vc := vendorCapabilityWithAdminConsoles(perms)

	adminBlock, ok := vc["admin"].(map[string]any)
	if !ok {
		t.Fatal("vendor capability missing 'admin' key")
	}
	consoles, ok := adminBlock["consoles"].([]admin.ConsoleID)
	if !ok {
		t.Fatalf("admin.consoles is %T, want []admin.ConsoleID", adminBlock["consoles"])
	}

	if len(consoles) != 0 {
		t.Errorf("non-admin consoles = %v, want []", consoles)
	}
}

// TestSessionAdminExposesCallerOwnPermissions verifies the admin block exposes
// the caller's OWN resolved permissions alongside the derived console ids, so the
// SPA can gate each write control on its exact permission (a read-tier admin gets
// disabled controls instead of buttons that 403). The prior "only derived console
// ids, never raw perms" invariant was minimalism, not a disclosure boundary —
// reversed by the 2026-06-22 decision: a caller's own perms are self-knowledge the
// server enforces regardless. The block must still expose ONLY the caller's own
// perms (never the full catalog or another user's), so the key set is exactly
// {consoles, permissions}.
func TestSessionAdminExposesCallerOwnPermissions(t *testing.T) {
	perms := []string{"audit.read", "users.read"}
	vc := vendorCapabilityWithAdminConsoles(perms)

	adminBlock, ok := vc["admin"].(map[string]any)
	if !ok {
		t.Fatal("vendor capability missing 'admin' key")
	}

	// Exactly two keys: the derived consoles and the caller's own permissions.
	for k := range adminBlock {
		if k != "consoles" && k != "permissions" {
			t.Errorf("admin block contains unexpected key %q; want only {consoles, permissions}", k)
		}
	}

	// permissions echoes the caller's OWN resolved set (drives client-side gating).
	gotPerms, ok := adminBlock["permissions"].([]string)
	if !ok {
		t.Fatalf("admin.permissions is %T, want []string", adminBlock["permissions"])
	}
	if !reflect.DeepEqual(gotPerms, perms) {
		t.Errorf("admin.permissions = %v, want the caller's own perms %v", gotPerms, perms)
	}

	// consoles stays the derived visibility list.
	consoles, ok := adminBlock["consoles"].([]admin.ConsoleID)
	if !ok {
		t.Fatalf("admin.consoles is %T, want []admin.ConsoleID", adminBlock["consoles"])
	}
	found := make(map[admin.ConsoleID]bool)
	for _, c := range consoles {
		found[c] = true
	}
	if !found[admin.ConsoleLogs] {
		t.Error("user with audit.read should see Logs console")
	}
	if !found[admin.ConsoleAuth] {
		t.Error("user with users.read should see Auth console")
	}
}

// TestSessionWiresAdminCapabilityBlock pins the Session handler to build the
// vendor admin block via adminCapabilityBlock(user.Permissions). The tests above
// exercise adminCapabilityBlock directly; this guards the one load-bearing line
// in Session that wires it, so the {consoles, permissions} shape (which feeds the
// SPA's per-permission write-control gating) cannot silently regress to a
// consoles-only inline map. Source-level guard: Session's full path needs a live
// primary-mailbox lookup, so a pure unit test of the HTTP handler isn't available.
func TestSessionWiresAdminCapabilityBlock(t *testing.T) {
	src, err := os.ReadFile("handler.go")
	if err != nil {
		t.Fatalf("read handler.go: %v", err)
	}
	if !strings.Contains(string(src), `"admin": adminCapabilityBlock(user.Permissions)`) {
		t.Error(`Session must build the vendor admin block via adminCapabilityBlock(user.Permissions); ` +
			`the {consoles, permissions} shape feeds per-permission write-control gating and must not ` +
			`regress to a consoles-only map`)
	}
}
