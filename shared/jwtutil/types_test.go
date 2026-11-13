package jwtutil

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestClaims_HasPermission_TruthTable pins the full truth table behind
// Claims.HasPermission (the gate for middleware auth + admin-console access).
// The legacy `IsAdmin && len(Permissions)==0 ⇒ true` bridge has been DELETED and
// the users.admin_role enum is GONE (the RBAC cut-over dropped the column):
// HasPermission is now a pure set-membership test, so IsAdmin no longer grants
// anything on its own. Authorization flows exclusively from the resolved
// Permissions slice — every empty-perms case DENIES regardless of the IsAdmin
// flag. The SCOPED-admin case stays the load-bearing guard: an admin with an
// explicit, non-empty slice gets ONLY those perms.
func TestClaims_HasPermission_TruthTable(t *testing.T) {
	const (
		usersRead   = "users.read"
		usersDelete = "users.delete"
	)

	tests := []struct {
		name    string
		isAdmin bool
		perms   []string
		query   string
		want    bool
	}{
		// C.1 — legacy admin (admin, nil/empty perms) ⇒ DENY.
		// The bridge is gone: an empty-perms token grants nothing.
		{"legacy admin nil perms denied (bridge deleted)", true, nil, usersDelete, false},
		{"legacy admin empty perms denied (bridge deleted)", true, []string{}, usersRead, false},

		// C.2 — scoped admin (admin, non-empty perms) ⇒ ONLY the listed perms.
		{"scoped admin gets held perm", true, []string{usersRead}, usersRead, true},
		{"scoped admin denied unheld perm", true, []string{usersRead}, usersDelete, false},

		// C.3 — non-admin: held perm true, unheld perm false.
		{"non-admin gets held perm", false, []string{usersRead}, usersRead, true},
		{"non-admin denied unheld perm", false, []string{usersRead}, usersDelete, false},

		// C.4 — non-admin, empty perms ⇒ false (membership test, nothing held).
		{"non-admin empty perms denied", false, nil, usersRead, false},

		// C.5 — admin with empty perms ⇒ DENY (bridge deleted). A real
		// super-admin gets AllPermissions via a governed assignment, not the flag.
		{"admin nil perms denied (bridge deleted)", true, nil, usersDelete, false},

		// C.6 — explicit perms work regardless of the IsAdmin flag (pure membership).
		{"admin with held perm", true, []string{usersRead}, usersRead, true},
		{"admin denied unheld perm", true, []string{usersRead}, usersDelete, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Claims{IsAdmin: tt.isAdmin, Permissions: tt.perms}
			if got := c.HasPermission(tt.query); got != tt.want {
				t.Fatalf("HasPermission(isAdmin=%v perms=%v, %q) = %v, want %v",
					tt.isAdmin, tt.perms, tt.query, got, tt.want)
			}
		})
	}
}

func TestClaimsMarshalUnmarshalRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	claims := Claims{
		UserID:       42,
		Email:        "alice@example.com",
		IsAdmin:      true,
		Type:         TypeAccess,
		JTI:          "abc123",
		AdminActorID: ptrInt64(99),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Subject:   "42",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded Claims
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.UserID != claims.UserID {
		t.Errorf("UserID: got %d, want %d", decoded.UserID, claims.UserID)
	}
	if decoded.Email != claims.Email {
		t.Errorf("Email: got %q, want %q", decoded.Email, claims.Email)
	}
	if decoded.IsAdmin != claims.IsAdmin {
		t.Errorf("IsAdmin: got %v, want %v", decoded.IsAdmin, claims.IsAdmin)
	}
	if decoded.Type != claims.Type {
		t.Errorf("Type: got %q, want %q", decoded.Type, claims.Type)
	}
	if decoded.JTI != claims.JTI {
		t.Errorf("JTI: got %q, want %q", decoded.JTI, claims.JTI)
	}
	if decoded.AdminActorID == nil || *decoded.AdminActorID != 99 {
		t.Errorf("AdminActorID: got %v, want 99", decoded.AdminActorID)
	}
	if decoded.Issuer != claims.Issuer {
		t.Errorf("Issuer: got %q, want %q", decoded.Issuer, claims.Issuer)
	}
}

func TestTokenTypeConstants(t *testing.T) {
	tests := []struct {
		constant TokenType
		value    string
	}{
		{TypeAccess, "access"},
		{TypeMFAPending, "mfa_pending"},
		{TypeRefresh, "refresh"},
		{TypeForcePasswordChange, "force_pw_change"},
		{TypePasswordReset, "password_reset"},
	}
	for _, tt := range tests {
		if string(tt.constant) != tt.value {
			t.Errorf("expected %s = %q, got %q", tt.value, tt.value, tt.constant)
		}
	}
}

func TestClaimsOmitEmpty(t *testing.T) {
	claims := Claims{
		UserID: 1,
		Email:  "test@example.com",
		Type:   TypeAccess,
	}
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map failed: %v", err)
	}

	for _, field := range []string{"admin", "role", "jti", "act", "perms", "domain"} {
		if _, exists := raw[field]; exists {
			t.Errorf("field %q should be omitted when empty/zero", field)
		}
	}
}

func TestClaimsAdminActorIDRoundTrip(t *testing.T) {
	claims := Claims{
		UserID:       1,
		Email:        "test@example.com",
		Type:         TypeAccess,
		AdminActorID: ptrInt64(42),
	}
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var decoded Claims
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if decoded.AdminActorID == nil || *decoded.AdminActorID != 42 {
		t.Errorf("AdminActorID: got %v, want 42", decoded.AdminActorID)
	}
}

func TestClaimsWithoutJTI(t *testing.T) {
	claims := Claims{
		UserID: 1,
		Email:  "test@example.com",
		Type:   TypeAccess,
	}
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded Claims
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.JTI != "" {
		t.Errorf("JTI should be empty, got %q", decoded.JTI)
	}
}

// TestClaimsNeverCarryRoleClaim pins the RBAC cut-over invariant: the JWT must
// NEVER carry an `admin_role` ("role") claim. The users.admin_role enum and the
// Claims.AdminRole field that fed this claim were both removed — authorization
// flows exclusively from the resolved Permissions slice. A marshalled token,
// even for an admin, must have no "role" key.
func TestClaimsNeverCarryRoleClaim(t *testing.T) {
	claims := Claims{
		UserID:  1,
		Email:   "test@example.com",
		IsAdmin: true,
		Type:    TypeAccess,
	}
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map failed: %v", err)
	}

	if _, exists := raw["role"]; exists {
		t.Error(`JWT must not carry a "role" (admin_role) claim after the RBAC cut-over`)
	}
}

func ptrInt64(v int64) *int64 { return &v }

func TestDeviceClaim_JSONRoundTrip(t *testing.T) {
	dc := &DeviceClaim{
		ID:               "d_781",
		Platform:         "iOS",
		TrustTier:        TrustTierTrusted,
		ComplianceStatus: ComplianceOK,
		WipeRequested:    false,
	}

	data, err := json.Marshal(dc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out DeviceClaim
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.ID != dc.ID {
		t.Errorf("ID = %q, want %q", out.ID, dc.ID)
	}
	if out.Platform != dc.Platform {
		t.Errorf("Platform = %q, want %q", out.Platform, dc.Platform)
	}
	if out.TrustTier != dc.TrustTier {
		t.Errorf("TrustTier = %q, want %q", out.TrustTier, dc.TrustTier)
	}
	if out.WipeRequested != dc.WipeRequested {
		t.Errorf("WipeRequested = %v, want %v", out.WipeRequested, dc.WipeRequested)
	}
}

func TestMAMClaim_JSONRoundTrip(t *testing.T) {
	mc := MAMClaim{
		PolicyVersion:       7,
		CopyPaste:           "block_external",
		ScreenCapture:       "block",
		Encryption:          "required",
		Watermark:           true,
		NotificationProfile: NotificationPush,
		MaxOfflineDays:      30,
	}

	data, err := json.Marshal(mc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out MAMClaim
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.PolicyVersion != mc.PolicyVersion {
		t.Errorf("PolicyVersion = %d, want %d", out.PolicyVersion, mc.PolicyVersion)
	}
	if out.CopyPaste != mc.CopyPaste {
		t.Errorf("CopyPaste = %q, want %q", out.CopyPaste, mc.CopyPaste)
	}
	if out.Encryption != mc.Encryption {
		t.Errorf("Encryption = %q, want %q", out.Encryption, mc.Encryption)
	}
}

func TestRiskClaim_JSONRoundTrip(t *testing.T) {
	rc := RiskClaim{
		UserScore:   42,
		RequiresMFA: true,
		Signals:     []string{"email_spam_blast", "geo_anomaly"},
	}

	data, err := json.Marshal(rc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out RiskClaim
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.UserScore != rc.UserScore {
		t.Errorf("UserScore = %d, want %d", out.UserScore, rc.UserScore)
	}
	if !out.RequiresMFA {
		t.Error("RequiresMFA should be true")
	}
	if len(out.Signals) != 2 {
		t.Errorf("Signals length = %d, want 2", len(out.Signals))
	}
}

func TestClaims_NewDeviceFieldsOmitEmpty(t *testing.T) {
	c := Claims{
		UserID: 1,
		Email:  "test@example.com",
		Type:   TypeAccess,
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	// device, mam, risk should be omitted when empty
	for _, field := range []string{"device", "mam", "risk"} {
		if _, exists := raw[field]; exists {
			t.Errorf("field %q should be omitted when empty", field)
		}
	}
}

func TestTrustTierConstants(t *testing.T) {
	if TrustTierTrusted != "trusted" {
		t.Errorf("TrustTierTrusted = %q", TrustTierTrusted)
	}
	if TrustTierCompliant != "compliant" {
		t.Errorf("TrustTierCompliant = %q", TrustTierCompliant)
	}
	if TrustTierQuarantined != "quarantined" {
		t.Errorf("TrustTierQuarantined = %q", TrustTierQuarantined)
	}
	if TrustTierUnknown != "unknown" {
		t.Errorf("TrustTierUnknown = %q", TrustTierUnknown)
	}
}

func TestComplianceStatusConstants(t *testing.T) {
	if ComplianceOK != "ok" {
		t.Errorf("ComplianceOK = %q", ComplianceOK)
	}
	if ComplianceJailbroken != "jailbroken" {
		t.Errorf("ComplianceJailbroken = %q", ComplianceJailbroken)
	}
	if ComplianceOSOutdated != "os_outdated" {
		t.Errorf("ComplianceOSOutdated = %q", ComplianceOSOutdated)
	}
}

func TestNotificationProfileConstants(t *testing.T) {
	if NotificationPush != "push" {
		t.Errorf("NotificationPush = %q", NotificationPush)
	}
	if NotificationBatch != "batch" {
		t.Errorf("NotificationBatch = %q", NotificationBatch)
	}
	if NotificationSilent != "silent" {
		t.Errorf("NotificationSilent = %q", NotificationSilent)
	}
}
