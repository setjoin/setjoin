package pwhash

import (
	"testing"

	"setjoin.com/shared/toggle"
)

func TestAuthEventStruct(t *testing.T) {
	userID := int64(42)
	ev := AuthEvent{
		UserID:    &userID,
		Event:     "login",
		Provider:  "bcrypt",
		Email:     "user@example.com",
		IPAddress: "10.0.0.1",
		Details:   `{"reason":"test"}`,
	}

	if *ev.UserID != 42 {
		t.Errorf("UserID = %d, want 42", *ev.UserID)
	}
	if ev.Event != "login" {
		t.Errorf("Event = %q, want %q", ev.Event, "login")
	}
	if ev.Provider != "bcrypt" {
		t.Errorf("Provider = %q, want %q", ev.Provider, "bcrypt")
	}
	if ev.Email != "user@example.com" {
		t.Errorf("Email = %q, want %q", ev.Email, "user@example.com")
	}
	if ev.IPAddress != "10.0.0.1" {
		t.Errorf("IPAddress = %q, want %q", ev.IPAddress, "10.0.0.1")
	}
}

func TestAuthEventNilUserID(t *testing.T) {
	// Failed auths have nil UserID
	ev := AuthEvent{
		Event:    "login_failed",
		Provider: "bcrypt",
		Email:    "bad@example.com",
	}
	if ev.UserID != nil {
		t.Error("UserID should be nil for failed auth")
	}
	if ev.Event != "login_failed" {
		t.Errorf("Event = %q, want login_failed", ev.Event)
	}
}

func TestLogAuthEventCompiles(t *testing.T) {
	// Verify LogAuthEvent function exists and compiles
	var _ func() = func() {
		_ = AuthEvent{
			Event:    "login",
			Provider: "app_password",
			Email:    "test@test.com",
		}
	}
}

type mockChecker struct {
	enabled map[string]bool
}

func (m *mockChecker) IsEnabled(key string) bool {
	if m.enabled == nil {
		return true
	}
	v, ok := m.enabled[key]
	if !ok {
		return true
	}
	return v
}

func TestToggleCheckerInterface(t *testing.T) {
	var c ToggleChecker = &mockChecker{}
	if !c.IsEnabled("anything") {
		t.Error("mockChecker should default to enabled")
	}
}

func TestToggleCheckerDisabled(t *testing.T) {
	c := &mockChecker{enabled: map[string]bool{"feature.auth_log_bcrypt": false}}
	if c.IsEnabled("feature.auth_log_bcrypt") {
		t.Error("mockChecker should return false for disabled toggle")
	}
}

func TestAuthProviderFeatureKeysAreFiniteAndRegistered(t *testing.T) {
	seen := map[string]bool{}
	for _, provider := range AuthProviders() {
		key, ok := AuthLogFeatureKey(provider)
		if !ok || key == "" {
			t.Fatalf("provider %q has no feature key", provider)
		}
		if seen[key] {
			t.Fatalf("duplicate auth-log feature key %q", key)
		}
		seen[key] = true
		if _, ok := toggle.Lookup(key); !ok {
			t.Fatalf("auth-log key %q is absent from toggle definitions", key)
		}
	}
	if _, ok := AuthLogFeatureKey(AuthProvider("operator_supplied")); ok {
		t.Fatal("unknown provider constructed a dynamic feature key")
	}
}
