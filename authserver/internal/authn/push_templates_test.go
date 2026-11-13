package authn

import (
	"strings"
	"testing"
)

func TestPushBodyEnglish(t *testing.T) {
	body := PushBody(TemplateNewDeviceLogin, "en", map[string]string{
		"device":   "iPhone 16",
		"platform": "iOS 26",
	})
	if !strings.Contains(body, "iPhone 16") {
		t.Errorf("expected device name in body, got: %s", body)
	}
	if !strings.Contains(body, "iOS 26") {
		t.Errorf("expected platform in body, got: %s", body)
	}
	if !strings.Contains(body, "New login from") {
		t.Errorf("expected English prefix, got: %s", body)
	}
}

func TestPushBodyChinese(t *testing.T) {
	body := PushBody(TemplateNewDeviceLogin, "zh", map[string]string{
		"device":   "iPhone 16",
		"platform": "iOS 26",
	})
	if !strings.Contains(body, "新设备登录") {
		t.Errorf("expected Chinese text, got: %s", body)
	}
	if !strings.Contains(body, "iPhone 16") {
		t.Errorf("expected device name in body, got: %s", body)
	}
}

func TestPushBodyGerman(t *testing.T) {
	body := PushBody(TemplateNewDeviceLogin, "de", map[string]string{
		"device":   "iPhone 16",
		"platform": "iOS 26",
	})
	if !strings.Contains(body, "Neue Anmeldung") {
		t.Errorf("expected German text, got: %s", body)
	}
}

func TestPushBodyFallbackEnglish(t *testing.T) {
	// Unknown locale should fall back to English.
	body := PushBody(TemplatePasswordChange, "jp", nil)
	if body != "Your password was changed" {
		t.Errorf("expected English fallback, got: %s", body)
	}
}

func TestPushBodyUnknownTemplate(t *testing.T) {
	body := PushBody(PushTemplateKey("nonexistent"), "en", nil)
	if body != "" {
		t.Errorf("expected empty string for unknown template, got: %s", body)
	}
}

func TestPushTitle(t *testing.T) {
	tests := []struct {
		locale, want string
	}{
		{"en", "SetJoin Security"},
		{"zh", "SetJoin 安全通知"},
		{"de", "SetJoin Sicherheit"},
		{"fr", "SetJoin Security"}, // fallback
	}
	for _, tt := range tests {
		t.Run(tt.locale, func(t *testing.T) {
			got := PushTitle(tt.locale)
			if got != tt.want {
				t.Errorf("PushTitle(%q) = %q, want %q", tt.locale, got, tt.want)
			}
		})
	}
}

func TestPushBodyMFASetupWithMethod(t *testing.T) {
	body := PushBody(TemplateMFASetup, "en", map[string]string{
		"method": "TOTP",
	})
	if !strings.Contains(body, "TOTP") {
		t.Errorf("expected method in body, got: %s", body)
	}
}

func TestPushBodyAdminLock(t *testing.T) {
	body := PushBody(TemplateAdminLock, "en", map[string]string{
		"admin": "admin@example.com",
	})
	if !strings.Contains(body, "admin@example.com") {
		t.Errorf("expected admin email in body, got: %s", body)
	}
}

func TestPushBodyAdminWipe(t *testing.T) {
	body := PushBody(TemplateAdminWipe, "en", map[string]string{
		"admin": "admin@example.com",
	})
	if !strings.Contains(body, "admin@example.com") {
		t.Errorf("expected admin email in body, got: %s", body)
	}
}
