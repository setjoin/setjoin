package mdm

import (
	"testing"
)

func TestResolveNotificationProfile(t *testing.T) {
	tests := []struct {
		name     string
		admin    string // admin-configured profile
		platform string
		want     string
	}{
		{"ios hybrid", "hybrid", "ios", "hybrid"},
		{"ios push_only", "push_only", "ios", "push_only"},
		{"ios websocket_only falls back", "websocket_only", "ios", "push_only"}, // Apple restriction
		{"android gms hybrid", "hybrid", "android_gms", "hybrid"},
		{"android china websocket_only", "websocket_only", "android_china", "websocket_only"},
		{"desktop hybrid falls back", "hybrid", "macos", "websocket_only"}, // No push on desktop
		{"desktop push_only unsupported", "push_only", "windows", "websocket_only"},
		{"unknown platform default", "hybrid", "unknown", "websocket_only"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := ResolveNotificationProfile(tt.admin, tt.platform)
			if profile != tt.want {
				t.Errorf("ResolveNotificationProfile(%q, %q) = %q, want %q",
					tt.admin, tt.platform, profile, tt.want)
			}
		})
	}
}

func TestPlatformSupportsPush(t *testing.T) {
	tests := []struct {
		platform string
		wants    bool
	}{
		{"ios", true},         // APNs
		{"android_gms", true}, // FCM
		{"android_hms", true}, // HMS
		{"android_china", false},
		{"macos", false},
		{"windows", false},
		{"linux", false},
		{"webmail", false},
		{"harmonyos", true}, // HMS Push Kit native
	}

	for _, tt := range tests {
		t.Run(tt.platform, func(t *testing.T) {
			got := PlatformSupportsPush(tt.platform)
			if got != tt.wants {
				t.Errorf("PlatformSupportsPush(%q) = %v, want %v", tt.platform, got, tt.wants)
			}
		})
	}
}

func TestNotificationProfileDefaults(t *testing.T) {
	np := DefaultNotificationProfile()
	if np.Profile != "hybrid" {
		t.Errorf("expected default profile=hybrid, got %s", np.Profile)
	}
	if np.WebsocketKeepaliveSecs != 30 {
		t.Errorf("expected default keepalive=30, got %d", np.WebsocketKeepaliveSecs)
	}
}
