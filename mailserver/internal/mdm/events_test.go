package mdm

import (
	"testing"
	"time"
)

// ── Device event unit tests (no DB required) ─────────────────────────────

func TestDeviceEvent_Validate(t *testing.T) {
	tests := []struct {
		name    string
		event   DeviceEvent
		wantErr bool
	}{
		{
			name: "valid event",
			event: DeviceEvent{
				DeviceID:  1,
				EventType: "policy_applied",
				Severity:  "info",
				Details:   map[string]any{"version": 42},
			},
			wantErr: false,
		},
		{
			name: "invalid event type",
			event: DeviceEvent{
				DeviceID:  1,
				EventType: "invalid_type",
				Severity:  "info",
			},
			wantErr: true,
		},
		{
			name: "invalid severity",
			event: DeviceEvent{
				DeviceID:  1,
				EventType: "screenshot_detected",
				Severity:  "unknown",
			},
			wantErr: true,
		},
		{
			name: "missing device ID",
			event: DeviceEvent{
				EventType: "policy_applied",
				Severity:  "info",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.event.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSeverityLevels(t *testing.T) {
	if SeverityInfo != "info" {
		t.Errorf("SeverityInfo = %s, want info", SeverityInfo)
	}
	if SeverityWarn != "warn" {
		t.Errorf("SeverityWarn = %s, want warn", SeverityWarn)
	}
	if SeverityCritical != "critical" {
		t.Errorf("SeverityCritical = %s, want critical", SeverityCritical)
	}
}

func TestValidEventTypes(t *testing.T) {
	valid := map[string]bool{
		"screenshot_detected":    true,
		"jailbreak_detected":     true,
		"root_detected":          true,
		"debugger_detected":      true,
		"vpn_detected":           true,
		"emulator_detected":      true,
		"policy_applied":         true,
		"policy_violation":       true,
		"wipe_completed":         true,
		"device_locked":          true,
		"device_unlocked":        true,
		"crypto_profile_changed": true,
		"invalid_made_up_type":   false,
	}
	for eventType, want := range valid {
		got := isValidEventType(eventType)
		if got != want {
			t.Errorf("isValidEventType(%q) = %v, want %v", eventType, got, want)
		}
	}
}

func TestDetectionResponseChain(t *testing.T) {
	chain := DetectionResponseChain{
		ScreenshotDetected: SeverityWarn,
		JailbreakDetected:  SeverityCritical,
		RootDetected:       SeverityCritical,
		DebuggerDetected:   SeverityCritical,
		PolicyViolation:    SeverityWarn,
	}

	if chain.ScreenshotDetected != SeverityWarn {
		t.Errorf("expected screenshot_detected=warn, got %s", chain.ScreenshotDetected)
	}
	if chain.JailbreakDetected != SeverityCritical {
		t.Errorf("expected jailbreak_detected=critical, got %s", chain.JailbreakDetected)
	}
}

func TestDefaultResponseChain(t *testing.T) {
	chain := DefaultResponseChain()

	if chain.ScreenshotDetected != SeverityWarn {
		t.Errorf("expected screenshot_detected=%s, got %s", SeverityWarn, chain.ScreenshotDetected)
	}
	if chain.JailbreakDetected != SeverityCritical {
		t.Errorf("expected jailbreak_detected=%s, got %s", SeverityCritical, chain.JailbreakDetected)
	}
	if chain.RootDetected != SeverityCritical {
		t.Errorf("expected root_detected=%s, got %s", SeverityCritical, chain.RootDetected)
	}
	if chain.DebuggerDetected != SeverityCritical {
		t.Errorf("expected debugger_detected=%s, got %s", SeverityCritical, chain.DebuggerDetected)
	}
	if chain.PolicyViolation != SeverityWarn {
		t.Errorf("expected policy_violation=%s, got %s", SeverityWarn, chain.PolicyViolation)
	}
}

func TestDeviceEvent_OccurredAtDefault(t *testing.T) {
	e := DeviceEvent{
		DeviceID:  1,
		EventType: "policy_applied",
		Severity:  "info",
	}
	// OccurredAt zero value should be handled by LogDeviceEvent
	if !e.OccurredAt.IsZero() {
		t.Error("expected zero OccurredAt for new event")
	}
	// Set and verify
	now := time.Now()
	e.OccurredAt = now
	if e.OccurredAt != now {
		t.Error("OccurredAt not preserved")
	}
}
