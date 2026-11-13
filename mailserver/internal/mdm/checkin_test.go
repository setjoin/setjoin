package mdm

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/google/uuid"
)

// ── Engine tests (unit — no DB) ──────────────────────────────────────────

func TestNewEngine(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	engine := NewEngine(nil, logger)
	if engine == nil {
		t.Fatal("NewEngine returned nil")
	}
	if engine.logger != logger {
		t.Error("logger not set")
	}
}

func TestEngine_CheckinResponseStructure(t *testing.T) {
	resp := &CheckinResponse{
		Policy: Policy{
			ID:                    1,
			Name:                  "Default",
			PasscodeMinLength:     6,
			PasscodeComplexity:    "numeric",
			HeartbeatIntervalSecs: 3600,
			GracePeriodMins:       60,
		},
		ComplianceStatus:  StatusCompliant,
		HeartbeatInterval: 3600,
	}
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal CheckinResponse: %v", err)
	}
	var decoded CheckinResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal CheckinResponse: %v", err)
	}
	if decoded.ComplianceStatus != StatusCompliant {
		t.Errorf("expected %s, got %s", StatusCompliant, decoded.ComplianceStatus)
	}
}

func TestDeviceReport_JSONRoundTrip(t *testing.T) {
	deviceID := uuid.New()
	report := DeviceReport{
		DeviceID:          deviceID,
		Platform:          "ios",
		DeviceName:        "iPhone 15",
		OSVersion:         "17.0",
		AppVersion:        "1.0.0",
		PasscodeSet:       true,
		PasscodeCompliant: true,
		EncryptionEnabled: true,
		Jailbroken:        false,
		WipeAck:           false,
	}
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal DeviceReport: %v", err)
	}
	var decoded DeviceReport
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal DeviceReport: %v", err)
	}
	if decoded.DeviceID != deviceID {
		t.Errorf("DeviceID mismatch: %s != %s", decoded.DeviceID, deviceID)
	}
	if decoded.Platform != "ios" {
		t.Errorf("Platform mismatch: %s", decoded.Platform)
	}
}

func TestWipeCommand_JSONRoundTrip(t *testing.T) {
	wc := &WipeCommand{Level: "account"}
	body, err := json.Marshal(wc)
	if err != nil {
		t.Fatalf("marshal WipeCommand: %v", err)
	}
	if string(body) != `{"level":"account"}` {
		t.Errorf("unexpected JSON: %s", body)
	}
	var decoded WipeCommand
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal WipeCommand: %v", err)
	}
	if decoded.Level != "account" {
		t.Errorf("Level mismatch: %s", decoded.Level)
	}
}

// The JWT-only check-in handlers (HandleCheckin, HandleMAMCheckin,
// HandleGetDevicePolicy) and their tests were RETIRED as dead code: no mux
// mounted them — native clients check in via authserver's POST /device/checkin
// behind per-device HMAC. Reintroduction of any JWT-only device mount is
// failed by mailserver/cmd/mailserverd/device_jwt_route_absence_test.go.
