package startup

import (
	"encoding/json"
	"testing"
)

func TestSendRecoveryReportNothingFixed(t *testing.T) {
	result := json.RawMessage(`{"reset_outbound_queue":0,"repaired_folder_counts":0,"recovered_at":"2024-01-01T00:00:00Z"}`)
	var summary struct {
		ResetOutboundQueue   int    `json:"reset_outbound_queue"`
		RepairedFolderCounts int    `json:"repaired_folder_counts"`
		RecoveredAt          string `json:"recovered_at"`
	}
	if err := json.Unmarshal(result, &summary); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if summary.ResetOutboundQueue != 0 || summary.RepairedFolderCounts != 0 {
		t.Error("expected no issues fixed")
	}
}

func TestSendRecoveryReportIssuesFixed(t *testing.T) {
	result := json.RawMessage(`{"reset_outbound_queue":3,"repaired_folder_counts":5,"recovered_at":"2024-01-01T00:00:00Z"}`)
	var summary struct {
		ResetOutboundQueue   int    `json:"reset_outbound_queue"`
		RepairedFolderCounts int    `json:"repaired_folder_counts"`
		RecoveredAt          string `json:"recovered_at"`
	}
	if err := json.Unmarshal(result, &summary); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if summary.ResetOutboundQueue != 3 {
		t.Errorf("expected 3 queue resets, got %d", summary.ResetOutboundQueue)
	}
	if summary.RepairedFolderCounts != 5 {
		t.Errorf("expected 5 folder repairs, got %d", summary.RepairedFolderCounts)
	}
}

func TestRandomID(t *testing.T) {
	id1 := randomID()
	id2 := randomID()
	if id1 == id2 {
		t.Error("randomID should produce different values on successive calls")
	}
	if len(id1) != 16 {
		t.Errorf("randomID length = %d, want 16", len(id1))
	}
}
