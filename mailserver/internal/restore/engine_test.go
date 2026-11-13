package restore

import (
	"testing"
)

func TestDetectMode_Setup(t *testing.T) {
	if DetectMode(0, 0) != "setup" {
		t.Error("zero users should be setup mode")
	}
}

func TestDetectMode_Normal(t *testing.T) {
	if DetectMode(1, 0) != "normal" {
		t.Error("users present, no pending restores should be normal mode")
	}
}

func TestDetectMode_RestoreResume(t *testing.T) {
	// User count doesn't matter — pending restore jobs take priority
	if DetectMode(100, 3) != "restore_resume" {
		t.Error("pending restore jobs should trigger restore_resume mode")
	}
}
