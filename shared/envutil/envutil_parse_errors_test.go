package envutil

import (
	"testing"
	"time"
)

// TestParseIntErrorBranches pins ParseInt's substitution contract: an empty
// value silently takes the default (unset is not an operator error), while a
// set-yet-unparseable value is logged loudly before the default is
// substituted.
func TestParseIntErrorBranches(t *testing.T) {
	if got := ParseInt("", 7); got != 7 {
		t.Fatalf("empty → %d, want default 7", got)
	}
	if got := ParseInt("not-a-number", 7); got != 7 {
		t.Fatalf("invalid → %d, want default 7", got)
	}
	if got := ParseInt("12", 7); got != 12 {
		t.Fatalf("valid → %d, want 12", got)
	}
}

// TestParseDurationErrorBranches pins ParseDuration's mirror contract.
func TestParseDurationErrorBranches(t *testing.T) {
	if got := ParseDuration("", 5); got != 5 {
		t.Fatalf("empty → %v, want default 5", got)
	}
	if got := ParseDuration("soon", 5); got != 5 {
		t.Fatalf("invalid → %v, want default 5", got)
	}
	if got := ParseDuration("3s", 5); got != 3*time.Second {
		t.Fatalf("valid → %v, want 3s", got)
	}
}
