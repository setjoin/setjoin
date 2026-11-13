package main

import (
	"testing"
)

// excludeListPresentFrom returns true when the CA-0a break-glass exclude list has
// at least one row. The pure shape is testable with a fake counter.
func TestExcludeListPresentLogic(t *testing.T) {
	if excludeListPresentFrom(0) {
		t.Fatal("0 exclude rows -> not present")
	}
	if !excludeListPresentFrom(1) {
		t.Fatal(">=1 exclude rows -> present")
	}
}
