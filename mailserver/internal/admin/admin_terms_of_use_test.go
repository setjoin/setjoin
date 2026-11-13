package admin

import (
	"net/http/httptest"
	"testing"
)

// touCreateValid is the pure request-shape gate the Create handler applies before
// touching the DB (name + non-empty body required; version >= 1).
func TestToUCreateValid(t *testing.T) {
	if touCreateValid("", "body", 1) {
		t.Fatal("empty name must be rejected")
	}
	if touCreateValid("AUP", "", 1) {
		t.Fatal("empty body must be rejected")
	}
	if touCreateValid("AUP", "body", 0) {
		t.Fatal("version < 1 must be rejected")
	}
	if !touCreateValid("AUP", "body", 1) {
		t.Fatal("valid ToU must pass")
	}
}

// TestParseTouLimit verifies the ?limit= clamping logic (F5): unbounded requests
// are capped at 500; bad/missing params fall back to the 100-row default.
func TestParseTouLimit(t *testing.T) {
	cases := []struct {
		param string
		want  int
	}{
		{"", 100},     // no param → default
		{"50", 50},    // explicit valid
		{"500", 500},  // at max
		{"501", 500},  // over max → clamped
		{"9999", 500}, // way over → clamped
		{"-1", 100},   // negative → default
		{"abc", 100},  // non-numeric → default
	}
	for _, tc := range cases {
		r := httptest.NewRequest("GET", "/admin/terms-of-use?limit="+tc.param, nil)
		if got := parseTouLimit(r); got != tc.want {
			t.Errorf("limit param=%q: got %d, want %d", tc.param, got, tc.want)
		}
	}
}
