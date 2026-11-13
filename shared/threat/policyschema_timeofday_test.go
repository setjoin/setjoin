package threat

import "testing"

// TestIsValidTimeOfDay pins the strict HH:MM grammar enforced on
// kindTimeRange bounds: exactly five characters, colon separator, digits only,
// and calendar-valid ranges. Non-digit characters in either half must be
// rejected at authoring time (D-SHARED-THREAT-009) rather than parsing as
// match-all.
func TestIsValidTimeOfDay(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"00:00", true},
		{"09:30", true},
		{"23:59", true},
		{"24:00", false}, // hour out of range
		{"00:60", false}, // minute out of range
		{"9:30", false},  // too short
		{"09:300", false},
		{"", false},
		{"0930", false},
		{"09-30", false}, // wrong separator
		{"0a:30", false}, // non-digit hour
		{"09:3a", false}, // non-digit minute
		{"ab:cd", false}, // all non-digit
		{"99:99", false}, // digits but out of range
		{"09:3.", false}, // punctuation minute
	}
	for _, tc := range cases {
		if got := isValidTimeOfDay(tc.in); got != tc.want {
			t.Errorf("isValidTimeOfDay(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
