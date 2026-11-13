package main

import "testing"

// TestLastPortColon_HTTPSUrl verifies the offset-into-full-string fix.
// Before the fix: lastPortColon("http://s3.internal:9000") returned 11
// (offset into "s3.internal:9000"), so the caller produced "http://s3.i:9333".
// After the fix: returns the correct colon position in the full string.
func TestLastPortColon_HTTPSUrl(t *testing.T) {
	tests := []struct {
		url  string
		want int
	}{
		{"http://s3.internal:9000", len("http://s3.internal")},
		{"https://s3.example.com:9000", len("https://s3.example.com")},
		{"http://192.168.1.1:9000", len("http://192.168.1.1")},
		{"s3.internal:9000", len("s3.internal")}, // no scheme
		{"http://noporthere", -1},
	}
	for _, tc := range tests {
		got := lastPortColon(tc.url)
		if got != tc.want {
			t.Errorf("lastPortColon(%q) = %d, want %d", tc.url, got, tc.want)
		}
	}
}
