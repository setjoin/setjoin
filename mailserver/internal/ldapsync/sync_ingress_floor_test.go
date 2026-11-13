package ldapsync

import "testing"

// LDAPSYNC-006: the AssumeValidated ingress floor must admit ordinary
// addresses and bare UPNs while rejecting control characters and
// non-printable bytes before they can reach a provisioned identity.
func TestPrintableASCIIAddress(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"plain address", "user@example.com", true},
		{"bare UPN", "user@CORP.EXAMPLE", true},
		{"display-style local part", "first.last+tag@sub.example.com", true},
		{"empty", "", false},
		{"CR", "user@example.com\r", false},
		{"LF injection", "user@example.com\nBcc: victim@example.com", false},
		{"NUL", "user\x00@example.com", false},
		{"tab", "user\t@example.com", false},
		{"high byte", "user\xc3\xa9@example.com", false},
		{"DEL", "user\x7f@example.com", false},
	}
	for _, tc := range cases {
		if got := printableASCIIAddress(tc.in); got != tc.want {
			t.Errorf("%s: printableASCIIAddress(%q) = %v, want %v", tc.name, tc.in, got, tc.want)
		}
	}
}
