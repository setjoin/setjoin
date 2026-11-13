package imap

import "testing"

// postAuthGate is the helper extracted in step 3: given the post-auth result it
// reports whether the connection should be denied. Pure, table-testable.
func TestPostAuthGateDenies(t *testing.T) {
	cases := []struct {
		name   string
		reject bool
		want   bool // true = deny (drop auth)
	}{
		{"blocked", true, true},
		{"allowed", false, false},
	}
	for _, c := range cases {
		if got := postAuthDenied(c.reject); got != c.want {
			t.Fatalf("%s: postAuthDenied(%v)=%v want %v", c.name, c.reject, got, c.want)
		}
	}
}
