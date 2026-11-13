package ldap

import (
	"strings"
	"testing"
	"time"
)

// Tests for the filter-byte bounds on parseFilter (search.go): one linear
// pre-validation pass must reject over-long and over-deep attacker input
// before any structural parsing, so the O(n·depth) matchParen rescan on
// adversarial bytes is unreachable, while every documented client filter
// shape still parses.

// TestLDAPFilterBounds_RejectsOversizedFilter: a balanced, well-formed filter
// longer than maxLDAPFilterBytes is rejected by the length bound alone.
func TestLDAPFilterBounds_RejectsOversizedFilter(t *testing.T) {
	// (|(cn=a…)(mail=a…)) padded past 8192 bytes with legal assertion bytes.
	long := "(|(cn=" + strings.Repeat("a", maxLDAPFilterBytes) + ")(mail=a))"
	if len(long) <= maxLDAPFilterBytes {
		t.Fatalf("test filter only %d bytes; must exceed the %d-byte bound", len(long), maxLDAPFilterBytes)
	}
	start := time.Now()
	if _, err := parseFilter(long); err == nil {
		t.Fatal("oversized filter accepted; want length-bound rejection")
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("oversized rejection took %v; pre-validation must be linear and fast", d)
	}
}

// TestLDAPFilterBounds_RejectsExcessiveDepth: nesting past maxLDAPFilterDepth
// is rejected even when the filter is small — the bound that caps recursion
// depth and the per-node matchParen rescan.
func TestLDAPFilterBounds_RejectsExcessiveDepth(t *testing.T) {
	// "!(" is 2 bytes per level plus "cn=a" core and closing parens: stays
	// under the length bound while exceeding the depth bound by ~60x.
	const depth = 2000
	deep := strings.Repeat("!( ", depth) + "cn=a" + strings.Repeat(")", depth)
	if len(deep) >= maxLDAPFilterBytes {
		t.Fatalf("test filter %d bytes must stay under the length bound to prove the DEPTH bound fires", len(deep))
	}
	if _, err := parseFilter(deep); err == nil {
		t.Fatal("over-deep filter accepted; want depth-bound rejection")
	}

	// Just under the depth bound: accepted. The string starts with "!" so
	// parseFilter's bare-assertion wrap adds one level; 30 NOT levels plus the
	// innermost assertion plus the wrap reach exactly maxLDAPFilterDepth.
	// (The assertion only checks acceptance: how nested single-child NOT
	// chains decompile to leaves is the parser's existing behavior, covered by
	// filter_test.go — this test owns the depth bound.)
	shallow := strings.Repeat("!(", maxLDAPFilterDepth-2) + "(cn=a)" + strings.Repeat(")", maxLDAPFilterDepth-2)
	if node, err := parseFilter(shallow); err != nil || node == nil {
		t.Fatalf("filter at depth %d rejected or empty (err=%v, node=%v)", maxLDAPFilterDepth, err, node)
	}
}

// TestLDAPFilterBounds_OverLimitRejectedLinearly is the bounded-work property
// test: worst-case adversarial shapes (megabyte filters, extreme nesting) are
// rejected in time that scales with the linear pre-validation pass — work the
// old O(n·depth) structural rescan would have amplified quadratically.
func TestLDAPFilterBounds_OverLimitRejectedLinearly(t *testing.T) {
	cases := []struct {
		name   string
		filter string
	}{
		{"1MiB balanced groups", "(|(" + strings.Repeat("a", 1<<20) + "=b)(" + strings.Repeat("b", 1<<20) + "=c))"},
		{"1MiB unbalanced open", "(" + strings.Repeat("(", 1<<20)},
		{"1MiB unbalanced close", strings.Repeat(")", 1<<20)},
		{"200k nesting depth", strings.Repeat("(", 200_000) + "cn=a" + strings.Repeat(")", 200_000)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			_, err := parseFilter(tc.filter)
			d := time.Since(start)
			if err == nil {
				t.Fatal("adversarial filter accepted; want bound rejection")
			}
			// The rejection is a single linear scan: microseconds. Allow three
			// orders of magnitude of scheduler slack; the old quadratic path
			// (length × depth ≥ 10^11 byte comparisons for these inputs) could
			// not come close to passing, so this bound is load-bearing.
			if d > 100*time.Millisecond {
				t.Errorf("rejection took %v; want linear-time pre-validation", d)
			}
		})
	}
}

// TestLDAPFilterBounds_WorstCaseAcceptedInputParsesFast: the largest input the
// bounds admit (≈8192 bytes at depth 32) parses comfortably — proving the
// remaining structural parse is bounded, not just the rejection path.
func TestLDAPFilterBounds_WorstCaseAcceptedInputParsesFast(t *testing.T) {
	branch := "(cn=" + strings.Repeat("x", 24) + ")"                 // 29 bytes, legal
	inner := "(|" + strings.Repeat(branch, 270) + ")"                // wide OR at depth 31
	big := strings.Repeat("(&", maxLDAPFilterDepth-2) + inner + strings.Repeat(")", maxLDAPFilterDepth-2)
	if len(big) > maxLDAPFilterBytes {
		t.Fatalf("test construction exceeded the bound: %d bytes", len(big))
	}

	start := time.Now()
	node, err := parseFilter(big)
	if err != nil {
		t.Fatalf("worst-case admitted filter rejected: %v", err)
	}
	if node == nil {
		t.Fatal("worst-case admitted filter parsed to a nil tree")
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("worst-case admitted filter took %v to parse; want bounded fast parse", d)
	}
}

// TestLDAPFilterBounds_DocumentedClientFiltersStillParse: the exact shapes
// Outlook and Thunderbird send to the GAL keep parsing (regression half of
// the bounded-parser change).
func TestLDAPFilterBounds_DocumentedClientFiltersStillParse(t *testing.T) {
	cases := []string{
		"(objectClass=*)",
		"(cn=jo*)",
		"(&(objectClass=*)(|(cn=jo*)(mail=jo*)))",
		"(&(displayName=a*)(!(msExchHideFromAddressLists=TRUE)))",
		"(|(mail=user@example.com)(cn=user))",
		"(&(objectCategory=person)(objectClass=contact))",
		"telephoneNumber>=5",
		"cn", // bare assertion, no outer parens
	}
	for _, f := range cases {
		if _, err := parseFilter(f); err != nil {
			t.Errorf("parseFilter(%q): %v — documented client shape must keep parsing", f, err)
		}
	}

	// End-to-end: the parsed tree still converts to scoped SQL.
	sql, args := applyFilter("(&(objectClass=*)(|(cn=jo*)(mail=jo*)))", 1, "people")
	if sql == "" {
		t.Fatal("applyFilter produced no SQL for a documented client filter")
	}
	if len(args) != 2 {
		t.Errorf("applyFilter args = %v, want 2 bound values", args)
	}
}

// TestLDAPFilterBounds_MalformedStillRejected keeps the pre-existing
// malformed-filter contract (TestParseFilterMalformed) green under the new
// pre-validation pass.
func TestLDAPFilterBounds_MalformedStillRejected(t *testing.T) {
	for _, f := range []string{"(&(cn=a)", "(", "(|)", ")(", "()"} {
		if _, err := parseFilter(f); err == nil {
			t.Errorf("parseFilter(%q): expected error, got nil", f)
		}
	}
}
