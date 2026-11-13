package kql

// parser_bounds_test.go — med-shard2-020: resource bounds for the recursive
// KQL parser (CWE-674 unbounded recursion / CWE-405 unbounded allocation).
//
// Contract under test:
//   - every cap (MaxQueryLength, MaxNestingDepth, MaxTerms) accepts exactly
//     at-cap input and rejects one-past-the-bound input with a bounded error;
//   - a deep/long/term-heavy hostile query returns a bounded error and never
//     a fatal process abort (pre-fix, unbounded recursion could kill the
//     process for a compliance.write principal);
//   - a stored malicious query is rejected IDENTICALLY on every application
//     (the eDiscovery stored-query re-application path parses per fetch).

import (
	"fmt"
	"strings"
	"testing"
)

// hostileQueries returns one representative query per cap dimension, each
// violating exactly one bound.
func hostileQueries() map[string]string {
	return map[string]string{
		// 4,096 open parens: within the length cap, one past the depth cap.
		"too_deep": strings.Repeat("(", MaxQueryLength),
		// One rune past the length cap.
		"too_long": strings.Repeat("a", MaxQueryLength+1),
		// 129 terms: one past the term cap.
		"too_many_terms": strings.Join(termsSlice(MaxTerms+1), " "),
	}
}

// termsSlice builds n distinct single-token terms ("t1".."tn").
func termsSlice(n int) []string {
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = fmt.Sprintf("t%d", i+1)
	}
	return out
}

func TestParseQueryLengthCapBoundary(t *testing.T) {
	atCap := strings.Repeat("a", MaxQueryLength)
	ast, err := Parse(atCap)
	if err != nil {
		t.Fatalf("query at exactly MaxQueryLength (%d) must parse, got error: %v", MaxQueryLength, err)
	}
	if len(ast.Terms) != 1 {
		t.Fatalf("len(Terms) = %d, want 1", len(ast.Terms))
	}

	onePast := strings.Repeat("a", MaxQueryLength+1)
	_, err = Parse(onePast)
	if err == nil {
		t.Fatal("query one past MaxQueryLength must be rejected")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("maximum length of %d", MaxQueryLength)) {
		t.Errorf("bounded length error = %q, want it to name the %d-character cap", err.Error(), MaxQueryLength)
	}
}

func TestParseNestingDepthCapBoundary(t *testing.T) {
	atCap := strings.Repeat("(", MaxNestingDepth) + "x" + strings.Repeat(")", MaxNestingDepth)
	ast, err := Parse(atCap)
	if err != nil {
		t.Fatalf("query nested exactly MaxNestingDepth (%d) must parse, got error: %v", MaxNestingDepth, err)
	}
	depth := 0
	term := ast.Terms[0]
	for term.Group != nil {
		depth++
		term = term.Group.Terms[0]
	}
	if depth != MaxNestingDepth {
		t.Errorf("AST nesting depth = %d, want %d", depth, MaxNestingDepth)
	}

	onePast := strings.Repeat("(", MaxNestingDepth+1) + "x" + strings.Repeat(")", MaxNestingDepth+1)
	_, err = Parse(onePast)
	if err == nil {
		t.Fatal("query nested one past MaxNestingDepth must be rejected")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("maximum nesting depth of %d", MaxNestingDepth)) {
		t.Errorf("bounded depth error = %q, want it to name the %d-level cap", err.Error(), MaxNestingDepth)
	}
}

func TestParseTermCountCapBoundary(t *testing.T) {
	atCap := strings.Join(termsSlice(MaxTerms), " ")
	ast, err := Parse(atCap)
	if err != nil {
		t.Fatalf("query with exactly MaxTerms (%d) must parse, got error: %v", MaxTerms, err)
	}
	if len(ast.Terms) != MaxTerms {
		t.Fatalf("len(Terms) = %d, want %d", len(ast.Terms), MaxTerms)
	}

	onePast := strings.Join(termsSlice(MaxTerms+1), " ")
	_, err = Parse(onePast)
	if err == nil {
		t.Fatal("query with MaxTerms+1 terms must be rejected")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("maximum of %d terms", MaxTerms)) {
		t.Errorf("bounded term error = %q, want it to name the %d-term cap", err.Error(), MaxTerms)
	}
}

// TestParseDeepNestingBoundedErrorNotAbort proves a hostile deep query is
// rejected as a bounded error: the recursive descent must terminate at the
// depth/length caps instead of overflowing the stack and aborting the
// process. The test completing (rather than crashing) is the assertion.
func TestParseDeepNestingBoundedErrorNotAbort(t *testing.T) {
	// Deep within the length cap: recursion must stop at MaxNestingDepth.
	_, err := Parse(strings.Repeat("(", MaxQueryLength))
	if err == nil {
		t.Fatal("deeply nested query must be rejected")
	}
	if !strings.Contains(err.Error(), "nesting depth") {
		t.Errorf("deep query error = %q, want a nesting-depth bound error", err.Error())
	}

	// Absurdly deep (would be far past any stack budget if unbounded): the
	// length cap rejects it before any recursion happens.
	_, err = Parse(strings.Repeat("(", 1_000_000))
	if err == nil {
		t.Fatal("million-paren query must be rejected")
	}
	if !strings.Contains(err.Error(), "maximum length") {
		t.Errorf("million-paren query error = %q, want the length bound error", err.Error())
	}
}

// TestStoredMaliciousQueryRejectedIdenticallyOnEveryApplication pins the
// stored-query re-application contract: eDiscovery re-parses the stored KQL
// on every fetch, so each application of a stored hostile query must yield
// the identical bounded error — never a crash and never divergent behavior.
func TestStoredMaliciousQueryRejectedIdenticallyOnEveryApplication(t *testing.T) {
	const applications = 5
	for name, query := range hostileQueries() {
		firstErr := ""
		for i := 0; i < applications; i++ {
			_, err := Parse(query)
			if err == nil {
				t.Fatalf("%s: application %d parsed a hostile query successfully", name, i+1)
			}
			if !strings.Contains(err.Error(), "maximum") {
				t.Errorf("%s: application %d error = %q, want a bounded resource-cap error", name, i+1, err.Error())
			}
			if i == 0 {
				firstErr = err.Error()
				continue
			}
			if err.Error() != firstErr {
				t.Fatalf("%s: application %d error = %q, want identical rejection %q", name, i+1, err.Error(), firstErr)
			}
		}
	}
}

// TestValidateMatchesParseBoundedErrors pins that the handler-boundary
// helper returns exactly the same bounded errors Parse enforces internally.
func TestValidateMatchesParseBoundedErrors(t *testing.T) {
	for name, query := range hostileQueries() {
		_, parseErr := Parse(query)
		validateErr := Validate(query)
		if parseErr == nil || validateErr == nil {
			t.Fatalf("%s: Parse err=%v, Validate err=%v — both must reject", name, parseErr, validateErr)
		}
		if parseErr.Error() != validateErr.Error() {
			t.Errorf("%s: Parse error %q != Validate error %q", name, parseErr.Error(), validateErr.Error())
		}
	}
	if err := Validate("hello AND world"); err != nil {
		t.Errorf("Validate rejected a benign query: %v", err)
	}
}
