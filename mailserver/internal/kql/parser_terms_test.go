package kql

import (
	"strings"
	"testing"
)

// TestParseRejectsQueriesBeyondTermBudget pins the total-term cap: a query
// with more than MaxTerms terms across nesting levels fails closed instead of
// allocating unbounded AST nodes.
func TestParseRejectsQueriesBeyondTermBudget(t *testing.T) {
	query := strings.Repeat("a ", MaxTerms+1)
	if _, err := Parse(strings.TrimSpace(query)); err == nil {
		t.Fatalf("Parse accepted a query with %d terms (max %d)", MaxTerms+1, MaxTerms)
	}

	// Exactly at budget parses fine.
	ok := strings.TrimSpace(strings.Repeat("a ", MaxTerms))
	if _, err := Parse(ok); err != nil {
		t.Fatalf("Parse rejected an at-budget query: %v", err)
	}
}
