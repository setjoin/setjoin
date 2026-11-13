package smtp

import (
	"context"
	"strings"
	"testing"
)

func TestNormalizeDomain_HomoglyphMapping(t *testing.T) {
	d := &LookalikeDetector{
		protectedDomains: make(map[string]bool),
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Cyrillic o to Latin o",
			input:    string([]rune{0x0067, 0x043E, 0x043E, 0x0067, 0x006C, 0x0065}) + ".com",
			expected: "google.com",
		},
		{
			name:     "Cyrillic a to Latin a",
			input:    string([]rune{0x006D, 0x0430, 0x0069, 0x006C}) + ".ru",
			expected: "mail.ru",
		},
		{
			name:     "already ASCII",
			input:    "example.com",
			expected: "example.com",
		},
		{
			name:     "Greek nu to Latin v",
			input:    string([]rune{0x0073, 0x0065, 0x0072, 0x03BD, 0x0065, 0x0072}) + ".com",
			expected: "server.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := d.normalizeDomain(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeDomain(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestLookalikeHomoglyphMatch_Reject(t *testing.T) {
	d := NewLookalikeDetector([]string{"google.com", "microsoft.com"})

	input := &PhishInput{
		ReturnPathDomain: string([]rune{0x0067, 0x006F, 0x043E, 0x0067, 0x006C, 0x0065}) + ".com",
		FromAddr:         "attacker@evil.com",
	}

	result, err := d.Check(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result for homoglyph match, got nil")
	}
	if result.Verdict != PhishReject {
		t.Errorf("expected PhishReject for homoglyph domain, got %v", result.Verdict)
	}
	if !strings.Contains(result.Evidence[0], "homoglyph_domain") {
		t.Errorf("expected evidence to contain 'homoglyph_domain', got %v", result.Evidence)
	}
}

func TestLookalikeLevenshtein_Warn(t *testing.T) {
	d := NewLookalikeDetector([]string{"google.com", "paypal.com"})

	input := &PhishInput{
		ReturnPathDomain: "googie.com",
		FromAddr:         "attacker@googie.com",
	}

	result, err := d.Check(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result for Levenshtein match, got nil")
	}
	if result.Verdict != PhishWarn {
		t.Errorf("expected PhishWarn for close Levenshtein domain, got %v", result.Verdict)
	}
	if !strings.Contains(result.Evidence[0], "lookalike_domain") {
		t.Errorf("expected evidence to contain 'lookalike_domain', got %v", result.Evidence)
	}
}

func TestLookalikeExactMatchProtected_None(t *testing.T) {
	d := NewLookalikeDetector([]string{"google.com"})

	input := &PhishInput{
		ReturnPathDomain: "google.com",
		FromAddr:         "legit@google.com",
	}

	result, err := d.Check(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for exact match on protected domain, got verdict=%v", result.Verdict)
	}
}

func TestLookalikeDifferentDomain_None(t *testing.T) {
	d := NewLookalikeDetector([]string{"google.com", "paypal.com"})

	input := &PhishInput{
		ReturnPathDomain: "totally-unrelated-domain.org",
		FromAddr:         "someone@totally-unrelated-domain.org",
	}

	result, err := d.Check(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for unrelated domain, got verdict=%v", result.Verdict)
	}
}

func TestLookalikeEmptyDomain_None(t *testing.T) {
	d := NewLookalikeDetector([]string{"google.com"})

	input := &PhishInput{
		ReturnPathDomain: "",
		FromAddr:         "",
	}

	result, err := d.Check(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for empty domain, got verdict=%v", result.Verdict)
	}
}

func TestLevenshteinThreshold(t *testing.T) {
	tests := []struct {
		name      string
		a, b      string
		threshold int
		want      int
	}{
		// Exact match
		{name: "exact match", a: "google.com", b: "google.com", threshold: 2, want: 0},
		// Single substitution
		{name: "one substitution", a: "googie.com", b: "google.com", threshold: 2, want: 1},
		// Two substitutions – at threshold boundary
		{name: "two substitutions", a: "googie.cxm", b: "google.com", threshold: 2, want: 2},
		// Three substitutions – exceeds threshold, early exit
		{name: "three substitutions", a: "googie.xxm", b: "google.com", threshold: 2, want: 3},
		// Length difference exceeds threshold – quick early exit
		{name: "length diff > threshold", a: "g.cn", b: "google.com", threshold: 2, want: 3},
		// One character shorter (deletion)
		{name: "one deletion", a: "gogle.com", b: "google.com", threshold: 2, want: 1},
		// Two deletions – at boundary
		{name: "two deletions", a: "gogl.com", b: "google.com", threshold: 2, want: 2},
		// Long strings with many differences – early row exit saves work
		{name: "long strings far apart", a: "abcdefghij.com", b: "zyxwvutsrq.org", threshold: 2, want: 3},
		// Empty first string
		{name: "empty a", a: "", b: "ab", threshold: 2, want: 2},
		// Empty second string
		{name: "empty b", a: "ab", b: "", threshold: 2, want: 2},
		// Both empty
		{name: "both empty", a: "", b: "", threshold: 2, want: 0},
		// Threshold=0, same strings
		{name: "threshold 0 same", a: "abc", b: "abc", threshold: 0, want: 0},
		// Threshold=0, different strings
		{name: "threshold 0 diff", a: "abc", b: "abd", threshold: 0, want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := levenshteinDistance(tt.a, tt.b, tt.threshold)
			if got != tt.want {
				t.Errorf("levenshteinDistance(%q, %q, %d) = %d, want %d",
					tt.a, tt.b, tt.threshold, got, tt.want)
			}
		})
	}
}

func TestLookalikeEmptyProtectionList_None(t *testing.T) {
	d := NewLookalikeDetector(nil)

	input := &PhishInput{
		ReturnPathDomain: "google.com",
		FromAddr:         "attacker@evil.com",
	}

	result, err := d.Check(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for empty protection list, got verdict=%v", result.Verdict)
	}
}
