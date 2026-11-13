package smtp

import (
	"context"
	"strings"
	"testing"
)

// newTestDisplayNameDetector creates a detector with a pre-populated user cache
// and a configurable similarity function for unit testing (no DB required).
func newTestDisplayNameDetector(internalDomains []string, threshold float64) *DisplayNameDetector {
	d := &DisplayNameDetector{
		internalDomains: make(map[string]bool),
		userCache:       make(map[string]bool),
		threshold:       threshold,
	}
	for _, domain := range internalDomains {
		d.internalDomains[strings.ToLower(domain)] = true
	}
	return d
}

func TestDisplayNameExactMatchExternal_Reject(t *testing.T) {
	d := newTestDisplayNameDetector([]string{"example.com"}, 0.85)
	d.userCache["jane doe"] = true
	d.userCache["john smith"] = true

	input := &PhishInput{
		FromName: "Jane Doe",
		FromAddr: "jane.doe@evil.com",
	}
	result, err := d.Check(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Verdict != PhishReject {
		t.Errorf("expected PhishReject for exact name match from external domain, got %v", result.Verdict)
	}
	if result.Detector != "display_name" {
		t.Errorf("expected detector name 'display_name', got %q", result.Detector)
	}
}

func TestDisplayNameFuzzyMatch_Warn(t *testing.T) {
	// Use exact matching test helper — fuzzy is tested via pg_trgm in integration
	d := newTestDisplayNameDetector([]string{"example.com"}, 0.85)

	// "Jane Doe" is ~85% similar to "Jane Do" (10/12 chars) via custom similarity
	d.similarityFunc = func(a, b string) float64 {
		// Simple similarity: count matching characters / max length
		if a == b {
			return 1.0
		}
		common := 0
		runesA := []rune(a)
		runesB := []rune(b)
		maxLen := len(runesA)
		if len(runesB) > maxLen {
			maxLen = len(runesB)
		}
		for i := 0; i < len(runesA) && i < len(runesB); i++ {
			if runesA[i] == runesB[i] {
				common++
			}
		}
		return float64(common) / float64(maxLen)
	}
	d.userCache["jane doe"] = true

	input := &PhishInput{
		FromName: "Jane Do",
		FromAddr: "jane.do@evil.com",
	}
	result, err := d.Check(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Verdict != PhishWarn {
		t.Errorf("expected PhishWarn for fuzzy name match, got %v", result.Verdict)
	}
}

func TestDisplayNameInternalDomain_None(t *testing.T) {
	d := newTestDisplayNameDetector([]string{"example.com", "corp.local"}, 0.85)
	d.userCache["jane doe"] = true

	input := &PhishInput{
		FromName: "Jane Doe",
		FromAddr: "jane.doe@corp.local",
	}
	result, err := d.Check(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for internal domain match, got verdict=%v", result.Verdict)
	}
}

func TestDisplayNameNoMatch_None(t *testing.T) {
	d := newTestDisplayNameDetector([]string{"example.com"}, 0.85)
	d.userCache["jane doe"] = true
	d.userCache["john smith"] = true

	input := &PhishInput{
		FromName: "Unrelated Name",
		FromAddr: "attacker@evil.com",
	}
	result, err := d.Check(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for no match, got verdict=%v", result.Verdict)
	}
}

func TestDisplayNameEmpty_None(t *testing.T) {
	d := newTestDisplayNameDetector([]string{"example.com"}, 0.85)
	d.userCache["jane doe"] = true

	input := &PhishInput{
		FromName: "",
		FromAddr: "attacker@evil.com",
	}
	result, err := d.Check(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for empty display name, got verdict=%v", result.Verdict)
	}
}

func TestDisplayNameEmptyCache_None(t *testing.T) {
	d := newTestDisplayNameDetector([]string{"example.com"}, 0.85)
	// intentionally empty cache

	input := &PhishInput{
		FromName: "Jane Doe",
		FromAddr: "attacker@evil.com",
	}
	result, err := d.Check(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for empty cache, got verdict=%v", result.Verdict)
	}
}
