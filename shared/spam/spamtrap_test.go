package spam

import (
	"sync"
	"testing"
)

func TestNewSpamtrapStore(t *testing.T) {
	addresses := []string{"honeypot@example.com", "trap@test.org"}
	s := NewSpamtrapStore(addresses, true)
	if s == nil {
		t.Fatal("expected non-nil store")
	}
	if !s.ShouldAutoTrain() {
		t.Error("expected autoTrain=true")
	}
}

func TestIsSpamtrap_ExactMatch(t *testing.T) {
	s := NewSpamtrapStore([]string{"honeypot@example.com"}, false)
	if !s.IsSpamtrap("honeypot@example.com") {
		t.Error("expected exact match to be detected as spamtrap")
	}
}

func TestIsSpamtrap_CaseInsensitive(t *testing.T) {
	s := NewSpamtrapStore([]string{"HoneyPot@Example.COM"}, false)
	if !s.IsSpamtrap("honeypot@example.com") {
		t.Error("spamtrap check should be case-insensitive")
	}
	if !s.IsSpamtrap("HONEYPOT@EXAMPLE.COM") {
		t.Error("spamtrap check should be case-insensitive (all caps)")
	}
}

func TestIsSpamtrap_WhitespaceTrimmed(t *testing.T) {
	s := NewSpamtrapStore([]string{" trap@test.org "}, false)
	if !s.IsSpamtrap("trap@test.org") {
		t.Error("spamtrap addresses should have whitespace trimmed on add")
	}
	if !s.IsSpamtrap(" trap@test.org ") {
		t.Error("spamtrap check should trim whitespace on lookup")
	}
}

func TestIsSpamtrap_NotFound(t *testing.T) {
	s := NewSpamtrapStore([]string{"honeypot@example.com"}, false)
	if s.IsSpamtrap("legit@example.com") {
		t.Error("legitimate address should not match spamtrap")
	}
	if s.IsSpamtrap("honeypot@other.com") {
		t.Error("different domain should not match spamtrap")
	}
}

func TestIsSpamtrap_EmptyStore(t *testing.T) {
	s := NewSpamtrapStore(nil, false)
	if s.IsSpamtrap("anything@example.com") {
		t.Error("empty store should not match anything")
	}
	s2 := NewSpamtrapStore([]string{}, false)
	if s2.IsSpamtrap("anything@example.com") {
		t.Error("empty store should not match anything")
	}
}

func TestIsSpamtrap_MultipleAddresses(t *testing.T) {
	addresses := []string{
		"honeypot@example.com",
		"trap@test.org",
		"spamcatcher@domain.net",
	}
	s := NewSpamtrapStore(addresses, false)
	for _, addr := range addresses {
		if !s.IsSpamtrap(addr) {
			t.Errorf("expected %q to be detected as spamtrap", addr)
		}
	}
	if s.IsSpamtrap("normal@example.com") {
		t.Error("normal address should not match")
	}
}

func TestSpamtrapStore_ShouldAutoTrain(t *testing.T) {
	sTrue := NewSpamtrapStore(nil, true)
	if !sTrue.ShouldAutoTrain() {
		t.Error("expected ShouldAutoTrain=true")
	}
	sFalse := NewSpamtrapStore(nil, false)
	if sFalse.ShouldAutoTrain() {
		t.Error("expected ShouldAutoTrain=false")
	}
}

func TestSpamtrapStore_Count(t *testing.T) {
	s := NewSpamtrapStore([]string{"a@b.com", "c@d.org", "e@f.net"}, false)
	if s.Count() != 3 {
		t.Errorf("expected count=3, got %d", s.Count())
	}
}

func TestSpamtrapStore_List(t *testing.T) {
	addresses := []string{"a@b.com", "c@d.org"}
	s := NewSpamtrapStore(addresses, false)
	list := s.List()
	if len(list) != 2 {
		t.Errorf("expected 2 addresses, got %d", len(list))
	}
	// List should return normalized addresses
	seen := make(map[string]bool)
	for _, a := range list {
		seen[a] = true
	}
	if !seen["a@b.com"] || !seen["c@d.org"] {
		t.Errorf("list missing expected addresses: %v", list)
	}
}

func TestSpamtrapStore_Concurrent(t *testing.T) {
	s := NewSpamtrapStore([]string{"honeypot@example.com"}, false)
	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if !s.IsSpamtrap("honeypot@example.com") {
					errCh <- nil // should not happen
				}
				if s.IsSpamtrap("legit@example.com") {
					errCh <- nil // should not happen
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)

	if len(errCh) > 0 {
		t.Errorf("concurrent access had %d errors", len(errCh))
	}
}

func TestSpamtrapStore_ZeroFalsePositives(t *testing.T) {
	// High-signal, zero false positives: spamtrap addresses are explicit,
	// deliberately created addresses. A normal address should NEVER match.
	spamtraps := []string{
		"honeypot-2024@example.com",
		"never-sent@internal.net",
	}
	s := NewSpamtrapStore(spamtraps, false)

	normalAddresses := []string{
		"user@example.com",
		"admin@example.com",
		"john.doe@example.com",
		"jane.smith@test.org",
		"support@domain.net",
		"",  // empty should not panic or match
		"@", // weird but should not match
	}

	for _, addr := range normalAddresses {
		if s.IsSpamtrap(addr) {
			t.Errorf("FALSE POSITIVE: %q should never match spamtrap", addr)
		}
	}
}
