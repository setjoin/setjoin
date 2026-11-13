package identity

import (
	"strings"
	"testing"
)

func TestValidateSSOGroupClaimsBounds(t *testing.T) {
	if err := ValidateSSOGroupClaims([]string{"Engineering", ""}); err != nil {
		t.Fatalf("valid claims: %v", err)
	}
	if err := ValidateSSOGroupClaims(make([]string, MaxSSOGroupClaims+1)); err == nil {
		t.Fatal("oversized claim count accepted")
	}
	if err := ValidateSSOGroupClaims([]string{strings.Repeat("x", MaxSSOGroupNameBytes+1)}); err == nil {
		t.Fatal("oversized claim value accepted")
	}
	if err := ValidateSSOGroupClaims([]string{"safe\nunsafe"}); err == nil {
		t.Fatal("control character accepted in claim")
	}
}

func TestValidateSSOGroupMappingsBounds(t *testing.T) {
	if err := ValidateSSOGroupMappings([]string{"Engineering"}); err != nil {
		t.Fatalf("valid mappings: %v", err)
	}
	if err := ValidateSSOGroupMappings(make([]string, MaxSSOGroupMappings+1)); err == nil {
		t.Fatal("oversized mapping count accepted")
	}
	for _, group := range []string{"", " \t ", strings.Repeat("x", MaxSSOGroupNameBytes+1), "bad\x00group"} {
		if err := ValidateSSOGroupMappings([]string{group}); err == nil {
			t.Errorf("invalid mapping group %q accepted", group)
		}
	}
}
