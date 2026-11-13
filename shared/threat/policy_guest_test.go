package threat

import "testing"

func TestScopeMatchesGuests(t *testing.T) {
	t.Parallel()
	if !scopeMatches("guests", "", 42, nil, nil, true) {
		t.Fatal("authoritative guest context must match guests scope")
	}
	if scopeMatches("guests", "", 42, nil, nil, false) {
		t.Fatal("ordinary member must not match guests scope")
	}
	if scopeMatches("guests", "unexpected-target", 42, nil, nil, true) {
		t.Fatal("guest scope with a target must fail closed")
	}
}
