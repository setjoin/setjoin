package device

import "testing"

// TestPolicyVersion pins the content-hash version against the two failure modes of
// the old additive char-sum: (a) a change that LOWERS the char-sum (so the checkin
// `client < server` diff never fired → stale policy), and (b) an anagram collision
// across the key/value boundary (so a change was undetected on the diff AND the 304
// path). The new version must change on ANY edit and distinguish field boundaries.
func TestPolicyVersion(t *testing.T) {
	base := map[string]string{"lock_timeout": "300", "wipe_on_jailbreak": "true"}
	v0 := policyVersion(base, false)

	// (a) value change that shrinks the char-sum ("true" -> "fals") must still
	// yield a different version — the case the old `<` gate silently dropped.
	lower := map[string]string{"lock_timeout": "300", "wipe_on_jailbreak": "fals"}
	if policyVersion(lower, false) == v0 {
		t.Error("a value change must yield a different version (lower-char-sum edit)")
	}
	// removing a key must change the version.
	if policyVersion(map[string]string{"lock_timeout": "300"}, false) == v0 {
		t.Error("removing a key must change the version")
	}
	// toggling the wipe flag must change the version (old code only added +1, which
	// a routine edit could collide with).
	if policyVersion(base, true) == v0 {
		t.Error("toggling wipeRequested must change the version")
	}

	// (b) key/value boundary anagram: the old char-sum hashed these identically.
	if policyVersion(map[string]string{"ab": "c"}, false) == policyVersion(map[string]string{"a": "bc"}, false) {
		t.Error("key/value boundary must affect the version (no anagram collision)")
	}

	// determinism: same input -> same version regardless of map iteration order.
	if policyVersion(map[string]string{"wipe_on_jailbreak": "true", "lock_timeout": "300"}, false) != v0 {
		t.Error("policyVersion must be deterministic across map iteration order")
	}
}
