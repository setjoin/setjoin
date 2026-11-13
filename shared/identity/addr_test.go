package identity

import "testing"

// TestCanonicalizeAddress is the table-driven contract for the matching-side
// canonicalizer: trim → ASCII-fold lower → RFC-5322 display-name strip ONLY.
// It must NEVER reject (no error path) — a value that does not parse as an
// address (a bare UPN, a Kerberos principal) still has to resolve against
// ad_upn / aliases, so canonicalization can't be gated on address validity.
func TestCanonicalizeAddress(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ascii mixed case", "Alice.Smith@Example.Com", "alice.smith@example.com"},
		{"surrounding whitespace", "  alice@example.com  ", "alice@example.com"},
		{"messy mixed case + whitespace", "  Alice.Smith@Example.Com  ", "alice.smith@example.com"},
		{"display name form", `"Alice Smith" <Alice@Example.Com>`, "alice@example.com"},
		{"display name no quotes", `Alice Smith <a@b.com>`, "a@b.com"},
		{"angle-bracket-only", "<a@B.com>", "a@b.com"},
		// Kerberos principal / bare UPN forms MUST pass through unchanged (modulo
		// trim+lower) — they don't parse as addresses, so the display-strip must
		// not fire and they must not be rejected; they resolve against ad_upn.
		{"kerberos principal", "alice@CORP.EXAMPLE.COM", "alice@corp.example.com"},
		{"bare upn no dot", "ALICE@corp", "alice@corp"},
		{"kerberos with instance", "alice/admin@CORP.EXAMPLE.COM", "alice/admin@corp.example.com"},
		// Empty / garbage inputs are canonicalized, never rejected.
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
		{"garbage", "not an address", "not an address"},
		// ASCII fold ONLY (NOT Unicode strings.ToLower). The Turkish dotted-I 'İ'
		// has NO ASCII fold, so it must pass through UNCHANGED while the ASCII tail
		// ('Example.Com') folds. Unicode ToLower would have produced 'istanbul@…'
		// (the Turkish-I hazard). This case is the live proof we did not use it.
		{"ascii-fold leaves non-ascii rune intact", "İstanbul@Example.Com", "İstanbul@example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CanonicalizeAddress(tc.in).String()
			if got != tc.want {
				t.Errorf("CanonicalizeAddress(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestCanonicalizeAddress_Idempotent pins f(f(x)) == f(x) for every input —
// the property the writer-first migration and the matching seam both rely on
// (canonicalizing an already-canonical row / input is a no-op).
func TestCanonicalizeAddress_Idempotent(t *testing.T) {
	for _, in := range []string{
		"Alice.Smith@Example.Com",
		"  alice@example.com  ",
		`"Alice Smith" <Alice@Example.Com>`,
		"alice@CORP.EXAMPLE.COM",
		"ALICE@corp",
		"",
		"   ",
		"not an address",
	} {
		once := CanonicalizeAddress(in).String()
		twice := CanonicalizeAddress(once).String()
		if once != twice {
			t.Errorf("not idempotent: f(%q)=%q, f(f(%q))=%q", in, once, in, twice)
		}
	}
}

// TestNormalizeAndValidate_Golden pins the provisioning-side contract: the
// trim+lower+strip golden (auth_security_test.go:262) plus the exact hostile
// rejections (auth_security_test.go:271-287). NormalizeAndValidate is
// CanonicalizeAddress + validate.ValidateEmail.
func TestNormalizeAndValidate_Golden(t *testing.T) {
	got, err := NormalizeAndValidate("  Alice.Smith@Example.Com  ")
	if err != nil {
		t.Fatalf("valid email rejected: %v", err)
	}
	if got.String() != "alice.smith@example.com" {
		t.Errorf("NormalizeAndValidate = %q, want %q", got.String(), "alice.smith@example.com")
	}

	for _, bad := range []string{
		"attacker@evil.com\nBcc: victim@corp.com",
		"a\r\nFrom: root@corp.com",
		"attacker@evil.com\x00x@corp.com",
		"not-an-email",
		"user@localhost",
		"",
		"   ",
	} {
		out, err := NormalizeAndValidate(bad)
		if err == nil {
			t.Errorf("expected rejection for %q, got nil error", bad)
		}
		if out.String() != "" {
			t.Errorf("expected empty result on rejection for %q, got %q", bad, out.String())
		}
	}
}

// TestNormalizeAndValidate_IsCanonicalizePrefix is the load-bearing invariant:
// whenever NormalizeAndValidate(x) SUCCEEDS, its output is byte-identical to
// CanonicalizeAddress(x). This is what makes the match key (CanonicalizeAddress)
// and the provision key (NormalizeAndValidate) un-droppably equal — the
// duplicate-JIT-on-normalization bug becomes structurally un-writable. If the
// two halves ever drift, this test fails.
func TestNormalizeAndValidate_IsCanonicalizePrefix(t *testing.T) {
	for _, x := range []string{
		"Alice.Smith@Example.Com",
		"  alice@example.com  ",
		`"Alice Smith" <Alice@Example.Com>`,
		"BOB@Example.COM",
		"carol+tag@sub.example.com",
	} {
		norm, err := NormalizeAndValidate(x)
		if err != nil {
			t.Fatalf("expected %q to validate: %v", x, err)
		}
		canon := CanonicalizeAddress(x)
		if norm.String() != canon.String() {
			t.Errorf("drift for %q: NormalizeAndValidate=%q != CanonicalizeAddress=%q", x, norm.String(), canon.String())
		}
	}
}
