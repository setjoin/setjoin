package identity

import "testing"

// TestValidateAndCanonicalizeEmail_Golden pins the provisioning-input contract
// for the ValidatedAddress mint: CanonicalizeAddress + validate.ValidateEmail on
// the canonical form. A valid operator/admin email canonicalizes (trim + ASCII
// fold + display-name strip) and mints a ValidatedAddress; hostile or non-RFC
// input is rejected before any ValidatedAddress exists.
func TestValidateAndCanonicalizeEmail_Golden(t *testing.T) {
	got, err := ValidateAndCanonicalizeEmail("  Alice.Smith@Example.Com  ")
	if err != nil {
		t.Fatalf("valid email rejected: %v", err)
	}
	if got.String() != "alice.smith@example.com" {
		t.Errorf("ValidateAndCanonicalizeEmail = %q, want %q", got.String(), "alice.smith@example.com")
	}

	for _, bad := range []string{
		"attacker@evil.com\nBcc: victim@corp.com",
		"a\r\nFrom: root@corp.com",
		"attacker@evil.com\x00x@corp.com",
		"not-an-email",
		"user@localhost", // bare UPN: rejected on the provision side (no dot in domain)
		"",
		"   ",
	} {
		out, err := ValidateAndCanonicalizeEmail(bad)
		if err == nil {
			t.Errorf("expected rejection for %q, got nil error", bad)
		}
		if out.String() != "" {
			t.Errorf("expected empty result on rejection for %q, got %q", bad, out.String())
		}
	}
}

// TestValidateAndCanonicalizeEmail_IsCanonicalizePrefix is the load-bearing
// invariant: whenever ValidateAndCanonicalizeEmail(x) SUCCEEDS, its underlying
// value is byte-identical to CanonicalizeAddress(x). The validated provision key
// and the match key cannot disagree about a person's canonical address, so the
// duplicate-account-on-normalization bug stays structurally un-writable even
// though provisioning now demands the stronger ValidatedAddress type.
func TestValidateAndCanonicalizeEmail_IsCanonicalizePrefix(t *testing.T) {
	for _, x := range []string{
		"Alice.Smith@Example.Com",
		"  alice@example.com  ",
		`"Alice Smith" <Alice@Example.Com>`,
		"BOB@Example.COM",
		"carol+tag@sub.example.com",
	} {
		v, err := ValidateAndCanonicalizeEmail(x)
		if err != nil {
			t.Fatalf("expected %q to validate: %v", x, err)
		}
		canon := CanonicalizeAddress(x)
		if v.String() != canon.String() {
			t.Errorf("drift for %q: ValidateAndCanonicalizeEmail=%q != CanonicalizeAddress=%q", x, v.String(), canon.String())
		}
	}
}

// TestValidatedAddress_CanonicalRoundTrip pins that a ValidatedAddress projects
// back to its CanonicalAddress (Canonical()) and that the two stringify equally —
// the ValidatedAddress IS a canonical address that additionally passed
// validation, so provisioning code can read either view without drift.
func TestValidatedAddress_CanonicalRoundTrip(t *testing.T) {
	v, err := ValidateAndCanonicalizeEmail("Carol.Jones@Example.Com")
	if err != nil {
		t.Fatalf("valid email rejected: %v", err)
	}
	if v.Canonical().String() != v.String() {
		t.Errorf("Canonical() drift: %q != %q", v.Canonical().String(), v.String())
	}
	if v.Canonical().String() != "carol.jones@example.com" {
		t.Errorf("Canonical() = %q, want %q", v.Canonical().String(), "carol.jones@example.com")
	}
}

// TestAssumeValidated_DirectoryTrustLift pins the validation-free directory lift:
// a CanonicalAddress minted by the directory-sync path (AD/LDAP, whose `mail`
// attribute may legitimately not pass RFC-5321 — a bare UPN like `alice@corp`)
// can be lifted to a ValidatedAddress WITHOUT re-validation, so directory sync
// stays validation-free while still satisfying the provisioning type gate. The
// lifted value is byte-identical to the source CanonicalAddress.
func TestAssumeValidated_DirectoryTrustLift(t *testing.T) {
	for _, raw := range []string{
		"Alice@CORP",                   // bare UPN: would FAIL ValidateAndCanonicalizeEmail, must pass the lift
		"  Bob.Smith@Example.Com  ",    // ordinary address
		"alice/admin@CORP.EXAMPLE.COM", // Kerberos-style principal
	} {
		canon := CanonicalizeAddress(raw)
		v := canon.AssumeValidated()
		if v.String() != canon.String() {
			t.Errorf("AssumeValidated drift for %q: %q != %q", raw, v.String(), canon.String())
		}
	}

	// The bare UPN that the lift accepts is exactly the input the validating
	// mint rejects — proving the lift is the deliberate validation-free escape.
	if _, err := ValidateAndCanonicalizeEmail("alice@corp"); err == nil {
		t.Fatal("expected ValidateAndCanonicalizeEmail to reject the bare UPN (no dot in domain)")
	}
}
