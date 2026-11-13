package pkce

import (
	"strings"
	"testing"
)

// rfc7636AppendixBVerifier and rfc7636AppendixBChallenge are the exact test
// vector from RFC 7636 Appendix B; ChallengeS256 must reproduce it byte for
// byte or the implementation is not interoperable with any conforming IdP.
const (
	rfc7636AppendixBVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfc7636AppendixBChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestChallengeS256_RFC7636AppendixBVector(t *testing.T) {
	got, err := ChallengeS256(rfc7636AppendixBVerifier)
	if err != nil {
		t.Fatalf("ChallengeS256(rfc vector) = %v, want nil", err)
	}
	if got != rfc7636AppendixBChallenge {
		t.Fatalf("ChallengeS256(rfc vector) = %q, want %q", got, rfc7636AppendixBChallenge)
	}
}

func TestNewVerifier(t *testing.T) {
	seen := make(map[string]bool, 256)
	for i := 0; i < 256; i++ {
		v, err := NewVerifier()
		if err != nil {
			t.Fatalf("NewVerifier() = %v, want nil", err)
		}
		if len(v) != 43 { // 32 CSPRNG bytes -> 43 unpadded base64url chars
			t.Fatalf("NewVerifier() length = %d, want 43", len(v))
		}
		if err := ValidateVerifier(v); err != nil {
			t.Fatalf("generated verifier rejected by ValidateVerifier: %v", err)
		}
		if seen[v] {
			t.Fatalf("duplicate verifier after %d generations", i+1)
		}
		seen[v] = true
	}
}

func TestValidateVerifier(t *testing.T) {
	cases := []struct {
		name     string
		verifier string
		wantErr  bool
	}{
		{"rfc vector accepted", rfc7636AppendixBVerifier, false},
		{"43 chars accepted", strings.Repeat("a", 43), false},
		{"128 chars accepted", strings.Repeat("a", 128), false},
		{"empty rejected", "", true},
		{"42 chars rejected", strings.Repeat("a", 42), true},
		{"129 chars rejected", strings.Repeat("a", 129), true},
		{"base64 '+' rejected", strings.Repeat("a", 42) + "+", true},
		{"base64 '/' rejected", strings.Repeat("a", 42) + "/", true},
		{"base64 padding '=' rejected", rfc7636AppendixBVerifier[:42] + "=", true},
		{"space rejected", strings.Repeat("a", 42) + " ", true},
		{"unicode rejected", strings.Repeat("a", 42) + "é", true},
		{"all unreserved symbols accepted", strings.Repeat("-._~", 11) + "-", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateVerifier(tc.verifier)
			if tc.wantErr && err == nil {
				t.Fatalf("ValidateVerifier(%q-length %d) = nil, want error", tc.verifier, len(tc.verifier))
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateVerifier(%q) = %v, want nil", tc.verifier, err)
			}
		})
	}
}

func TestChallengeS256_RejectsInvalidVerifier(t *testing.T) {
	for _, v := range []string{"", "short", strings.Repeat("a", 129), strings.Repeat("a", 42) + "+"} {
		if _, err := ChallengeS256(v); err == nil {
			t.Fatalf("ChallengeS256(%q) = nil error, want rejection", v)
		}
	}
}

func TestVerify(t *testing.T) {
	verifier, err := NewVerifier()
	if err != nil {
		t.Fatalf("NewVerifier() = %v", err)
	}
	challenge, err := ChallengeS256(verifier)
	if err != nil {
		t.Fatalf("ChallengeS256() = %v", err)
	}

	if err := Verify(verifier, challenge); err != nil {
		t.Fatalf("Verify(matching pair) = %v, want nil", err)
	}

	other, err := NewVerifier()
	if err != nil {
		t.Fatalf("NewVerifier() = %v", err)
	}
	if err := Verify(other, challenge); err == nil {
		t.Fatal("Verify(different verifier, original challenge) = nil, want mismatch error")
	}

	// A tampered challenge must not verify either.
	if err := Verify(verifier, challenge[:len(challenge)-2]+"xx"); err == nil {
		t.Fatal("Verify(tampered challenge) = nil, want mismatch error")
	}
	if err := Verify(verifier, ""); err == nil {
		t.Fatal("Verify(empty challenge) = nil, want mismatch error")
	}

	// The RFC vector round-trips.
	if err := Verify(rfc7636AppendixBVerifier, rfc7636AppendixBChallenge); err != nil {
		t.Fatalf("Verify(rfc vector) = %v, want nil", err)
	}

	// Malformed verifiers fail closed without deriving.
	if err := Verify("", challenge); err == nil {
		t.Fatal("Verify(empty verifier) = nil, want error")
	}
}
