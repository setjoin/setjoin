package handlers

import (
	"context"
	"testing"

	"setjoin.com/shared/threat"
)

// buildCnf is the small pure helper this task introduces to convert the SPA's
// DPoP JWK into a ConfirmationClaim (kept pure so it is unit-testable without a
// full login round-trip).
func TestBuildCnfFromJWK(t *testing.T) {
	jwk := map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
		"y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
	}
	cnf, err := buildCnf(jwk)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := threat.JKTFromJWK(jwk)
	if cnf == nil || cnf.JKT != want {
		t.Fatalf("buildCnf jkt mismatch: %+v want %s", cnf, want)
	}
	// nil/empty JWK ⇒ no cnf (unbound token).
	if c, _ := buildCnf(nil); c != nil {
		t.Fatalf("nil JWK must yield nil cnf, got %+v", c)
	}
}

// TestPersistentSessionFromPolicyFailClosed verifies the fail-closed fix: when
// a policy IS matched but the DB read fails, the function returns "never"
// (most restrictive), not "always" (most permissive).
func TestPersistentSessionFromPolicyFailClosed(t *testing.T) {
	// createClosedPool (auth_mfa_fixes_test.go) returns a pool that errors on any query.
	pool := createClosedPool(t)
	got := persistentSessionFromPolicy(context.Background(), pool, 42)
	if got != "never" {
		t.Fatalf("DB error with matched policy: want %q (fail-closed), got %q", "never", got)
	}
}

// TestSignInFreqFromPolicyFailClosed verifies the fail-closed fix: when a
// policy IS matched but the DB read fails, the function returns a short SIF
// (not nil) so the session re-auth mandate is never silently disabled.
func TestSignInFreqFromPolicyFailClosed(t *testing.T) {
	pool := createClosedPool(t)
	got := signInFreqSecondsFromPolicy(context.Background(), pool, 42)
	if got == nil {
		t.Fatal("DB error with matched policy: want short SIF, got nil (fail-open)")
	}
	if *got != sifDBErrorFallbackSecs {
		t.Fatalf("SIF fallback: want %d s, got %d s", sifDBErrorFallbackSecs, *got)
	}
}
