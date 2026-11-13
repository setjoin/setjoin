package jwtutil

import (
	"encoding/json"
	"testing"
)

func TestCnfAndSifOmitemptyRoundTrip(t *testing.T) {
	// Empty claims: cnf and sif must be absent (byte-compat with old tokens).
	b, _ := json.Marshal(Claims{UserID: 1})
	if got := string(b); cnfContains(got, `"cnf"`) || cnfContains(got, `"sif"`) {
		t.Fatalf("empty Cnf/SignInFreq should be omitted, got %s", got)
	}

	sif := int64(28800)
	c := Claims{UserID: 1, Cnf: &ConfirmationClaim{JKT: "abc"}, SignInFreq: &sif}
	b, _ = json.Marshal(c)
	var back Claims
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Cnf == nil || back.Cnf.JKT != "abc" {
		t.Fatalf("cnf.jkt round-trip failed: %+v", back.Cnf)
	}
	if back.SignInFreq == nil || *back.SignInFreq != 28800 {
		t.Fatalf("sif round-trip failed: %v", back.SignInFreq)
	}
}

// ponytail: renamed from contains/indexOf to avoid clash with authcontext_test.go's []string contains.
func cnfContains(s, sub string) bool { return len(s) >= len(sub) && (cnfIndexOf(s, sub) >= 0) }
func cnfIndexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
