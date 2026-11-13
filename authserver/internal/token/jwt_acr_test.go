package token

import (
	"testing"
	"time"

	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/jwtutil"
)

func newACRTestProvider() *JWTProvider {
	return NewJWTProvider(
		"test-secret-32-bytes-long-ok-now!!",
		nil,
		cryptokey.ProfileStandard,
		time.Hour,
		720*time.Hour,
		"test-issuer",
	)
}

func amrContains(amr []string, v string) bool {
	for _, m := range amr {
		if m == v {
			return true
		}
	}
	return false
}

// TestIssueAccessFull_AAL2 proves a password+TOTP session yields acr=aal2 and an
// amr that includes pwd, otp, and the mfa marker, surviving sign→Validate.
func TestIssueAccessFull_AAL2(t *testing.T) {
	p := newACRTestProvider()

	authCtx := jwtutil.AuthContextFromFactors(AMRPassword, AMROTP)
	tok, err := p.IssueAccessFull(42, "u@example.com", false, nil, nil, nil, nil, authCtx)
	if err != nil {
		t.Fatalf("IssueAccessFull: %v", err)
	}

	claims, err := p.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.ACR != jwtutil.ACRAAL2 {
		t.Errorf("ACR = %q, want aal2", claims.ACR)
	}
	for _, want := range []string{AMRPassword, AMROTP, AMRMultiFactor} {
		if !amrContains(claims.AMR, want) {
			t.Errorf("AMR %v missing %q", claims.AMR, want)
		}
	}
}

// TestIssueAccessFull_AAL1 proves a password-only session yields acr=aal1 with
// amr=[pwd] and no mfa marker.
func TestIssueAccessFull_AAL1(t *testing.T) {
	p := newACRTestProvider()

	authCtx := jwtutil.AuthContextFromFactors(AMRPassword)
	tok, err := p.IssueAccessFull(7, "u@example.com", false, nil, nil, nil, nil, authCtx)
	if err != nil {
		t.Fatalf("IssueAccessFull: %v", err)
	}
	claims, err := p.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.ACR != jwtutil.ACRAAL1 {
		t.Errorf("ACR = %q, want aal1", claims.ACR)
	}
	if len(claims.AMR) != 1 || claims.AMR[0] != AMRPassword {
		t.Errorf("AMR = %v, want [pwd]", claims.AMR)
	}
	if amrContains(claims.AMR, AMRMultiFactor) {
		t.Error("single-factor token must not carry the mfa marker")
	}
}

// TestIssueAccess_BackwardCompat proves the legacy IssueAccess emits no acr/amr,
// so pre-existing consumers see byte-for-byte the same token shape.
func TestIssueAccess_NoACRByDefault(t *testing.T) {
	p := newACRTestProvider()
	tok, err := p.IssueAccess(1, "u@example.com", false)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	claims, err := p.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.ACR != "" {
		t.Errorf("ACR = %q, want empty for legacy IssueAccess", claims.ACR)
	}
	if claims.AMR != nil {
		t.Errorf("AMR = %v, want nil for legacy IssueAccess", claims.AMR)
	}
}

// TestIssueMFAPending_RecordsFirstFactor proves the MFA-pending token records the
// password first factor by default, and a custom first factor when requested.
func TestIssueMFAPending_RecordsFirstFactor(t *testing.T) {
	p := newACRTestProvider()

	tok, err := p.IssueMFAPending(9, "u@example.com")
	if err != nil {
		t.Fatalf("IssueMFAPending: %v", err)
	}
	claims, err := p.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Type != TypeMFAPending {
		t.Fatalf("Type = %q, want mfa_pending", claims.Type)
	}
	if len(claims.AMR) != 1 || claims.AMR[0] != AMRPassword {
		t.Errorf("AMR = %v, want [pwd]", claims.AMR)
	}

	// Passkey-first MFA-pending.
	tok2, err := p.IssueMFAPendingWithAMR(9, "u@example.com", AMRHardwareKey)
	if err != nil {
		t.Fatalf("IssueMFAPendingWithAMR: %v", err)
	}
	claims2, err := p.Validate(tok2)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(claims2.AMR) != 1 || claims2.AMR[0] != AMRHardwareKey {
		t.Errorf("AMR = %v, want [hwk]", claims2.AMR)
	}

	fence := &jwtutil.IdentityFenceClaim{
		SourceID:         101,
		SourceGeneration: 7,
		LinkID:           202,
		LinkGeneration:   9,
	}
	tok3, err := p.IssueMFAPendingWithIdentityFence(
		9, "u@example.com", fence, AMRPassword,
	)
	if err != nil {
		t.Fatalf("IssueMFAPendingWithIdentityFence: %v", err)
	}
	claims3, err := p.Validate(tok3)
	if err != nil {
		t.Fatalf("Validate identity-fenced MFA token: %v", err)
	}
	if claims3.IdentityFence == nil || *claims3.IdentityFence != *fence {
		t.Fatalf("IdentityFence = %+v, want %+v", claims3.IdentityFence, fence)
	}
}
