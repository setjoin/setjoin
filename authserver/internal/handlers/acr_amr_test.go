package handlers

import (
	"testing"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/jwtutil"
)

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestFactorsFromMFAPending_PasswordPlusOTP proves that a password-first
// MFA-pending token, completed with OTP, yields the pwd+otp factor set that
// derives acr=aal2.
func TestFactorsFromMFAPending_PasswordPlusOTP(t *testing.T) {
	mfaClaims := &token.Claims{AMR: []string{token.AMRPassword}}
	factors := factorsFromMFAPending(mfaClaims, token.AMROTP)

	if !contains(factors, token.AMRPassword) || !contains(factors, token.AMROTP) {
		t.Fatalf("factors = %v, want pwd+otp", factors)
	}
	acr, amr := jwtutil.DeriveAuthContext(factors...)
	if acr != jwtutil.ACRAAL2 {
		t.Errorf("acr = %q, want aal2", acr)
	}
	if !contains(amr, jwtutil.AMRMultiFactor) {
		t.Errorf("amr = %v, want mfa marker", amr)
	}
}

// TestFactorsFromMFAPending_PasskeyFirst proves a passkey-first MFA-pending
// token (hwk) completed with OTP yields hwk+otp → aal2.
func TestFactorsFromMFAPending_PasskeyFirst(t *testing.T) {
	mfaClaims := &token.Claims{AMR: []string{token.AMRHardwareKey}}
	factors := factorsFromMFAPending(mfaClaims, token.AMROTP)

	acr, amr := jwtutil.DeriveAuthContext(factors...)
	if acr != jwtutil.ACRAAL2 {
		t.Errorf("acr = %q, want aal2", acr)
	}
	if !contains(amr, jwtutil.AMRHardwareKey) || !contains(amr, jwtutil.AMROTP) {
		t.Errorf("amr = %v, want hwk+otp", amr)
	}
}

// TestFactorsFromMFAPending_LegacyTokenAssumesPassword proves a legacy
// MFA-pending token with no AMR still produces a genuine MFA (aal2) result: the
// missing first factor is assumed to be the password.
func TestFactorsFromMFAPending_LegacyTokenAssumesPassword(t *testing.T) {
	mfaClaims := &token.Claims{} // no AMR (pre-acr/amr token)
	factors := factorsFromMFAPending(mfaClaims, token.AMROTP)

	if !contains(factors, token.AMRPassword) {
		t.Errorf("factors = %v, want assumed pwd", factors)
	}
	acr, _ := jwtutil.DeriveAuthContext(factors...)
	if acr != jwtutil.ACRAAL2 {
		t.Errorf("acr = %q, want aal2", acr)
	}
}

// TestFactorsFromMFAPending_PushTwoTags proves push verify contributes both swk
// and user without manufacturing a spurious extra factor (still aal2 over the
// password + the single push factor).
func TestFactorsFromMFAPending_PushTwoTags(t *testing.T) {
	mfaClaims := &token.Claims{AMR: []string{token.AMRPassword}}
	factors := factorsFromMFAPending(mfaClaims, token.AMRSoftwareKey, token.AMRUserPresence)

	acr, amr := jwtutil.DeriveAuthContext(factors...)
	if acr != jwtutil.ACRAAL2 {
		t.Errorf("acr = %q, want aal2", acr)
	}
	if !contains(amr, token.AMRSoftwareKey) || !contains(amr, token.AMRUserPresence) {
		t.Errorf("amr = %v, want swk+user", amr)
	}
}
