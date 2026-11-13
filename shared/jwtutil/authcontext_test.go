package jwtutil

import (
	"reflect"
	"testing"
)

func TestDeriveAuthContext(t *testing.T) {
	tests := []struct {
		name    string
		methods []string
		wantACR string
		wantAMR []string
	}{
		{
			name:    "no methods → empty (backward compatible)",
			methods: nil,
			wantACR: "",
			wantAMR: nil,
		},
		{
			name:    "password only → aal1 / [pwd]",
			methods: []string{AMRPassword},
			wantACR: ACRAAL1,
			wantAMR: []string{AMRPassword},
		},
		{
			name:    "password + TOTP → aal2 / [mfa otp pwd]",
			methods: []string{AMRPassword, AMROTP},
			wantACR: ACRAAL2,
			wantAMR: []string{AMRMultiFactor, AMROTP, AMRPassword},
		},
		{
			name:    "passkey only → aal1 / [hwk] (single factor)",
			methods: []string{AMRHardwareKey},
			wantACR: ACRAAL1,
			wantAMR: []string{AMRHardwareKey},
		},
		{
			name:    "password + passkey → aal2 / [hwk mfa pwd]",
			methods: []string{AMRPassword, AMRHardwareKey},
			wantACR: ACRAAL2,
			wantAMR: []string{AMRHardwareKey, AMRMultiFactor, AMRPassword},
		},
		{
			name:    "password + push (swk+user) → aal2; user does not double-count",
			methods: []string{AMRPassword, AMRSoftwareKey, AMRUserPresence},
			wantACR: ACRAAL2,
			wantAMR: []string{AMRMultiFactor, AMRPassword, AMRSoftwareKey, AMRUserPresence},
		},
		{
			name:    "push only (swk+user) → aal1: presence is not a second factor",
			methods: []string{AMRSoftwareKey, AMRUserPresence},
			wantACR: ACRAAL1,
			wantAMR: []string{AMRSoftwareKey, AMRUserPresence},
		},
		{
			name:    "duplicate methods collapse, no spurious mfa",
			methods: []string{AMRPassword, AMRPassword},
			wantACR: ACRAAL1,
			wantAMR: []string{AMRPassword},
		},
		{
			name:    "empty strings ignored",
			methods: []string{"", AMRPassword, ""},
			wantACR: ACRAAL1,
			wantAMR: []string{AMRPassword},
		},
		{
			name:    "only empty strings → empty",
			methods: []string{"", ""},
			wantACR: "",
			wantAMR: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acr, amr := DeriveAuthContext(tt.methods...)
			if acr != tt.wantACR {
				t.Errorf("acr = %q, want %q", acr, tt.wantACR)
			}
			if !reflect.DeepEqual(amr, tt.wantAMR) {
				t.Errorf("amr = %v, want %v", amr, tt.wantAMR)
			}
		})
	}
}

func TestDeriveAuthContext_MFAMarkerNeverCountedAsFactor(t *testing.T) {
	// Passing "mfa" explicitly must not, by itself, manufacture a second factor.
	acr, amr := DeriveAuthContext(AMRPassword, AMRMultiFactor)
	if acr != ACRAAL1 {
		t.Errorf("acr = %q, want aal1 (mfa marker is not a factor)", acr)
	}
	for _, m := range amr {
		if m == AMRMultiFactor {
			// mfa present only because the caller passed it; still must be aal1
			// because only one real factor (pwd) was satisfied.
			return
		}
	}
}

func TestACRSatisfies(t *testing.T) {
	tests := []struct {
		name        string
		tokenACR    string
		requiredACR string
		want        bool
	}{
		{"no requirement satisfied by anything", "", "", true},
		{"no requirement satisfied by aal1", ACRAAL1, "", true},
		{"aal1 satisfies aal1", ACRAAL1, ACRAAL1, true},
		{"aal2 satisfies aal1", ACRAAL2, ACRAAL1, true},
		{"aal2 satisfies aal2", ACRAAL2, ACRAAL2, true},
		{"aal1 does NOT satisfy aal2", ACRAAL1, ACRAAL2, false},
		{"empty token does NOT satisfy aal2", "", ACRAAL2, false},
		{"empty token does NOT satisfy aal1", "", ACRAAL1, false},
		{"unknown required matched exactly", "custom", "custom", true},
		{"unknown required not matched", ACRAAL2, "custom", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ACRSatisfies(tt.tokenACR, tt.requiredACR); got != tt.want {
				t.Errorf("ACRSatisfies(%q, %q) = %v, want %v", tt.tokenACR, tt.requiredACR, got, tt.want)
			}
		})
	}
}

func TestAuthContextFromFactors(t *testing.T) {
	ac := AuthContextFromFactors(AMRPassword, AMROTP)
	if ac.ACR != ACRAAL2 {
		t.Errorf("ACR = %q, want aal2", ac.ACR)
	}
	if !contains(ac.AMR, AMRMultiFactor) || !contains(ac.AMR, AMRPassword) || !contains(ac.AMR, AMROTP) {
		t.Errorf("AMR = %v, want pwd+otp+mfa", ac.AMR)
	}

	// Empty input → zero AuthContext (emits nothing).
	empty := AuthContextFromFactors()
	if empty.ACR != "" || empty.AMR != nil {
		t.Errorf("empty factors → %+v, want zero AuthContext", empty)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
