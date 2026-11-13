package config

import (
	"testing"

	"setjoin.com/shared/cryptokey"
)

func TestCryptoProfileConfig_Parse(t *testing.T) {
	tests := []struct {
		raw     string
		want    cryptokey.CryptoProfile
		wantErr bool
	}{
		{"standard", cryptokey.ProfileStandard, false},
		{"smx", cryptokey.ProfileSMx, false},
		{"hybrid", cryptokey.ProfileHybrid, false},
		{"invalid", cryptokey.ProfileStandard, false}, // falls back to standard
		{"", cryptokey.ProfileStandard, false},
	}

	for _, tt := range tests {
		got := cryptokey.ParseCryptoProfile(tt.raw)
		if got != tt.want {
			t.Errorf("ParseCryptoProfile(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestCryptoReloader_InitialProfile(t *testing.T) {
	r := NewCryptoReloader(cryptokey.ProfileStandard)
	if r.CurrentProfile() != cryptokey.ProfileStandard {
		t.Errorf("expected standard, got %s", r.CurrentProfile())
	}
}

func TestCryptoReloader_SwitchProfile(t *testing.T) {
	r := NewCryptoReloader(cryptokey.ProfileStandard)

	// Switch to SMx
	r.Switch(cryptokey.ProfileSMx)
	if r.CurrentProfile() != cryptokey.ProfileSMx {
		t.Errorf("expected smx after switch, got %s", r.CurrentProfile())
	}

	// Switch back
	r.Switch(cryptokey.ProfileStandard)
	if r.CurrentProfile() != cryptokey.ProfileStandard {
		t.Errorf("expected standard after switch, got %s", r.CurrentProfile())
	}
}

func TestCryptoReloader_SameProfile(t *testing.T) {
	r := NewCryptoReloader(cryptokey.ProfileStandard)
	changed := r.Switch(cryptokey.ProfileStandard)
	if changed {
		t.Error("expected no change when switching to same profile")
	}
}

func TestCryptoReloader_AlgorithmTag(t *testing.T) {
	r := NewCryptoReloader(cryptokey.ProfileStandard)
	if r.AlgorithmTag() != cryptokey.AlgoAES256GCM {
		t.Errorf("standard profile should use AES-256-GCM")
	}

	r.Switch(cryptokey.ProfileSMx)
	if r.AlgorithmTag() != cryptokey.AlgoSM4GCM {
		t.Errorf("smx profile should use SM4-GCM")
	}
}

func TestCryptoReloader_OnSwitchCallback(t *testing.T) {
	r := NewCryptoReloader(cryptokey.ProfileStandard)

	var oldProfile, newProfile cryptokey.CryptoProfile
	r.OnSwitch(func(old, new cryptokey.CryptoProfile) {
		oldProfile = old
		newProfile = new
	})

	r.Switch(cryptokey.ProfileSMx)

	if oldProfile != cryptokey.ProfileStandard {
		t.Errorf("OnSwitch old = %q, want %q", oldProfile, cryptokey.ProfileStandard)
	}
	if newProfile != cryptokey.ProfileSMx {
		t.Errorf("OnSwitch new = %q, want %q", newProfile, cryptokey.ProfileSMx)
	}
}

func TestCryptoReloader_SwitchReturnsTrue(t *testing.T) {
	r := NewCryptoReloader(cryptokey.ProfileStandard)
	if !r.Switch(cryptokey.ProfileSMx) {
		t.Error("expected true when switching to different profile")
	}
}
