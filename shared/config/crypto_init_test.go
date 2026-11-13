package config

import (
	"testing"

	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/pwhash"
)

// TestInitCryptoProfile_SyncsGlobal pins the startup-sync contract: calling
// InitCryptoProfile(profile) must push that profile into the pwhash global so
// password hashing uses the configured algorithm. Before this seam existed the
// global was never set at startup, so an smx/hybrid deploy still bcrypt-hashed.
func TestInitCryptoProfile_SyncsGlobal(t *testing.T) {
	t.Cleanup(func() { pwhash.SetCryptoProfile(cryptokey.ProfileStandard) })

	InitCryptoProfile(cryptokey.ProfileSMx)
	if got := pwhash.CryptoProfile(); got != cryptokey.ProfileSMx {
		t.Errorf("after InitCryptoProfile(smx): pwhash.CryptoProfile() = %q, want %q", got, cryptokey.ProfileSMx)
	}

	InitCryptoProfile(cryptokey.ProfileHybrid)
	if got := pwhash.CryptoProfile(); got != cryptokey.ProfileHybrid {
		t.Errorf("after InitCryptoProfile(hybrid): pwhash.CryptoProfile() = %q, want %q", got, cryptokey.ProfileHybrid)
	}
}

// TestInitCryptoProfile_ReloadCallbackUpdatesGlobal pins the reload path: the
// returned callback has the CryptoReloader.OnSwitch signature func(old, new) and,
// when fired, re-syncs the pwhash global to the NEW profile (the value the
// reloader switched to), never the old one.
func TestInitCryptoProfile_ReloadCallbackUpdatesGlobal(t *testing.T) {
	t.Cleanup(func() { pwhash.SetCryptoProfile(cryptokey.ProfileStandard) })

	onSwitch := InitCryptoProfile(cryptokey.ProfileStandard)
	if got := pwhash.CryptoProfile(); got != cryptokey.ProfileStandard {
		t.Fatalf("after InitCryptoProfile(standard): pwhash.CryptoProfile() = %q, want %q", got, cryptokey.ProfileStandard)
	}

	// Simulate a hot-swap standard -> smx (what CryptoReloader.Switch passes).
	onSwitch(cryptokey.ProfileStandard, cryptokey.ProfileSMx)
	if got := pwhash.CryptoProfile(); got != cryptokey.ProfileSMx {
		t.Errorf("after onSwitch(standard, smx): pwhash.CryptoProfile() = %q, want %q (new profile)", got, cryptokey.ProfileSMx)
	}

	// Swap back smx -> standard.
	onSwitch(cryptokey.ProfileSMx, cryptokey.ProfileStandard)
	if got := pwhash.CryptoProfile(); got != cryptokey.ProfileStandard {
		t.Errorf("after onSwitch(smx, standard): pwhash.CryptoProfile() = %q, want %q (new profile)", got, cryptokey.ProfileStandard)
	}
}

// TestInitCryptoProfile_CallbackSignatureMatchesReloader is a compile-time pin:
// the returned callback must satisfy the func(old, new cryptokey.CryptoProfile)
// type that CryptoReloader.OnSwitch accepts. If the signature drifts, this fails
// to compile.
func TestInitCryptoProfile_CallbackSignatureMatchesReloader(t *testing.T) {
	t.Cleanup(func() { pwhash.SetCryptoProfile(cryptokey.ProfileStandard) })

	var cb func(oldProfile, newProfile cryptokey.CryptoProfile) = InitCryptoProfile(cryptokey.ProfileStandard)
	if cb == nil {
		t.Fatal("InitCryptoProfile returned a nil callback")
	}
}
