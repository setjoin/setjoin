package config

import (
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/pwhash"
)

// InitCryptoProfile is the one place a service syncs the configured crypto
// profile into the process-global password-hashing selector, and the seam that
// keeps that global correct across a hot-swap.
//
// It does two things:
//
//  1. Pushes profile into pwhash via SetCryptoProfile, so password hashing uses
//     the configured algorithm (bcrypt for standard, PBKDF2-SM3 for smx/hybrid).
//     This MUST be called once at startup after config load — without it the
//     pwhash global stays at its ProfileStandard default and an smx/hybrid deploy
//     would silently bcrypt-hash new passwords.
//
//  2. Returns a callback with the CryptoReloader.OnSwitch signature
//     (func(old, new cryptokey.CryptoProfile)). Register it with the reloader so
//     a runtime profile switch re-syncs the pwhash global to the NEW profile.
//
// Both servers call this once at startup; the mailserver also registers the
// returned callback with cfg.CryptoReloader.OnSwitch so a SIGHUP/HTTP reload that
// flips crypto.algorithm_profile keeps password hashing in lock-step.
func InitCryptoProfile(profile cryptokey.CryptoProfile) func(oldProfile, newProfile cryptokey.CryptoProfile) {
	pwhash.SetCryptoProfile(profile)
	return func(_ /* oldProfile */, newProfile cryptokey.CryptoProfile) {
		pwhash.SetCryptoProfile(newProfile)
	}
}
