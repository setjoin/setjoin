package config

import (
	"sync"
	"sync/atomic"

	"setjoin.com/shared/cryptokey"
)

// CryptoReloader manages hot-swapping the active crypto profile at runtime.
// When the admin changes crypto.algorithm_profile in the config file, koanf
// triggers a reload, which calls Switch(). No restart needed.
//
// New data uses the new algorithm. Old data keeps its algorithm tag and
// remains readable forever — no migration.
type CryptoReloader struct {
	profile  atomic.Value // stores cryptokey.CryptoProfile
	mu       sync.RWMutex
	onSwitch []func(oldProfile, newProfile cryptokey.CryptoProfile)
}

// NewCryptoReloader creates a CryptoReloader with the given initial profile.
func NewCryptoReloader(initial cryptokey.CryptoProfile) *CryptoReloader {
	r := &CryptoReloader{}
	r.profile.Store(initial)
	return r
}

// CurrentProfile returns the currently active crypto profile.
func (r *CryptoReloader) CurrentProfile() cryptokey.CryptoProfile {
	return r.profile.Load().(cryptokey.CryptoProfile)
}

// AlgorithmTag returns the symmetric algorithm tag for the current profile.
// Used by SealEnvelope when encrypting new data.
func (r *CryptoReloader) AlgorithmTag() cryptokey.AlgorithmTag {
	return cryptokey.AlgorithmTagFromProfile(r.CurrentProfile())
}

// Switch changes the active crypto profile. Returns true if the profile changed.
// Fires OnSwitch callbacks for re-encryption hooks, key derivation refresh, etc.
func (r *CryptoReloader) Switch(newProfile cryptokey.CryptoProfile) bool {
	old := r.CurrentProfile()
	if old == newProfile {
		return false
	}
	r.profile.Store(newProfile)

	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, cb := range r.onSwitch {
		cb(old, newProfile)
	}
	return true
}

// OnSwitch registers a callback invoked when the crypto profile changes.
// Use for actions like refreshing derived keys, notifying clients, etc.
func (r *CryptoReloader) OnSwitch(cb func(oldProfile, newProfile cryptokey.CryptoProfile)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onSwitch = append(r.onSwitch, cb)
}
