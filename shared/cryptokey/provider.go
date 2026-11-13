// Package cryptokey provides cryptographic key derivation and profile selection
// (standard, SMx, hybrid).
package cryptokey

// CryptoProfile selects the active algorithm suite.
type CryptoProfile string

const (
	ProfileStandard CryptoProfile = "standard" // HMAC-SHA256 + bcrypt + AES-256-GCM
	ProfileSMx      CryptoProfile = "smx"      // SM2 + SM3 + SM4-GCM
	ProfileHybrid   CryptoProfile = "hybrid"   // SM3 for new passwords, bcrypt verify; both HS256 + SM2 JWTs
)

// ParseCryptoProfile parses a profile string, returning ProfileStandard for empty/unknown.
func ParseCryptoProfile(s string) CryptoProfile {
	switch CryptoProfile(s) {
	case ProfileSMx, ProfileHybrid:
		return CryptoProfile(s)
	default:
		return ProfileStandard
	}
}
