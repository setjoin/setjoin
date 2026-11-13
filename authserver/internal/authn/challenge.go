package authn

import "context"

// ChallengeProvider is the interface for MFA challenge methods.
// Each provider (push notification, biometric prompt, QR cross-device)
// implements this contract so the handler layer can resolve challenges
// without provider-specific branching.
type ChallengeProvider interface {
	// Name returns the provider identifier (e.g., "push", "totp").
	Name() string

	// Available reports whether this challenge method is available for
	// the given user (e.g., push_mfa_enabled, device registered).
	Available(ctx context.Context, userID int64) bool

	// GenerateChallenge creates a new challenge and returns its metadata.
	// sessionID is an opaque value the handler can use to correlate the
	// challenge with a pending authentication session.
	GenerateChallenge(ctx context.Context, userID int64, sessionID string) (*ChallengeResponse, error)

	// VerifyChallenge checks the answer against an active challenge.
	// The userID parameter provides ownership validation.
	VerifyChallenge(ctx context.Context, userID int64, nonce, answer string) error
}

// ChallengeResponse is returned by GenerateChallenge and serialized into
// the MFA-required (202) response body.
//
// SECURITY (C10): there is deliberately NO field carrying the correct
// number-match code. The answer is an OUT-OF-BAND proof — it is delivered only
// to the enrolled device (ECIES native push / webpush) and verified solely on
// the device-authenticated channel (POST /auth/mfa/approve). Returning it to the
// login client let a password-only attacker read the answer and submit it back
// in-band: a full 2FA bypass. Do not re-add a "challenge_number"/answer field.
type ChallengeResponse struct {
	Method     string `json:"mfa_method"`
	Nonce      string `json:"nonce"`
	TTLSeconds int    `json:"ttl_seconds"`
	Fallback   string `json:"fallback,omitempty"` // e.g., "totp"
}
