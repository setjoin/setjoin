package authn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
)

const PushApprovalProtocol = "setjoin.push-approval.v1"

// PushApprovalAssertion is the closed, device-signed approval envelope. All
// identity/session values come from the locked server-side challenge row; the
// request may supply only the time window and signature over these exact bytes.
type PushApprovalAssertion struct {
	Protocol  string `json:"protocol"`
	Nonce     string `json:"nonce"`
	Code      string `json:"code"`
	DeviceID  int64  `json:"device_id"`
	UserID    int64  `json:"user_id"`
	SessionID string `json:"session_id"`
	Decision  string `json:"decision"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
}

// CanonicalPushApproval returns RFC-8785-compatible bytes for this closed
// string/integer-only envelope. encoding/json sorts map keys and these values
// need none of RFC 8785's floating-point normalization.
func CanonicalPushApproval(a PushApprovalAssertion) ([]byte, error) {
	return json.Marshal(map[string]any{
		"code": a.Code, "decision": a.Decision, "device_id": a.DeviceID,
		"expires_at": a.ExpiresAt, "issued_at": a.IssuedAt, "nonce": a.Nonce,
		"protocol": a.Protocol, "session_id": a.SessionID, "user_id": a.UserID,
	})
}

func VerifyPushApproval(publicKey, canonical []byte, signature string) error {
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKey)
	if x == nil || y == nil {
		return errors.New("invalid P-256 device public key")
	}
	raw, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(raw) != 64 {
		return errors.New("invalid approval signature encoding")
	}
	digest := sha256.Sum256(canonical)
	r := new(big.Int).SetBytes(raw[:32])
	s := new(big.Int).SetBytes(raw[32:])
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest[:], r, s) {
		return errors.New("invalid approval signature")
	}
	return nil
}
