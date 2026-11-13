package continuity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	decimalPattern    = regexp.MustCompile(`^(0|[1-9][0-9]{0,18})$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
)

type TokenClaims struct {
	Version            int    `json:"v"`
	InstallationID     string `json:"installationId"`
	AccountID          string `json:"accountId"`
	TimelineGeneration string `json:"timelineGeneration"`
	StateWatermark     string `json:"stateWatermark"`
	IssuedAt           string `json:"issuedAt"`
	BootEpoch          string `json:"bootEpoch"`
	KeyID              string `json:"keyId"`
}

type VerifyOptions struct {
	Now            time.Time
	ClockSkew      time.Duration
	MaxAge         time.Duration
	InstallationID string
	AccountID      string
}

func NewTokenClaims(installationID, accountID, generation, watermark, bootEpoch string, issuedAt time.Time, keyID string) TokenClaims {
	return TokenClaims{Version: Version, InstallationID: installationID, AccountID: accountID,
		TimelineGeneration: generation, StateWatermark: watermark,
		IssuedAt: issuedAt.UTC().Truncate(time.Second).Format(time.RFC3339), BootEpoch: bootEpoch, KeyID: keyID}
}

func SignToken(claims TokenClaims, signer Signer) (string, error) {
	if err := signer.Validate(); err != nil {
		return "", err
	}
	claims.KeyID = signer.KeyID
	if _, err := validateTokenClaims(claims); err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal token: %w", err)
	}
	signature := ed25519.Sign(signer.PrivateKey, payload)
	compact := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature)
	if len(compact) > MaxCompactBytes {
		return "", fmt.Errorf("%w: token too large", ErrMalformed)
	}
	return compact, nil
}

func VerifyToken(compact string, keys KeySet, options VerifyOptions) (TokenClaims, error) {
	var claims TokenClaims
	// Freshness policy is REQUIRED (fail closed). A zero MaxAge previously
	// disabled expiry entirely, so the package could vouch "correctly signed"
	// without "currently applicable" for a caller that forgot the freshness
	// duty. Both production call sites set MaxAge (jmap: 180d, mail recovery:
	// receiptMaximumAge), so the gate only fires on future callers that
	// forget it — exactly the fail-open this closes.
	if options.MaxAge <= 0 {
		return claims, fmt.Errorf("continuity: VerifyOptions.MaxAge must be > 0 (a freshness policy is required; refusing expiry-free verification): %w", ErrMalformed)
	}
	if len(compact) == 0 || len(compact) > MaxCompactBytes || strings.Count(compact, ".") != 1 {
		return claims, ErrMalformed
	}
	parts := strings.SplitN(compact, ".", 2)
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) == 0 || len(payload) > MaxCompactBytes {
		return claims, ErrMalformed
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return claims, ErrMalformed
	}
	if err := strictJSON(payload, &claims); err != nil {
		return claims, err
	}
	issuedAt, err := validateTokenClaims(claims)
	if err != nil {
		return claims, err
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	skew := options.ClockSkew
	if skew == 0 {
		skew = DefaultClockSkew
	}
	key, err := keys.key(claims.KeyID, issuedAt, now, skew)
	if err != nil {
		return claims, err
	}
	if !ed25519.Verify(key, payload, signature) {
		return claims, ErrInvalidSignature
	}
	if options.MaxAge > 0 && issuedAt.Before(now.Add(-options.MaxAge-skew)) {
		return claims, ErrExpired
	}
	if (options.InstallationID != "" && claims.InstallationID != options.InstallationID) ||
		(options.AccountID != "" && claims.AccountID != options.AccountID) {
		return claims, ErrScope
	}
	return claims, nil
}

func validateTokenClaims(claims TokenClaims) (time.Time, error) {
	if claims.Version != Version || uuid.Validate(claims.InstallationID) != nil ||
		uuid.Validate(claims.BootEpoch) != nil || !validDecimal(claims.AccountID) || claims.AccountID == "0" ||
		!validDecimal(claims.TimelineGeneration) || claims.TimelineGeneration == "0" ||
		!validDecimal(claims.StateWatermark) || !validIdentifier(claims.KeyID, 1, 64) {
		return time.Time{}, ErrMalformed
	}
	issuedAt, err := time.Parse(time.RFC3339, claims.IssuedAt)
	if err != nil || claims.IssuedAt != issuedAt.UTC().Format(time.RFC3339) {
		return time.Time{}, ErrMalformed
	}
	return issuedAt, nil
}

func strictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrMalformed
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrMalformed
	}
	return nil
}

func validDecimal(value string) bool {
	if !decimalPattern.MatchString(value) {
		return false
	}
	_, err := strconv.ParseUint(value, 10, 63)
	return err == nil
}

func validIdentifier(value string, min, max int) bool {
	return len(value) >= min && len(value) <= max && identifierPattern.MatchString(value)
}
