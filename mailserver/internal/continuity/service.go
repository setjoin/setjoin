package continuity

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	sharedcontinuity "setjoin.com/shared/continuity"
	"setjoin.com/shared/exchangeartifact"
)

type SignalClass string

const (
	SignalNone                  SignalClass = "none"
	SignalClockAnomaly          SignalClass = "clock_anomaly"
	SignalLocalTimelineMismatch SignalClass = "local_timeline_mismatch"
)

type Service struct {
	Signer    sharedcontinuity.Signer
	Keys      sharedcontinuity.KeySet
	BootEpoch string
	Now       func() time.Time
}

func Load(privateKeyPath, keyID string) (*Service, error) {
	if privateKeyPath == "" || strings.IndexByte(privateKeyPath, 0) >= 0 || !filepath.IsAbs(privateKeyPath) || filepath.Clean(privateKeyPath) != privateKeyPath {
		return nil, errors.New("continuity signing key path must be a clean absolute path")
	}
	// #nosec G304 -- the path is operator configuration, never request data, and is constrained above to a clean absolute path.
	data, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read continuity signing key: %w", err)
	}
	block, rest := pem.Decode(data)
	if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
		return nil, errors.New("continuity signing key must be one PKCS#8 PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid continuity signing key")
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("continuity signing key must be Ed25519")
	}
	signer := sharedcontinuity.Signer{KeyID: keyID, PrivateKey: privateKey}
	if err := signer.Validate(); err != nil {
		return nil, err
	}
	publicKey := append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	return &Service{Signer: signer, Keys: sharedcontinuity.KeySet{Keys: map[string]sharedcontinuity.VerificationKey{
		keyID: {PublicKey: publicKey},
	}}, BootEpoch: uuid.NewString(), Now: time.Now}, nil
}

func (service *Service) Issue(installationID, accountID, generation, watermark string) (string, error) {
	if service == nil {
		return "", errors.New("continuity service unavailable")
	}
	now := service.Now
	if now == nil {
		now = time.Now
	}
	claims := sharedcontinuity.NewTokenClaims(installationID, accountID, generation, watermark,
		service.BootEpoch, now().UTC(), service.Signer.KeyID)
	return sharedcontinuity.SignToken(claims, service.Signer)
}

func (service *Service) SignReceipt(claims sharedcontinuity.ReceiptClaims) (sharedcontinuity.SignedReceipt, error) {
	if service == nil {
		return sharedcontinuity.SignedReceipt{}, errors.New("continuity service unavailable")
	}
	now := service.Now
	if now == nil {
		now = time.Now
	}
	claims.Version = sharedcontinuity.Version
	claims.BootEpoch = service.BootEpoch
	claims.IssuedAt = now().UTC().Truncate(time.Second).Format(time.RFC3339)
	claims.KeyID = service.Signer.KeyID
	return sharedcontinuity.SignReceipt(claims, service.Signer)
}

// SignExchangeReceipt reuses the installation's rotating continuity key while
// retaining a distinct, schema-bound canonical payload. A receipt from either
// protocol cannot be replayed as the other protocol's signature input.
func (service *Service) SignExchangeReceipt(claims exchangeartifact.ReceiptClaims) (exchangeartifact.SignedReceipt, error) {
	if service == nil {
		return exchangeartifact.SignedReceipt{}, errors.New("continuity service unavailable")
	}
	now := service.Now
	if now == nil {
		now = time.Now
	}
	claims.KeyID = service.Signer.KeyID
	claims.IssuedAt = now().UTC().Truncate(time.Second).Format(time.RFC3339)
	return exchangeartifact.SignReceipt(claims, service.Signer.PrivateKey)
}

func ClassifyBoot(now, previousWall time.Time, previousInstallation, installation string,
	previousGeneration, generation int64, restoreDeclaredAt time.Time) SignalClass {
	if !previousWall.IsZero() && (now.Before(previousWall.Add(-5*time.Minute)) || now.After(previousWall.Add(24*time.Hour))) {
		return SignalClockAnomaly
	}
	if previousInstallation != "" && (previousInstallation != installation || previousGeneration != generation) {
		if !restoreDeclaredAt.IsZero() && restoreDeclaredAt.After(previousWall) && previousGeneration < generation {
			return SignalNone
		}
		return SignalLocalTimelineMismatch
	}
	return SignalNone
}
