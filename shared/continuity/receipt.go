package continuity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

type BlobDigest struct {
	BlobID string `json:"blobId"`
	SHA256 string `json:"sha256"`
	Size   string `json:"size"`
}

type ReceiptClaims struct {
	Version            int          `json:"v"`
	InstallationID     string       `json:"installationId"`
	AccountID          string       `json:"accountId"`
	OriginalMessageID  string       `json:"originalMessageId"`
	Eligibility        string       `json:"eligibility"`
	RawMIMESHA256      string       `json:"rawMimeSha256"`
	RawMIMESize        string       `json:"rawMimeSize"`
	Blobs              []BlobDigest `json:"blobs"`
	TimelineGeneration string       `json:"timelineGeneration"`
	StateWatermark     string       `json:"stateWatermark"`
	BootEpoch          string       `json:"bootEpoch"`
	IssuedAt           string       `json:"issuedAt"`
	KeyID              string       `json:"keyId"`
}

type SignedReceipt struct {
	Claims    ReceiptClaims `json:"claims"`
	Signature string        `json:"signature"`
}

func SignReceipt(claims ReceiptClaims, signer Signer) (SignedReceipt, error) {
	if err := signer.Validate(); err != nil {
		return SignedReceipt{}, err
	}
	claims.KeyID = signer.KeyID
	canonical, err := canonicalReceipt(claims)
	if err != nil {
		return SignedReceipt{}, err
	}
	return SignedReceipt{Claims: claims, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer.PrivateKey, canonical))}, nil
}

func VerifyReceipt(receipt SignedReceipt, keys KeySet, options VerifyOptions) error {
	canonical, err := canonicalReceipt(receipt.Claims)
	if err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(receipt.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrMalformed
	}
	issuedAt, _ := time.Parse(time.RFC3339, receipt.Claims.IssuedAt)
	now := options.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	skew := options.ClockSkew
	if skew == 0 {
		skew = DefaultClockSkew
	}
	key, err := keys.key(receipt.Claims.KeyID, issuedAt, now, skew)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, canonical, signature) {
		return ErrInvalidSignature
	}
	if options.MaxAge > 0 && issuedAt.Before(now.Add(-options.MaxAge-skew)) {
		return ErrExpired
	}
	if (options.InstallationID != "" && receipt.Claims.InstallationID != options.InstallationID) ||
		(options.AccountID != "" && receipt.Claims.AccountID != options.AccountID) {
		return ErrScope
	}
	return nil
}

func ArtifactIdentity(claims ReceiptClaims) (string, error) {
	if _, err := canonicalReceipt(claims); err != nil {
		return "", err
	}
	payload := fmt.Sprintf("v1\x00%s\x00%s\x00%s\x00%s", claims.InstallationID, claims.AccountID, claims.OriginalMessageID, claims.RawMIMESHA256)
	digest := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(digest[:]), nil
}

func canonicalReceipt(claims ReceiptClaims) ([]byte, error) {
	if claims.Version != Version || uuid.Validate(claims.InstallationID) != nil || uuid.Validate(claims.BootEpoch) != nil ||
		!validDecimal(claims.AccountID) || claims.AccountID == "0" || !validIdentifier(claims.OriginalMessageID, 1, 256) ||
		(claims.Eligibility != "received" && claims.Eligibility != "sent-terminal") ||
		!validDigest(claims.RawMIMESHA256) || !validDecimal(claims.RawMIMESize) || claims.RawMIMESize == "0" ||
		!validDecimal(claims.TimelineGeneration) || claims.TimelineGeneration == "0" || !validDecimal(claims.StateWatermark) ||
		!validIdentifier(claims.KeyID, 1, 64) {
		return nil, ErrMalformed
	}
	issuedAt, err := time.Parse(time.RFC3339, claims.IssuedAt)
	if err != nil || claims.IssuedAt != issuedAt.UTC().Format(time.RFC3339) || len(claims.Blobs) > 4096 {
		return nil, ErrMalformed
	}
	copyClaims := claims
	copyClaims.Blobs = append([]BlobDigest(nil), claims.Blobs...)
	sort.Slice(copyClaims.Blobs, func(i, j int) bool { return copyClaims.Blobs[i].BlobID < copyClaims.Blobs[j].BlobID })
	for i, blob := range copyClaims.Blobs {
		if !validIdentifier(blob.BlobID, 1, 256) || !validDigest(blob.SHA256) || !validDecimal(blob.Size) ||
			(i > 0 && copyClaims.Blobs[i-1].BlobID == blob.BlobID) {
			return nil, ErrMalformed
		}
	}
	return json.Marshal(copyClaims)
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}
