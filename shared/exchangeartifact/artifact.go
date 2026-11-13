// Package exchangeartifact defines the portable, crypto-profile-aware wire
// contract for Exchange assessment artifacts and Setjoin-signed receipts. It
// contains no authorization, database, or support-claim decisions.
package exchangeartifact

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sync/atomic"
	"time"

	"setjoin.com/shared/cryptokey"
)

const (
	EnvelopeSchema = "setjoin.exchange.artifact-envelope/v1"
	ReceiptSchema  = "setjoin.exchange.receipt/v1"

	// DefaultMaxEnvelope is the shipped artifact envelope ceiling: 1 GiB. It
	// stays the effective limit unless an operator configures an override
	// through the exchangeartifact.max_envelope config key (env
	// EXCHANGEARTIFACT_MAX_ENVELOPE) applied via SetMaxEnvelope.
	DefaultMaxEnvelope = 1 << 30

	// MinMaxEnvelope is the floor for operator-configured ceilings. Artifacts
	// are large assessment bundles; a smaller bound would only produce
	// confusing client-side rejections, so it is refused rather than applied.
	MinMaxEnvelope = 1 << 20

	// MaxSettableEnvelope is the upper ceiling guard: the largest value
	// SetMaxEnvelope accepts. The FULL downstream arithmetic a limit feeds —
	// the raw bound, the +128-byte AEAD headroom, and the RawStd base64
	// expansion decodeBounded applies, EncodedLen(n) = (n*8+5)/6 — must stay
	// inside non-negative int range. Anything larger overflows that
	// expansion negative, which makes every ciphertext bound check reject
	// legitimate artifacts. Derived: n = limit+128 must satisfy n <=
	// (MaxInt-5)/8, so limit <= (MaxInt-5)/8 - 128.
	MaxSettableEnvelope = (math.MaxInt-5)/8 - 128
)

// maxEnvelopeLimit holds the effective envelope ceiling. It is atomic so the
// Seal/Open/DecodeStrict paths read it without locks and a config reload can
// publish a new ceiling safely; process start initializes it to the shipped
// 1 GiB default.
var maxEnvelopeLimit atomic.Int64

func init() { maxEnvelopeLimit.Store(DefaultMaxEnvelope) }

// MaxEnvelope returns the effective maximum artifact envelope size in bytes:
// DefaultMaxEnvelope (1 GiB) unless SetMaxEnvelope configured an override.
func MaxEnvelope() int { return int(maxEnvelopeLimit.Load()) }

// SetMaxEnvelope configures the artifact envelope ceiling in bytes. The value
// must be positive, at least MinMaxEnvelope, and small enough that the FULL
// downstream bound arithmetic — the raw limit, the +128 ciphertext headroom,
// and the RawStd base64 expansion decodeBounded applies to that expanded
// bound — stays within non-negative int range (MaxSettableEnvelope). An unset
// config resolves to DefaultMaxEnvelope in the caller — zero is a rejected
// value here, keeping "unset" and "invalid" distinct. Rejected values never
// disturb the currently effective limit.
func SetMaxEnvelope(maxBytes int64) error {
	if maxBytes <= 0 {
		return fmt.Errorf("exchangeartifact: max envelope must be positive, got %d", maxBytes)
	}
	if maxBytes < MinMaxEnvelope {
		return fmt.Errorf("exchangeartifact: max envelope %d is below the %d byte minimum", maxBytes, MinMaxEnvelope)
	}
	if maxBytes > MaxSettableEnvelope {
		return fmt.Errorf("exchangeartifact: max envelope %d exceeds the platform-safe maximum %d", maxBytes, int64(MaxSettableEnvelope))
	}
	maxEnvelopeLimit.Store(maxBytes)
	return nil
}

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Binding struct {
	InstallationID string `json:"installationId"`
	TenantID       int64  `json:"tenantId"`
	ProjectID      int64  `json:"projectId"`
	Kind           string `json:"kind"`
	PlainSHA256    string `json:"plainSha256"`
}

type Envelope struct {
	SchemaVersion string  `json:"schemaVersion"`
	Profile       string  `json:"profile"`
	Binding       Binding `json:"binding"`
	WrappedDEK    string  `json:"wrappedDek"`
	Ciphertext    string  `json:"ciphertext"`
}

type ReceiptClaims struct {
	SchemaVersion  string `json:"schemaVersion"`
	ReceiptID      string `json:"receiptId"`
	Kind           string `json:"kind"`
	SubjectSHA256  string `json:"subjectSha256"`
	InstallationID string `json:"installationId"`
	TenantID       int64  `json:"tenantId"`
	ProjectID      int64  `json:"projectId"`
	KeyID          string `json:"keyId"`
	IssuedAt       string `json:"issuedAt"`
	Disposition    string `json:"disposition"`
}

type SignedReceipt struct {
	Claims    ReceiptClaims `json:"claims"`
	Algorithm string        `json:"algorithm"`
	Signature string        `json:"signature"`
}

type Metadata struct {
	CiphertextSize int64
	Nonce          []byte
	WrappedDEK     []byte
	AADSHA256      string
}

func (envelope Envelope) Metadata() (Metadata, error) {
	wrapped, err := decodeBounded(envelope.WrappedDEK, 8192)
	if err != nil {
		return Metadata{}, errors.New("invalid wrapped artifact key")
	}
	ciphertext, err := decodeBounded(envelope.Ciphertext, ciphertextBound())
	if err != nil || len(ciphertext) < 13 {
		return Metadata{}, errors.New("invalid artifact ciphertext")
	}
	nonceLen := int(ciphertext[11])<<8 | int(ciphertext[12])
	if nonceLen < 1 || 13+nonceLen > len(ciphertext) {
		return Metadata{}, errors.New("invalid artifact nonce")
	}
	aad, _ := json.Marshal(envelope.Binding)
	digest := sha256.Sum256(aad)
	return Metadata{CiphertextSize: int64(len(ciphertext)), Nonce: append([]byte(nil), ciphertext[13:13+nonceLen]...), WrappedDEK: wrapped, AADSHA256: hex.EncodeToString(digest[:])}, nil
}

func Seal(plain, masterKey []byte, profile cryptokey.CryptoProfile, binding Binding) (Envelope, error) {
	if err := validateBinding(binding); err != nil {
		return Envelope{}, err
	}
	digest := sha256.Sum256(plain)
	if binding.PlainSHA256 != hex.EncodeToString(digest[:]) {
		return Envelope{}, errors.New("artifact binding digest mismatch")
	}
	dekLen := 32
	if profile == cryptokey.ProfileSMx {
		dekLen = 16
	}
	dek := make([]byte, dekLen)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return Envelope{}, fmt.Errorf("generate artifact key: %w", err)
	}
	aad, _ := json.Marshal(binding)
	ciphertext, err := cryptokey.SealEnvelope(cryptokey.AlgorithmTagFromProfile(profile), dek, plain, aad)
	if err != nil {
		return Envelope{}, err
	}
	wrapperKey := cryptokey.DeriveEncryptionKey(masterKey, "exchange-assessment-artifact-dek/v1", profile)
	wrapped, err := cryptokey.EncryptColumnWithAAD(dek, wrapperKey, profile, aad)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{SchemaVersion: EnvelopeSchema, Profile: string(profile), Binding: binding, WrappedDEK: base64.RawStdEncoding.EncodeToString(wrapped), Ciphertext: base64.RawStdEncoding.EncodeToString(ciphertext)}, nil
}

func Open(envelope Envelope, masterKey []byte, expected Binding) ([]byte, error) {
	if envelope.SchemaVersion != EnvelopeSchema || envelope.Binding != expected {
		return nil, errors.New("artifact envelope binding mismatch")
	}
	if err := validateBinding(envelope.Binding); err != nil {
		return nil, err
	}
	profile, err := exactProfile(envelope.Profile)
	if err != nil {
		return nil, err
	}
	wrapped, err := decodeBounded(envelope.WrappedDEK, 8192)
	if err != nil {
		return nil, errors.New("invalid wrapped artifact key")
	}
	ciphertext, err := decodeBounded(envelope.Ciphertext, ciphertextBound())
	if err != nil {
		return nil, errors.New("invalid artifact ciphertext")
	}
	aad, _ := json.Marshal(envelope.Binding)
	wrapperKey := cryptokey.DeriveEncryptionKey(masterKey, "exchange-assessment-artifact-dek/v1", profile)
	dek, err := cryptokey.DecryptColumnWithAAD(wrapped, wrapperKey, aad)
	if err != nil {
		return nil, errors.New("artifact key unwrap failed")
	}
	plain, _, err := cryptokey.OpenEnvelope(ciphertext, dek, aad)
	if err != nil {
		return nil, errors.New("artifact decrypt failed")
	}
	digest := sha256.Sum256(plain)
	if envelope.Binding.PlainSHA256 != hex.EncodeToString(digest[:]) {
		return nil, errors.New("artifact plaintext digest mismatch")
	}
	return plain, nil
}

func DecodeStrict(raw []byte) (Envelope, error) {
	if len(raw) == 0 || len(raw) > MaxEnvelope() {
		return Envelope{}, errors.New("artifact envelope size is invalid")
	}
	var value Envelope
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&value); err != nil {
		return value, errors.New("invalid artifact envelope JSON")
	}
	if err := d.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return value, errors.New("multiple artifact envelope values")
	}
	return value, nil
}

func SignReceipt(claims ReceiptClaims, private ed25519.PrivateKey) (SignedReceipt, error) {
	if len(private) != ed25519.PrivateKeySize {
		return SignedReceipt{}, errors.New("invalid receipt signing key")
	}
	claims.SchemaVersion = ReceiptSchema
	claims.ReceiptID = ""
	canonical, err := receiptBytes(claims)
	if err != nil {
		return SignedReceipt{}, err
	}
	id := sha256.Sum256(canonical)
	claims.ReceiptID = hex.EncodeToString(id[:])
	// The first receiptBytes call validated every field; adding ReceiptID
	// cannot invalidate them, but the error is handled rather than discarded.
	canonical, err = receiptBytes(claims)
	if err != nil {
		return SignedReceipt{}, fmt.Errorf("receipt canonicalization: %w", err)
	}
	return SignedReceipt{Claims: claims, Algorithm: "ed25519", Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, canonical))}, nil
}

// VerifyReceipt verifies a signed receipt against the trusted key set. It
// enforces schema, digest shape, future-dating (IssuedAt may not be in the
// future beyond a minute of clock slack), canonical receipt-ID binding, and
// the Ed25519 signature. It deliberately does NOT enforce a LIFETIME policy:
// point-in-time evidence legitimately never expires as evidence, and the
// current CLI consumer reports rather than decides. A consumer that DECIDES
// on a receipt (admits, credits, or gates on it) must enforce freshness with
// VerifyReceiptWithMaxAge.
func VerifyReceipt(receipt SignedReceipt, keys map[string]ed25519.PublicKey, now time.Time) error {
	if receipt.Algorithm != "ed25519" || receipt.Claims.SchemaVersion != ReceiptSchema {
		return errors.New("unsupported receipt")
	}
	if !digestPattern.MatchString(receipt.Claims.ReceiptID) || !digestPattern.MatchString(receipt.Claims.SubjectSHA256) {
		return errors.New("invalid receipt digest")
	}
	issued, err := time.Parse(time.RFC3339, receipt.Claims.IssuedAt)
	if err != nil || issued.After(now.Add(time.Minute)) {
		return errors.New("invalid receipt time")
	}
	copyClaims := receipt.Claims
	copyClaims.ReceiptID = ""
	// Canonicalization failure is fail-closed: the receipt-ID digest gate
	// only means something over validated, non-empty canonical bytes.
	canonicalID, err := receiptBytes(copyClaims)
	if err != nil {
		return fmt.Errorf("receipt claims invalid: %w", err)
	}
	id := sha256.Sum256(canonicalID)
	if receipt.Claims.ReceiptID != hex.EncodeToString(id[:]) {
		return errors.New("receipt ID mismatch")
	}
	canonical, err := receiptBytes(receipt.Claims)
	if err != nil {
		return fmt.Errorf("receipt claims invalid: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(receipt.Signature)
	if err != nil {
		return errors.New("invalid receipt signature")
	}
	key := keys[receipt.Claims.KeyID]
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, canonical, sig) {
		return errors.New("invalid receipt signature")
	}
	return nil
}

// VerifyReceiptWithMaxAge verifies a signed receipt AND enforces a lifetime
// policy on top of VerifyReceipt: a receipt whose IssuedAt is older than
// maxAge (or more than maxAge in the future, beyond VerifyReceipt's minute of
// clock slack) is rejected as expired. This is the entry point for consumers
// that DECIDE on a receipt; maxAge <= 0 disables the bound (plain
// VerifyReceipt semantics) and remains the caller's explicit opt-out.
func VerifyReceiptWithMaxAge(receipt SignedReceipt, keys map[string]ed25519.PublicKey, now time.Time, maxAge time.Duration) error {
	if err := VerifyReceipt(receipt, keys, now); err != nil {
		return err
	}
	if maxAge <= 0 {
		return nil
	}
	// VerifyReceipt already validated the IssuedAt parse and future-dating.
	issued, _ := time.Parse(time.RFC3339, receipt.Claims.IssuedAt)
	if now.Sub(issued) > maxAge {
		return errors.New("receipt expired")
	}
	return nil
}

func receiptBytes(claims ReceiptClaims) ([]byte, error) {
	if claims.Kind == "" || claims.InstallationID == "" || claims.TenantID < 1 || claims.ProjectID < 1 || claims.KeyID == "" || claims.Disposition == "" || !digestPattern.MatchString(claims.SubjectSHA256) {
		return nil, errors.New("invalid receipt claims")
	}
	return json.Marshal(claims)
}

func validateBinding(binding Binding) error {
	if binding.InstallationID == "" || binding.TenantID < 1 || binding.ProjectID < 1 || binding.Kind == "" || !digestPattern.MatchString(binding.PlainSHA256) {
		return errors.New("invalid artifact binding")
	}
	return nil
}
func exactProfile(raw string) (cryptokey.CryptoProfile, error) {
	p := cryptokey.CryptoProfile(raw)
	if p != cryptokey.ProfileStandard && p != cryptokey.ProfileSMx && p != cryptokey.ProfileHybrid {
		return "", errors.New("unknown artifact crypto profile")
	}
	return p, nil
}

// ciphertextBound is the largest raw ciphertext the effective envelope
// ceiling can carry: the limit plus the 128-byte AEAD headroom (v1 framing:
// 2-byte nonce length, nonce, authentication tag). SetMaxEnvelope bounds
// every accepted ceiling — and the shipped default sits far below the guard —
// so this value and its RawStd base64 expansion in decodeBounded stay within
// positive int range and can never overflow into spuriously rejecting valid
// artifacts.
func ciphertextBound() int { return MaxEnvelope() + 128 }

func decodeBounded(raw string, max int) ([]byte, error) {
	if len(raw) > base64.RawStdEncoding.EncodedLen(max) {
		return nil, errors.New("encoded value too large")
	}
	return base64.RawStdEncoding.DecodeString(raw)
}
