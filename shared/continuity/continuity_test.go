package continuity

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (Signer, KeySet, time.Time) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 2, 3, 4, 5, 0, time.UTC)
	signer := Signer{KeyID: "continuity-2026-08", PrivateKey: priv}
	return signer, KeySet{Keys: map[string]VerificationKey{signer.KeyID: {
		PublicKey: pub, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
	}}}, now
}

func TestTokenRoundTripScopeRotationAndTamper(t *testing.T) {
	signer, keys, now := fixture(t)
	claims := NewTokenClaims("4ff38daa-7eaf-4d6f-8dc6-b238fa2c7ef2", "42", "7", "9001", "9eb2f490-f539-4f23-9d5e-4107ec63a048", now, signer.KeyID)
	compact, err := SignToken(claims, signer)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyToken(compact, keys, VerifyOptions{Now: now, MaxAge: 24 * time.Hour, InstallationID: claims.InstallationID, AccountID: "42"})
	if err != nil || got != claims {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	if _, err := VerifyToken(compact, keys, VerifyOptions{Now: now, MaxAge: 24 * time.Hour, InstallationID: claims.InstallationID, AccountID: "43"}); !errors.Is(err, ErrScope) {
		t.Fatalf("wrong account: %v", err)
	}
	if _, err := VerifyToken(compact, KeySet{Keys: map[string]VerificationKey{}}, VerifyOptions{Now: now, MaxAge: 24 * time.Hour}); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key: %v", err)
	}
	parts := strings.Split(compact, ".")
	tampered := parts[0][:len(parts[0])-1] + "A." + parts[1]
	if _, err := VerifyToken(tampered, keys, VerifyOptions{Now: now, MaxAge: 24 * time.Hour}); err == nil {
		t.Fatal("tampered token accepted")
	}
}

func TestTokenRejectsMalformedCanonicalAndTimeBounds(t *testing.T) {
	signer, keys, now := fixture(t)
	for _, account := range []string{"", "0", "01", "-1", "18446744073709551615"} {
		claims := NewTokenClaims("4ff38daa-7eaf-4d6f-8dc6-b238fa2c7ef2", account, "1", "0", "9eb2f490-f539-4f23-9d5e-4107ec63a048", now, signer.KeyID)
		if _, err := SignToken(claims, signer); err == nil {
			t.Fatalf("account %q accepted", account)
		}
	}
	claims := NewTokenClaims("4ff38daa-7eaf-4d6f-8dc6-b238fa2c7ef2", "42", "1", "0", "9eb2f490-f539-4f23-9d5e-4107ec63a048", now, signer.KeyID)
	compact, _ := SignToken(claims, signer)
	if _, err := VerifyToken(compact, keys, VerifyOptions{Now: now.Add(25 * time.Hour), MaxAge: 24 * time.Hour}); !errors.Is(err, ErrExpired) {
		t.Fatalf("stale: %v", err)
	}
	if _, err := VerifyToken(strings.Repeat("a", MaxCompactBytes+1), keys, VerifyOptions{Now: now, MaxAge: 24 * time.Hour}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("oversized: %v", err)
	}
}

func TestReceiptCanonicalBlobOrderIdentityAndTamper(t *testing.T) {
	signer, keys, now := fixture(t)
	claims := ReceiptClaims{Version: Version, InstallationID: "4ff38daa-7eaf-4d6f-8dc6-b238fa2c7ef2", AccountID: "42",
		OriginalMessageID: "m-7", Eligibility: "received", RawMIMESHA256: strings.Repeat("a", 64), RawMIMESize: "99",
		Blobs:              []BlobDigest{{BlobID: "z", SHA256: strings.Repeat("b", 64), Size: "2"}, {BlobID: "a", SHA256: strings.Repeat("c", 64), Size: "3"}},
		TimelineGeneration: "4", StateWatermark: "8", BootEpoch: "9eb2f490-f539-4f23-9d5e-4107ec63a048", IssuedAt: now.Format(time.RFC3339), KeyID: signer.KeyID}
	receipt, err := SignReceipt(claims, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReceipt(receipt, keys, VerifyOptions{Now: now, InstallationID: claims.InstallationID, AccountID: "42"}); err != nil {
		t.Fatal(err)
	}
	first, _ := ArtifactIdentity(claims)
	claims.TimelineGeneration, claims.BootEpoch = "99", "169c680d-4f7d-46bc-90bf-64f2fcab8ea7"
	second, _ := ArtifactIdentity(claims)
	if first != second {
		t.Fatal("timeline/boot epoch changed canonical artifact identity")
	}
	receipt.Claims.RawMIMESHA256 = strings.Repeat("d", 64)
	if err := VerifyReceipt(receipt, keys, VerifyOptions{Now: now}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tamper: %v", err)
	}
}

func TestReceiptEligibilityIsRequiredAndSigned(t *testing.T) {
	signer, keys, now := fixture(t)
	claims := ReceiptClaims{
		Version: Version, InstallationID: "4ff38daa-7eaf-4d6f-8dc6-b238fa2c7ef2", AccountID: "42",
		OriginalMessageID: "m-7", Eligibility: "received", RawMIMESHA256: strings.Repeat("a", 64), RawMIMESize: "99",
		Blobs: nil, TimelineGeneration: "4", StateWatermark: "8", BootEpoch: "9eb2f490-f539-4f23-9d5e-4107ec63a048",
		IssuedAt: now.Format(time.RFC3339), KeyID: signer.KeyID,
	}
	receipt, err := SignReceipt(claims, signer)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Claims.Eligibility = "sent-terminal"
	if err := VerifyReceipt(receipt, keys, VerifyOptions{Now: now}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("eligibility tamper: %v", err)
	}
	for _, eligibility := range []string{"", "draft", "sent"} {
		claims.Eligibility = eligibility
		if _, err := SignReceipt(claims, signer); !errors.Is(err, ErrMalformed) {
			t.Fatalf("eligibility %q accepted: %v", eligibility, err)
		}
	}
}

func TestReceiptRejectsZeroRawMIMESize(t *testing.T) {
	signer, _, now := fixture(t)
	claims := ReceiptClaims{
		Version: Version, InstallationID: "4ff38daa-7eaf-4d6f-8dc6-b238fa2c7ef2", AccountID: "42",
		OriginalMessageID: "m-7", Eligibility: "received", RawMIMESHA256: strings.Repeat("a", 64), RawMIMESize: "0",
		Blobs: nil, TimelineGeneration: "4", StateWatermark: "8", BootEpoch: "9eb2f490-f539-4f23-9d5e-4107ec63a048",
		IssuedAt: now.Format(time.RFC3339), KeyID: signer.KeyID,
	}
	if _, err := SignReceipt(claims, signer); !errors.Is(err, ErrMalformed) {
		t.Fatalf("zero-byte raw MIME accepted: %v", err)
	}
	claims.RawMIMESize = "99"
	claims.RawMIMESHA256 = strings.Repeat("A", 64)
	if _, err := SignReceipt(claims, signer); !errors.Is(err, ErrMalformed) {
		t.Fatalf("uppercase raw MIME digest accepted: %v", err)
	}
}

func TestVerifyTokenRequiresFreshnessPolicy(t *testing.T) {
	signer, keys, now := fixture(t)
	claims := NewTokenClaims("4ff38daa-7eaf-4d6f-8dc6-b238fa2c7ef2", "42", "7", "9001", "9eb2f490-f539-4f23-9d5e-4107ec63a048", now, signer.KeyID)
	compact, err := SignToken(claims, signer)
	if err != nil {
		t.Fatal(err)
	}
	// Fail closed: a zero (or negative) MaxAge refuses verification entirely
	// instead of silently disabling expiry.
	for _, maxAge := range []time.Duration{0, -time.Hour} {
		if _, err := VerifyToken(compact, keys, VerifyOptions{Now: now, MaxAge: maxAge}); !errors.Is(err, ErrMalformed) {
			t.Fatalf("MaxAge %v: err = %v, want ErrMalformed (freshness policy required)", maxAge, err)
		}
	}
}
