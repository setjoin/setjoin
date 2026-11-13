package mailrecovery

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	sharedcontinuity "setjoin.com/shared/continuity"
	"setjoin.com/shared/jwtutil"
)

func recoveryReceipt() sharedcontinuity.SignedReceipt {
	return sharedcontinuity.SignedReceipt{Claims: sharedcontinuity.ReceiptClaims{
		Version: 1, InstallationID: uuid.NewString(), AccountID: "7", OriginalMessageID: "42",
		Eligibility: "received", RawMIMESHA256: strings.Repeat("a", 64), RawMIMESize: "10",
		Blobs:              []sharedcontinuity.BlobDigest{{BlobID: "blob-1", SHA256: strings.Repeat("b", 64), Size: "20"}},
		TimelineGeneration: "2", StateWatermark: "8", BootEpoch: uuid.NewString(),
		IssuedAt: time.Now().UTC().Format(time.RFC3339), KeyID: "continuity-v1",
	}}
}

func TestValidateInventoryExactBinding(t *testing.T) {
	receipt := recoveryReceipt()
	inventory := []InventoryItem{
		{ItemID: "raw", Role: "raw", SHA256: receipt.Claims.RawMIMESHA256, Size: "10"},
		{ItemID: "blob-1", Role: "attachment", SHA256: receipt.Claims.Blobs[0].SHA256, Size: "20"},
	}
	if total, err := validateInventory(receipt, inventory); err != nil || total != 30 {
		t.Fatalf("valid inventory = (%d,%v), want (30,nil)", total, err)
	}
	for name, mutate := range map[string]func([]InventoryItem){
		"noncanonical raw id": func(items []InventoryItem) { items[0].ItemID = "mime" },
		"wrong blob id":       func(items []InventoryItem) { items[1].ItemID = "other" },
		"digest tamper":       func(items []InventoryItem) { items[1].SHA256 = strings.Repeat("c", 64) },
		"noncanonical size":   func(items []InventoryItem) { items[1].Size = "020" },
		"duplicate item":      func(items []InventoryItem) { items[1].ItemID = "raw" },
	} {
		t.Run(name, func(t *testing.T) {
			copyItems := append([]InventoryItem(nil), inventory...)
			mutate(copyItems)
			if _, err := validateInventory(receipt, copyItems); err == nil {
				t.Fatal("mutated inventory accepted")
			}
		})
	}
}

func TestSignedEligibilityRejectsRequestOverride(t *testing.T) {
	receipt := recoveryReceipt()
	if got, err := signedEligibility(receipt, "received"); err != nil || got != "received" {
		t.Fatalf("matching eligibility = (%q, %v)", got, err)
	}
	if _, err := signedEligibility(receipt, "sent-terminal"); err == nil {
		t.Fatal("request-owned eligibility override accepted")
	}
}

func TestParseContentRangeRejectsAmbiguousAndOversizedShapes(t *testing.T) {
	start, end, total, err := parseContentRange("bytes 0-262143/300000")
	if err != nil || start != 0 || end != 262143 || total != 300000 {
		t.Fatalf("valid range = %d,%d,%d,%v", start, end, total, err)
	}
	for _, value := range []string{
		"bytes 00-1/2", "bytes 0-1/2\nX: y", "bytes -1-0/1", "bytes 1-0/2",
		"bytes 0-2/2", "items 0-1/2", "bytes 0-1/*",
	} {
		if _, _, _, err := parseContentRange(value); err == nil {
			t.Fatalf("ambiguous range accepted: %q", value)
		}
	}
}

func TestRecoveredMIMEParsingIsBoundedAndEligibilityScoped(t *testing.T) {
	now := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	raw := []byte("Message-ID: <m@example.test>\r\nFrom: Sender <sender@example.test>\r\nTo: user@example.test\r\nSubject: recovered\r\nDate: Fri, 01 Aug 2026 12:00:00 +0000\r\n\r\nbody")
	parsed, err := parseRecoveredMessage(raw, "received", now)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.MessageID != "<m@example.test>" || parsed.FromAddr != "sender@example.test" || parsed.Eligibility != "received" {
		t.Fatalf("unexpected parsed message: %+v", parsed)
	}
	if _, err := parseRecoveredMessage(raw, "draft", now); err == nil {
		t.Fatal("mutable draft eligibility accepted")
	}
	if _, err := parseRecoveredMessage([]byte("not mail"), "received", now); err == nil {
		t.Fatal("malformed MIME accepted")
	}
}

func TestRecoveryStepUpRequiresFreshTwoFactorEvidence(t *testing.T) {
	now := time.Now().UTC()
	incidentID := uuid.New()
	claims := &jwtutil.Claims{
		UserID: 7, JTI: "jti", ACR: jwtutil.ACRAAL2,
		AMR: []string{jwtutil.AMRPassword, jwtutil.AMROTP, jwtutil.AMRMultiFactor},
	}
	claims.IssuedAt = jwtutil.NewNumericDate(now.Add(-time.Minute))
	binding, ok := recoveryStepUpBinding(claims, incidentID, now)
	if !ok || binding == ([sha256.Size]byte{}) {
		t.Fatal("fresh two-factor step-up rejected")
	}
	claims.IssuedAt = jwtutil.NewNumericDate(now.Add(-6 * time.Minute))
	if _, ok := recoveryStepUpBinding(claims, incidentID, now); ok {
		t.Fatal("stale step-up accepted")
	}
	claims.IssuedAt = jwtutil.NewNumericDate(now.Add(-time.Minute))
	claims.AMR = []string{jwtutil.AMRPassword, jwtutil.AMRMultiFactor}
	if _, ok := recoveryStepUpBinding(claims, incidentID, now); ok {
		t.Fatal("single-factor session accepted")
	}
}
