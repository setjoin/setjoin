package continuity

import (
	"bytes"
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"

	sharedcontinuity "setjoin.com/shared/continuity"
	"setjoin.com/shared/exchangeartifact"
)

func TestLoadRejectsNonAbsoluteOrUncleanSigningKeyPath(t *testing.T) {
	tests := []string{"", "continuity.pem", filepath.Join(t.TempDir(), "nested") + "/../continuity.pem"}
	for _, path := range tests {
		if _, err := Load(path, "continuity-test"); err == nil || err.Error() != "continuity signing key path must be a clean absolute path" {
			t.Fatalf("Load(%q) error = %v", path, err)
		}
	}
}

func TestSignExchangeReceiptUsesSchemaSeparatedRotatingKey(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	service := &Service{Signer: sharedcontinuity.Signer{KeyID: "continuity-v1", PrivateKey: private}, Now: func() time.Time { return now }}
	receipt, err := service.SignExchangeReceipt(exchangeartifact.ReceiptClaims{
		Kind: "deletion", SubjectSHA256: string(bytes.Repeat([]byte{'a'}, 64)),
		InstallationID: "install-1", TenantID: 7, ProjectID: 9, Disposition: "backup_expiry_pending",
	})
	if err != nil {
		t.Fatal(err)
	}
	public := private.Public().(ed25519.PublicKey)
	if err := exchangeartifact.VerifyReceipt(receipt, map[string]ed25519.PublicKey{"continuity-v1": public}, now); err != nil {
		t.Fatal(err)
	}
}

func TestClassifyBootSignalsAndCleanRestoreSuppression(t *testing.T) {
	previous := time.Date(2026, 8, 2, 8, 0, 0, 0, time.UTC)
	cases := []struct {
		name                               string
		now                                time.Time
		previousInstallation, installation string
		previousGeneration, generation     int64
		restore                            time.Time
		want                               SignalClass
	}{
		{"backward clock", previous.Add(-6 * time.Minute), "a", "a", 1, 1, time.Time{}, SignalClockAnomaly},
		{"forward clock", previous.Add(25 * time.Hour), "a", "a", 1, 1, time.Time{}, SignalClockAnomaly},
		{"timeline mismatch", previous.Add(time.Minute), "a", "a", 2, 1, time.Time{}, SignalLocalTimelineMismatch},
		{"declared restore", previous.Add(time.Minute), "a", "a", 1, 2, previous.Add(time.Second), SignalNone},
		{"ordinary reboot", previous.Add(time.Minute), "a", "a", 1, 1, time.Time{}, SignalNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyBoot(tc.now, previous, tc.previousInstallation, tc.installation, tc.previousGeneration, tc.generation, tc.restore); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
