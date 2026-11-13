package smtp

import (
	"testing"

	"setjoin.com/mailserver/internal/smime"
)

// TestBodyMutatorsApply pins the P0 bypass invariant: ONLY a fully-valid S/MIME
// signature exempts a message from the anti-phish/link-protect body mutators.
// Every other verdict — unsigned (nil), cryptographically invalid, or untrusted
// — must still be mutated, so a broken or untrusted signature can never be a hole
// that smuggles malicious links past link-protect.
func TestBodyMutatorsApply(t *testing.T) {
	tests := []struct {
		name string
		res  *smime.VerifyResult
		want bool // true = mutators run (message NOT exempt)
	}{
		{
			name: "unsigned (nil) is mutated",
			res:  nil,
			want: true,
		},
		{
			name: "invalid signature is still mutated (no bypass)",
			res:  &smime.VerifyResult{Status: smime.StatusInvalid},
			want: true,
		},
		{
			name: "untrusted signature is still mutated (no bypass)",
			res:  &smime.VerifyResult{Status: smime.StatusUntrusted},
			want: true,
		},
		{
			name: "revoked signature (blocklist/CRL evidence) is still mutated (no bypass)",
			res:  &smime.VerifyResult{Status: smime.StatusUntrusted, Revocation: smime.RevocationRevoked},
			want: true,
		},
		{
			name: "valid signature bypasses the mutators",
			res:  &smime.VerifyResult{Status: smime.StatusValid},
			want: false,
		},
		{
			name: "empty/unknown status is mutated (fail-safe default)",
			res:  &smime.VerifyResult{Status: ""},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := bodyMutatorsApply(tc.res); got != tc.want {
				t.Errorf("bodyMutatorsApply(%+v) = %v, want %v", tc.res, got, tc.want)
			}
		})
	}
}
