package guestinvite

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestSend_RejectsInvalidRecipient pins the recipient-binding fence
// (D-MAILSERVER-INTERNAL-GUESTINVITE-002): Send validates `to` with
// mail.ParseAddress BEFORE touching the mail queue, so an unparseable or
// header-polluting value can never ride the credential-bearing invitation mail
// as a To recipient. The rejection path must not require any live queue or
// MinIO client (the validation fires first).
func TestSend_RejectsInvalidRecipient(t *testing.T) {
	ctx := context.Background()
	invite := Prepared{
		inviteID:    1,
		rawToken:    "token-bytes-would-live-here",
		fromAddr:    "noreply@example.com",
		orgName:     "Example Org",
		authBaseURL: "https://auth.example.com",
		expiresAt:   time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond),
		ttlDays:     7,
	}

	for _, to := range []string{
		"",
		"not-an-address",
		"Guest <guest@example.com",
		"guest@example.com\r\nBcc: attacker@example.com",
		"guest@example.com\nBcc: attacker@example.com",
	} {
		err := Send(ctx, nil, nil, "", invite, to)
		if err == nil {
			t.Errorf("Send(%q) = nil error, want invalid-recipient refusal", to)
		} else if !strings.Contains(err.Error(), "invalid recipient") {
			t.Errorf("Send(%q) error = %v, want an invalid-recipient refusal", to, err)
		}
	}
}

// TestSend_AcceptsWellFormedRecipientBeyondValidation is the shape control: a
// well-formed recipient passes the fence (reaching the mail-queue call — not
// exercised here, that seam has its own suite); the fence itself must not
// reject the supported "Name <addr>" display form mail.ParseAddress accepts.
func TestSend_AcceptsWellFormedRecipientBeyondValidation(t *testing.T) {
	// mail.ParseAddress accepts the display-name form; the fence must not
	// over-reject it (Send itself cannot run further without a live queue,
	// so the fence helper is asserted directly).
	for _, to := range []string{"guest@example.com", `"Guest User" <guest@example.com>`} {
		if err := validateRecipient(to); err != nil {
			t.Errorf("recipient %q must pass the fence, got %v", to, err)
		}
	}
}
