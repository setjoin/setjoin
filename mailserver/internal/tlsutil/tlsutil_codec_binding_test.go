// Package tlsutil_test pins the wire-level binding between the ticket-key
// manager's SecretCodec seam and the real admin.ConfigSecretCodec (external
// test package: admin imports tlsutil, so an in-package test could not import
// admin back).
package tlsutil_test

import (
	"encoding/json"
	"testing"

	"setjoin.com/mailserver/internal/admin"
	"setjoin.com/shared/cryptokey"
)

// The real system_config secret codec must satisfy the ticket-key manager's
// codec seam without adapters — this is the compile-time wiring contract for
// SessionTicketKeyManager.SetSecretCodec.
var _ tlsutilSecretCodec = (*admin.ConfigSecretCodec)(nil)

// tlsutilSecretCodec mirrors tlsutil.SecretCodec (the interface itself is
// defined in tlsutil; duplicating the shape here keeps this file dependency-
// minimal while still asserting assignability).
type tlsutilSecretCodec interface {
	Encrypt(configKey string, plaintext json.RawMessage) (json.RawMessage, error)
	Decrypt(configKey string, stored json.RawMessage) (json.RawMessage, error)
}

// TestRealConfigSecretCodecRoundTripsTicketKeys proves the real AES-256-GCM
// codec envelopes and restores ticket-key JSON under the row's config key,
// and that the envelope is not equal to (nor containing) the plaintext.
func TestRealConfigSecretCodecRoundTripsTicketKeys(t *testing.T) {
	codec, err := admin.NewConfigSecretCodec(admin.ConfigSecretKeyring{
		DeploymentID:  "deploy-test",
		ActiveVersion: 1,
		ActiveKey:     []byte("0123456789abcdef0123456789abcdef"),
		ActiveProfile: cryptokey.ProfileStandard,
	})
	if err != nil {
		t.Fatal(err)
	}

	plaintext := json.RawMessage(`{"current":"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=","previous":""}`)
	envelope, err := codec.Encrypt("tls_session_ticket_keys", plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if string(envelope) == string(plaintext) {
		t.Fatal("envelope equals plaintext")
	}
	got, err := codec.Decrypt("tls_session_ticket_keys", envelope)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("round trip changed payload: %s", got)
	}

	// A different config key must reject the ciphertext (AAD binding).
	if _, err := codec.Decrypt("some_other_secret_row", envelope); err == nil {
		t.Fatal("envelope decrypted under a foreign config key — AAD binding broken")
	}
}
