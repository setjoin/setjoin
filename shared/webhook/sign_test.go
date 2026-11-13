package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSignReturnsNonEmpty(t *testing.T) {
	secret := "test-secret-32-bytes-long-enough!!"
	body := []byte(`{"specversion":"1.0","id":"evt_123","type":"test"}`)

	header, err := Sign(body, secret)
	if err != nil {
		t.Fatalf("Sign returned error for a %d-byte secret: %v", len(secret), err)
	}
	if header == "" {
		t.Fatal("Sign returned empty header")
	}
}

func TestSignatureFormat(t *testing.T) {
	body := []byte(`{"test":"data"}`)

	// "secret" is only 6 bytes: below MinSecretLen the signing boundary must
	// fail closed instead of minting a forgeable header (D-SHARED-WEBHOOK-002).
	header, err := Sign(body, "secret")
	if err == nil {
		t.Fatal("Sign accepted a 6-byte secret; short secrets must be rejected")
	}
	if header != "" {
		t.Errorf("Sign returned a header alongside a short-secret error: %q", header)
	}

	header, err = Sign(body, strings.Repeat("s", MinSecretLen))
	if err != nil {
		t.Fatalf("Sign rejected a %d-byte secret: %v", MinSecretLen, err)
	}
	if len(header) < 10 {
		t.Error("signature header too short")
	}
	if !strings.HasPrefix(header, "v1,t=") {
		t.Errorf("header should start with v1,t=, got %q", header)
	}
}

// TestSignRejectsEmptySecret pins the signing-boundary guard: an empty or
// guessable secret would produce headers anyone can forge.
func TestSignRejectsEmptySecret(t *testing.T) {
	if _, err := Sign([]byte(`{}`), ""); err == nil {
		t.Fatal("Sign accepted an empty secret")
	}
	if _, err := Sign([]byte(`{}`), "short"); err == nil {
		t.Fatal("Sign accepted a below-floor secret")
	}
}

// TestSignScheme pins the exact wire scheme so a receiver implementation and
// the doc comment cannot drift apart silently (D-SHARED-WEBHOOK-001): the MAC
// covers "<timestamp>.<body>" only (no msg_id prefix), hex-encoded, inside a
// single v1,t=...,sig=... header.
func TestSignScheme(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	body := []byte(`{"id":"evt_1"}`)

	header, err := Sign(body, secret)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	rest := strings.TrimPrefix(header, "v1,t=")
	comma := strings.Index(rest, ",sig=")
	if comma < 0 {
		t.Fatalf("header missing ,sig= separator: %q", header)
	}
	tsRaw, sig := rest[:comma], rest[comma+len(",sig="):]
	ts, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		t.Fatalf("timestamp %q is not a unix integer", tsRaw)
	}
	if ts <= 0 || ts > time.Now().Add(time.Minute).Unix() {
		t.Errorf("timestamp %d is not a plausible current unix time", ts)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = fmt.Fprintf(mac, "%d.%s", ts, body)
	want := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(want)) {
		t.Errorf("signature does not verify under the documented scheme: got %s want %s", sig, want)
	}
}
