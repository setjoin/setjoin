package device

// Tests for med-auth-baseline-secrets-001 (D-AUTHSERVER-SQL--ARCHIVE-003):
// devices.hmac_secret moved from plaintext TEXT to the family's AES-256-GCM
// _enc envelope with key-id handling.
//
// Acceptance legs proven here (this package's claims ONLY — V060 read-policy
// scope is med-dbschema-rls-001's evidence and is deliberately not asserted):
//
//  1. New and migrated rows store only _enc ciphertext: registration-shaped
//     writes and the lazy migration of a legacy plaintext row both leave
//     hmac_secret NULL with a sealed envelope + key id in their place.
//  2. Device check-in / policy-read HMAC verification (the single
//     VerifyDeviceRequest seam behind both endpoints) passes against migrated
//     keys, including rows migrated from plaintext (compatibility leg).
//
// DB-backed tests need DB_DSN (testsupport skips otherwise; REQUIRE_DB makes a
// missing DB fail instead of silently passing).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/cryptokey"
	_ "setjoin.com/shared/testsupport"
)

// ── Pure unit: codec contract ────────────────────────────────────────────────

func TestSecretCodec_RoundTripAndFailClosed(t *testing.T) {
	codec := NewSecretCodec([]byte("device-test-master-secret-key"), cryptokey.ProfileStandard)

	envelope, err := codec.Seal("a-device-hmac-secret")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// EK01 magic: the family's self-describing envelope, not plaintext.
	if !strings.HasPrefix(string(envelope), "EK01") {
		t.Fatalf("envelope must carry the EK01 magic, got %q", string(envelope[:4]))
	}
	if strings.Contains(string(envelope), "a-device-hmac-secret") {
		t.Fatal("envelope must not contain the plaintext secret")
	}

	opened, err := codec.Open(envelope, SecretKeyIDV1)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if opened != "a-device-hmac-secret" {
		t.Fatalf("round trip mismatch: %q", opened)
	}

	// Unknown / unstamped key version fails closed — never decrypts under a
	// guessed key generation.
	if _, err := codec.Open(envelope, ""); err == nil {
		t.Error("opening under an unstamped key id must fail")
	}
	if _, err := codec.Open(envelope, "v999"); err == nil {
		t.Error("opening under an unknown key version must fail")
	}

	// A nil codec fails closed at every seam (no silent plaintext fallback).
	if _, err := (*SecretCodec)(nil).Seal("x"); err == nil {
		t.Error("nil codec Seal must fail")
	}
	if _, err := (*SecretCodec)(nil).Open(envelope, SecretKeyIDV1); err == nil {
		t.Error("nil codec Open must fail")
	}
}

func TestGetDeviceSecret_NilCodecFailsClosed(t *testing.T) {
	if err := VerifyDeviceRequest(context.Background(), nil, 1,
		httptestProof(), nil); err == nil {
		t.Error("verification without a configured codec must fail closed")
	}
}

// httptestProof mints a request whose headers are well-formed enough to reach
// the secret lookup (the nil-codec failure fires after header validation).
func httptestProof() *http.Request {
	req, _ := http.NewRequest(http.MethodPost, "/device/checkin", http.NoBody)
	req.Header.Set(HeaderHMAC, "ab")
	req.Header.Set(HeaderTimestamp, time.Now().UTC().Format(time.RFC3339))
	req.Header.Set(HeaderNonce, "nonce-codec-probe")
	req.Header.Set(HeaderBodyHash, hex.EncodeToString(make([]byte, sha256.Size)))
	return req
}

// ── DB-backed: at-rest form + compatibility leg ─────────────────────────────

func TestGetDeviceSecret_LegacyPlaintextRowVerifiesAndMigratesToCiphertextOnly(t *testing.T) {
	pool, deviceID, secret := openNonceFixture(t, "enctest")
	ctx := context.Background()
	codec := NewSecretCodec([]byte("device-test-master-secret-key"), cryptokey.ProfileStandard)

	// Fixture rows are pre-V247 shaped: the issued value sits in plaintext.
	var legacy *string
	var envelope []byte
	if err := pool.QueryRow(ctx,
		`SELECT hmac_secret, hmac_secret_enc FROM devices WHERE id = $1`, deviceID,
	).Scan(&legacy, &envelope); err != nil {
		t.Fatalf("load legacy row: %v", err)
	}
	if legacy == nil || *legacy != secret || envelope != nil {
		t.Fatal("fixture must start in the legacy plaintext form")
	}

	// Compatibility leg: HMAC verification (the check-in/policy-read seam)
	// passes against the issued key BEFORE any migration.
	req := signedProofRequest("POST", "/device/checkin", secret, deviceID, freshTS(), "nonce-enc-compat-1", "")
	if err := VerifyDeviceRequest(ctx, pool, deviceID, req, codec); err != nil {
		t.Fatalf("legacy plaintext row must still verify: %v", err)
	}

	// The successful verification lazily migrated the row: it now stores ONLY
	// the _enc ciphertext — plaintext gone, envelope + key id present.
	var gotLegacy *string
	var gotEnvelope []byte
	var keyID *string
	if err := pool.QueryRow(ctx,
		`SELECT hmac_secret, hmac_secret_enc, hmac_secret_key_id FROM devices WHERE id = $1`, deviceID,
	).Scan(&gotLegacy, &gotEnvelope, &keyID); err != nil {
		t.Fatalf("load migrated row: %v", err)
	}
	if gotLegacy != nil {
		t.Fatal("migrated row must not retain the plaintext secret")
	}
	if gotEnvelope == nil {
		t.Fatal("migrated row must hold the sealed envelope")
	}
	if keyID == nil || *keyID != SecretKeyIDV1 {
		t.Fatalf("migrated row must be stamped with the active key id, got %v", keyID)
	}

	// The migrated key still verifies (check-in AND the policy-read challenge
	// shape — same seam, different request URI cells).
	req2 := signedProofRequest("GET", "/device/policy", secret, deviceID, freshTS(), "nonce-enc-compat-2", "")
	if err := VerifyDeviceRequest(ctx, pool, deviceID, req2, codec); err != nil {
		t.Fatalf("migrated key must verify through the policy-read challenge: %v", err)
	}
}

func TestGetDeviceSecret_CiphertextOnlyRowVerifies(t *testing.T) {
	pool, deviceID, secret := openNonceFixture(t, "encnew")
	ctx := context.Background()
	codec := NewSecretCodec([]byte("device-test-master-secret-key"), cryptokey.ProfileStandard)

	// Simulate a V247-native write (registration-shaped): envelope + key id in,
	// plaintext never stored.
	envelope, err := codec.Seal(secret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE devices SET hmac_secret = NULL, hmac_secret_enc = $2, hmac_secret_key_id = $3
		  WHERE id = $1`, deviceID, envelope, codec.ActiveKeyID()); err != nil {
		t.Fatalf("shape ciphertext-only row: %v", err)
	}

	got, err := GetDeviceSecret(ctx, pool, deviceID, codec)
	if err != nil {
		t.Fatalf("GetDeviceSecret on ciphertext-only row: %v", err)
	}
	if got != secret {
		t.Fatal("opened secret must equal the issued value")
	}

	req := signedProofRequest("POST", "/device/checkin", secret, deviceID, freshTS(), "nonce-enc-new-1", "")
	if err := VerifyDeviceRequest(ctx, pool, deviceID, req, codec); err != nil {
		t.Fatalf("ciphertext-only row must verify: %v", err)
	}
}

func TestGetDeviceSecret_UnknownKeyVersionFailsClosed(t *testing.T) {
	pool, deviceID, secret := openNonceFixture(t, "enckey")
	ctx := context.Background()
	codec := NewSecretCodec([]byte("device-test-master-secret-key"), cryptokey.ProfileStandard)

	envelope, err := codec.Seal(secret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE devices SET hmac_secret = NULL, hmac_secret_enc = $2, hmac_secret_key_id = 'v-future'
		  WHERE id = $1`, deviceID, envelope); err != nil {
		t.Fatalf("shape unknown-key row: %v", err)
	}

	if _, err := GetDeviceSecret(ctx, pool, deviceID, codec); err == nil {
		t.Fatal("an envelope stamped with an unavailable key version must fail closed")
	}
}
