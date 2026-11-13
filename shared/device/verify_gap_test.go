package device

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestWithVerifiedDeviceMarksContext pins the trusted-context marker: a
// wrapped request short-circuits re-verification for that device.
func TestWithVerifiedDeviceMarksContext(t *testing.T) {
	req := httptest.NewRequest("POST", "/device/checkin", nil)
	if verifiedDeviceAlready(req.Context(), 7) {
		t.Fatal("unmarked request already considered verified")
	}
	marked := WithVerifiedDevice(req, 7)
	if !verifiedDeviceAlready(marked.Context(), 7) {
		t.Fatal("marked request lost the verification marker")
	}
	if verifiedDeviceAlready(marked.Context(), 8) {
		t.Fatal("marker leaked across device ids")
	}

	// The marker short-circuits verification before any DB access or HMAC
	// check: a nil pool and headerless request still pass for that device.
	if err := VerifyDeviceRequest(marked.Context(), nil, 7, marked, testSecretCodec); err != nil {
		t.Fatalf("already-verified device re-challenged: %v", err)
	}
}

// TestVerifyDeviceRequest_NonceLengthGuard pins the oversized-nonce rejection
// (fires before timestamp/body evaluation).
func TestVerifyDeviceRequest_NonceLengthGuard(t *testing.T) {
	req := httptest.NewRequest("POST", "/device/checkin", nil)
	req.Header.Set(HeaderHMAC, "ab")
	req.Header.Set(HeaderNonce, strings.Repeat("n", NonceMaxLen+1))
	if err := VerifyDeviceRequest(context.Background(), nil, 1, req, testSecretCodec); err == nil ||
		err.Error() != "device: nonce too long" {
		t.Fatalf("oversized nonce err = %v, want nonce-too-long", err)
	}
}

// TestVerifyDeviceRequest_UppercaseBodyHashRejected pins the lowercase-hex
// body-hash guard.
func TestVerifyDeviceRequest_UppercaseBodyHashRejected(t *testing.T) {
	req := httptest.NewRequest("POST", "/device/checkin", nil)
	req.Header.Set(HeaderHMAC, "ab")
	req.Header.Set(HeaderNonce, "nonce-unit")
	req.Header.Set(HeaderBodyHash, strings.Repeat("F", 64))
	req.Header.Set(HeaderTimestamp, freshTS())
	if err := VerifyDeviceRequest(context.Background(), nil, 1, req, testSecretCodec); err == nil ||
		err.Error() != "device: body hash must be lowercase hex" {
		t.Fatalf("uppercase body hash err = %v, want lowercase-hex rejection", err)
	}
}

// failingBody is a request body whose read always fails.
type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("socket gone") }
func (failingBody) Close() error             { return nil }

// TestVerifyBodyHash_ReadFailureSurfaces pins the body-read arm: a body that
// fails mid-read surfaces the failure instead of binding a partial digest.
func TestVerifyBodyHash_ReadFailureSurfaces(t *testing.T) {
	req := httptest.NewRequest("POST", "/device/checkin", nil)
	req.Body = io.NopCloser(failingBody{})
	err := verifyBodyHash(req, sha256Hex("whatever"))
	if err == nil || !strings.Contains(err.Error(), "read body for proof binding") {
		t.Fatalf("verifyBodyHash = %v, want read failure", err)
	}
}

// TestVerifyBodyHash_OversizedBodyRejected pins the proof-binding bound.
func TestVerifyBodyHash_OversizedBodyRejected(t *testing.T) {
	req := httptest.NewRequest("POST", "/device/checkin",
		strings.NewReader(strings.Repeat("x", MaxChallengeBodyBytes+1)))
	req.ContentLength = MaxChallengeBodyBytes + 1
	err := verifyBodyHash(req, sha256Hex("whatever"))
	if err == nil || !strings.Contains(err.Error(), "exceeds proof-binding bound") {
		t.Fatalf("verifyBodyHash = %v, want bound rejection", err)
	}
}

// TestVerifyBodyHash_ZeroLengthDeclaredEmptyBody pins the empty-body shape:
// a non-NoBody reader delivering zero bytes with ContentLength 0 binds the
// canonical empty-body commitment.
func TestVerifyBodyHash_ZeroLengthDeclaredEmptyBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/device/checkin", nil)
	req.Body = io.NopCloser(strings.NewReader(""))
	req.ContentLength = 0
	err := verifyBodyHash(WithServerBodyDigest(req, sha256Hex("")), sha256Hex(""))
	if err != nil {
		t.Fatalf("declared-empty body rejected: %v", err)
	}
}

// TestRequestURIOf_DefaultsToSlash pins the URI fallback.
func TestRequestURIOf_DefaultsToSlash(t *testing.T) {
	req := httptest.NewRequest("POST", "/device/checkin", nil)
	if got := requestURIOf(req); got != "/device/checkin" {
		t.Fatalf("requestURIOf = %q", got)
	}
	bare := &http.Request{URL: &url.URL{}}
	if got := requestURIOf(bare); got != "/" {
		t.Fatalf("requestURIOf(empty) = %q, want /", got)
	}
}

// TestGetDeviceSecret_ShapeGuards pins the secret-row shape guards against
// the real devices table: an envelope without a key id and a row with no
// usable secret both fail closed with distinct errors.
func TestGetDeviceSecret_ShapeGuards(t *testing.T) {
	ctx := context.Background()

	t.Run("envelope without key id", func(t *testing.T) {
		fixturePool, deviceID, _ := openNonceFixture(t, "envnoid")
		if _, err := fixturePool.Exec(ctx,
			`UPDATE devices SET hmac_secret = NULL, hmac_secret_enc = $1, hmac_secret_key_id = NULL WHERE id = $2`,
			[]byte{0x01, 0x02}, deviceID); err != nil {
			t.Fatalf("plant envelope without key id: %v", err)
		}
		if _, err := GetDeviceSecret(ctx, fixturePool, deviceID, testSecretCodec); err == nil ||
			err.Error() != "device: hmac secret envelope missing key id" {
			t.Fatalf("GetDeviceSecret = %v, want missing-key-id rejection", err)
		}
	})

	t.Run("no usable secret", func(t *testing.T) {
		fixturePool, deviceID, _ := openNonceFixture(t, "nosecret")
		if _, err := fixturePool.Exec(ctx,
			`UPDATE devices SET hmac_secret = NULL, hmac_secret_enc = NULL, hmac_secret_key_id = NULL WHERE id = $1`,
			deviceID); err != nil {
			t.Fatalf("clear secret columns: %v", err)
		}
		_, err := GetDeviceSecret(ctx, fixturePool, deviceID, testSecretCodec)
		if err == nil || err.Error() != "device: holds no usable secret" && !strings.Contains(err.Error(), "no usable secret") {
			t.Fatalf("GetDeviceSecret = %v, want no-usable-secret rejection", err)
		}
	})
}
