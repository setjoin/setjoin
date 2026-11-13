package authn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestPushApprovalCrossClientGolden(t *testing.T) {
	var vector struct {
		Canonical          string `json:"canonical"`
		PublicKeyHex       string `json:"public_key_hex"`
		SignatureBase64URL string `json:"signature_base64url"`
	}
	raw, err := os.ReadFile("../../../docs/standards/PUSH_APPROVAL_V1_GOLDEN.json")
	if err != nil || json.Unmarshal(raw, &vector) != nil {
		t.Fatalf("load golden vector: %v", err)
	}
	publicKey, err := hex.DecodeString(vector.PublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPushApproval(publicKey, []byte(vector.Canonical), vector.SignatureBase64URL); err != nil {
		t.Fatalf("Rust-produced approval signature rejected: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(vector.Canonical), &decoded); err != nil || decoded["protocol"] != PushApprovalProtocol {
		t.Fatalf("invalid canonical envelope: %v", err)
	}
}

func TestVerifyPushApprovalRejectsMalformedAndTamperedInputs(t *testing.T) {
	if err := VerifyPushApproval([]byte("bad-key"), []byte("payload"), "x"); err == nil {
		t.Fatal("malformed public key accepted")
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := elliptic.Marshal(elliptic.P256(), privateKey.X, privateKey.Y)
	for _, signature := range []string{"%%%", base64.RawURLEncoding.EncodeToString(make([]byte, 63))} {
		if err := VerifyPushApproval(publicKey, []byte("payload"), signature); err == nil {
			t.Fatalf("malformed signature %q accepted", signature)
		}
	}
	digest := sha256.Sum256([]byte("payload"))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	encoded := make([]byte, 64)
	r.FillBytes(encoded[:32])
	s.FillBytes(encoded[32:])
	if err := VerifyPushApproval(publicKey, []byte("tampered"), base64.RawURLEncoding.EncodeToString(encoded)); err == nil {
		t.Fatal("tampered payload accepted")
	}
}
