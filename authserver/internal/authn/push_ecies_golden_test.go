package authn

// Cross-end golden vector for the ECDH push-challenge contract.
//
// This pins authserver's ECIES ENCRYPT to a byte-for-byte ciphertext that
// guard-core's decrypt_ecies (Rust) also asserts in
// clients/rust/guard-core/tests/ecdh_golden.rs (ecies_cross_end_golden_vector).
// The hex constants below are IDENTICAL on both ends. Any future change to either
// side's wire format / KDF / AEAD / point-encoding that breaks interop FAILS this
// committed test instead of a user's push login.
//
// ECIES is non-deterministic (fresh random ephemeral key + nonce per call), so a
// naive EncryptECIES is not byte-reproducible. The test feeds a FIXED ephemeral
// private scalar + FIXED nonce into encryptECIESDeterministic (the shared
// implementation EncryptECIES wraps) to make the output reproducible. The fixed
// material is test-only; production EncryptECIES always samples fresh randomness.
//
// Contract (single source of truth): docs/standards/PUSH_ECIES_CONTRACT.md.
//
// DO NOT regenerate these constants to "make the test pass". If this fails, the
// interop contract changed — fix the code, or re-derive the vector on BOTH ends
// deliberately (see the contract doc's "Changing the contract" section).

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"testing"
)

const (
	// Recipient (device) P-256 public key, raw 65-byte uncompressed SEC1 — what
	// EncryptECIES takes. Private half is committed in the Rust golden test.
	goldenRecipPubRaw65 = "043ffa8457dbd2917d7ab2555efa3b1c1669079eef5933ecc4bd5fa6b1701787d3ee4d370c8e54b99ca7f14fdf08329eb19fc87d33e83108a3e9577d6709b8fc75"
	// Fixed ephemeral private scalar (32-byte big-endian) — re-imported here so the
	// encrypt is reproducible. NEVER do this in production: a reused (ephemeral key,
	// nonce) pair under the same derived key destroys GCM security.
	goldenEphPrivScalar32 = "d93039eced4d88635f7c968d0c58144d5f90b3c2f82bc54a65d1bbe5b0525a23"
	// Fixed 12-byte GCM nonce.
	goldenNonce12 = "a4ff6b6dfd563c638179f6fa"
	// Plaintext: a 2-digit number-match challenge code.
	goldenPlaintext = "42"
	// The committed cross-end payload. Byte-for-byte identical to GOLDEN_PAYLOAD in
	// clients/rust/guard-core/tests/ecdh_golden.rs.
	goldenPayload = "0484d4083d3cce31d97122787043abdff18a900a421e471747e0aa0cad7ba4c00b78422c16286d6f57ddd9d2cbaa429ee04efce4ffb5d944a3571bb7c38f9670b1a4ff6b6dfd563c638179f6fa93db6bc2399d727d12c0f9c07916870c5a44"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex constant: %v", err)
	}
	return b
}

// TestECIESGoldenVector asserts that the Go encrypt, run with the committed fixed
// ephemeral key + nonce, reproduces the exact bytes that guard-core's Rust test
// decrypts. This is the cross-end pin: both ends are anchored to one byte string.
func TestECIESGoldenVector(t *testing.T) {
	recipPub := mustHex(t, goldenRecipPubRaw65)
	ephScalar := mustHex(t, goldenEphPrivScalar32)
	nonce := mustHex(t, goldenNonce12)
	want := mustHex(t, goldenPayload)

	ephKey, err := ecdh.P256().NewPrivateKey(ephScalar)
	if err != nil {
		t.Fatalf("import fixed ephemeral key: %v", err)
	}

	got, err := encryptECIESDeterministic(recipPub, []byte(goldenPlaintext), ephKey, nonce)
	if err != nil {
		t.Fatalf("encryptECIESDeterministic: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("ECIES golden vector drifted — Go encrypt no longer matches the\n"+
			"cross-end vector guard-core decrypts. The interop contract is broken\n"+
			"(see docs/standards/PUSH_ECIES_CONTRACT.md).\n got: %x\nwant: %x", got, want)
	}

	// Structural assertions on the wire format the contract promises.
	if len(got) != 95 {
		t.Fatalf("payload length = %d, want 95 (65 eph pub + 12 nonce + 2 ct + 16 tag)", len(got))
	}
	if got[0] != 0x04 {
		t.Fatalf("ephemeral point not uncompressed: first byte = 0x%02x, want 0x04", got[0])
	}
	if !bytes.Equal(got[65:77], nonce) {
		t.Fatal("nonce not at bytes [65:77] of the wire format")
	}
}

// TestECIESDeterministicMatchesProductionShape proves the test seam and the
// production EncryptECIES produce the same wire shape for the same inputs (only
// the random eph key + nonce differ), so the deterministic path is a faithful
// stand-in for what ships.
func TestECIESDeterministicMatchesProductionShape(t *testing.T) {
	recipPub := mustHex(t, goldenRecipPubRaw65)
	prod, err := EncryptECIES(recipPub, []byte(goldenPlaintext))
	if err != nil {
		t.Fatalf("EncryptECIES: %v", err)
	}
	golden := mustHex(t, goldenPayload)
	if len(prod) != len(golden) {
		t.Fatalf("production payload len %d != golden len %d for same plaintext", len(prod), len(golden))
	}
	if prod[0] != 0x04 {
		t.Fatalf("production ephemeral point not uncompressed: 0x%02x", prod[0])
	}
}
