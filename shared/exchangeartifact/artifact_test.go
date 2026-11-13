package exchangeartifact

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"testing"
	"time"

	"setjoin.com/shared/cryptokey"
)

func TestEnvelopeProfileRotationAndBindings(t *testing.T) {
	plain := []byte("bounded assessment evidence")
	d := sha256.Sum256(plain)
	binding := Binding{InstallationID: "install-a", TenantID: 7, ProjectID: 9, Kind: "normalized-bundle", PlainSHA256: hex.EncodeToString(d[:])}
	master := make([]byte, 32)
	_, _ = rand.Read(master)
	for _, profile := range []cryptokey.CryptoProfile{cryptokey.ProfileStandard, cryptokey.ProfileHybrid, cryptokey.ProfileSMx} {
		envelope, err := Seal(plain, master, profile, binding)
		if err != nil {
			t.Fatalf("%s: %v", profile, err)
		}
		got, err := Open(envelope, master, binding)
		if err != nil || string(got) != string(plain) {
			t.Fatalf("%s open: %q %v", profile, got, err)
		}
		bad := binding
		bad.ProjectID++
		if _, err := Open(envelope, master, bad); err == nil {
			t.Fatalf("%s accepted wrong AAD binding", profile)
		}
		raw, _ := json.Marshal(envelope)
		decoded, err := DecodeStrict(raw)
		if err != nil || decoded.Profile != string(profile) {
			t.Fatalf("decode: %v", err)
		}
	}
}

func TestEnvelopeTamperAndUnknownProfile(t *testing.T) {
	plain := []byte("x")
	d := sha256.Sum256(plain)
	b := Binding{InstallationID: "i", TenantID: 1, ProjectID: 1, Kind: "bundle", PlainSHA256: hex.EncodeToString(d[:])}
	key := make([]byte, 32)
	env, _ := Seal(plain, key, cryptokey.ProfileStandard, b)
	// Flip a ciphertext byte deterministically. Overwriting the last base64
	// character with 'A' was a no-op whenever that character was already 'A'
	// (~1/64 of runs): the decoded bytes were unchanged, Open legitimately
	// succeeded, and the test failed intermittently with "tamper accepted".
	raw, err := base64.RawStdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff
	env.Ciphertext = base64.RawStdEncoding.EncodeToString(raw)
	if _, err := Open(env, key, b); err == nil {
		t.Fatal("tamper accepted")
	}
	env.Profile = "future"
	if _, err := Open(env, key, b); err == nil {
		t.Fatal("unknown profile accepted")
	}
	if _, err := DecodeStrict(append([]byte(`{"schemaVersion":"x","unknown":1}`), '\n')); err == nil {
		t.Fatal("unknown field accepted")
	}
}

// TestMaxEnvelopeDefaultIsOneGiB pins the shipped ceiling: with no
// configuration applied the effective limit is the 1 GiB default, and the
// floor constant stays below it.
func TestMaxEnvelopeDefaultIsOneGiB(t *testing.T) {
	if got := MaxEnvelope(); got != DefaultMaxEnvelope {
		t.Fatalf("unconfigured MaxEnvelope = %d, want DefaultMaxEnvelope %d", got, DefaultMaxEnvelope)
	}
	if DefaultMaxEnvelope != 1<<30 {
		t.Fatalf("DefaultMaxEnvelope = %d, want the shipped 1 GiB (%d)", DefaultMaxEnvelope, 1<<30)
	}
	if MinMaxEnvelope >= DefaultMaxEnvelope || MinMaxEnvelope <= 0 {
		t.Fatalf("MinMaxEnvelope = %d, want a positive value below the default", MinMaxEnvelope)
	}
}

// TestMaxEnvelopeOverrideEnforced proves the knob changes real enforcement,
// not just the getter: an envelope above a configured 2 MiB ceiling is
// rejected by DecodeStrict while the 1 GiB default accepts it.
func TestMaxEnvelopeOverrideEnforced(t *testing.T) {
	plain := bytes.Repeat([]byte("e"), 3<<20) // 3 MiB plain → raw envelope above 2 MiB
	d := sha256.Sum256(plain)
	binding := Binding{InstallationID: "install-a", TenantID: 7, ProjectID: 9, Kind: "normalized-bundle", PlainSHA256: hex.EncodeToString(d[:])}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	envelope, err := Seal(plain, key, cryptokey.ProfileStandard, binding)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= 2<<20 {
		t.Fatalf("fixture envelope only %d bytes; want > 2 MiB so the override bound can trip", len(raw))
	}

	t.Cleanup(func() { _ = SetMaxEnvelope(DefaultMaxEnvelope) })
	if err := SetMaxEnvelope(2 << 20); err != nil {
		t.Fatalf("SetMaxEnvelope override: %v", err)
	}
	if got := MaxEnvelope(); got != 2<<20 {
		t.Fatalf("MaxEnvelope after override = %d, want %d", got, 2<<20)
	}
	if _, err := DecodeStrict(raw); err == nil {
		t.Fatal("DecodeStrict accepted an envelope above the configured ceiling")
	}
	// The restore path proves the default re-admits the same envelope.
	if err := SetMaxEnvelope(DefaultMaxEnvelope); err != nil {
		t.Fatalf("restore default: %v", err)
	}
	if _, err := DecodeStrict(raw); err != nil {
		t.Fatalf("DecodeStrict rejected a valid envelope under the restored default: %v", err)
	}
}

// TestMaxEnvelopeRejectsInvalid pins the validation contract: zero and
// negative values are not positive, sub-MiB values are not reasonable, and
// every rejection leaves the previously effective limit untouched.
func TestMaxEnvelopeRejectsInvalid(t *testing.T) {
	t.Cleanup(func() { _ = SetMaxEnvelope(DefaultMaxEnvelope) })
	if err := SetMaxEnvelope(64 << 20); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []int64{0, -1, 1 << 10, MinMaxEnvelope - 1} {
		if err := SetMaxEnvelope(bad); err == nil {
			t.Fatalf("SetMaxEnvelope(%d) accepted; want rejection", bad)
		}
	}
	if got := MaxEnvelope(); got != 64<<20 {
		t.Fatalf("rejected values changed the limit to %d; want the prior override %d", got, 64<<20)
	}
}

// TestMaxEnvelopeUpperEdgeAcceptsFullArithmetic pins the r2 overflow guard:
// the largest accepted ceiling keeps the FULL downstream arithmetic — the raw
// limit, the +128 AEAD headroom, and the RawStd base64 expansion decodeBounded
// applies, EncodedLen(n) = (n*8+5)/6 — inside positive int range, so valid
// artifacts are never spuriously rejected by an overflowed bound. The
// historical guard accepted MaxInt-1024, which overflowed exactly that
// expansion negative; anything at or beyond the safe edge is now refused.
func TestMaxEnvelopeUpperEdgeAcceptsFullArithmetic(t *testing.T) {
	t.Cleanup(func() { _ = SetMaxEnvelope(DefaultMaxEnvelope) })

	// The safe edge is accepted.
	if err := SetMaxEnvelope(MaxSettableEnvelope); err != nil {
		t.Fatalf("SetMaxEnvelope(MaxSettableEnvelope) refused: %v", err)
	}
	if got := MaxEnvelope(); got != MaxSettableEnvelope {
		t.Fatalf("MaxEnvelope = %d, want %d", got, MaxSettableEnvelope)
	}
	// The full bound arithmetic stays non-negative at the edge.
	if bound := ciphertextBound(); bound <= 0 {
		t.Fatalf("ciphertext bound overflowed at the edge limit: %d", bound)
	} else if encoded := base64.RawStdEncoding.EncodedLen(bound); encoded <= 0 {
		t.Fatalf("base64 expansion of the ciphertext bound overflowed negative at the edge limit: bound=%d encoded=%d", bound, encoded)
	}
	// A valid artifact well inside the bound still decodes at the edge limit
	// (the historical overflow rejected every artifact).
	valid := base64.RawStdEncoding.EncodeToString([]byte("edge artifact"))
	if _, err := decodeBounded(valid, ciphertextBound()); err != nil {
		t.Fatalf("decodeBounded rejected a valid artifact at the edge limit: %v", err)
	}
	// Beyond the safe edge is refused, including the historically accepted
	// MaxInt-1024 overflow value.
	for _, bad := range []int64{MaxSettableEnvelope + 1, math.MaxInt - 1024, math.MaxInt} {
		if err := SetMaxEnvelope(bad); err == nil {
			t.Fatalf("SetMaxEnvelope(%d) accepted; want overflow-guard rejection", bad)
		}
	}
	if got := MaxEnvelope(); got != MaxSettableEnvelope {
		t.Fatalf("overflow-guard refusals changed the limit to %d; want the prior edge override %d", got, MaxSettableEnvelope)
	}
}

func TestSignedReceiptRotationAndTamper(t *testing.T) {
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	claims := ReceiptClaims{Kind: "import", SubjectSHA256: hex.EncodeToString(make([]byte, 32)), InstallationID: "install-a", TenantID: 7, ProjectID: 9, KeyID: "receipt-a", IssuedAt: now.Format(time.RFC3339), Disposition: "active"}
	receipt, err := SignReceipt(claims, privA)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReceipt(receipt, map[string]ed25519.PublicKey{"receipt-a": pubA, "receipt-b": pubB}, now); err != nil {
		t.Fatal(err)
	}
	receipt.Claims.ProjectID++
	if err := VerifyReceipt(receipt, map[string]ed25519.PublicKey{"receipt-a": pubA}, now); err == nil {
		t.Fatal("tampered receipt accepted")
	}
}

func FuzzDecodeStrictEnvelope(f *testing.F) {
	f.Add([]byte(`{"schemaVersion":"setjoin.exchange.artifact-envelope/v1"}`))
	f.Add([]byte(`{"wrappedDek":"!!!","ciphertext":"!!!"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			t.Skip()
		}
		envelope, err := DecodeStrict(raw)
		if err == nil {
			_, _ = envelope.Metadata()
		}
	})
}

func receiptTestFixture(t *testing.T) (SignedReceipt, map[string]ed25519.PublicKey, time.Time) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	issue := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	claims := ReceiptClaims{Kind: "import", SubjectSHA256: hex.EncodeToString(make([]byte, 32)), InstallationID: "install-a", TenantID: 7, ProjectID: 9, KeyID: "receipt-a", IssuedAt: issue.Format(time.RFC3339), Disposition: "active"}
	receipt, err := SignReceipt(claims, priv)
	if err != nil {
		t.Fatal(err)
	}
	return receipt, map[string]ed25519.PublicKey{"receipt-a": pub}, issue
}

func TestVerifyReceiptCanonicalizationFailureFailsClosed(t *testing.T) {
	receipt, keys, issue := receiptTestFixture(t)
	// A receipt whose claims fail canonical validation (empty kind) must be
	// rejected by the claims gate itself — not merely fall through to a
	// signature mismatch over nil bytes.
	receipt.Claims.Kind = ""
	if err := VerifyReceipt(receipt, keys, issue); err == nil || err.Error() != "receipt claims invalid: invalid receipt claims" {
		t.Fatalf("VerifyReceipt with invalid claims = %v, want fail-closed claims error", err)
	}
}

func TestVerifyReceiptWithMaxAge(t *testing.T) {
	receipt, keys, issue := receiptTestFixture(t)

	if err := VerifyReceiptWithMaxAge(receipt, keys, issue.Add(time.Hour), 24*time.Hour); err != nil {
		t.Fatalf("fresh receipt within maxAge rejected: %v", err)
	}
	if err := VerifyReceiptWithMaxAge(receipt, keys, issue.Add(25*time.Hour), 24*time.Hour); err == nil || err.Error() != "receipt expired" {
		t.Fatalf("stale receipt accepted: %v, want expired", err)
	}
	// maxAge <= 0 is the explicit opt-out (plain VerifyReceipt semantics).
	if err := VerifyReceiptWithMaxAge(receipt, keys, issue.Add(1000*time.Hour), 0); err != nil {
		t.Fatalf("maxAge=0 opt-out rejected a valid receipt: %v", err)
	}
}
