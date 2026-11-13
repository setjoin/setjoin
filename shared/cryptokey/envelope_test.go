package cryptokey

import (
	"bytes"
	"testing"
)

// --- Negative security invariants (WAVE 11 / Cand 4) ---
//
// The envelope header (magic, algo tag, key length) is self-describing and is
// NOT covered by the GCM AAD (buildEnvelope only feeds the caller's aad to
// gcm.Seal). The security property "you cannot open an AES-sealed envelope with
// an SM4 key, or flip the algo tag and get plaintext" therefore rests entirely
// on GCM key-schedule divergence plus the explicit keyLen guard. These tests pin
// that the *unsafe* outcome (a plaintext return under the wrong cipher / key) is
// the failing case.

// TestEnvelope_AlgoConfusion_AESFlippedToSM4 seals with AES-256-GCM, then flips
// the header algo byte to SM4. OpenEnvelope must NEVER return plaintext: either
// the 16-byte SM4 key-length check rejects it, or GCM tag verification fails.
// The invariant asserted is only "err != nil AND no plaintext".
func TestEnvelope_AlgoConfusion_AESFlippedToSM4(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("algorithm-confusion test vector")

	env, err := SealEnvelope(AlgoAES256GCM, key, plaintext, nil)
	if err != nil {
		t.Fatalf("SealEnvelope: %v", err)
	}
	if AlgorithmTag(env[4]) != AlgoAES256GCM {
		t.Fatalf("precondition: header algo = %d, want AES", env[4])
	}

	// Flip the algo tag in the clear header to claim SM4-GCM.
	confused := make([]byte, len(env))
	copy(confused, env)
	confused[4] = byte(AlgoSM4GCM)

	pt, _, err := OpenEnvelope(confused, key, nil)
	if err == nil {
		t.Fatal("SECURITY: AES envelope opened under flipped SM4 algo tag — expected error")
	}
	if pt != nil {
		t.Fatalf("SECURITY: cross-cipher open returned non-nil plaintext %q", pt)
	}
}

// TestEnvelope_AlgoConfusion_SM4FlippedToAES is the mirror: seal with SM4-GCM
// (16-byte key), flip the algo byte to AES-256-GCM. AES requires a 16/24/32-byte
// key; a 16-byte key is a valid AES-128 length, so aes.NewCipher succeeds — the
// guard here is GCM tag verification under a different key schedule. Either way:
// error, never plaintext.
func TestEnvelope_AlgoConfusion_SM4FlippedToAES(t *testing.T) {
	key := make([]byte, 16) // SM4-128
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("国密 reverse confusion test")

	env, err := SealEnvelope(AlgoSM4GCM, key, plaintext, nil)
	if err != nil {
		t.Fatalf("SealEnvelope SM4: %v", err)
	}
	if AlgorithmTag(env[4]) != AlgoSM4GCM {
		t.Fatalf("precondition: header algo = %d, want SM4", env[4])
	}

	confused := make([]byte, len(env))
	copy(confused, env)
	confused[4] = byte(AlgoAES256GCM)

	pt, _, err := OpenEnvelope(confused, key, nil)
	if err == nil {
		t.Fatal("SECURITY: SM4 envelope opened under flipped AES algo tag — expected error")
	}
	if pt != nil {
		t.Fatalf("SECURITY: cross-cipher open returned non-nil plaintext %q", pt)
	}
}

// TestEnvelope_KeySizeMismatch_Rejected pins the explicit keyLen != len(key)
// guard (envelope.go): a 32-byte envelope opened with a 16-byte key (and the
// reverse) must return the explicit mismatch error, NOT silently truncate /
// pad / read past the key. The match path is tested elsewhere; this is the
// rejection half.
func TestEnvelope_KeySizeMismatch_Rejected(t *testing.T) {
	key32 := make([]byte, 32)
	key16 := make([]byte, 16)
	for i := range key32 {
		key32[i] = byte(i)
	}
	for i := range key16 {
		key16[i] = byte(i)
	}

	// 32-byte (AES) envelope opened with a 16-byte key.
	envAES, err := SealEnvelope(AlgoAES256GCM, key32, []byte("mismatch-a"), nil)
	if err != nil {
		t.Fatalf("SealEnvelope AES: %v", err)
	}
	if pt, _, err := OpenEnvelope(envAES, key16, nil); err == nil {
		t.Fatalf("SECURITY: 32-byte envelope opened with 16-byte key (plaintext=%q) — expected mismatch error", pt)
	}

	// 16-byte (SM4) envelope opened with a 32-byte key.
	envSM4, err := SealEnvelope(AlgoSM4GCM, key16, []byte("mismatch-b"), nil)
	if err != nil {
		t.Fatalf("SealEnvelope SM4: %v", err)
	}
	if pt, _, err := OpenEnvelope(envSM4, key32, nil); err == nil {
		t.Fatalf("SECURITY: 16-byte envelope opened with 32-byte key (plaintext=%q) — expected mismatch error", pt)
	}
}

// TestEnvelope_CrossKey_NoPlaintext seals under master key A and opens under a
// same-length but different master key B. GCM authentication must fail — never
// silently return garbage as if it were plaintext.
func TestEnvelope_CrossKey_NoPlaintext(t *testing.T) {
	keyA := make([]byte, 32)
	keyB := make([]byte, 32)
	for i := range keyA {
		keyA[i] = byte(i)
		keyB[i] = byte(255 - i)
	}
	plaintext := []byte("cross-key open must fail")

	env, err := SealEnvelope(AlgoAES256GCM, keyA, plaintext, nil)
	if err != nil {
		t.Fatalf("SealEnvelope: %v", err)
	}
	pt, _, err := OpenEnvelope(env, keyB, nil)
	if err == nil {
		t.Fatal("SECURITY: envelope opened under the wrong (different) key — expected error")
	}
	if bytes.Equal(pt, plaintext) {
		t.Fatal("SECURITY: cross-key open recovered the plaintext")
	}
}

func TestEnvelopeMagicBytes(t *testing.T) {
	if string(EnvelopeMagic) != "EK01" {
		t.Errorf("EnvelopeMagic = %q, want %q", string(EnvelopeMagic), "EK01")
	}
	if len(EnvelopeMagic) != 4 {
		t.Errorf("EnvelopeMagic length = %d, want 4", len(EnvelopeMagic))
	}
}

func TestAlgorithmTags(t *testing.T) {
	tests := []struct {
		algo AlgorithmTag
		name string
	}{
		{AlgoAES256GCM, "AES-256-GCM"},
		{AlgoSM4GCM, "SM4-GCM"},
		{AlgoAES256Kyber768, "AES-256-Kyber768"},
	}
	for _, tt := range tests {
		if tt.algo.String() == "" {
			t.Errorf("AlgorithmTag %d has empty name", tt.algo)
		}
	}
}

func TestEnvelopeRoundTrip_AES256GCM(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("SetJoin MAM encrypted payload — test vector")

	// Encrypt
	env, err := SealEnvelope(AlgoAES256GCM, key, plaintext, nil)
	if err != nil {
		t.Fatalf("SealEnvelope: %v", err)
	}

	// Verify magic bytes
	if string(env[:4]) != string(EnvelopeMagic) {
		t.Errorf("envelope magic = %q, want %q", string(env[:4]), string(EnvelopeMagic))
	}

	// Verify algorithm tag at byte 4
	if AlgorithmTag(env[4]) != AlgoAES256GCM {
		t.Errorf("algorithm tag = %d, want %d", env[4], AlgoAES256GCM)
	}

	// Decrypt
	decrypted, algo, err := OpenEnvelope(env, key, nil)
	if err != nil {
		t.Fatalf("OpenEnvelope: %v", err)
	}
	if algo != AlgoAES256GCM {
		t.Errorf("OpenEnvelope algo = %d, want %d", algo, AlgoAES256GCM)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestEnvelopeRoundTrip_SM4GCM(t *testing.T) {
	key := make([]byte, 16) // SM4-128
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("国密 SM4-GCM 加密测试数据")

	env, err := SealEnvelope(AlgoSM4GCM, key, plaintext, nil)
	if err != nil {
		t.Fatalf("SealEnvelope SM4: %v", err)
	}
	if AlgorithmTag(env[4]) != AlgoSM4GCM {
		t.Errorf("algorithm tag = %d, want %d", env[4], AlgoSM4GCM)
	}

	decrypted, algo, err := OpenEnvelope(env, key, nil)
	if err != nil {
		t.Fatalf("OpenEnvelope SM4: %v", err)
	}
	if algo != AlgoSM4GCM {
		t.Errorf("OpenEnvelope algo = %d, want %d", algo, AlgoSM4GCM)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("round-trip mismatch for SM4-GCM")
	}
}

func TestEnvelope_TamperedData(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("tamper test")

	env, err := SealEnvelope(AlgoAES256GCM, key, plaintext, nil)
	if err != nil {
		t.Fatalf("SealEnvelope: %v", err)
	}

	// Flip a bit in the ciphertext portion (skip header: 4 magic + 1 algo + 4 key_len + 2 reserved + 2 nonce_len + 12 nonce = 25 bytes)
	tampered := make([]byte, len(env))
	copy(tampered, env)
	tampered[len(env)-1] ^= 0x01

	_, _, err = OpenEnvelope(tampered, key, nil)
	if err == nil {
		t.Error("expected error for tampered ciphertext, got nil")
	}
}

func TestEnvelope_BadMagic(t *testing.T) {
	key := make([]byte, 32)
	bad := make([]byte, 30)
	copy(bad[:4], []byte("BAD0"))
	bad[4] = 0 // AES-256-GCM

	_, _, err := OpenEnvelope(bad, key, nil)
	if err == nil {
		t.Error("expected error for bad magic bytes")
	}
}

func TestEnvelope_UnknownAlgorithm(t *testing.T) {
	key := make([]byte, 32)
	unknown := make([]byte, 30)
	copy(unknown[:4], EnvelopeMagic)
	unknown[4] = 0xFF // Unknown algorithm

	_, _, err := OpenEnvelope(unknown, key, nil)
	if err == nil {
		t.Error("expected error for unknown algorithm")
	}
}

func TestSealEnvelopeDeterministic_SameInputSameOutput(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	plaintext := []byte("deterministic test")

	env1, err := SealEnvelopeDeterministic(AlgoAES256GCM, key, nonce, plaintext, nil)
	if err != nil {
		t.Fatalf("SealEnvelopeDeterministic #1: %v", err)
	}
	env2, err := SealEnvelopeDeterministic(AlgoAES256GCM, key, nonce, plaintext, nil)
	if err != nil {
		t.Fatalf("SealEnvelopeDeterministic #2: %v", err)
	}

	if string(env1) != string(env2) {
		t.Error("deterministic seal must produce identical output for same inputs")
	}
}

func TestSealEnvelopeDeterministic_CanDecrypt(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	plaintext := []byte("deterministic decrypt test")

	env, err := SealEnvelopeDeterministic(AlgoAES256GCM, key, nonce, plaintext, nil)
	if err != nil {
		t.Fatalf("SealEnvelopeDeterministic: %v", err)
	}

	decrypted, algo, err := OpenEnvelope(env, key, nil)
	if err != nil {
		t.Fatalf("OpenEnvelope of deterministic: %v", err)
	}
	if algo != AlgoAES256GCM {
		t.Errorf("algo = %d, want %d", algo, AlgoAES256GCM)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestAlgorithmTagFromProfile(t *testing.T) {
	tests := []struct {
		profile CryptoProfile
		want    AlgorithmTag
	}{
		{ProfileStandard, AlgoAES256GCM},
		{ProfileSMx, AlgoSM4GCM},
		{ProfileHybrid, AlgoAES256GCM},
		{CryptoProfile("unknown"), AlgoAES256GCM},
	}

	for _, tt := range tests {
		got := AlgorithmTagFromProfile(tt.profile)
		if got != tt.want {
			t.Errorf("AlgorithmTagFromProfile(%q) = %d, want %d", tt.profile, got, tt.want)
		}
	}
}

func TestOpenEnvelopeRejectsHostileHeaderWithoutPanic(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	valid, err := SealEnvelope(AlgoAES256GCM, key, []byte("payload"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func([]byte) []byte{
		"nonzero reserved":  func(in []byte) []byte { in[9] = 1; return in },
		"zero nonce":        func(in []byte) []byte { in[11], in[12] = 0, 0; return in },
		"oversized nonce":   func(in []byte) []byte { in[11], in[12] = 0xff, 0xff; return in },
		"short tag":         func(in []byte) []byte { return in[:13+12+15] },
		"unknown algorithm": func(in []byte) []byte { in[4] = 0xff; return in },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := mutate(append([]byte(nil), valid...))
			if _, _, err := OpenEnvelope(candidate, key, []byte("aad")); err == nil {
				t.Fatal("hostile envelope accepted")
			}
		})
	}
}
