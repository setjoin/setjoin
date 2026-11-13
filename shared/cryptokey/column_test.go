package cryptokey

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestEncryptDecryptColumn(t *testing.T) {
	masterKey := []byte("test-master-key-32-bytes!!!!!!")
	plaintext := []byte("sensitive column data: user email, phone, etc.")

	// Encrypt with standard profile
	ciphertext, err := EncryptColumn(plaintext, masterKey, ProfileStandard)
	if err != nil {
		t.Fatalf("EncryptColumn: %v", err)
	}
	if string(ciphertext[:4]) != string(EnvelopeMagic) {
		t.Error("column encryption should use envelope format")
	}

	// Decrypt
	decrypted, err := DecryptColumn(ciphertext, masterKey)
	if err != nil {
		t.Fatalf("DecryptColumn: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("column round-trip mismatch: got %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestEncryptColumn_NilPlaintext(t *testing.T) {
	masterKey := []byte("test-master-key-32-bytes!!!!!!")
	ciphertext, err := EncryptColumn(nil, masterKey, ProfileStandard)
	if err != nil {
		t.Fatalf("EncryptColumn nil: %v", err)
	}
	if ciphertext != nil {
		t.Error("nil plaintext should produce nil ciphertext")
	}
}

func TestDecryptColumn_NilCiphertext(t *testing.T) {
	masterKey := []byte("test-master-key-32-bytes!!!!!!")
	plaintext, err := DecryptColumn(nil, masterKey)
	if err != nil {
		t.Fatalf("DecryptColumn nil: %v", err)
	}
	if plaintext != nil {
		t.Error("nil ciphertext should produce nil plaintext")
	}
}

func TestDecryptColumn_OldFormat_Compatibility(t *testing.T) {
	// If a column was encrypted before envelope format existed (raw AES-GCM),
	// we should detect the missing magic bytes and fall back gracefully.
	masterKey := []byte("test-master-key-32-bytes!!!!!!")
	badEnvelope := []byte("RAW_OLD_FORMAT_DATA_WITHOUT_ENVELOPE_")

	_, err := DecryptColumn(badEnvelope, masterKey)
	if err == nil {
		t.Error("expected error for old-format data without envelope magic")
	}
}

// TestDecryptColumn_CrossKey pins that a column sealed under master key A does
// NOT decrypt under master key B: the re-derived column key diverges and GCM
// auth fails. The result must be an error with no recovered plaintext — never
// garbage masquerading as the cleartext column value.
func TestDecryptColumn_CrossKey(t *testing.T) {
	keyA := []byte("master-key-A-32-bytes-padding!!!")
	keyB := []byte("master-key-B-different-32-bytes!")
	plaintext := []byte("sensitive column under key A")

	ciphertext, err := EncryptColumn(plaintext, keyA, ProfileStandard)
	if err != nil {
		t.Fatalf("EncryptColumn: %v", err)
	}

	got, err := DecryptColumn(ciphertext, keyB)
	if err == nil {
		t.Fatal("SECURITY: column decrypted under the wrong master key — expected error")
	}
	if bytes.Equal(got, plaintext) {
		t.Fatal("SECURITY: cross-key column decrypt recovered the plaintext")
	}
}

// TestDecryptColumn_GarbageKeyLenHeader exercises the early
// binary.BigEndian.Uint32(ciphertext[5:9]) read + HKDF re-derive path with a
// non-envelope blob carrying an arbitrary (large) keyLen in the header. It must
// error cleanly — never panic (e.g. on a huge make([]byte, keyLen)) and never
// return plaintext. TestDecryptColumn_OldFormat covers a specific short string;
// this covers the "valid-length blob with garbage keyLen header" shape.
func TestDecryptColumn_GarbageKeyLenHeader(t *testing.T) {
	masterKey := []byte("test-master-key-32-bytes!!!!!!")

	// Build a >=13-byte blob: valid magic, junk algo, and a keyLen of 64 (which
	// no profile produces) so the re-derived key length cannot match any real
	// envelope. Bytes after the header are arbitrary.
	blob := make([]byte, 64)
	copy(blob[0:4], EnvelopeMagic)
	blob[4] = 0x00 // claim AES
	binary.BigEndian.PutUint32(blob[5:9], 64)
	binary.BigEndian.PutUint16(blob[11:13], 12) // claim a 12-byte nonce
	for i := 13; i < len(blob); i++ {
		blob[i] = byte(i)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("SECURITY: DecryptColumn panicked on garbage keyLen header: %v", r)
		}
	}()

	pt, err := DecryptColumn(blob, masterKey)
	if err == nil {
		t.Fatalf("expected error for garbage keyLen header, got plaintext %q", pt)
	}
	if pt != nil {
		t.Fatalf("SECURITY: garbage-header column returned non-nil plaintext %q", pt)
	}
}

func TestEncryptColumn_SM4(t *testing.T) {
	masterKey := make([]byte, 16)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	plaintext := []byte("国密数据库列加密")

	ciphertext, err := EncryptColumn(plaintext, masterKey, ProfileSMx)
	if err != nil {
		t.Fatalf("EncryptColumn SM4: %v", err)
	}
	if AlgorithmTag(ciphertext[4]) != AlgoSM4GCM {
		t.Errorf("expected SM4-GCM tag, got %d", ciphertext[4])
	}

	decrypted, err := DecryptColumn(ciphertext, masterKey)
	if err != nil {
		t.Fatalf("DecryptColumn SM4: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Error("SM4 column round-trip mismatch")
	}
}
