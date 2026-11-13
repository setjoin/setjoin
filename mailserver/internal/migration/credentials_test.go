package migration

import (
	"crypto/rand"
	"testing"
)

const testPurpose = "migration"

func TestDeriveKey(t *testing.T) {
	key1, err := DeriveKey("test-encryption-key-32-chars!", testPurpose)
	if err != nil {
		t.Fatal(err)
	}
	if len(key1) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key1))
	}

	key2, _ := DeriveKey("test-encryption-key-32-chars!", testPurpose)
	if string(key1) != string(key2) {
		t.Fatal("deriveKey is not deterministic")
	}
}

func TestDeriveKey_Empty(t *testing.T) {
	_, err := DeriveKey("", testPurpose)
	if err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestDeriveKey_HKDF(t *testing.T) {
	root := "test-root-key-for-hkdf-derivation-32chars-min"
	k1, err := DeriveKey(root, "migration")
	if err != nil {
		t.Fatal("derive migration key:", err)
	}
	k2, err := DeriveKey(root, "m365")
	if err != nil {
		t.Fatal("derive m365 key:", err)
	}
	if len(k1) != 32 || len(k2) != 32 {
		t.Fatalf("expected 32-byte keys, got %d and %d", len(k1), len(k2))
	}
	if string(k1) == string(k2) {
		t.Fatal("different purposes produced identical keys")
	}
}

func TestDeriveKey_Deterministic(t *testing.T) {
	root := "deterministic-test-key-32chars-minval"
	k1, _ := DeriveKey(root, "m365")
	k2, _ := DeriveKey(root, "m365")
	if string(k1) != string(k2) {
		t.Fatal("same inputs produced different keys")
	}
}

func TestDeriveKey_EmptyRoot(t *testing.T) {
	_, err := DeriveKey("", "migration")
	if err == nil {
		t.Fatal("expected error for empty root key")
	}
}

func TestLogValue_Redacted(t *testing.T) {
	// Verify LogValue returns the redacted string
	v := IMAPCredentials{}.LogValue()
	if v.String() != "***REDACTED***" {
		t.Errorf("expected ***REDACTED***, got %s", v.String())
	}

	v = IMAPConfig{}.LogValue()
	if v.String() != "***REDACTED***" {
		t.Errorf("expected ***REDACTED***, got %s", v.String())
	}
}

func TestEncryptDecrypt_M365Config(t *testing.T) {
	key, _ := DeriveKey("test-root-key-for-m365-config-test--32", "m365")
	cfg := MigrationM365Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		TenantID:     "test-tenant-id",
		Cloud:        "global",
		SourceEmail:  "source@example.com",
		SourceUserID: "immutable-user-id",
	}
	enc, err := EncryptConfigAny(cfg, key)
	if err != nil {
		t.Fatal("encrypt:", err)
	}
	var dec MigrationM365Config
	if err := DecryptConfigAny(enc, key, &dec); err != nil {
		t.Fatal("decrypt:", err)
	}
	if dec.ClientID != cfg.ClientID || dec.ClientSecret != cfg.ClientSecret ||
		dec.SourceEmail != cfg.SourceEmail || dec.SourceUserID != cfg.SourceUserID {
		t.Fatal("round-trip mismatch")
	}
}

func TestEncryptDecrypt_GlobalEWSConfig(t *testing.T) {
	key, _ := DeriveKey("test-root-key-for-ews-config-test-32ch", "system")
	cfg := GlobalEWSConfig{
		ServerURL:          "https://exchange.example.com/EWS/Exchange.asmx",
		Username:           "DOMAIN\\admin",
		Password:           "super-secret-password",
		AuthMode:           "impersonation",
		InsecureSkipVerify: true,
	}
	enc, err := EncryptConfigAny(cfg, key)
	if err != nil {
		t.Fatal("encrypt:", err)
	}
	var dec GlobalEWSConfig
	if err := DecryptConfigAny(enc, key, &dec); err != nil {
		t.Fatal("decrypt:", err)
	}
	if dec.Username != cfg.Username || dec.Password != cfg.Password {
		t.Fatal("round-trip mismatch")
	}
}

func TestMigrationM365Config_LogValue(t *testing.T) {
	cfg := MigrationM365Config{ClientSecret: "secret"}
	v := cfg.LogValue()
	if v.String() != "***REDACTED***" {
		t.Fatal("LogValue did not redact")
	}
}

// Ensure crypto/rand import is used (some linters flag unused imports)
var _ = rand.Reader
