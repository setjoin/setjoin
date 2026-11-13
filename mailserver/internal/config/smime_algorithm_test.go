package config

import (
	"strings"
	"testing"
)

// smime_algorithm_config_test.go — owner decision A5: the smime.encrypt_algorithm
// config key (env SMIME_ENCRYPT_ALGORITHM) selects the outbound S/MIME content-
// encryption algorithm. Default "aes-256-gcm" (CMS AuthEnvelopedData, RFC 5083);
// "aes-256-cbc" is the S/MIME 3.2 fallback; an unknown spelling must refuse
// startup (Validate) rather than silently change the wire format peers see.

// loadWithSMIMEAlg runs Load with the minimal required env plus (optionally) the
// SMIME_ENCRYPT_ALGORITHM override; t.Setenv restores everything afterwards.
func loadWithSMIMEAlg(t *testing.T, alg string) (*Config, error) {
	t.Helper()
	setTestTLS(t)
	t.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("MINIO_ACCESS_KEY", "testaccess")
	t.Setenv("MINIO_SECRET_KEY", "testsecret")
	t.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	if alg != "" {
		t.Setenv("SMIME_ENCRYPT_ALGORITHM", alg)
	}
	return Load()
}

func TestSMIMEEncryptAlgorithmDefaultsToGCM(t *testing.T) {
	cfg, err := loadWithSMIMEAlg(t, "")
	if err != nil {
		t.Fatal("Load failed:", err)
	}
	if cfg.SMIMEEncryptAlgorithm != "aes-256-gcm" {
		t.Errorf("default SMIMEEncryptAlgorithm = %q, want %q (owner decision A5)",
			cfg.SMIMEEncryptAlgorithm, "aes-256-gcm")
	}
}

func TestSMIMEEncryptAlgorithmCBCFallbackFromEnv(t *testing.T) {
	cfg, err := loadWithSMIMEAlg(t, "aes-256-cbc")
	if err != nil {
		t.Fatal("Load failed:", err)
	}
	if cfg.SMIMEEncryptAlgorithm != "aes-256-cbc" {
		t.Errorf("SMIMEEncryptAlgorithm = %q, want %q", cfg.SMIMEEncryptAlgorithm, "aes-256-cbc")
	}
}

func TestSMIMEEncryptAlgorithmInvalidRefusesLoad(t *testing.T) {
	_, err := loadWithSMIMEAlg(t, "rot13")
	if err == nil {
		t.Fatal("Load must refuse an unknown SMIME_ENCRYPT_ALGORITHM")
	}
	if !strings.Contains(err.Error(), "SMIME_ENCRYPT_ALGORITHM") {
		t.Errorf("error must name the config key, got: %v", err)
	}
}
