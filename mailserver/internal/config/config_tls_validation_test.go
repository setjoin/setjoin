package config

import (
	"strings"
	"testing"
)

// baseValidateConfig returns a Config that passes ValidateBase and the
// object-storage credential checks, so each case isolates the listener
// TLS validation under test.
func baseValidateConfig() *Config {
	cfg := &Config{}
	cfg.DatabaseDSN = "postgres://test:test@localhost:5432/testdb"
	cfg.JWTSecret = "test-secret-32-bytes-long-ok-now!!"
	cfg.S3AccessKey = "testaccess"
	cfg.S3SecretKey = "testsecret"
	return cfg
}

func TestValidateRefusesCertlessNonLoopbackSubmission(t *testing.T) {
	tests := []struct {
		name    string
		submAdd string
		cert    string
		key     string
		wantErr bool
	}{
		{name: "default all-interfaces binding certless", submAdd: ":587", wantErr: true},
		{name: "custom all-interfaces binding certless", submAdd: ":1587", wantErr: true},
		{name: "wildcard IPv4 certless", submAdd: "0.0.0.0:1587", wantErr: true},
		{name: "routable IPv4 certless", submAdd: "192.0.2.1:1587", wantErr: true},
		{name: "explicit TLS all-interfaces passes", submAdd: ":1587", cert: "/tmp/setjoin-test-cert.pem", key: "/tmp/setjoin-test-key.pem"},
		{name: "loopback IPv4 certless passes", submAdd: "127.0.0.1:1587"},
		{name: "loopback IPv6 certless passes", submAdd: "[::1]:1587"},
		{name: "localhost certless passes", submAdd: "localhost:1587"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseValidateConfig()
			cfg.SMTPSubmissionAddr = tt.submAdd
			cfg.TLSCertFile = tt.cert
			cfg.TLSKeyFile = tt.key
			err := cfg.Validate()
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "SMTP_SUBMISSION_ADDR listens beyond loopback") {
					t.Fatalf("Validate error = %v, want fail-closed submission TLS error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate rejected submission binding %q: %v", tt.submAdd, err)
			}
		})
	}
}

func TestValidateInboundOnlyCertlessStillPasses(t *testing.T) {
	// The inbound MTA listener (port 25) never offers AUTH, so it stays
	// outside the fail-closed AUTH-listener TLS invariant.
	cfg := baseValidateConfig()
	cfg.SMTPInboundAddr = ":25"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate rejected certless non-AUTH inbound listener: %v", err)
	}
}

func TestLoadDefaultConfigRefusesCertlessSubmission(t *testing.T) {
	setRequiredTestEnv(t)
	t.Setenv("TLS_CERT", "")
	t.Setenv("TLS_KEY", "")
	t.Setenv("IMAP_ADDR", "127.0.0.1:1143")
	// SMTP_SUBMISSION_ADDR is left unset on purpose: it defaults to the
	// all-interfaces :587 binding, so a certless default config must
	// refuse to start rather than serve AUTH in cleartext.
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "SMTP_SUBMISSION_ADDR listens beyond loopback") {
		t.Fatalf("Load error = %v, want default certless :587 submission refused", err)
	}
}

func TestLoadExplicitTLSAllowsDefaultSubmission(t *testing.T) {
	setTestTLS(t)
	setRequiredTestEnv(t)
	t.Setenv("IMAP_ADDR", "127.0.0.1:1143")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load with explicit TLS rejected default submission binding: %v", err)
	}
	if cfg.SMTPSubmissionAddr != ":587" {
		t.Fatalf("SMTPSubmissionAddr = %q, want default :587", cfg.SMTPSubmissionAddr)
	}
}
