package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setTestTLS(t *testing.T) {
	t.Helper()
	t.Setenv("TLS_CERT", "/tmp/setjoin-test-cert.pem")
	t.Setenv("TLS_KEY", "/tmp/setjoin-test-key.pem")
}

func setRequiredTestEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	t.Setenv("MINIO_ACCESS_KEY", "testaccess")
	t.Setenv("MINIO_SECRET_KEY", "testsecret")
}

func TestLoadRejectsNonLoopbackIMAPWithoutTLS(t *testing.T) {
	setRequiredTestEnv(t)
	t.Setenv("TLS_CERT", "")
	t.Setenv("TLS_KEY", "")
	t.Setenv("IMAP_ADDR", ":143")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "IMAP_ADDR listens beyond loopback") {
		t.Fatalf("Load error = %v, want fail-closed IMAP TLS error", err)
	}
}

func TestLoadAllowsLoopbackIMAPWithoutTLS(t *testing.T) {
	setRequiredTestEnv(t)
	t.Setenv("TLS_CERT", "")
	t.Setenv("TLS_KEY", "")
	t.Setenv("IMAP_ADDR", "127.0.0.1:1143")
	// Submission is also AUTH-capable and defaults to all-interfaces :587,
	// so a certless dev posture must bind it to loopback explicitly.
	t.Setenv("SMTP_SUBMISSION_ADDR", "127.0.0.1:1587")

	if _, err := Load(); err != nil {
		t.Fatalf("Load rejected loopback-only development IMAP: %v", err)
	}
}

func TestLoadMailAttachmentPreviousSecret(t *testing.T) {
	setTestTLS(t)
	setRequiredTestEnv(t)
	t.Setenv("JWT_MAIL_ATTACHMENT_SECRET", "current-secret-32-bytes-long-enough!!!!")
	t.Setenv("JWT_MAIL_ATTACHMENT_PREVIOUS_SECRET", "previous-secret-32-bytes-long-enough!!")
	t.Setenv("IMAP_ADDR", "127.0.0.1:1143")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MailAttachmentTokenPreviousSecret != "previous-secret-32-bytes-long-enough!!" {
		t.Fatalf("previous secret env override was not loaded")
	}
	if cfg.MailAttachmentTokenSecret != "current-secret-32-bytes-long-enough!!!!" {
		t.Fatalf("current attachment secret env override was not loaded")
	}
}

func TestValidateRejectsShortMailAttachmentPreviousSecret(t *testing.T) {
	cfg := &Config{MailAttachmentTokenPreviousSecret: "short"}
	cfg.DatabaseDSN = "postgres://localhost/testdb"
	cfg.JWTSecret = "test-secret-32-bytes-long-ok-now!!"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "JWT_MAIL_ATTACHMENT_PREVIOUS_SECRET") {
		t.Fatalf("Validate error = %v, want previous-secret length error", err)
	}
}

func TestIsLoopbackListenerCoversMalformedLocalhostAndIPv6(t *testing.T) {
	tests := map[string]bool{
		"not-an-address": false,
		"localhost:143":  true,
		"[::1]:143":      true,
		"192.0.2.1:143":  false,
	}
	for addr, want := range tests {
		if got := isLoopbackListener(addr); got != want {
			t.Fatalf("isLoopbackListener(%q)=%t, want %t", addr, got, want)
		}
	}
}

func TestLoadRequiresDBDSN(t *testing.T) {
	// Unset DB_DSN so it falls back to the empty default.
	os.Unsetenv("DB_DSN")
	os.Unsetenv("DB_DIRECT_DSN")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	os.Setenv("MINIO_ACCESS_KEY", "testaccess")
	os.Setenv("MINIO_SECRET_KEY", "testsecret")
	defer func() {
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("MINIO_ACCESS_KEY")
		os.Unsetenv("MINIO_SECRET_KEY")
		os.Unsetenv("DB_DSN")
		os.Unsetenv("DB_DIRECT_DSN")
	}()

	_, err := Load()
	if err == nil {
		t.Fatal("expected Load() to return an error when DB_DSN is not set")
	}
}

func TestLoadDefaults(t *testing.T) {
	setTestTLS(t)
	oldLogFormat, hadLogFormat := os.LookupEnv("LOG_FORMAT")
	os.Unsetenv("LOG_FORMAT")
	os.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	os.Setenv("MINIO_ACCESS_KEY", "testaccess")
	os.Setenv("MINIO_SECRET_KEY", "testsecret")
	defer func() {
		if hadLogFormat {
			os.Setenv("LOG_FORMAT", oldLogFormat)
		} else {
			os.Unsetenv("LOG_FORMAT")
		}
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("MINIO_ACCESS_KEY")
		os.Unsetenv("MINIO_SECRET_KEY")
		os.Unsetenv("DB_DSN")
		os.Unsetenv("DB_DIRECT_DSN")
	}()
	cfg, err := Load()
	if err != nil {
		t.Fatal("Load failed:", err)
	}
	if cfg.ListenAddr != ":80" {
		t.Errorf("expected ListenAddr :80, got %s", cfg.ListenAddr)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected LogLevel info, got %s", cfg.LogLevel)
	}
	if cfg.LogFormat != "text" {
		t.Errorf("expected LogFormat text, got %s", cfg.LogFormat)
	}
	if cfg.JWTExpiry != time.Hour {
		t.Errorf("expected JWTExpiry 1h, got %v", cfg.JWTExpiry)
	}
	if cfg.DBMaxConns != 50 {
		t.Errorf("expected DBMaxConns 50, got %d", cfg.DBMaxConns)
	}
	if cfg.SMTPInboundAddr != ":25" {
		t.Errorf("expected SMTPInboundAddr :25, got %s", cfg.SMTPInboundAddr)
	}
	if cfg.SMTPSubmissionAddr != ":587" {
		t.Errorf("expected SMTPSubmissionAddr :587, got %s", cfg.SMTPSubmissionAddr)
	}
	if cfg.IMAPAddr != ":143" {
		t.Errorf("expected IMAPAddr :143, got %s", cfg.IMAPAddr)
	}
	if cfg.IMAPTLSAddr != ":993" {
		t.Errorf("expected IMAPTLSAddr :993, got %s", cfg.IMAPTLSAddr)
	}
	if cfg.IdentityConfigSecretKeyVersion != 1 || cfg.IdentityConfigSecretRetiringKeys != "{}" {
		t.Errorf("unexpected identity secret keyring defaults: version=%d retiring=%q",
			cfg.IdentityConfigSecretKeyVersion, cfg.IdentityConfigSecretRetiringKeys)
	}
}

func TestLoadFromEnv(t *testing.T) {
	setTestTLS(t)
	os.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	os.Setenv("MINIO_ACCESS_KEY", "testaccess")
	os.Setenv("MINIO_SECRET_KEY", "testsecret")
	os.Setenv("LISTEN_ADDR", ":9090")
	os.Setenv("DB_MAX_CONNS", "50")
	os.Setenv("DB_ENCRYPTION_KEY", "test-key-32-bytes-long-ok-now!!!")
	os.Setenv("SMTP_INBOUND_ADDR", ":1025")
	os.Setenv("SMTP_SUBMISSION_ADDR", ":1587")
	os.Setenv("IMAP_ADDR", ":1143")
	os.Setenv("IDENTITY_CONFIG_SECRET_KEY", "identity-secret-key-32-bytes-long!")
	os.Setenv("IDENTITY_CONFIG_SECRET_KEY_VERSION", "7")
	os.Setenv("IDENTITY_CONFIG_SECRET_RETIRING_KEYS", `{"6":"retiring-secret-key-32-bytes-long"}`)
	defer func() {
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("MINIO_ACCESS_KEY")
		os.Unsetenv("MINIO_SECRET_KEY")
		os.Unsetenv("LISTEN_ADDR")
		os.Unsetenv("DB_MAX_CONNS")
		os.Unsetenv("DB_ENCRYPTION_KEY")
		os.Unsetenv("SMTP_INBOUND_ADDR")
		os.Unsetenv("SMTP_SUBMISSION_ADDR")
		os.Unsetenv("IMAP_ADDR")
		os.Unsetenv("IDENTITY_CONFIG_SECRET_KEY")
		os.Unsetenv("IDENTITY_CONFIG_SECRET_KEY_VERSION")
		os.Unsetenv("IDENTITY_CONFIG_SECRET_RETIRING_KEYS")
		os.Unsetenv("DB_DSN")
		os.Unsetenv("DB_DIRECT_DSN")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatal("Load failed:", err)
	}
	if cfg.ListenAddr != ":9090" {
		t.Errorf("expected ListenAddr :9090, got %s", cfg.ListenAddr)
	}
	if cfg.DBMaxConns != 50 {
		t.Errorf("expected DBMaxConns 50, got %d", cfg.DBMaxConns)
	}
	if cfg.DBEncryptionKey != "test-key-32-bytes-long-ok-now!!!" {
		t.Errorf("expected DBEncryptionKey from env, got %s", cfg.DBEncryptionKey)
	}
	if cfg.SMTPInboundAddr != ":1025" {
		t.Errorf("expected SMTPInboundAddr :1025, got %s", cfg.SMTPInboundAddr)
	}
	if cfg.SMTPSubmissionAddr != ":1587" {
		t.Errorf("expected SMTPSubmissionAddr :1587, got %s", cfg.SMTPSubmissionAddr)
	}
	if cfg.IMAPAddr != ":1143" {
		t.Errorf("expected IMAPAddr :1143, got %s", cfg.IMAPAddr)
	}
	if cfg.IdentityConfigSecretKey != "identity-secret-key-32-bytes-long!" ||
		cfg.IdentityConfigSecretKeyVersion != 7 ||
		cfg.IdentityConfigSecretRetiringKeys != `{"6":"retiring-secret-key-32-bytes-long"}` {
		t.Errorf("identity config secret keyring env overrides not loaded")
	}
}

func TestLDAPSyncDefaults(t *testing.T) {
	setTestTLS(t)
	os.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	os.Setenv("MINIO_ACCESS_KEY", "testaccess")
	os.Setenv("MINIO_SECRET_KEY", "testsecret")
	defer func() {
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("MINIO_ACCESS_KEY")
		os.Unsetenv("MINIO_SECRET_KEY")
		os.Unsetenv("DB_DSN")
		os.Unsetenv("DB_DIRECT_DSN")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatal("Load failed:", err)
	}
	if cfg.LDAPSyncPort != 636 {
		t.Errorf("expected LDAPSyncPort 636, got %d", cfg.LDAPSyncPort)
	}
	if !cfg.LDAPSyncTLS {
		t.Error("expected LDAPSyncTLS true by default")
	}
	if cfg.LDAPSyncIntervalMin != 15 {
		t.Errorf("expected LDAPSyncIntervalMin 15, got %d", cfg.LDAPSyncIntervalMin)
	}
}

func TestWORMConfigDefaults(t *testing.T) {
	setTestTLS(t)
	os.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	os.Setenv("MINIO_ACCESS_KEY", "testaccess")
	os.Setenv("MINIO_SECRET_KEY", "testsecret")
	defer func() {
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("MINIO_ACCESS_KEY")
		os.Unsetenv("MINIO_SECRET_KEY")
		os.Unsetenv("DB_DSN")
		os.Unsetenv("DB_DIRECT_DSN")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatal("Load failed:", err)
	}
	if cfg.WORMRetentionDays != 2557 {
		t.Errorf("expected WORMRetentionDays 2557, got %d", cfg.WORMRetentionDays)
	}
	if cfg.WORMMode != "" {
		t.Errorf("expected WORMMode empty by default, got %q", cfg.WORMMode)
	}
	if cfg.WORMLegalHoldEnabled {
		t.Error("expected WORMLegalHoldEnabled false by default (WORM disabled)")
	}
}

func TestWORMConfigFromEnv(t *testing.T) {
	setTestTLS(t)
	os.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	os.Setenv("MINIO_ACCESS_KEY", "testaccess")
	os.Setenv("MINIO_SECRET_KEY", "testsecret")
	os.Setenv("WORM_MODE", "compliance")
	os.Setenv("WORM_RETENTION_DAYS", "3650")
	os.Setenv("WORM_LEGAL_HOLD_ENABLED", "true")
	defer func() {
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("MINIO_ACCESS_KEY")
		os.Unsetenv("MINIO_SECRET_KEY")
		os.Unsetenv("WORM_MODE")
		os.Unsetenv("WORM_RETENTION_DAYS")
		os.Unsetenv("WORM_LEGAL_HOLD_ENABLED")
		os.Unsetenv("DB_DSN")
		os.Unsetenv("DB_DIRECT_DSN")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatal("Load failed:", err)
	}
	if cfg.WORMMode != "compliance" {
		t.Errorf("expected WORMMode compliance, got %q", cfg.WORMMode)
	}
	if cfg.WORMRetentionDays != 3650 {
		t.Errorf("expected WORMRetentionDays 3650, got %d", cfg.WORMRetentionDays)
	}
	if !cfg.WORMLegalHoldEnabled {
		t.Error("expected WORMLegalHoldEnabled true")
	}
}

func TestWORMConfigLegalHoldDefaultsOn(t *testing.T) {
	setTestTLS(t)
	// When WORM_MODE is set but WORM_LEGAL_HOLD_ENABLED is not,
	// legal hold should default to true.
	os.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	os.Setenv("MINIO_ACCESS_KEY", "testaccess")
	os.Setenv("MINIO_SECRET_KEY", "testsecret")
	os.Setenv("WORM_MODE", "governance")
	defer func() {
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("MINIO_ACCESS_KEY")
		os.Unsetenv("MINIO_SECRET_KEY")
		os.Unsetenv("WORM_MODE")
		os.Unsetenv("DB_DSN")
		os.Unsetenv("DB_DIRECT_DSN")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatal("Load failed:", err)
	}
	if cfg.WORMMode != "governance" {
		t.Errorf("expected WORMMode governance, got %q", cfg.WORMMode)
	}
	if !cfg.WORMLegalHoldEnabled {
		t.Error("expected WORMLegalHoldEnabled to default true when WORM_MODE is set")
	}
}

func TestValidateEncryptionKey_Missing(t *testing.T) {
	// Ensure SETJOIN_DEV is not set
	t.Setenv("SETJOIN_DEV", "")

	cfg := &Config{}
	err := cfg.ValidateEncryptionKey()
	if err == nil {
		t.Error("expected error for missing encryption key in production")
	}
}

func TestValidateEncryptionKey_DevMode(t *testing.T) {
	t.Setenv("SETJOIN_DEV", "true")

	cfg := &Config{}
	err := cfg.ValidateEncryptionKey()
	if err != nil {
		t.Errorf("dev mode should auto-generate key, got error: %v", err)
	}
	if len(cfg.BaseConfig.DBEncryptionKey) < 32 {
		t.Errorf("auto-generated key too short: %d chars", len(cfg.BaseConfig.DBEncryptionKey))
	}
}

func TestValidateEncryptionKey_TooShort(t *testing.T) {
	cfg := &Config{}
	cfg.BaseConfig.DBEncryptionKey = "short"
	err := cfg.ValidateEncryptionKey()
	if err == nil {
		t.Error("expected error for short key")
	}
}

func TestValidateEncryptionKey_Valid(t *testing.T) {
	cfg := &Config{}
	cfg.BaseConfig.DBEncryptionKey = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" // 32 hex chars
	err := cfg.ValidateEncryptionKey()
	if err != nil {
		t.Errorf("valid key should pass: %v", err)
	}
}

func TestValidateEncryptionKey_Exact32(t *testing.T) {
	// 32 hex chars = 16 bytes, the minimum boundary
	cfg := &Config{}
	cfg.BaseConfig.DBEncryptionKey = "0123456789abcdef0123456789abcdef"
	err := cfg.ValidateEncryptionKey()
	if err != nil {
		t.Errorf("32-char key should pass: %v", err)
	}
}

func TestValidateEncryptionKey_64Chars(t *testing.T) {
	// 64 hex chars = 32 bytes (AES-256)
	cfg := &Config{}
	cfg.BaseConfig.DBEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	err := cfg.ValidateEncryptionKey()
	if err != nil {
		t.Errorf("64-char key should pass: %v", err)
	}
}

func TestValidateEncryptionKey_31Chars(t *testing.T) {
	cfg := &Config{}
	cfg.BaseConfig.DBEncryptionKey = "0123456789abcdef0123456789abcde" // 31 chars
	err := cfg.ValidateEncryptionKey()
	if err == nil {
		t.Error("expected error for 31-char key (below minimum)")
	}
}

func TestLoadWithConfigFile(t *testing.T) {
	setTestTLS(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configYAML := []byte(`
listen:
  addr: ":9999"
log:
  level: "debug"
smtp:
  inbound_addr: ":2525"
`)
	if err := os.WriteFile(configPath, configYAML, 0644); err != nil {
		t.Fatal(err)
	}

	// Required env vars for validation
	t.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	t.Setenv("MINIO_ACCESS_KEY", "testaccess")
	t.Setenv("MINIO_SECRET_KEY", "testsecret")
	// This env var should override the YAML value
	t.Setenv("LOG_LEVEL", "warn")

	cfg, err := LoadWithKoanf(configPath)
	if err != nil {
		t.Fatalf("LoadWithKoanf: %v", err)
	}

	// YAML values should be picked up
	if cfg.ListenAddr != ":9999" {
		t.Errorf("ListenAddr = %q, want %q (from YAML)", cfg.ListenAddr, ":9999")
	}
	if cfg.SMTPInboundAddr != ":2525" {
		t.Errorf("SMTPInboundAddr = %q, want %q (from YAML)", cfg.SMTPInboundAddr, ":2525")
	}
	// Env var should override YAML value
	if cfg.LogLevel != "warn" {
		t.Errorf("LogLevel = %q, want %q (env override of YAML)", cfg.LogLevel, "warn")
	}
	// Fields not in YAML or env should use defaults
	if cfg.SMTPSubmissionAddr != ":587" {
		t.Errorf("SMTPSubmissionAddr = %q, want %q (default)", cfg.SMTPSubmissionAddr, ":587")
	}
}

func TestLoadWithConfigFile_BaseRoleDSNs(t *testing.T) {
	setTestTLS(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configYAML := []byte(`
db:
  dsn: "postgres://yaml/app"
  direct_dsn: "postgres://yaml/direct"
  worker_dsn: "postgres://yaml/worker"
  owner_dsn: "postgres://yaml/owner"
`)
	if err := os.WriteFile(configPath, configYAML, 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("DB_DSN", "postgres://env/app")
	t.Setenv("DB_DIRECT_DSN", "")
	t.Setenv("DB_WORKER_DSN", "")
	t.Setenv("DB_OWNER_DSN", "")
	os.Unsetenv("DB_DIRECT_DSN")
	os.Unsetenv("DB_WORKER_DSN")
	os.Unsetenv("DB_OWNER_DSN")
	t.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	t.Setenv("MINIO_ACCESS_KEY", "testaccess")
	t.Setenv("MINIO_SECRET_KEY", "testsecret")

	cfg, err := LoadWithKoanf(configPath)
	if err != nil {
		t.Fatalf("LoadWithKoanf: %v", err)
	}
	if cfg.DatabaseDSN != "postgres://env/app" {
		t.Fatalf("DatabaseDSN = %q, want environment override", cfg.DatabaseDSN)
	}
	if cfg.DatabaseDirect != "postgres://yaml/direct" {
		t.Errorf("DatabaseDirect = %q, want YAML value", cfg.DatabaseDirect)
	}
	if cfg.DatabaseWorker != "postgres://yaml/worker" {
		t.Errorf("DatabaseWorker = %q, want YAML value", cfg.DatabaseWorker)
	}
	if cfg.DatabaseOwner != "postgres://yaml/owner" {
		t.Errorf("DatabaseOwner = %q, want YAML value", cfg.DatabaseOwner)
	}
}

// TestDNSSECResolverConfigKeys is the C6 config-plumbing table test: the
// dnssec.upstream and dnssec.trusted_resolvers koanf keys bind from their
// defaults (empty) and from environment overrides (DNSSEC_UPSTREAM,
// DNSSEC_TRUSTED_RESOLVERS). dnssec.enabled semantics are unchanged.
func TestDNSSECResolverConfigKeys(t *testing.T) {
	cases := []struct {
		name            string
		env             map[string]string
		wantUpstream    string
		wantTrustedList string
	}{
		{
			name:            "defaults are empty (built-in upstream, trust nothing)",
			env:             nil,
			wantUpstream:    "",
			wantTrustedList: "",
		},
		{
			name: "env overrides bind both keys",
			env: map[string]string{
				"DNSSEC_UPSTREAM":          "9.9.9.9:53",
				"DNSSEC_TRUSTED_RESOLVERS": "9.9.9.9:53,149.112.112.112:53",
			},
			wantUpstream:    "9.9.9.9:53",
			wantTrustedList: "9.9.9.9:53,149.112.112.112:53",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setTestTLS(t)
			setRequiredTestEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.DNSSECUpstream != tc.wantUpstream {
				t.Errorf("DNSSECUpstream = %q, want %q", cfg.DNSSECUpstream, tc.wantUpstream)
			}
			if cfg.DNSSECTrustedResolvers != tc.wantTrustedList {
				t.Errorf("DNSSECTrustedResolvers = %q, want %q", cfg.DNSSECTrustedResolvers, tc.wantTrustedList)
			}
			if !cfg.DNSSECEnabled {
				t.Error("DNSSECEnabled = false, want the unchanged true default")
			}
		})
	}
}

// TestLoadRejectsInvalidMinioSecure pins the strict security-value parse
// (D-MAILSERVER-INTERNAL-CONFIG-002): an unparseable MINIO_SECURE is a startup
// error naming the env key — it must never silently disable object-store TLS
// via the old parse-to-false fallback.
func TestLoadRejectsInvalidMinioSecure(t *testing.T) {
	setRequiredTestEnv(t)
	t.Setenv("MINIO_SECURE", "ture") // plausible typo — must not parse as false

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "MINIO_SECURE") {
		t.Fatalf("Load error = %v, want a MINIO_SECURE validation failure", err)
	}
}

// TestValidateRejectsUnknownSandboxFailMode pins the fail-mode spelling guard:
// only "", "open" and "closed" pass Validate — a misspelled value must refuse
// startup instead of silently widening to fail-open.
func TestValidateRejectsUnknownSandboxFailMode(t *testing.T) {
	cfg := &Config{}
	for _, mode := range []string{"", "open", "closed"} {
		cfg.SandboxFailMode = mode
		if err := cfg.sandboxFailModeValid(); err != nil {
			t.Errorf("SandboxFailMode %q: unexpected error %v", mode, err)
		}
	}
	cfg.SandboxFailMode = "cloesd"
	if err := cfg.sandboxFailModeValid(); err == nil {
		t.Error("misspelled fail mode must be rejected, got nil error")
	}
}

// TestValidateRefusesUnenforceableBackupObjectLock (occ_c878e94c) pins that a
// BACKUP_OBJECT_LOCK selection the active backup writer cannot honor is a
// startup error, not silent dead configuration: the writer never consumes the
// Object Lock fields, so accepting a value would promise WORM protection that
// never applies. Mode-less days stay allowed (no lock configured, no promise
// made), and the end-to-end Load path surfaces the same refusal.
func TestValidateRefusesUnenforceableBackupObjectLock(t *testing.T) {
	for _, mode := range []string{"governance", "compliance", "bogus"} {
		cfg := &Config{BackupObjectLock: mode}
		err := cfg.backupObjectLockHonest()
		if err == nil || !strings.Contains(err.Error(), "BACKUP_OBJECT_LOCK") {
			t.Errorf("BackupObjectLock %q: error = %v, want an unenforceable-setting refusal", mode, err)
		}
	}
	cfg := &Config{BackupObjectLockDays: 90}
	if err := cfg.backupObjectLockHonest(); err != nil {
		t.Errorf("mode-less BackupObjectLockDays=90: unexpected error %v", err)
	}

	setTestTLS(t)
	setRequiredTestEnv(t)
	t.Setenv("IMAP_ADDR", "127.0.0.1:1143")
	t.Setenv("SMTP_SUBMISSION_ADDR", "127.0.0.1:1587")
	t.Setenv("BACKUP_OBJECT_LOCK", "governance")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "BACKUP_OBJECT_LOCK") {
		t.Fatalf("Load error = %v, want a BACKUP_OBJECT_LOCK startup refusal", err)
	}
}
