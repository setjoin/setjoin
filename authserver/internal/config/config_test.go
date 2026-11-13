package config

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/cryptokey"
)

// captureSlog redirects the default logger into a buffer for warning
// assertions (same pattern as the shared/config base tests).
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestLoadRequiresDBDSN(t *testing.T) {
	os.Unsetenv("DB_DSN")
	os.Unsetenv("DB_DIRECT_DSN")
	os.Setenv("INTERNAL_API_KEY", "test-api-key-for-authserver-tests")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	defer func() {
		os.Unsetenv("DB_DSN")
		os.Unsetenv("DB_DIRECT_DSN")
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("INTERNAL_API_KEY")
	}()

	_, err := Load()
	if err == nil {
		t.Fatal("expected Load() to return an error when DB_DSN is not set")
	}
}

func TestLoadDefaults(t *testing.T) {
	os.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("INTERNAL_API_KEY", "test-api-key-for-authserver-tests")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	defer func() {
		os.Unsetenv("DB_DSN")
		os.Unsetenv("DB_DIRECT_DSN")
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("INTERNAL_API_KEY")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatal("Load failed:", err)
	}
	if cfg.ListenAddr != "127.0.0.1:8443" {
		t.Errorf("expected the loopback default ListenAddr 127.0.0.1:8443, got %s (the wildcard cleartext default is refused by config validation)", cfg.ListenAddr)
	}
	if cfg.Hostname != "localhost" {
		t.Errorf("expected Hostname localhost, got %s", cfg.Hostname)
	}
	if cfg.JWTExpiry != time.Hour {
		t.Errorf("expected JWTExpiry 1h, got %v", cfg.JWTExpiry)
	}
	if cfg.JWTRefreshExpiry != 720*time.Hour {
		t.Errorf("expected JWTRefreshExpiry 720h, got %v", cfg.JWTRefreshExpiry)
	}
	if cfg.JWTIssuer != "mailserver" {
		t.Errorf("expected JWTIssuer mailserver, got %s", cfg.JWTIssuer)
	}
	if cfg.DBMaxConns != 25 {
		t.Errorf("expected DBMaxConns 25, got %d", cfg.DBMaxConns)
	}
	if cfg.OIDCProviderPrivateKeyFile != "/opt/setjoin/oidc_key.pem" ||
		cfg.OIDCProviderPublicKeyFile != "/opt/setjoin/oidc_pub.pem" {
		t.Fatalf("unexpected OIDC provider key defaults: %q %q",
			cfg.OIDCProviderPrivateKeyFile, cfg.OIDCProviderPublicKeyFile)
	}
}

func TestLoadOIDCProviderFromDocumentedEnv(t *testing.T) {
	t.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	t.Setenv("OIDC_PROVIDER_ENABLED", "true")
	t.Setenv("OIDC_PROVIDER_PRIVATE_KEY_FILE", "/tmp/op-private.pem")
	t.Setenv("OIDC_PROVIDER_PUBLIC_KEY_FILE", "/tmp/op-public.pem")
	t.Setenv("OIDC_PROVIDER_ALLOWED_ORIGINS", "https://spa.example.test")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.OIDCProviderEnabled {
		t.Fatal("OIDC_PROVIDER_ENABLED did not enable the provider")
	}
	if cfg.OIDCProviderPrivateKeyFile != "/tmp/op-private.pem" ||
		cfg.OIDCProviderPublicKeyFile != "/tmp/op-public.pem" {
		t.Fatalf("OIDC provider key paths did not load: %q %q",
			cfg.OIDCProviderPrivateKeyFile, cfg.OIDCProviderPublicKeyFile)
	}
	if cfg.OIDCProviderAllowedOrigins != "https://spa.example.test" {
		t.Fatalf("OIDC provider allowed origins did not load: %q", cfg.OIDCProviderAllowedOrigins)
	}
}

func TestLoadRejectsMissingOrSharedOIDCProviderKeyPaths(t *testing.T) {
	for _, paths := range [][2]string{{"", "/tmp/public.pem"}, {"/tmp/same.pem", "/tmp/same.pem"}} {
		t.Run(paths[0]+"|"+paths[1], func(t *testing.T) {
			t.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
			t.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
			t.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
			t.Setenv("OIDC_PROVIDER_ENABLED", "true")
			t.Setenv("OIDC_PROVIDER_PRIVATE_KEY_FILE", paths[0])
			t.Setenv("OIDC_PROVIDER_PUBLIC_KEY_FILE", paths[1])
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "non-empty and distinct") {
				t.Fatalf("key paths %q/%q error = %v", paths[0], paths[1], err)
			}
		})
	}
}

func TestLoadRejectsUnsafeOIDCProviderOrigins(t *testing.T) {
	for _, origin := range []string{
		"*",
		"https://spa.example.test/callback",
		"https://user@spa.example.test",
		"http://spa.example.test",
	} {
		t.Run(origin, func(t *testing.T) {
			t.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
			t.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
			t.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
			t.Setenv("OIDC_PROVIDER_ENABLED", "true")
			t.Setenv("OIDC_PROVIDER_ALLOWED_ORIGINS", origin)
			if _, err := Load(); err == nil {
				t.Fatalf("unsafe OIDC provider origin %q was accepted", origin)
			}
		})
	}
}

func TestLoadAllowsLoopbackHTTPForOIDCProviderDevelopment(t *testing.T) {
	t.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	t.Setenv("OIDC_PROVIDER_ENABLED", "true")
	t.Setenv("OIDC_PROVIDER_ALLOWED_ORIGINS", "http://127.0.0.1:3000")
	if _, err := Load(); err != nil {
		t.Fatalf("loopback development origin rejected: %v", err)
	}
}

func TestLoadAllowsCommaSeparatedOriginsWithEmptySegments(t *testing.T) {
	t.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	t.Setenv("OIDC_PROVIDER_ENABLED", "true")
	t.Setenv("OIDC_PROVIDER_ALLOWED_ORIGINS", ", https://spa.example.test/, ,http://localhost:3000,")
	if _, err := Load(); err != nil {
		t.Fatalf("bounded origin list rejected: %v", err)
	}
}

func TestLoadRejectsAccessTokenBeyondRevocationWindow(t *testing.T) {
	t.Setenv("SETJOIN_CONFIG", "")
	t.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("INTERNAL_API_KEY", "test-api-key-for-authserver-tests")
	t.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	t.Setenv("JWT_EXPIRY", "721h")

	if _, err := Load(); err == nil {
		t.Fatal("JWT_EXPIRY beyond 30 days must fail configuration validation")
	}
}

func TestLoadSSOAllowSuperAdminMappingDefaultsFalse(t *testing.T) {
	os.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("INTERNAL_API_KEY", "test-api-key-for-authserver-tests")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	os.Unsetenv("SSO_ALLOW_SUPER_ADMIN_MAPPING")
	defer func() {
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("INTERNAL_API_KEY")
		os.Unsetenv("DB_DSN")
		os.Unsetenv("DB_DIRECT_DSN")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatal("Load failed:", err)
	}
	if cfg.SSOAllowSuperAdminMapping {
		t.Error("expected SSOAllowSuperAdminMapping to default to false (safe ceiling)")
	}
}

func TestLoadSSOAllowSuperAdminMappingFromEnv(t *testing.T) {
	os.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("INTERNAL_API_KEY", "test-api-key-for-authserver-tests")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	os.Setenv("SSO_ALLOW_SUPER_ADMIN_MAPPING", "true")
	defer func() {
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("INTERNAL_API_KEY")
		os.Unsetenv("DB_DSN")
		os.Unsetenv("DB_DIRECT_DSN")
		os.Unsetenv("SSO_ALLOW_SUPER_ADMIN_MAPPING")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatal("Load failed:", err)
	}
	if !cfg.SSOAllowSuperAdminMapping {
		t.Error("expected SSOAllowSuperAdminMapping true from SSO_ALLOW_SUPER_ADMIN_MAPPING=true")
	}
}

func TestLoadFromEnv(t *testing.T) {
	os.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("INTERNAL_API_KEY", "test-api-key-for-authserver-tests")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	os.Setenv("LISTEN_ADDR", "127.0.0.1:9443")
	os.Setenv("DB_MAX_CONNS", "50")
	os.Setenv("DB_ENCRYPTION_KEY", "abcdefghijklmnopqrstuvwxyz123456")
	os.Setenv("JWT_EXPIRY", "2h")
	os.Setenv("THREAT_SPRAY_WINDOW_SECS", "600")
	os.Setenv("KERBEROS_ENABLED", "true")
	os.Setenv("TARPIT_ENABLED", "false")
	defer func() {
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("INTERNAL_API_KEY")
		os.Unsetenv("LISTEN_ADDR")
		os.Unsetenv("DB_MAX_CONNS")
		os.Unsetenv("DB_ENCRYPTION_KEY")
		os.Unsetenv("JWT_EXPIRY")
		os.Unsetenv("THREAT_SPRAY_WINDOW_SECS")
		os.Unsetenv("KERBEROS_ENABLED")
		os.Unsetenv("TARPIT_ENABLED")
		os.Unsetenv("DB_DSN")
		os.Unsetenv("DB_DIRECT_DSN")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatal("Load failed:", err)
	}
	if cfg.ListenAddr != "127.0.0.1:9443" {
		t.Errorf("expected ListenAddr 127.0.0.1:9443, got %s", cfg.ListenAddr)
	}
	if cfg.DBMaxConns != 50 {
		t.Errorf("expected DBMaxConns 50, got %d", cfg.DBMaxConns)
	}
	if cfg.DBEncryptionKey != "abcdefghijklmnopqrstuvwxyz123456" {
		t.Errorf("expected DBEncryptionKey from env, got %s", cfg.DBEncryptionKey)
	}
	if cfg.JWTExpiry != 2*time.Hour {
		t.Errorf("expected JWTExpiry 2h, got %v", cfg.JWTExpiry)
	}
	if cfg.ThreatSprayWindowSecs != 600 {
		t.Errorf("expected ThreatSprayWindowSecs 600, got %d", cfg.ThreatSprayWindowSecs)
	}
	if !cfg.KerberosEnabled {
		t.Error("expected KerberosEnabled true from env")
	}
	if cfg.TarpitEnabled {
		t.Error("expected TarpitEnabled false from env")
	}
}

func TestLoadThreatDefaults(t *testing.T) {
	os.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("INTERNAL_API_KEY", "test-api-key-for-authserver-tests")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	defer func() {
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("INTERNAL_API_KEY")
		os.Unsetenv("DB_DSN")
		os.Unsetenv("DB_DIRECT_DSN")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatal("Load failed:", err)
	}
	if cfg.ThreatSprayWindowSecs != 300 {
		t.Errorf("expected ThreatSprayWindowSecs 300, got %d", cfg.ThreatSprayWindowSecs)
	}
	if cfg.ThreatSprayMaxUsers != 5 {
		t.Errorf("expected ThreatSprayMaxUsers 5, got %d", cfg.ThreatSprayMaxUsers)
	}
	if cfg.ThreatSprayLockoutMins != 30 {
		t.Errorf("expected ThreatSprayLockoutMins 30, got %d", cfg.ThreatSprayLockoutMins)
	}
	if cfg.ThreatRateLimitPerMin != 20 {
		t.Errorf("expected ThreatRateLimitPerMin 20, got %d", cfg.ThreatRateLimitPerMin)
	}
	if !cfg.ThreatFeedEnabled {
		t.Error("expected ThreatFeedEnabled true by default")
	}
	if !cfg.GeoBlockEnabled {
		t.Error("expected GeoBlockEnabled true by default")
	}
	if !cfg.SprayDetectEnabled {
		t.Error("expected SprayDetectEnabled true by default")
	}
	if !cfg.CaptchaEnabled {
		t.Error("expected CaptchaEnabled true by default")
	}
	if !cfg.TarpitEnabled {
		t.Error("expected TarpitEnabled true by default")
	}
}

func TestLoadCaptchaSecretDerivedFromJWTSecret(t *testing.T) {
	os.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("INTERNAL_API_KEY", "test-api-key-for-authserver-tests")
	os.Setenv("JWT_SECRET", "test-jwt-secret-for-captcha-fallback")
	defer func() {
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("INTERNAL_API_KEY")
		os.Unsetenv("DB_DSN")
		os.Unsetenv("DB_DIRECT_DSN")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatal("Load failed:", err)
	}
	// Key-purpose separation (D-AUTHSERVER-CMD-AUTHSERVERD-004): the captcha
	// signing key must NEVER be the raw JWT secret.
	if cfg.CaptchaSecret == "test-jwt-secret-for-captcha-fallback" {
		t.Fatal("CaptchaSecret reused the raw JWT secret — key-purpose separation broken")
	}
	if cfg.CaptchaSecret == "" {
		t.Fatal("CaptchaSecret must be derived, not left empty")
	}
	// Deterministic domain-separated HKDF derivation with the captcha info string.
	want := string(cryptokey.DeriveEncryptionKey([]byte("test-jwt-secret-for-captcha-fallback"), "mailserver-captcha-token-v1", cryptokey.ProfileStandard))
	if cfg.CaptchaSecret != want {
		t.Errorf("CaptchaSecret = derived value mismatch: got %d bytes, want %d bytes", len(cfg.CaptchaSecret), len(want))
	}
}

func TestLoadCaptchaSecretExplicitValueWins(t *testing.T) {
	os.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	os.Setenv("CAPTCHA_SECRET", "independent-captcha-secret-value")
	defer func() {
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("CAPTCHA_SECRET")
		os.Unsetenv("DB_DSN")
		os.Unsetenv("DB_DIRECT_DSN")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatal("Load failed:", err)
	}
	if cfg.CaptchaSecret != "independent-captcha-secret-value" {
		t.Errorf("explicit CAPTCHA_SECRET must win over the derived fallback, got %q", cfg.CaptchaSecret)
	}
}

func TestLoadRejectsNonPositiveOrAbsurdThreatTunables(t *testing.T) {
	for _, tc := range []struct{ env, val string }{
		{"THREAT_SPRAY_WINDOW_SECS", "0"},
		{"THREAT_SPRAY_WINDOW_SECS", "-300"},
		{"THREAT_SPRAY_WINDOW_SECS", "99999999"},
		{"THREAT_SPRAY_MAX_USERS", "0"},
		{"THREAT_SPRAY_MAX_USERS", "-1"},
		{"THREAT_SPRAY_LOCKOUT_MINS", "0"},
		{"THREAT_CAPTCHA_WINDOW_MINS", "0"},
		{"THREAT_CAPTCHA_THRESHOLD", "-3"},
		{"THREAT_TARPIT_WINDOW_MINS", "0"},
		{"THREAT_TARPIT_THRESHOLD", "0"},
		{"THREAT_RATE_LIMIT_PER_MIN", "-20"},
	} {
		t.Run(tc.env+"="+tc.val, func(t *testing.T) {
			t.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
			t.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
			t.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
			t.Setenv(tc.env, tc.val)

			_, err := Load()
			if err == nil {
				t.Fatalf("%s=%s must fail configuration validation (silent defense degradation)", tc.env, tc.val)
			}
			if !strings.Contains(err.Error(), tc.env) {
				t.Fatalf("validation error must name the offending key %s, got: %v", tc.env, err)
			}
		})
	}
}

func TestLoadRejectsUnparseableDurations(t *testing.T) {
	for _, tc := range []struct{ env, val string }{
		{"JWT_EXPIRY", "168"},
		{"JWT_EXPIRY", "soon"},
		{"JWT_REFRESH_EXPIRY", "720 h"},
		{"JWT_REFRESH_EXPIRY", "30d"},
	} {
		t.Run(tc.env+"="+tc.val, func(t *testing.T) {
			t.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
			t.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
			t.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
			t.Setenv(tc.env, tc.val)

			_, err := Load()
			if err == nil {
				t.Fatalf("%s=%q must fail configuration instead of silently substituting the default", tc.env, tc.val)
			}
			if !strings.Contains(err.Error(), tc.env) {
				t.Fatalf("validation error must name the offending key %s, got: %v", tc.env, err)
			}
		})
	}
}

func TestLoadWithConfigFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configYAML := []byte(`
listen:
  addr: "127.0.0.1:9999"
hostname: "auth.example.com"
db:
  worker_dsn: "postgres://yaml/worker"
  owner_dsn: "postgres://yaml/owner"
jwt:
  expiry: "4h"
  issuer: "setjoin-corp"
threat:
  spray_window_secs: 900
  rate_limit_per_min: 50
kerberos:
  enabled: true
webauthn:
  rp_id: "auth.example.com"
  rp_name: "Example Corp"
`)
	if err := os.WriteFile(configPath, configYAML, 0644); err != nil {
		t.Fatal(err)
	}

	// Required env vars for validation
	t.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("DB_WORKER_DSN", "")
	t.Setenv("DB_OWNER_DSN", "")
	os.Unsetenv("DB_WORKER_DSN")
	os.Unsetenv("DB_OWNER_DSN")
	t.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	// This env var should override the YAML value
	t.Setenv("JWT_ISSUER", "overridden-issuer")

	cfg, err := LoadWithKoanf(configPath)
	if err != nil {
		t.Fatalf("LoadWithKoanf: %v", err)
	}

	// YAML values should be picked up
	if cfg.ListenAddr != "127.0.0.1:9999" {
		t.Errorf("ListenAddr = %q, want %q (from YAML)", cfg.ListenAddr, "127.0.0.1:9999")
	}
	if cfg.Hostname != "auth.example.com" {
		t.Errorf("Hostname = %q, want %q (from YAML)", cfg.Hostname, "auth.example.com")
	}
	if cfg.DatabaseWorker != "postgres://yaml/worker" || cfg.DatabaseOwner != "postgres://yaml/owner" {
		t.Errorf("role DSNs = worker %q owner %q, want YAML values", cfg.DatabaseWorker, cfg.DatabaseOwner)
	}
	if cfg.JWTExpiry != 4*time.Hour {
		t.Errorf("JWTExpiry = %v, want 4h (from YAML)", cfg.JWTExpiry)
	}
	if cfg.ThreatSprayWindowSecs != 900 {
		t.Errorf("ThreatSprayWindowSecs = %d, want 900 (from YAML)", cfg.ThreatSprayWindowSecs)
	}
	if cfg.ThreatRateLimitPerMin != 50 {
		t.Errorf("ThreatRateLimitPerMin = %d, want 50 (from YAML)", cfg.ThreatRateLimitPerMin)
	}
	if !cfg.KerberosEnabled {
		t.Error("expected KerberosEnabled true from YAML")
	}
	if cfg.WebAuthnRPID != "auth.example.com" {
		t.Errorf("WebAuthnRPID = %q, want %q (from YAML)", cfg.WebAuthnRPID, "auth.example.com")
	}
	if cfg.WebAuthnRPDisplayName != "Example Corp" {
		t.Errorf("WebAuthnRPDisplayName = %q, want %q (from YAML)", cfg.WebAuthnRPDisplayName, "Example Corp")
	}

	// Env var should override YAML value
	if cfg.JWTIssuer != "overridden-issuer" {
		t.Errorf("JWTIssuer = %q, want %q (env override of YAML)", cfg.JWTIssuer, "overridden-issuer")
	}

	// Fields not in YAML or env should use defaults
	if cfg.JWTRefreshExpiry != 720*time.Hour {
		t.Errorf("JWTRefreshExpiry = %v, want 720h (default)", cfg.JWTRefreshExpiry)
	}
	if cfg.DBMaxConns != 25 {
		t.Errorf("DBMaxConns = %d, want 25 (default)", cfg.DBMaxConns)
	}
	if !cfg.TarpitEnabled {
		t.Error("expected TarpitEnabled true (default)")
	}
}

// D-AUTHSERVER-INTERNAL-CONFIG-003 (inverted arm): INTERNAL_API_KEY set with
// no connector configured has no consumer in the current topology — the load
// must say so loudly (naming the key and the absence of consumers) instead of
// letting an unused shared secret sit silently in the deployment.
func TestLoadWarnsWhenInternalAPIKeyHasNoConnectorConsumer(t *testing.T) {
	os.Unsetenv("AD_SYNC_ENABLED")
	os.Unsetenv("AD_SYNC_DOMAIN")
	defer func() {
		os.Unsetenv("AD_SYNC_ENABLED")
		os.Unsetenv("AD_SYNC_DOMAIN")
	}()
	t.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	t.Setenv("INTERNAL_API_KEY", "test-api-key-for-authserver-tests")

	buf := captureSlog(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal("Load failed:", err)
	}
	if cfg.InternalAPIKey == "" {
		t.Fatal("expected InternalAPIKey to be set")
	}
	out := buf.String()
	if !strings.Contains(out, "INTERNAL_API_KEY") || !strings.Contains(out, "no connector is configured") {
		t.Fatalf("expected loud topology WARN naming INTERNAL_API_KEY and its absent consumers, got: %q", out)
	}
	if strings.Contains(out, "INTERNAL_API_KEY is required") {
		t.Fatalf("key is set — the requirement arm must not fire, got: %q", out)
	}
}

// A set key with a configured connector (AD sync — the config-level consumer
// that requires the key) is a purposeful topology: no topology WARN.
func TestLoadNoTopologyWarnWhenConnectorConsumesInternalAPIKey(t *testing.T) {
	t.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	t.Setenv("INTERNAL_API_KEY", "test-api-key-for-authserver-tests")
	t.Setenv("AD_SYNC_ENABLED", "true")
	t.Setenv("AD_SYNC_DOMAIN", "corp.example.test")
	defer func() {
		os.Unsetenv("AD_SYNC_ENABLED")
		os.Unsetenv("AD_SYNC_DOMAIN")
	}()

	buf := captureSlog(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal("Load failed:", err)
	}
	if !cfg.ADSyncEnabled || cfg.ADSyncDomain != "corp.example.test" {
		t.Fatalf("AD sync did not load as configured: enabled=%v domain=%q", cfg.ADSyncEnabled, cfg.ADSyncDomain)
	}
	if out := buf.String(); strings.Contains(out, "no connector is configured") {
		t.Fatalf("configured connector consumes the key — topology WARN must stay silent, got: %q", out)
	}
}

// Key unset + connector configured keeps the EXISTING behavior unchanged:
// validation fails naming INTERNAL_API_KEY (the requirement arm), and the
// inverted topology WARN stays out of the picture.
func TestLoadKeyUnsetWithConnectorStillRequiresInternalAPIKey(t *testing.T) {
	os.Unsetenv("INTERNAL_API_KEY")
	defer os.Unsetenv("INTERNAL_API_KEY")
	t.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
	t.Setenv("AD_SYNC_ENABLED", "true")
	t.Setenv("AD_SYNC_DOMAIN", "corp.example.test")
	defer func() {
		os.Unsetenv("AD_SYNC_ENABLED")
		os.Unsetenv("AD_SYNC_DOMAIN")
	}()

	buf := captureSlog(t)
	if _, err := Load(); err == nil {
		t.Fatal("AD sync configured with no INTERNAL_API_KEY must keep failing validation (existing behavior unchanged)")
	} else if !strings.Contains(err.Error(), "INTERNAL_API_KEY is required") {
		t.Fatalf("expected the existing INTERNAL_API_KEY requirement error, got: %v", err)
	}
	if out := buf.String(); strings.Contains(out, "no connector is configured") {
		t.Fatalf("topology WARN belongs to the set-but-unused arm only, got: %q", out)
	}
}

// Symmetry pin: no key and no connector is the quiet default topology — load
// succeeds with no topology signal on either arm.
func TestLoadKeyUnsetWithoutConnectorEmitsNoTopologyWarn(t *testing.T) {
	os.Unsetenv("INTERNAL_API_KEY")
	defer os.Unsetenv("INTERNAL_API_KEY")
	os.Unsetenv("AD_SYNC_ENABLED")
	os.Unsetenv("AD_SYNC_DOMAIN")
	defer func() {
		os.Unsetenv("AD_SYNC_ENABLED")
		os.Unsetenv("AD_SYNC_DOMAIN")
	}()
	t.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")

	buf := captureSlog(t)
	if _, err := Load(); err != nil {
		t.Fatal("Load failed:", err)
	}
	if out := buf.String(); strings.Contains(out, "no connector is configured") || strings.Contains(out, "INTERNAL_API_KEY is required") {
		t.Fatalf("quiet default topology must emit no INTERNAL_API_KEY signal, got: %q", out)
	}
}

// -- AUTHSERVERD-005 finding 3: trusted-proxy allowlist (auth.trusted_proxy_cidrs) --

func authConfigEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")
}

func TestLoadTrustedProxyCIDRsDefaultEmpty(t *testing.T) {
	authConfigEnv(t)
	os.Unsetenv("AUTH_TRUSTED_PROXY_CIDRS")
	defer os.Unsetenv("AUTH_TRUSTED_PROXY_CIDRS")

	cfg, err := Load()
	if err != nil {
		t.Fatal("Load failed:", err)
	}
	if cfg.AuthTrustedProxyCIDRs != "" {
		t.Errorf("AuthTrustedProxyCIDRs = %q, want empty (loopback-only default)", cfg.AuthTrustedProxyCIDRs)
	}
}

func TestLoadTrustedProxyCIDRsFromEnv(t *testing.T) {
	authConfigEnv(t)
	t.Setenv("AUTH_TRUSTED_PROXY_CIDRS", "10.0.8.0/24, 192.168.1.0/28,fd7a::/48")
	cfg, err := Load()
	if err != nil {
		t.Fatal("Load failed:", err)
	}
	if cfg.AuthTrustedProxyCIDRs != "10.0.8.0/24, 192.168.1.0/28,fd7a::/48" {
		t.Errorf("AuthTrustedProxyCIDRs = %q, want the configured allowlist verbatim", cfg.AuthTrustedProxyCIDRs)
	}
}

func TestLoadAcceptsWellFormedTrustedProxyCIDRs(t *testing.T) {
	for _, list := range []string{
		"10.0.8.0/24",
		"10.0.8.5/32",               // explicit single host
		"fd7a::/48",                 // IPv6
		"fd7a::10/128",              // IPv6 single host
		"10.0.8.0/24,,fd7a::/48",    // tolerated empty segment
		" 10.0.8.0/24 , fd7a::/48 ", // tolerated whitespace
	} {
		t.Run(list, func(t *testing.T) {
			authConfigEnv(t)
			t.Setenv("AUTH_TRUSTED_PROXY_CIDRS", list)
			if _, err := Load(); err != nil {
				t.Fatalf("well-formed allowlist %q rejected: %v", list, err)
			}
		})
	}
}

func TestLoadRejectsMalformedTrustedProxyCIDRs(t *testing.T) {
	for _, list := range []string{
		"10.0.8.5",             // bare IP — must carry its /32
		"fd7a::10",             // bare IPv6 — must carry its /128
		"10.0.8.0/33",          // impossible v4 mask
		"10.0.8.0/24,badnet",   // one bad entry poisons the list
		"banana",               // not an address at all
		"10.0.8.0/24,10.0.8.5", // trailing bare host entry
	} {
		t.Run(list, func(t *testing.T) {
			authConfigEnv(t)
			t.Setenv("AUTH_TRUSTED_PROXY_CIDRS", list)
			_, err := Load()
			if err == nil {
				t.Fatalf("malformed allowlist %q must fail configuration validation", list)
			}
			if !strings.Contains(err.Error(), "AUTH_TRUSTED_PROXY_CIDRS") {
				t.Fatalf("validation error must name the offending key, got: %v", err)
			}
		})
	}
}

func TestLoadRejectsDefaultRouteTrustedProxyCIDRs(t *testing.T) {
	for _, list := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/8,0.0.0.0/0"} {
		t.Run(list, func(t *testing.T) {
			authConfigEnv(t)
			t.Setenv("AUTH_TRUSTED_PROXY_CIDRS", list)
			_, err := Load()
			if err == nil {
				t.Fatalf("default-route allowlist %q must be refused — it trusts the entire internet", list)
			}
			if !strings.Contains(err.Error(), "AUTH_TRUSTED_PROXY_CIDRS") {
				t.Fatalf("validation error must name the offending key, got: %v", err)
			}
		})
	}
}

// -- AUTHSERVERD-005 finding 1: listen.addr presence capture --

// A YAML listen.addr equal to the compiled default is still EXPLICIT config:
// presence, not value equality, decides precedence for the AUTHSERVER_URL
// listen derivation in cmd/authserverd.
func TestLoadListenAddrExplicitFromYAMLDefault(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configYAML := []byte(`
listen:
  addr: "127.0.0.1:8443"
`)
	if err := os.WriteFile(configPath, configYAML, 0600); err != nil {
		t.Fatal(err)
	}
	authConfigEnv(t)
	t.Setenv("LISTEN_ADDR", "")
	os.Unsetenv("LISTEN_ADDR")
	defer os.Unsetenv("LISTEN_ADDR")

	cfg, err := LoadWithKoanf(configPath)
	if err != nil {
		t.Fatalf("LoadWithKoanf: %v", err)
	}
	if !cfg.ListenAddrExplicit {
		t.Error("ListenAddrExplicit = false, want true: the YAML pins listen.addr even though it equals the compiled default")
	}
	if cfg.ListenAddr != "127.0.0.1:8443" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, "127.0.0.1:8443")
	}
}

func TestLoadListenAddrExplicitFromEnv(t *testing.T) {
	authConfigEnv(t)
	t.Setenv("LISTEN_ADDR", "127.0.0.1:8443")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.ListenAddrExplicit {
		t.Error("ListenAddrExplicit = false, want true: LISTEN_ADDR is set")
	}
}

func TestLoadListenAddrExplicitFalseWhenUnconfigured(t *testing.T) {
	authConfigEnv(t)
	t.Setenv("LISTEN_ADDR", "")
	os.Unsetenv("LISTEN_ADDR")
	defer os.Unsetenv("LISTEN_ADDR")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddrExplicit {
		t.Error("ListenAddrExplicit = true, want false: neither env nor YAML configures listen.addr")
	}
}

// TestLoadEmptyYAMLListenAddrFallsBackToLoopbackDefault (fault injection): a
// YAML that EXPLICITLY sets listen.addr to the empty string overrides the
// defaults layer with "" — the post-processing belt must re-apply the
// loopback-scoped default, never a wildcard or cleartext bind (the cleartext
// wildcard default refusal is the whole point of defaultListenAddr).
func TestLoadEmptyYAMLListenAddrFallsBackToLoopbackDefault(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configYAML := []byte(`
listen:
  addr: ""
`)
	if err := os.WriteFile(configPath, configYAML, 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("DB_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("DB_DIRECT_DSN", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("JWT_SECRET", "test-secret-32-bytes-long-ok-now!!")

	cfg, err := LoadWithKoanf(configPath)
	if err != nil {
		t.Fatalf("LoadWithKoanf: %v", err)
	}
	if cfg.ListenAddr != defaultListenAddr {
		t.Errorf("ListenAddr = %q, want the loopback default %q after an explicitly empty YAML listen.addr", cfg.ListenAddr, defaultListenAddr)
	}
}
