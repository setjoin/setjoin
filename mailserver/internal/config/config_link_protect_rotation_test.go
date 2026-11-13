package config

// MAILSERVERD-004 (owner decision D3): link-protect dual-key overlap
// rotation. These tests pin the CONFIG side of the rotation protocol: the
// key-version + previous-secret spellings load from the environment, invalid
// values refuse startup, and the LinkProtectTokenKeys() conversion feeds a
// working rotation — a token signed under the old config verifies under the
// transition config and is rejected after the window is drained.

import (
	"strings"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/linkprotect"
)

func TestLoadLinkProtectKeyRotationConfig(t *testing.T) {
	setTestTLS(t)
	setRequiredTestEnv(t)
	t.Setenv("JWT_LINK_PROTECT_TOKEN_VERSION", "2")
	t.Setenv("JWT_LINK_PROTECT_TOKEN_PREVIOUS_SECRET", "retired-link-protect-secret-32-bytes!!")
	t.Setenv("IMAP_ADDR", "127.0.0.1:1143")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LinkProtectTokenVersion != 2 {
		t.Fatalf("LinkProtectTokenVersion = %d, want 2 (env override not loaded)", cfg.LinkProtectTokenVersion)
	}
	if cfg.LinkProtectTokenPreviousSecret != "retired-link-protect-secret-32-bytes!!" {
		t.Fatalf("LinkProtectTokenPreviousSecret env override was not loaded")
	}
}

func TestLoadLinkProtectKeyConfigDefaultsToVersion1(t *testing.T) {
	setTestTLS(t)
	setRequiredTestEnv(t)
	t.Setenv("IMAP_ADDR", "127.0.0.1:1143")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LinkProtectTokenVersion != 1 {
		t.Fatalf("LinkProtectTokenVersion default = %d, want 1 (pre-rotation derivation)", cfg.LinkProtectTokenVersion)
	}
	if cfg.LinkProtectTokenPreviousSecret != "" {
		t.Fatalf("LinkProtectTokenPreviousSecret default = %q, want empty (no rotation window)", cfg.LinkProtectTokenPreviousSecret)
	}
	// The default config builds the byte-identical pre-rotation key set: an
	// install that never rotates derives exactly the historical version-1 key.
	keys := cfg.LinkProtectTokenKeys()
	if keys.Version != 1 || len(keys.PreviousSecret) != 0 {
		t.Fatalf("default LinkProtectTokenKeys = {v%d, prev:%d bytes}, want {v1, none}", keys.Version, len(keys.PreviousSecret))
	}
}

func TestValidateNormalizesUnsetLinkProtectTokenVersion(t *testing.T) {
	cfg := &Config{}
	cfg.DatabaseDSN = "postgres://localhost/testdb"
	cfg.JWTSecret = "test-secret-32-bytes-long-ok-now!!"
	cfg.S3AccessKey = "testaccess"
	cfg.S3SecretKey = "testsecret"
	cfg.SMTPInboundAddr = ":25"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate with unset version: %v", err)
	}
	if cfg.LinkProtectTokenVersion != 1 {
		t.Fatalf("unset LinkProtectTokenVersion must normalize to 1, got %d", cfg.LinkProtectTokenVersion)
	}
}

func TestValidateRejectsNegativeLinkProtectTokenVersion(t *testing.T) {
	cfg := &Config{LinkProtectTokenVersion: -1}
	cfg.DatabaseDSN = "postgres://localhost/testdb"
	cfg.JWTSecret = "test-secret-32-bytes-long-ok-now!!"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "JWT_LINK_PROTECT_TOKEN_VERSION") {
		t.Fatalf("Validate error = %v, want link-protect key version error", err)
	}
}

// TestLoadRejectsMalformedLinkProtectTokenVersion pins the STRICT version
// parse (Astra impl-d3 P2): k.Int silently mapped any unparsable value to 0,
// which the version-1 normalization accepted — so JWT_LINK_PROTECT_TOKEN_
// VERSION=bogus passed validation and silently disabled previous-key
// selection mid-rotation. A malformed spelling must now refuse startup; only
// an UNSET key normalizes to version 1.
func TestLoadRejectsMalformedLinkProtectTokenVersion(t *testing.T) {
	for _, bogus := range []string{"bogus", "2.5", "1x", "v2"} {
		t.Run(bogus, func(t *testing.T) {
			setTestTLS(t)
			setRequiredTestEnv(t)
			t.Setenv("JWT_LINK_PROTECT_TOKEN_VERSION", bogus)
			t.Setenv("IMAP_ADDR", "127.0.0.1:1143")

			cfg, err := Load()
			if err == nil {
				t.Fatalf("Load with JWT_LINK_PROTECT_TOKEN_VERSION=%q must refuse startup (got version %d)", bogus, cfg.LinkProtectTokenVersion)
			}
			if !strings.Contains(err.Error(), "JWT_LINK_PROTECT_TOKEN_VERSION") {
				t.Fatalf("Load error = %v, want a JWT_LINK_PROTECT_TOKEN_VERSION error", err)
			}
		})
	}

	// Surrounding whitespace is an operator-friendliness trim, not garbage:
	// a padded integer still parses to its value.
	t.Run("padded-integer-parses", func(t *testing.T) {
		setTestTLS(t)
		setRequiredTestEnv(t)
		t.Setenv("JWT_LINK_PROTECT_TOKEN_VERSION", " 3 ")
		t.Setenv("IMAP_ADDR", "127.0.0.1:1143")

		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load with padded version: %v", err)
		}
		if cfg.LinkProtectTokenVersion != 3 {
			t.Fatalf("LinkProtectTokenVersion = %d, want 3", cfg.LinkProtectTokenVersion)
		}
	})
}

// TestValidateRejectsPreviousSecretWithoutPreviousGeneration pins the pairing
// rule: the previous secret verifies ONLY at Version-1, so pairing it with
// version 1 (explicitly, or via the unset-version normalization) would leave
// dead configuration that LOOKS like an open overlap window while every
// old-key link is already rejected. That mismatched pairing must refuse
// startup.
func TestValidateRejectsPreviousSecretWithoutPreviousGeneration(t *testing.T) {
	for _, version := range []int{0, 1} {
		cfg := &Config{
			LinkProtectTokenVersion:        version,
			LinkProtectTokenPreviousSecret: "retired-link-protect-secret-32-bytes!!",
		}
		cfg.DatabaseDSN = "postgres://localhost/testdb"
		cfg.JWTSecret = "test-secret-32-bytes-long-ok-now!!"
		cfg.S3AccessKey = "testaccess"
		cfg.S3SecretKey = "testsecret"
		cfg.SMTPInboundAddr = ":25"
		err := cfg.Validate()
		if err == nil {
			t.Fatalf("Validate with version %d + previous secret must refuse startup", version)
		}
		if !strings.Contains(err.Error(), "JWT_LINK_PROTECT_TOKEN_PREVIOUS_SECRET") {
			t.Fatalf("Validate error = %v, want a previous-secret pairing error", err)
		}
	}

	// The well-formed pairing (version bumped with the previous secret kept)
	// still validates — the negative arm must not block a real rotation.
	cfg := &Config{
		LinkProtectTokenVersion:        2,
		LinkProtectTokenPreviousSecret: "retired-link-protect-secret-32-bytes!!",
	}
	cfg.DatabaseDSN = "postgres://localhost/testdb"
	cfg.JWTSecret = "test-secret-32-bytes-long-ok-now!!"
	cfg.S3AccessKey = "testaccess"
	cfg.S3SecretKey = "testsecret"
	cfg.SMTPInboundAddr = ":25"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate with version 2 + previous secret: %v", err)
	}
}

func TestValidateRejectsShortLinkProtectPreviousSecret(t *testing.T) {
	cfg := &Config{
		LinkProtectTokenVersion:        2,
		LinkProtectTokenPreviousSecret: "short",
	}
	cfg.DatabaseDSN = "postgres://localhost/testdb"
	cfg.JWTSecret = "test-secret-32-bytes-long-ok-now!!"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "JWT_LINK_PROTECT_TOKEN_PREVIOUS_SECRET") {
		t.Fatalf("Validate error = %v, want previous-secret length error", err)
	}
}

// TestLinkProtectTokenKeys_ConfigDrivenRotation pins the full CONFIG-side
// rotation path: a token minted under the pre-rotation config verifies under
// the rotated config (version bumped + new secret + previous secret) and is
// rejected again once the window is drained (previous secret dropped).
func TestLinkProtectTokenKeys_ConfigDrivenRotation(t *testing.T) {
	oldSecret := "pre-rotation-gateway-secret-32-bytes!!"
	newSecret := "post-rotation-gateway-secret-32-bytes!"

	oldCfg := &Config{LinkProtectTokenVersion: 1}
	oldCfg.JWTSecret = oldSecret
	claims := linkprotect.TokenClaims{
		URL:       "https://example.com/in-live-mail",
		MessageID: "msg-rotation",
		MailboxID: 7,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour).Unix(),
	}
	token, err := linkprotect.SignTokenN(claims, oldCfg.LinkProtectTokenKeys())
	if err != nil {
		t.Fatalf("SignTokenN under the pre-rotation config: %v", err)
	}

	// Rotation wired: version bumped to 2, gateway secret replaced, retiring
	// secret kept for the overlap window.
	transitionCfg := &Config{
		LinkProtectTokenVersion:        2,
		LinkProtectTokenPreviousSecret: oldSecret,
	}
	transitionCfg.JWTSecret = newSecret
	keys := transitionCfg.LinkProtectTokenKeys()
	if keys.Version != 2 || string(keys.PreviousSecret) != oldSecret || string(keys.Secret) != newSecret {
		t.Fatalf("transition config built the wrong key set: %+v", keys)
	}
	if _, err := linkprotect.VerifyTokenN(token, keys); err != nil {
		t.Fatalf("pre-rotation token must verify under the rotated config keys: %v", err)
	}

	// Window drained: previous secret removed, version and secret unchanged.
	drainedCfg := &Config{LinkProtectTokenVersion: 2}
	drainedCfg.JWTSecret = newSecret
	if _, err := linkprotect.VerifyTokenN(token, drainedCfg.LinkProtectTokenKeys()); err == nil {
		t.Fatal("pre-rotation token must be rejected after the rotation window is drained")
	}
}
