package config

// Tests for the identity-critical file-authority gate (Options.IdentityFileAuthority).
//
// Contract under test (med-config-precedence-b1r2-012):
//   - DEFAULT OFF: the documented env-highest precedence is preserved for
//     every key, so existing valid configs boot unchanged.
//   - Opt-in ON: the file (YAML) keeps authority over the ambient environment
//     for IdentityCriticalKeys ("hostname" — the pin behind the WS origin,
//     OIDC issuer, SMTP Received identity and outbound approval/booking/push
//     URLs), and a conflicting environment value is surfaced as a loud
//     warning instead of being applied silently.
//   - Keys outside IdentityCriticalKeys keep env-highest precedence in BOTH
//     gate states (explicit compatibility boundary).

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// captureWarnings swaps the default slog logger for one that records
// Warn-or-higher records into a buffer and restores it on cleanup.
func captureWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func writeHostnameYAML(t *testing.T, hostname string) string {
	t.Helper()
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "config.yaml")
	content := "hostname: \"" + hostname + "\"\n"
	if hostname == "" {
		content = "db:\n  max_conns: 1\n" // valid YAML that does not pin hostname
	}
	// 0600: these tests capture ALL default-logger warnings to pin the
	// identity-conflict warning contract, so the fixture must carry the
	// correct config-file posture (regular owner-only file) and not trip the
	// separate permission-hygiene warning (koanf.go warnConfigFilePermissions).
	if err := os.WriteFile(yamlPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return yamlPath
}

// ambientDefaults mimics the production defaults seed: LoadBase projects the
// ambient HOSTNAME into the defaults layer before the YAML file loads.
func ambientDefaults() map[string]interface{} {
	return map[string]interface{}{
		"hostname": "container-abc123",
	}
}

func TestLoadIdentityFileAuthorityOffKeepsEnvHighest(t *testing.T) {
	// Gate OFF (the shipped default): a Docker-style HOSTNAME still wins over
	// YAML for hostname — the documented env-highest contract is unchanged.
	t.Setenv("HOSTNAME", "container-abc123")
	yamlPath := writeHostnameYAML(t, "mail.example.test")

	k, err := Load(ambientDefaults(), Options{FilePath: yamlPath})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := k.String("hostname"); got != "container-abc123" {
		t.Errorf("hostname = %q, want %q (default env-highest preserved)", got, "container-abc123")
	}
}

func TestLoadIdentityFileAuthorityYAMLBeatsAmbientHostname(t *testing.T) {
	// Gate ON: the operator's YAML hostname pin survives the ambient
	// Docker-style HOSTNAME environment, and downstream sinks read the YAML
	// value from the merged config.
	t.Setenv("HOSTNAME", "container-abc123")
	yamlPath := writeHostnameYAML(t, "mail.example.test")

	k, err := Load(ambientDefaults(), Options{FilePath: yamlPath, IdentityFileAuthority: true})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := k.String("hostname"); got != "mail.example.test" {
		t.Errorf("hostname = %q, want %q (file authority over ambient env)", got, "mail.example.test")
	}
}

func TestLoadIdentityFileAuthorityWarnsOnConflict(t *testing.T) {
	t.Run("conflict is warned loudly", func(t *testing.T) {
		t.Setenv("HOSTNAME", "container-abc123")
		yamlPath := writeHostnameYAML(t, "mail.example.test")
		warnings := captureWarnings(t)

		_, err := Load(ambientDefaults(), Options{FilePath: yamlPath, IdentityFileAuthority: true})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		out := warnings.String()
		if !strings.Contains(out, "config_key=hostname") || !strings.Contains(out, "env_var=HOSTNAME") {
			t.Errorf("expected a loud conflict warning naming config_key=hostname and env_var=HOSTNAME, got:\n%s", out)
		}
	})

	t.Run("identical values are not a conflict", func(t *testing.T) {
		t.Setenv("HOSTNAME", "mail.example.test")
		yamlPath := writeHostnameYAML(t, "mail.example.test")
		warnings := captureWarnings(t)

		_, err := Load(ambientDefaults(), Options{FilePath: yamlPath, IdentityFileAuthority: true})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if out := warnings.String(); out != "" {
			t.Errorf("identical file and env values must not warn, got:\n%s", out)
		}
	})
}

func TestLoadIdentityFileAuthorityKeepsAmbientFallbackWhenFileSilent(t *testing.T) {
	// Gate ON but the YAML does not pin hostname: existing valid configs that
	// rely on the machine HOSTNAME boot unchanged (no warning, ambient value).
	t.Setenv("HOSTNAME", "container-abc123")
	yamlPath := writeHostnameYAML(t, "") // does not set hostname
	warnings := captureWarnings(t)

	k, err := Load(ambientDefaults(), Options{FilePath: yamlPath, IdentityFileAuthority: true})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := k.String("hostname"); got != "container-abc123" {
		t.Errorf("hostname = %q, want %q (ambient fallback preserved)", got, "container-abc123")
	}
	if out := warnings.String(); out != "" {
		t.Errorf("unpinned identity key must not warn, got:\n%s", out)
	}
}

func TestLoadIdentityFileAuthorityCoversFileOnlyKey(t *testing.T) {
	// Gate ON: the file pins hostname even when the defaults map does not
	// carry the key at all — the ambient env still must not override it.
	t.Setenv("HOSTNAME", "container-abc123")
	yamlPath := writeHostnameYAML(t, "mail.example.test")
	warnings := captureWarnings(t)

	k, err := Load(map[string]interface{}{}, Options{FilePath: yamlPath, IdentityFileAuthority: true})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := k.String("hostname"); got != "mail.example.test" {
		t.Errorf("hostname = %q, want %q (file-only identity key keeps authority)", got, "mail.example.test")
	}
	if out := warnings.String(); !strings.Contains(out, "config_key=hostname") {
		t.Errorf("expected conflict warning for config_key=hostname, got:\n%s", out)
	}
}

func TestLoadIdentityFileAuthorityNonIdentityKeysKeepEnvHighest(t *testing.T) {
	// Explicit compatibility boundary: with the gate ON, keys outside
	// IdentityCriticalKeys (db.max_conns here) keep the documented
	// env-highest precedence.
	t.Setenv("DB_MAX_CONNS", "99")
	yamlPath := writeHostnameYAML(t, "mail.example.test")

	defaults := ambientDefaults()
	defaults["db.max_conns"] = 10

	k, err := Load(defaults, Options{FilePath: yamlPath, IdentityFileAuthority: true})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := k.Int("db.max_conns"); got != 99 {
		t.Errorf("db.max_conns = %d, want 99 (non-identity env-highest preserved under gate)", got)
	}
}

func TestLoadIdentityFileAuthorityCountsDefaultEqualYAMLAsPinned(t *testing.T) {
	// Presence of an identity-critical pin must be detected in the YAML layer
	// itself: a file that explicitly supplies a hostname equal to the ambient
	// default is a pin, not an unpinned key. Detecting presence by comparing
	// the merged value with the defaults projection misclassified exactly this
	// case as absent and let a conflicting environment value override the
	// operator's explicit file value.
	yamlPath := writeHostnameYAML(t, "container-abc123") // explicit, default-equal pin

	t.Run("gate OFF keeps documented env-highest precedence", func(t *testing.T) {
		t.Setenv("HOSTNAME", "container-abc123")
		k, err := Load(ambientDefaults(), Options{FilePath: yamlPath})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if got := k.String("hostname"); got != "container-abc123" {
			t.Errorf("hostname = %q, want %q (env-highest unchanged by explicit default-equal YAML)", got, "container-abc123")
		}
	})

	t.Run("gate ON: conflicting env cannot override explicit default-equal YAML", func(t *testing.T) {
		t.Setenv("HOSTNAME", "attacker.example.test")
		warnings := captureWarnings(t)

		k, err := Load(ambientDefaults(), Options{FilePath: yamlPath, IdentityFileAuthority: true})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if got := k.String("hostname"); got != "container-abc123" {
			t.Errorf("hostname = %q, want %q (explicit default-equal YAML pin beats conflicting env)", got, "container-abc123")
		}
		out := warnings.String()
		if !strings.Contains(out, "config_key=hostname") || !strings.Contains(out, "env_var=HOSTNAME") {
			t.Errorf("expected a loud conflict warning naming config_key=hostname and env_var=HOSTNAME, got:\n%s", out)
		}
	})

	t.Run("gate ON: identical env value is not a conflict", func(t *testing.T) {
		t.Setenv("HOSTNAME", "container-abc123")
		warnings := captureWarnings(t)

		k, err := Load(ambientDefaults(), Options{FilePath: yamlPath, IdentityFileAuthority: true})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if got := k.String("hostname"); got != "container-abc123" {
			t.Errorf("hostname = %q, want %q", got, "container-abc123")
		}
		if out := warnings.String(); out != "" {
			t.Errorf("identical file and env values must not warn, got:\n%s", out)
		}
	})
}

func TestLoadIdentityFileAuthorityWithoutFileKeepsAmbientFallback(t *testing.T) {
	// Gate ON but no file is configured: there is no YAML layer to pin
	// anything, so every key keeps the ambient env-highest fallback.
	t.Setenv("HOSTNAME", "container-abc123")
	warnings := captureWarnings(t)

	k, err := Load(ambientDefaults(), Options{IdentityFileAuthority: true})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := k.String("hostname"); got != "container-abc123" {
		t.Errorf("hostname = %q, want %q (ambient fallback without file)", got, "container-abc123")
	}
	if out := warnings.String(); out != "" {
		t.Errorf("unpinned identity key must not warn, got:\n%s", out)
	}
}

func TestIdentityCriticalKeysCompatibilityList(t *testing.T) {
	// Pin the explicit compatibility list: hostname is the only current
	// identity-critical key; widening it is a documented-contract change that
	// must be deliberate.
	want := []string{"hostname"}
	if !reflect.DeepEqual(IdentityCriticalKeys, want) {
		t.Errorf("IdentityCriticalKeys = %v, want %v", IdentityCriticalKeys, want)
	}
	for _, key := range IdentityCriticalKeys {
		if key == "db.max_conns" || strings.HasPrefix(key, "db.") {
			t.Errorf("database keys must stay in the env-highest compatibility set, found %q", key)
		}
	}
}
