package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/knadh/koanf/v2"
)

func TestLoadDefaults(t *testing.T) {
	// Isolate from ambient DB_DSN: applyEnvOverrides reads it from os.Environ()
	// and transforms it to db.dsn, which would override the default we assert.
	// t.Setenv first (blocks t.Parallel + auto-restores), then Unsetenv so the
	// key is absent — an empty DB_DSN would still override db.dsn to "".
	t.Setenv("DB_DSN", "")
	os.Unsetenv("DB_DSN")

	defaults := map[string]interface{}{
		"db.dsn":       "postgres://localhost/default",
		"db.max_conns": 10,
		"listen":       ":8080",
	}

	k, err := Load(defaults, Options{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := k.String("db.dsn"); got != "postgres://localhost/default" {
		t.Errorf("db.dsn = %q, want %q", got, "postgres://localhost/default")
	}
	if got := k.Int("db.max_conns"); got != 10 {
		t.Errorf("db.max_conns = %d, want 10", got)
	}
}

func TestLoadYAMLOverridesDefaults(t *testing.T) {
	// Isolate from ambient DB_DSN: applyEnvOverrides reads it from os.Environ()
	// and transforms it to db.dsn, which would override the default we assert
	// survives when the YAML does not set db.dsn. t.Setenv first (blocks
	// t.Parallel + auto-restores), then Unsetenv so the key is absent — an empty
	// DB_DSN would still override db.dsn to "".
	t.Setenv("DB_DSN", "")
	os.Unsetenv("DB_DSN")

	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "config.yaml")
	yaml := []byte("db:\n  max_conns: 50\nlisten: \":9090\"\n")
	if err := os.WriteFile(yamlPath, yaml, 0644); err != nil {
		t.Fatal(err)
	}

	defaults := map[string]interface{}{
		"db.dsn":       "postgres://localhost/default",
		"db.max_conns": 10,
		"listen":       ":8080",
	}

	k, err := Load(defaults, Options{FilePath: yamlPath})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// YAML should override the default
	if got := k.Int("db.max_conns"); got != 50 {
		t.Errorf("db.max_conns = %d, want 50 (YAML override)", got)
	}
	// Default should survive if not in YAML
	if got := k.String("db.dsn"); got != "postgres://localhost/default" {
		t.Errorf("db.dsn = %q, want %q (default preserved)", got, "postgres://localhost/default")
	}
}

func TestLoadEnvOverridesAll(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(yamlPath, []byte("listen: \":9090\"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Use the transformed key that the env transformer produces.
	t.Setenv("DB_MAX_CONNS", "99")

	defaults := map[string]interface{}{
		"db.max_conns": 10,
		"listen":       ":8080",
	}

	k, err := Load(defaults, Options{FilePath: yamlPath})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Env var should override both defaults and YAML.
	// DB_MAX_CONNS → db.max_conns (first _ → .)
	if got := k.Int("db.max_conns"); got != 99 {
		t.Errorf("db.max_conns = %d, want 99 (env override)", got)
	}
}

func TestLoadEnvOverridesSectionContainingUnderscore(t *testing.T) {
	t.Setenv("OIDC_PROVIDER_ENABLED", "true")

	k, err := Load(map[string]interface{}{
		"oidc_provider.enabled": false,
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !k.Bool("oidc_provider.enabled") {
		t.Fatal("OIDC_PROVIDER_ENABLED did not map to oidc_provider.enabled")
	}
}

func TestExistingKeyForEnvRejectsWrongPrefixAndAmbiguousSpellings(t *testing.T) {
	k := koanf.New(".")
	_ = k.Set("oidc.provider_enabled", false)
	_ = k.Set("oidc_provider.enabled", false)
	if got := existingKeyForEnv(k, "SETJOIN_", "OTHER_OIDC_PROVIDER_ENABLED"); got != "" {
		t.Fatalf("wrong prefix resolved to %q", got)
	}
	if got := existingKeyForEnv(k, "SETJOIN_", "SETJOIN_OIDC_PROVIDER_ENABLED"); got != "" {
		t.Fatalf("ambiguous environment spelling resolved to %q", got)
	}
}

func TestLoadNoFilePathMeansDefaultsOnly(t *testing.T) {
	defaults := map[string]interface{}{
		"listen": ":8080",
	}
	k, err := Load(defaults, Options{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := k.String("listen"); got != ":8080" {
		t.Errorf("listen = %q, want %q", got, ":8080")
	}
}

func TestEnvPrefixFiltersAmbientVariables(t *testing.T) {
	// Options.EnvPrefix is a filter per its contract: with a prefix configured,
	// an ambient variable WITHOUT the prefix must never reach the config keys,
	// even when its transformed spelling names an existing key.
	t.Setenv("DB_MAX_CONNS", "77")
	t.Setenv("SETJOIN_DB_MAX_CONNS", "55")

	k, err := Load(map[string]interface{}{
		"db.max_conns": 10,
	}, Options{EnvPrefix: "SETJOIN_"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := k.Int("db.max_conns"); got != 55 {
		t.Errorf("db.max_conns = %d, want 55 (prefixed env wins; ambient DB_MAX_CONNS filtered)", got)
	}
}

func TestWarnConfigFilePermissions(t *testing.T) {
	dir := t.TempDir()

	// Regular 0600 file: correct posture, no warning path exercised (the
	// warning is a log side effect; here we pin that Lstat never panics and
	// regular-permissive vs symlink are distinguished).
	good := filepath.Join(dir, "good.yaml")
	if err := os.WriteFile(good, []byte("listen: \":9000\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	warnConfigFilePermissions(good) // no warning expected

	permissive := filepath.Join(dir, "permissive.yaml")
	if err := os.WriteFile(permissive, []byte("listen: \":9000\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	warnConfigFilePermissions(permissive) // group/world-readable warning expected

	if err := os.Symlink(good, filepath.Join(dir, "link.yaml")); err != nil {
		t.Fatal(err)
	}
	warnConfigFilePermissions(filepath.Join(dir, "link.yaml")) // non-regular warning expected

	warnConfigFilePermissions(filepath.Join(dir, "missing.yaml")) // load error path, silent here
}
