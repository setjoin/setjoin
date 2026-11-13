package main

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// saveConfigFile is the permission boundary for the ~/.mailctl/config.yaml
// token store: os.WriteFile applies 0600 only at creation, so the unconditional
// post-write chmod is what keeps a pre-existing looser file from staying
// group/world-readable (occ_38e78d056239e7f5b8fb25e0,
// credential-storage.preexisting-file-permissions). These tests pin that
// boundary on the path-injectable body SaveConfig delegates to.

func TestSaveConfigTightensPreexistingLooseFile(t *testing.T) {
	for _, preMode := range []os.FileMode{0o644, 0o640, 0o664, 0o604} {
		t.Run(preMode.String(), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte("server: https://old.example\n"), preMode); err != nil {
				t.Fatalf("seed pre-existing config: %v", err)
			}
			cfg := &Config{
				Server: "https://mail.example",
				Auth:   AuthConfig{Mode: "jwt", Token: "t", RefreshToken: "r"},
			}
			if err := saveConfigFile(path, cfg); err != nil {
				t.Fatalf("saveConfigFile: %v", err)
			}
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatalf("lstat rewritten config: %v", err)
			}
			if got := info.Mode().Perm(); got != 0o600 {
				t.Errorf("pre-existing file mode %o was not tightened to 600 by saveConfigFile", got)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read rewritten config: %v", err)
			}
			var parsed Config
			if err := yaml.Unmarshal(raw, &parsed); err != nil {
				t.Fatalf("rewritten config does not parse: %v", err)
			}
			if parsed.Server != cfg.Server || parsed.Auth.Token != cfg.Auth.Token {
				t.Errorf("rewritten config content drifted: got server=%q token=%q", parsed.Server, parsed.Auth.Token)
			}
		})
	}
}

func TestSaveConfigCreatesNewFilePrivate0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "config.yaml")
	cfg := &Config{Server: "https://mail.example", Auth: AuthConfig{Mode: "jwt", Token: "t"}}
	if err := saveConfigFile(path, cfg); err != nil {
		t.Fatalf("saveConfigFile: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat created config: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("freshly created config mode = %o, want 600", got)
	}
	dirInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("lstat created dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Errorf("created config dir mode = %o, want 700", got)
	}
}

func TestSaveConfigKeepsTightModeAcrossRewrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := &Config{Server: "https://mail.example", Auth: AuthConfig{Mode: "jwt", Token: "t"}}
	if err := saveConfigFile(path, cfg); err != nil {
		t.Fatalf("first save: %v", err)
	}
	// The logout/login rewrite path saves over an existing 0600 file.
	cfg.Auth.Token = ""
	if err := saveConfigFile(path, cfg); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat rewritten config: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("config mode after rewrite = %o, want 600", got)
	}
}

// redirectConfigPath points the SaveConfig path resolver at a temporary
// location for the duration of the test.
func redirectConfigPath(t *testing.T, path string) {
	t.Helper()
	orig := configPathFn
	configPathFn = func() (string, error) { return path, nil }
	t.Cleanup(func() { configPathFn = orig })
}

func TestSaveConfigWritesThroughConfigPathTo0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	redirectConfigPath(t, path)
	cfg := &Config{Server: "https://mail.example", Auth: AuthConfig{Mode: "jwt", Token: "t"}}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat saved config: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("SaveConfig wrote mode %o, want 600", got)
	}
}

func TestSaveConfigPropagatesWriteFailure(t *testing.T) {
	dir := t.TempDir()
	// The resolved path is a DIRECTORY, so os.WriteFile fails after
	// MkdirAll succeeds; SaveConfig must surface that error, not mask it.
	blocked := filepath.Join(dir, "config.yaml")
	if err := os.MkdirAll(blocked, 0o700); err != nil {
		t.Fatalf("seed blocking directory: %v", err)
	}
	redirectConfigPath(t, blocked)
	if err := SaveConfig(&Config{Server: "https://mail.example"}); err == nil {
		t.Errorf("SaveConfig over a directory path succeeded; want the write error")
	}
}
