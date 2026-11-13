package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Coverage for the YAML file layer's failure arms and the non-string config
// value projection.

// TestLoadInvalidYAMLFileFails pins the file-layer error arm: a config file
// that does not parse as YAML fails Load instead of being silently ignored.
func TestLoadInvalidYAMLFileFails(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("listen: [unclosed\n\t- :\n  ::: not yaml <<<"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(map[string]interface{}{}, Options{FilePath: bad}); err == nil {
		t.Fatal("Load accepted an unparseable YAML config file")
	}
}

// TestKoanfStringProjectsNonStringValues pins the fmt.Sprint fallback: a
// merged value that is present but not a string (e.g. an int from a raw
// defaults map) is projected through its string form rather than "".
func TestKoanfStringProjectsNonStringValues(t *testing.T) {
	defaults := map[string]interface{}{}
	AddBaseDefaults(defaults, BaseConfig{})
	defaults["exchangeartifact.max_envelope"] = 4096 // non-string raw value
	k, err := Load(defaults, Options{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := DecodeBase(k, t.TempDir())
	if got.ExchangeArtifactMaxEnvelope != 4096 {
		t.Fatalf("max envelope = %d, want 4096 (non-string value projected)", got.ExchangeArtifactMaxEnvelope)
	}
}
