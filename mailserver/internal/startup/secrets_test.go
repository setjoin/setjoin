package startup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootstrapSecrets(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.env")

	// First call -- should generate
	if err := BootstrapSecrets(configPath, false); err != nil {
		t.Fatalf("BootstrapSecrets failed: %v", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("config.env not created: %v", err)
	}
	content := string(data)

	// Check all required keys present
	required := []string{"JWT_SECRET", "DB_ENCRYPTION_KEY", "INTERNAL_API_KEY",
		"VAPID_PRIVATE_KEY", "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY"}
	for _, key := range required {
		if !strings.Contains(content, key+"=") {
			t.Errorf("missing key %s in config.env", key)
		}
	}

	// Check values are non-empty
	lines := strings.Split(strings.TrimSpace(content), "\n")
	seen := map[string]string{}
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 || parts[1] == "" {
			t.Errorf("empty or malformed line: %s", line)
		}
		if other, ok := seen[parts[1]]; ok {
			t.Errorf("duplicate value: %s and %s both have same value", parts[0], other)
		}
		seen[parts[1]] = parts[0]
	}

	// Check file permissions
	info, _ := os.Stat(configPath)
	if info.Mode().Perm() != 0600 {
		t.Errorf("config.env permissions = %o, want 0600", info.Mode().Perm())
	}

	// Second call -- should be idempotent
	firstContent := string(data)
	if err := BootstrapSecrets(configPath, false); err != nil {
		t.Fatalf("second BootstrapSecrets failed: %v", err)
	}
	data2, _ := os.ReadFile(configPath)
	if string(data2) != firstContent {
		t.Error("BootstrapSecrets overwrote existing config")
	}
}

func TestBootstrapSecretsForce(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.env")

	// First write a marker file
	os.WriteFile(configPath, []byte("old"), 0644)
	// Force should overwrite
	if err := BootstrapSecrets(configPath, true); err != nil {
		t.Fatalf("BootstrapSecrets force failed: %v", err)
	}
	data, _ := os.ReadFile(configPath)
	if !strings.Contains(string(data), "JWT_SECRET=") {
		t.Error("force did not regenerate secrets")
	}
}
