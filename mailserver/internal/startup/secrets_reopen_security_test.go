package startup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// All fixtures are t.TempDir-based; no real secret files are touched.

// writeFixture creates path with content and then forces the exact mode,
// because WriteFile's mode argument is filtered by the process umask.
func writeFixture(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("Chmod(%s, %o): %v", path, mode, err)
	}
}

func currentFileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s): %v", path, err)
	}
	return info.Mode().Perm()
}

func assertGeneratedContent(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	if !strings.Contains(string(data), "JWT_SECRET=") {
		t.Fatalf("freshly generated secrets missing from %s", path)
	}
}

// A planted symlink at the secret path must be refused for both the normal
// and the force path; no secret may ever be written through the link.
func TestBootstrapSecretsRefusesSymlinkAtSecretPath(t *testing.T) {
	for _, tc := range []struct {
		name  string
		force bool
	}{
		{name: "normal", force: false},
		{name: "force", force: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.env")
			target := filepath.Join(dir, "attacker.target")
			const planted = "attacker-controlled"
			writeFixture(t, target, []byte(planted), 0o600)
			if err := os.Symlink(target, configPath); err != nil {
				t.Fatalf("Symlink: %v", err)
			}

			err := BootstrapSecrets(configPath, tc.force)
			if err == nil {
				t.Fatal("BootstrapSecrets accepted a symlinked secret path, want refusal")
			}
			if !strings.Contains(err.Error(), "refusing unsafe secret file") {
				t.Errorf("error lacks operator guidance: %v", err)
			}

			// The planted target must be untouched: no secrets written
			// through the symlink, and the symlink itself must survive
			// (never replaced by a regular file write).
			data, err := os.ReadFile(target)
			if err != nil {
				t.Fatalf("ReadFile(target): %v", err)
			}
			if string(data) != planted {
				t.Errorf("symlink target was written through: got %q, want %q", data, planted)
			}
			info, err := os.Lstat(configPath)
			if err != nil {
				t.Fatalf("Lstat(configPath): %v", err)
			}
			if info.Mode()&os.ModeSymlink == 0 {
				t.Error("symlink at secret path was replaced instead of refused")
			}
		})
	}
}

// A pre-existing zero-length group/other-accessible file is treated as a
// planted wide-mode secret file: refuse it, persist no secret into it.
func TestBootstrapSecretsRefusesPlantedWideModeEmptyFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.env")
	writeFixture(t, configPath, nil, 0o644)

	if err := BootstrapSecrets(configPath, false); err == nil {
		t.Fatal("BootstrapSecrets accepted a zero-length 0644 secret file, want refusal")
	} else if !strings.Contains(err.Error(), "refusing unsafe secret file") {
		t.Errorf("error lacks operator guidance: %v", err)
	}

	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("refused plant grew to %d bytes; no secret may be persisted", info.Size())
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Errorf("refused plant mode = %o, want untouched 0644", got)
	}
}

// A directory at the secret path is non-regular and must be refused.
func TestBootstrapSecretsRefusesDirectoryAtSecretPath(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.env")
	if err := os.Mkdir(configPath, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := BootstrapSecrets(configPath, false); err == nil {
		t.Fatal("BootstrapSecrets accepted a directory at the secret path, want refusal")
	}
}

// Re-open of a content-bearing secret file must not regenerate, must leave
// the content intact, and must fchmod the file down to 0600.
func TestBootstrapSecretsTightensWideModeBootstrappedFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.env")
	const existing = "JWT_SECRET=existing\n"
	writeFixture(t, configPath, []byte(existing), 0o644)

	if err := BootstrapSecrets(configPath, false); err != nil {
		t.Fatalf("BootstrapSecrets on wide-mode bootstrapped file: %v", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != existing {
		t.Errorf("bootstrapped content was rewritten: got %q", data)
	}
	if got := currentFileMode(t, configPath); got != 0o600 {
		t.Errorf("wide-mode bootstrapped file left at %o, want fchmod to 0600", got)
	}
}

// Force regeneration over a wide-mode file must succeed and must leave the
// freshly generated secrets at 0600, never wider.
func TestBootstrapSecretsForceOverwriteTightensTo0600(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.env")
	writeFixture(t, configPath, []byte("old"), 0o644)

	if err := BootstrapSecrets(configPath, true); err != nil {
		t.Fatalf("BootstrapSecrets force over wide-mode file: %v", err)
	}
	assertGeneratedContent(t, configPath)
	if got := currentFileMode(t, configPath); got != 0o600 {
		t.Errorf("force-regenerated secrets left at %o, want 0600", got)
	}
}

// A zero-length owner-only file is not hostile: normal crash-recovery
// re-open still regenerates secrets into it at 0600.
func TestBootstrapSecretsRegeneratesZeroLengthOwnerOnlyFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.env")
	writeFixture(t, configPath, nil, 0o600)

	if err := BootstrapSecrets(configPath, false); err != nil {
		t.Fatalf("BootstrapSecrets on zero-length 0600 file: %v", err)
	}
	assertGeneratedContent(t, configPath)
	if got := currentFileMode(t, configPath); got != 0o600 {
		t.Errorf("regenerated secrets left at %o, want 0600", got)
	}
}

// A normal restart against well-formed 0600 files must keep working:
// idempotent, unchanged content, mode still exactly 0600.
func TestBootstrapSecretsNormalRestartKeepsWellFormedFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.env")

	if err := BootstrapSecrets(configPath, false); err != nil {
		t.Fatalf("first boot: %v", err)
	}
	first, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if got := currentFileMode(t, configPath); got != 0o600 {
		t.Fatalf("first boot left %o, want 0600", got)
	}

	if err := BootstrapSecrets(configPath, false); err != nil {
		t.Fatalf("restart: %v", err)
	}
	second, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile after restart: %v", err)
	}
	if string(first) != string(second) {
		t.Error("restart regenerated an already-bootstrapped secret file")
	}
	if got := currentFileMode(t, configPath); got != 0o600 {
		t.Errorf("restart left %o, want 0600", got)
	}
}
