package startup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecretFileBootstrapped_StatFailureSurfaces pins the stat arm: a path
// whose resolution fails for a reason other than NotExist (a regular file in
// the middle of the path) is an error, not "not bootstrapped".
func TestSecretFileBootstrapped_StatFailureSurfaces(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	writeFixture(t, blocker, []byte("x"), 0o600)

	_, err := secretFileBootstrapped(filepath.Join(blocker, "config.env"))
	if err == nil {
		t.Fatal("stat through a regular file = nil error, want failure")
	}
	if !strings.Contains(err.Error(), "cannot stat secret file") {
		t.Fatalf("err = %v, want stat failure", err)
	}
}

// TestSecretFileBootstrapped_TightenFailureSurfaces pins the re-open arm of
// the boot-time permission tighten: a bootstrapped file that carries group/
// other bits but denies the owner read (mode 0066) cannot be re-opened, and
// the failure surfaces instead of silently accepting wide-mode secrets.
func TestSecretFileBootstrapped_TightenFailureSurfaces(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.env")
	writeFixture(t, configPath, []byte("JWT_SECRET=existing\n"), 0o066)

	bootstrapped, err := secretFileBootstrapped(configPath)
	if err == nil {
		t.Skip("running with privileges that can re-open a 0066 file; tighten-failure arm not reachable")
	}
	if bootstrapped {
		t.Error("bootstrapped = true alongside an error; want false")
	}
	if !strings.Contains(err.Error(), "re-open secret file") {
		t.Fatalf("err = %v, want re-open failure", err)
	}
}

// TestOpenSecretWriteFile_RefusesWideModeEmptyFile pins the planted-file
// guard on the write path itself: an empty, group/other-readable file at the
// secret path is refused before any handle is opened.
func TestOpenSecretWriteFile_RefusesWideModeEmptyFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.env")
	writeFixture(t, configPath, nil, 0o0644)

	f, err := openSecretWriteFile(configPath)
	if err == nil {
		_ = f.Close()
		t.Fatal("wide-mode empty file accepted on the write path, want refusal")
	}
	if !strings.Contains(err.Error(), "hostile") && !strings.Contains(err.Error(), "refus") {
		t.Fatalf("err = %v, want hostile-file refusal", err)
	}
}

// TestOpenSecretWriteFile_UnwritableExistingFile pins the re-open failure:
// an owner-readable but non-writable existing file fails the O_WRONLY open
// with the error surfaced (never a silent truncate-less continue).
func TestOpenSecretWriteFile_UnwritableExistingFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.env")
	writeFixture(t, configPath, []byte("data"), 0o0400)

	f, err := openSecretWriteFile(configPath)
	if err == nil {
		_ = f.Close()
		t.Skip("running with privileges that can write a 0400 file; re-open arm not reachable")
	}
	if !strings.Contains(err.Error(), "cannot open secret file") {
		t.Fatalf("err = %v, want open failure", err)
	}
}

// TestOpenSecretWriteFile_CreateUnderMissingDirectory pins the create-error
// arm: a path whose parent directory does not exist fails the O_CREATE open
// with ENOENT (which is not an ErrExist race), and the error surfaces.
func TestOpenSecretWriteFile_CreateUnderMissingDirectory(t *testing.T) {
	configPath := filepath.Join(os.TempDir(), "startup-gaps-missing-dir", "config.env")

	_, err := openSecretWriteFile(configPath)
	if err == nil {
		t.Fatal("create under a missing directory = nil error, want failure")
	}
	if !strings.Contains(err.Error(), "cannot create secret file") {
		t.Fatalf("err = %v, want create failure", err)
	}
}

// TestOpenSecretWriteFile_StatFailureSurfaces pins the default stat arm on
// the write path: a path whose resolution fails (regular file mid-path) is
// an error, never a create attempt.
func TestOpenSecretWriteFile_StatFailureSurfaces(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	writeFixture(t, blocker, []byte("x"), 0o600)

	_, err := openSecretWriteFile(filepath.Join(blocker, "config.env"))
	if err == nil {
		t.Fatal("stat through a regular file = nil error, want failure")
	}
	if !strings.Contains(err.Error(), "cannot stat secret file") {
		t.Fatalf("err = %v, want stat failure", err)
	}
}
