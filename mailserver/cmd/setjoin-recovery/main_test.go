package main

import (
	"os"
	"path/filepath"
	"testing"

	"setjoin.com/mailserver/internal/updater"
)

func recoveryFixture(t *testing.T) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "setjoin")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for name := range map[string]bool{"mailserverd": true, "authserverd": true, "mailctl": true} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "webmail"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "webmail", "index.html"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(base, "config.env")
	if err := os.WriteFile(config, []byte("SECRET=fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := updater.AdoptCurrentLayout(updater.AdoptionOptions{InstallRoot: root, ConfigPath: config, QuarantineDir: filepath.Join(base, "quarantine"), SchemaVersion: 178}); err != nil {
		t.Fatal(err)
	}
	priorRoot, priorJournal, priorEvidence, priorDSN, priorUID := installRoot, journalDir, evidenceDir, dsnFile, effectiveUID
	installRoot, journalDir, evidenceDir, dsnFile = root, filepath.Join(base, "journal"), filepath.Join(base, "evidence"), filepath.Join(base, "dsn")
	effectiveUID = func() int { return 501 }
	t.Cleanup(func() {
		installRoot, journalDir, evidenceDir, dsnFile, effectiveUID = priorRoot, priorJournal, priorEvidence, priorDSN, priorUID
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
}

func TestRecoveryCLIStatusEvidenceAndUsage(t *testing.T) {
	recoveryFixture(t)
	for _, args := range [][]string{nil, {"unknown"}, {"status", "extra"}, {"status", "--bad"}, {"evidence", "extra"}, {"activate-previous"}, {"activate-previous", "--reason", "   "}} {
		if got := run(args); got != 2 {
			t.Fatalf("args=%v exit=%d", args, got)
		}
	}
	if got := run([]string{"status"}); got != 0 {
		t.Fatalf("status exit=%d", got)
	}
	if got := run([]string{"status", "--json"}); got != 0 {
		t.Fatalf("json status exit=%d", got)
	}
	if got := run([]string{"evidence", "--reason", "operator inspection"}); got != 0 {
		t.Fatalf("evidence exit=%d", got)
	}
	entries, err := os.ReadDir(evidenceDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("evidence entries=%d err=%v", len(entries), err)
	}
	if got := run([]string{"activate-previous", "--reason", "operator rollback"}); got != 1 {
		t.Fatalf("non-root activation exit=%d", got)
	}
}

func TestRecoveryCLIJournalOpenFailureAndFailHelper(t *testing.T) {
	prior := journalDir
	journalDir = "relative"
	t.Cleanup(func() { journalDir = prior })
	if got := run([]string{"status"}); got != 1 {
		t.Fatalf("journal error exit=%d", got)
	}
	if got := fail(os.ErrInvalid); got != 1 {
		t.Fatalf("fail exit=%d", got)
	}
	usage()
}

func TestRecoveryCLIActivatePreviousRootAndCredentialBoundaries(t *testing.T) {
	recoveryFixture(t)
	effectiveUID = func() int { return 0 }
	if got := run([]string{"activate-previous", "--reason", "operator forced rollback", "--force"}); got != 1 {
		t.Fatalf("non-TTY forced activation exit=%d", got)
	}

	journal, err := updater.OpenJournal(journalDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Append(updater.Event{
		IntentID: "42", ReleaseID: "release-1",
		ManifestDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		LeaseID:        "11111111-1111-4111-8111-111111111111", ExecutorID: "updater-test",
		StateGeneration: 1, State: updater.StateRecoveryRequired, Step: "recovery_required",
		Evidence: []byte(`{"category":"rollback_failed"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := journal.Compact(true); err != nil {
		t.Fatal(err)
	}
	if got := run([]string{"activate-previous", "--reason", "operator authored recovery"}); got != 1 {
		t.Fatalf("missing credential exit=%d", got)
	}
	if err := os.WriteFile(dsnFile, []byte("not-a-postgres-dsn\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := run([]string{"activate-previous", "--reason", "operator authored recovery"}); got != 1 {
		t.Fatalf("invalid control-plane credential exit=%d", got)
	}
}
