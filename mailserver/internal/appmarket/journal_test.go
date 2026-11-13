package appmarket

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestAppJournalAppendReloadAndChecksum(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenAppJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	op := &Operation{OperationID: uuid.New(), LeaseID: uuid.New(), ExecutorID: "runner", StateGeneration: 3, State: "pulling"}
	if err := journal.Append(op, "pull:intent", map[string]any{"digest": "sha256:test"}); err != nil {
		t.Fatal(err)
	}
	if err := journal.Append(op, "pull:complete", map[string]any{"verified": true}); err != nil {
		t.Fatal(err)
	}
	records, err := journal.Load()
	if err != nil || len(records) != 2 || records[1].PreviousHash != records[0].Hash {
		t.Fatalf("Load()=(%+v,%v)", records, err)
	}
	path := filepath.Join(dir, "events.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := "0" + records[0].Hash[1:]
	if replacement == records[0].Hash {
		replacement = "1" + records[0].Hash[1:]
	}
	raw = []byte(strings.Replace(string(raw), records[0].Hash, replacement, 1))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Load(); !errors.Is(err, ErrAppJournalChecksum) {
		t.Fatalf("checksum error=%v", err)
	}
}

func TestAppJournalRejectsTornWriteAndSecondExecutor(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenAppJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Load(); !errors.Is(err, ErrAppJournalTorn) {
		t.Fatalf("torn error=%v", err)
	}
	if err := os.Remove(filepath.Join(dir, "events.jsonl")); err != nil {
		t.Fatal(err)
	}
	first, err := journal.AcquireLock()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := journal.AcquireLock(); err == nil {
		t.Fatal("second executor unexpectedly acquired the journal lock")
	}
}

func TestOpenAppJournalRequiresAbsoluteOwnerOnlyDirectory(t *testing.T) {
	if _, err := OpenAppJournal("relative"); err == nil {
		t.Fatal("relative directory accepted")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAppJournal(dir); err == nil {
		t.Fatal("group-readable directory accepted")
	}
}

func TestAppJournalRejectsMalformedOversizedAndUnencodableRecords(t *testing.T) {
	makeJournal := func(t *testing.T, raw []byte) *AppJournal {
		t.Helper()
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if raw != nil {
			if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return &AppJournal{dir: dir}
	}
	if _, err := makeJournal(t, []byte("{\n")).Load(); err == nil || !strings.Contains(err.Error(), "decode managed app journal") {
		t.Fatalf("malformed=%v", err)
	}
	long := append(make([]byte, maxAppJournalRecord+1), '\n')
	if _, err := makeJournal(t, long).Load(); err == nil || !strings.Contains(err.Error(), "scan managed app journal") {
		t.Fatalf("long record=%v", err)
	}
	tooLarge := append(make([]byte, maxAppJournalSize+1), '\n')
	if _, err := makeJournal(t, tooLarge).Load(); err == nil || !strings.Contains(err.Error(), "bounded size") {
		t.Fatalf("oversized=%v", err)
	}
	j := makeJournal(t, nil)
	op := &Operation{OperationID: uuid.New(), LeaseID: uuid.New()}
	if err := j.Append(op, "bad", func() {}); err == nil || !strings.Contains(err.Error(), "encode managed app journal evidence") {
		t.Fatalf("unencodable=%v", err)
	}
	if err := os.Mkdir(filepath.Join(j.dir, "events.jsonl"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Load(); err == nil || !strings.Contains(err.Error(), "read managed app journal") {
		t.Fatalf("directory journal=%v", err)
	}
	if err := j.Append(op, "blocked", nil); err == nil {
		t.Fatal("append accepted unreadable journal")
	}
}

func TestOpenAppJournalCreationAndExistingCorruptionFailures(t *testing.T) {
	base := t.TempDir()
	parentFile := filepath.Join(base, "file")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAppJournal(filepath.Join(parentFile, "journal")); err == nil || !strings.Contains(err.Error(), "create managed app journal") {
		t.Fatalf("creation=%v", err)
	}
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAppJournal(link); err == nil || !strings.Contains(err.Error(), "owner-only real directory") {
		t.Fatalf("symlink=%v", err)
	}
	corrupt := filepath.Join(base, "corrupt")
	if err := os.Mkdir(corrupt, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(corrupt, "events.jsonl"), []byte("broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAppJournal(corrupt); err == nil {
		t.Fatal("corrupt existing journal accepted")
	}
}
