package updater

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestLocalLockAdmitsOnlyOneExecutor(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "state")
	journal, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = journal
	first, err := AcquireLocalLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := AcquireLocalLock(dir); !errors.Is(err, ErrUpdaterAlreadyRunning) {
		t.Fatalf("second lock: got %v, want %v", err, ErrUpdaterAlreadyRunning)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := AcquireLocalLock(dir)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}
