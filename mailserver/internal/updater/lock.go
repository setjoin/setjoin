package updater

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

var ErrUpdaterAlreadyRunning = errors.New("another setjoin updater owns the local execution lock")

type LocalLock struct {
	file *os.File
}

func AcquireLocalLock(stateDir string) (*LocalLock, error) {
	// stateDir is the already validated owner-only journal directory and the lock
	// filename is fixed by the updater protocol.
	//nolint:gosec // G304: no caller-controlled filename is opened.
	file, err := os.OpenFile(filepath.Join(stateDir, "executor.lock"), os.O_CREATE|os.O_RDWR, journalFileMode)
	if err != nil {
		return nil, fmt.Errorf("open updater lock: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrUpdaterAlreadyRunning
		}
		return nil, fmt.Errorf("acquire updater lock: %w", err)
	}
	return &LocalLock{file: file}, nil
}

func (lock *LocalLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := unix.Flock(int(lock.file.Fd()), unix.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	if unlockErr != nil {
		return fmt.Errorf("release updater lock: %w", unlockErr)
	}
	return closeErr
}
