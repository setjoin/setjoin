package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var errPrivateArtifactInjected = errors.New("injected private artifact failure")

type privateArtifactFaultFile struct {
	name          string
	data          bytes.Buffer
	mode          os.FileMode
	maxWrite      int
	zeroWrite     bool
	chmodErr      error
	syncErr       error
	closeErr      error
	writeCalls    int
	closeCalls    int
	chmodCalls    int
	syncCalls     int
	zeroWriteDone bool
}

func (f *privateArtifactFaultFile) Write(data []byte) (int, error) {
	f.writeCalls++
	if f.zeroWrite && !f.zeroWriteDone {
		f.zeroWriteDone = true
		return 0, nil
	}
	if f.maxWrite > 0 && len(data) > f.maxWrite {
		data = data[:f.maxWrite]
	}
	return f.data.Write(data)
}

func (f *privateArtifactFaultFile) Chmod(mode os.FileMode) error {
	f.chmodCalls++
	f.mode = mode
	return f.chmodErr
}

func (f *privateArtifactFaultFile) Sync() error {
	f.syncCalls++
	return f.syncErr
}

func (f *privateArtifactFaultFile) Close() error {
	f.closeCalls++
	return f.closeErr
}

func (f *privateArtifactFaultFile) Name() string { return f.name }

type privateArtifactFaultHarness struct {
	file           *privateArtifactFaultFile
	createTempErr  error
	lstatInfo      os.FileInfo
	lstatErr       error
	linkErr        error
	replaceErr     error
	replaceResult  bool
	replaceCleanup privateArtifactCleanup
	replaceMutated bool
	removeErr      error
	dirSyncStatus  privateArtifactDirectorySync
	dirSyncErr     error
	dirSyncCalls   int
	removeCalls    []string
	linkCalls      [][2]string
	replaceCalls   [][2]string
}

func newPrivateArtifactFaultHarness() *privateArtifactFaultHarness {
	return &privateArtifactFaultHarness{
		file:           &privateArtifactFaultFile{name: "/parent/.temp"},
		lstatErr:       os.ErrNotExist,
		replaceResult:  true,
		replaceCleanup: privateArtifactCleanupComplete,
		dirSyncStatus:  privateArtifactDirectorySyncComplete,
	}
}

func (h *privateArtifactFaultHarness) operations() privateArtifactOperations {
	return privateArtifactOperations{
		createTemp: func(_, _ string) (privateArtifactFile, error) {
			return h.file, h.createTempErr
		},
		lstat: func(string) (os.FileInfo, error) {
			return h.lstatInfo, h.lstatErr
		},
		link: func(oldPath, newPath string) error {
			h.linkCalls = append(h.linkCalls, [2]string{oldPath, newPath})
			return h.linkErr
		},
		replace: func(oldPath, newPath string, _ os.FileInfo) (bool, privateArtifactCleanup, bool, error) {
			h.replaceCalls = append(h.replaceCalls, [2]string{oldPath, newPath})
			return h.replaceResult, h.replaceCleanup, h.replaceMutated, h.replaceErr
		},
		remove: func(path string) error {
			h.removeCalls = append(h.removeCalls, path)
			return h.removeErr
		},
		syncDir: func(string) (privateArtifactDirectorySync, error) {
			h.dirSyncCalls++
			return h.dirSyncStatus, h.dirSyncErr
		},
	}
}

func TestPrivateArtifactInstallFaultTable(t *testing.T) {
	t.Run("create-only requests private mode and completes short writes", func(t *testing.T) {
		h := newPrivateArtifactFaultHarness()
		h.file.maxWrite = 2
		result, err := publishPrivateNewWithOperations(h.operations(), "/parent/output", []byte("payload"))
		if err != nil {
			t.Fatal(err)
		}
		if h.file.chmodCalls != 1 || h.file.mode.Perm() != 0o600 {
			t.Fatalf("chmod calls/mode = %d/%04o", h.file.chmodCalls, h.file.mode.Perm())
		}
		if got := h.file.data.String(); got != "payload" || h.file.writeCalls < 2 {
			t.Fatalf("short-write result = %q across %d calls", got, h.file.writeCalls)
		}
		assertPrivateArtifactResult(t, result, privateArtifactCreateOnly, true, privateArtifactCleanupComplete, privateArtifactDirectorySyncComplete)
	})

	t.Run("replace requests private mode", func(t *testing.T) {
		h := newPrivateArtifactFaultHarness()
		result, err := installPrivateReplaceWithOperations(h.operations(), "/parent/output", []byte("payload"))
		if err != nil {
			t.Fatal(err)
		}
		if h.file.chmodCalls != 1 || h.file.mode.Perm() != 0o600 {
			t.Fatalf("chmod calls/mode = %d/%04o", h.file.chmodCalls, h.file.mode.Perm())
		}
		assertPrivateArtifactResult(t, result, privateArtifactReplaceExisting, true, privateArtifactCleanupComplete, privateArtifactDirectorySyncComplete)
	})

	for _, test := range []struct {
		name       string
		mode       privateArtifactMode
		configure  func(*privateArtifactFaultHarness)
		published  bool
		cleanup    privateArtifactCleanup
		dirSync    privateArtifactDirectorySync
		wantRemove bool
	}{
		{
			name: "create-only permission failure has nothing to clean", mode: privateArtifactCreateOnly,
			configure: func(h *privateArtifactFaultHarness) { h.createTempErr = os.ErrPermission },
			cleanup:   privateArtifactCleanupNotRequired, dirSync: privateArtifactDirectorySyncNotAttempted,
		},
		{
			name: "create-only zero write cleans partial destination", mode: privateArtifactCreateOnly,
			configure: func(h *privateArtifactFaultHarness) { h.file.zeroWrite = true },
			cleanup:   privateArtifactCleanupComplete, dirSync: privateArtifactDirectorySyncNotAttempted, wantRemove: true,
		},
		{
			name: "create-only sync failure cleans partial destination", mode: privateArtifactCreateOnly,
			configure: func(h *privateArtifactFaultHarness) { h.file.syncErr = errPrivateArtifactInjected },
			cleanup:   privateArtifactCleanupComplete, dirSync: privateArtifactDirectorySyncNotAttempted, wantRemove: true,
		},
		{
			name: "create-only close failure cleans partial destination", mode: privateArtifactCreateOnly,
			configure: func(h *privateArtifactFaultHarness) { h.file.closeErr = errPrivateArtifactInjected },
			cleanup:   privateArtifactCleanupComplete, dirSync: privateArtifactDirectorySyncNotAttempted, wantRemove: true,
		},
		{
			name: "create-only publication failure cleans temp", mode: privateArtifactCreateOnly,
			configure: func(h *privateArtifactFaultHarness) { h.linkErr = errPrivateArtifactInjected },
			cleanup:   privateArtifactCleanupComplete, dirSync: privateArtifactDirectorySyncNotAttempted, wantRemove: true,
		},
		{
			name: "create-only cleanup failure is explicit", mode: privateArtifactCreateOnly,
			configure: func(h *privateArtifactFaultHarness) {
				h.linkErr = errPrivateArtifactInjected
				h.removeErr = os.ErrPermission
			},
			cleanup: privateArtifactCleanupFailed, dirSync: privateArtifactDirectorySyncNotAttempted, wantRemove: true,
		},
		{
			name: "create-only post-publication cleanup failure reports published", mode: privateArtifactCreateOnly,
			configure: func(h *privateArtifactFaultHarness) { h.removeErr = os.ErrPermission },
			published: true, cleanup: privateArtifactCleanupFailed, dirSync: privateArtifactDirectorySyncNotAttempted, wantRemove: true,
		},
		{
			name: "create-only directory sync failure reports published", mode: privateArtifactCreateOnly,
			configure: func(h *privateArtifactFaultHarness) {
				h.dirSyncStatus = privateArtifactDirectorySyncFailed
				h.dirSyncErr = errPrivateArtifactInjected
			},
			published: true, cleanup: privateArtifactCleanupComplete, dirSync: privateArtifactDirectorySyncFailed, wantRemove: true,
		},
		{
			name: "replace chmod failure cleans temp", mode: privateArtifactReplaceExisting,
			configure: func(h *privateArtifactFaultHarness) { h.file.chmodErr = errPrivateArtifactInjected },
			cleanup:   privateArtifactCleanupComplete, dirSync: privateArtifactDirectorySyncNotAttempted, wantRemove: true,
		},
		{
			name: "replace zero write cleans temp", mode: privateArtifactReplaceExisting,
			configure: func(h *privateArtifactFaultHarness) { h.file.zeroWrite = true },
			cleanup:   privateArtifactCleanupComplete, dirSync: privateArtifactDirectorySyncNotAttempted, wantRemove: true,
		},
		{
			name: "replace sync failure cleans temp", mode: privateArtifactReplaceExisting,
			configure: func(h *privateArtifactFaultHarness) { h.file.syncErr = errPrivateArtifactInjected },
			cleanup:   privateArtifactCleanupComplete, dirSync: privateArtifactDirectorySyncNotAttempted, wantRemove: true,
		},
		{
			name: "replace close failure cleans temp", mode: privateArtifactReplaceExisting,
			configure: func(h *privateArtifactFaultHarness) { h.file.closeErr = errPrivateArtifactInjected },
			cleanup:   privateArtifactCleanupComplete, dirSync: privateArtifactDirectorySyncNotAttempted, wantRemove: true,
		},
		{
			name: "replace rename failure cleans temp", mode: privateArtifactReplaceExisting,
			configure: func(h *privateArtifactFaultHarness) {
				h.lstatInfo = privateArtifactTestFileInfo{mode: 0o600}
				h.lstatErr = nil
				h.replaceResult = false
				h.replaceCleanup = privateArtifactCleanupNotRequired
				h.replaceErr = errPrivateArtifactInjected
			},
			cleanup: privateArtifactCleanupComplete, dirSync: privateArtifactDirectorySyncNotAttempted, wantRemove: true,
		},
		{
			name: "replace cleanup failure is explicit", mode: privateArtifactReplaceExisting,
			configure: func(h *privateArtifactFaultHarness) {
				h.lstatInfo = privateArtifactTestFileInfo{mode: 0o600}
				h.lstatErr = nil
				h.replaceResult = false
				h.replaceCleanup = privateArtifactCleanupNotRequired
				h.replaceErr = errPrivateArtifactInjected
				h.removeErr = os.ErrPermission
			},
			cleanup: privateArtifactCleanupFailed, dirSync: privateArtifactDirectorySyncNotAttempted, wantRemove: true,
		},
		{
			name: "replace directory sync failure reports published", mode: privateArtifactReplaceExisting,
			configure: func(h *privateArtifactFaultHarness) {
				h.dirSyncStatus = privateArtifactDirectorySyncFailed
				h.dirSyncErr = errPrivateArtifactInjected
			},
			published: true, cleanup: privateArtifactCleanupComplete, dirSync: privateArtifactDirectorySyncFailed, wantRemove: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newPrivateArtifactFaultHarness()
			test.configure(h)
			var result privateArtifactInstallResult
			var err error
			if test.mode == privateArtifactCreateOnly {
				result, err = publishPrivateNewWithOperations(h.operations(), "/parent/output", []byte("payload"))
			} else {
				result, err = installPrivateReplaceWithOperations(h.operations(), "/parent/output", []byte("payload"))
			}
			if err == nil {
				t.Fatal("fault was accepted")
			}
			if test.published && !strings.Contains(err.Error(), "artifact is published but directory durability is uncertain") {
				t.Fatalf("post-publication error is ambiguous: %v", err)
			}
			assertPrivateArtifactResult(t, result, test.mode, test.published, test.cleanup, test.dirSync)
			if got := len(h.removeCalls) > 0; got != test.wantRemove {
				t.Fatalf("remove called = %v, want %v", got, test.wantRemove)
			}
		})
	}
}

func TestPrivateArtifactInstallFilesystemContract(t *testing.T) {
	t.Run("create-only publishes a synced private file once", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "artifact")
		result, err := publishPrivateNew(path, []byte("first"))
		if err != nil {
			t.Fatal(err)
		}
		assertPrivateArtifactPlatformResult(t, result, privateArtifactCreateOnly)
		assertPrivateArtifactFile(t, path, "first")
		if matches, err := filepath.Glob(filepath.Join(dir, ".mailctl-private-artifact-*")); err != nil || len(matches) != 0 {
			t.Fatalf("temporary artifacts = %v / %v", matches, err)
		}
		if _, err := publishPrivateNew(path, []byte("second")); err == nil {
			t.Fatal("create-only replaced an existing destination")
		}
		assertPrivateArtifactFile(t, path, "first")
	})

	t.Run("create-only refuses existing symlink and non-regular destinations", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := publishPrivateNew(dir, []byte("x")); err == nil {
			t.Fatal("create-only accepted a directory destination")
		}
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if _, err := publishPrivateNew(link, []byte("replacement")); err == nil {
			t.Fatal("create-only accepted a symlink destination")
		}
		assertPrivateArtifactFile(t, target, "keep")
	})

	t.Run("replace publishes privately over absent and regular destinations", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "artifact")
		result, err := installPrivateReplace(path, []byte("first"))
		if err != nil {
			t.Fatal(err)
		}
		assertPrivateArtifactPlatformResult(t, result, privateArtifactReplaceExisting)
		assertPrivateArtifactFile(t, path, "first")
		result, err = installPrivateReplace(path, []byte("second"))
		if runtime.GOOS == "windows" {
			if err == nil || result.Replacement != privateArtifactReplacementUnsupported {
				t.Fatalf("Windows existing-target result = %#v / %v", result, err)
			}
			assertPrivateArtifactFile(t, path, "first")
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		assertPrivateArtifactPlatformResult(t, result, privateArtifactReplaceExisting)
		if result.Replacement != privateArtifactReplacementComplete {
			t.Fatalf("replacement status = %s, want complete", result.Replacement)
		}
		assertPrivateArtifactFile(t, path, "second")
		if matches, err := filepath.Glob(filepath.Join(dir, ".mailctl-private-artifact-*")); err != nil || len(matches) != 0 {
			t.Fatalf("temporary artifacts = %v / %v", matches, err)
		}
	})

	t.Run("replace refuses symlink destination", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "artifact")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}

		if _, err := installPrivateReplace(link, []byte("replacement")); err == nil {
			t.Fatal("replace accepted a symlink destination")
		}
		assertPrivateArtifactFile(t, target, "keep")
	})

	t.Run("replace refuses other non-regular destinations", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := installPrivateReplace(dir, []byte("replacement")); err == nil {
			t.Fatal("replace accepted a directory destination")
		}
	})

	t.Run("families do not create parent directories", func(t *testing.T) {
		missingParent := filepath.Join(t.TempDir(), "missing")
		if _, err := publishPrivateNew(filepath.Join(missingParent, "new"), []byte("x")); err == nil {
			t.Fatal("create-only created a missing parent")
		}
		if _, err := installPrivateReplace(filepath.Join(missingParent, "replace"), []byte("x")); err == nil {
			t.Fatal("replace created a missing parent")
		}
	})
}

func TestPrivateArtifactInstallExistingTargetPolicy(t *testing.T) {
	t.Run("guarded rollback cleans and syncs the restored namespace", func(t *testing.T) {
		h := newPrivateArtifactFaultHarness()
		h.lstatInfo = privateArtifactTestFileInfo{mode: 0o600}
		h.lstatErr = nil
		h.replaceResult = false
		h.replaceCleanup = privateArtifactCleanupNotRequired
		h.replaceMutated = true
		h.replaceErr = errPrivateArtifactInjected
		result, err := installPrivateReplaceWithOperations(h.operations(), "/parent/output", []byte("payload"))
		if err == nil || !errors.Is(err, errPrivateArtifactInjected) {
			t.Fatalf("rollback mismatch error = %v", err)
		}
		assertPrivateArtifactResult(t, result, privateArtifactReplaceExisting, false, privateArtifactCleanupComplete, privateArtifactDirectorySyncComplete)
		if h.dirSyncCalls != 1 || len(h.removeCalls) != 1 {
			t.Fatalf("rollback durability calls: sync=%d remove=%v", h.dirSyncCalls, h.removeCalls)
		}
	})

	t.Run("guarded rollback sync failure is explicitly durability uncertain", func(t *testing.T) {
		h := newPrivateArtifactFaultHarness()
		h.lstatInfo = privateArtifactTestFileInfo{mode: 0o600}
		h.lstatErr = nil
		h.replaceResult = false
		h.replaceCleanup = privateArtifactCleanupNotRequired
		h.replaceMutated = true
		h.replaceErr = errPrivateArtifactInjected
		h.dirSyncStatus = privateArtifactDirectorySyncFailed
		h.dirSyncErr = os.ErrPermission
		result, err := installPrivateReplaceWithOperations(h.operations(), "/parent/output", []byte("payload"))
		var durabilityErr privateArtifactRollbackDurabilityError
		if !errors.As(err, &durabilityErr) || !strings.Contains(err.Error(), "target was restored but directory durability is uncertain") {
			t.Fatalf("rollback sync error = %v", err)
		}
		assertPrivateArtifactResult(t, result, privateArtifactReplaceExisting, false, privateArtifactCleanupComplete, privateArtifactDirectorySyncFailed)
		if h.dirSyncCalls != 1 || len(h.removeCalls) != 1 {
			t.Fatalf("rollback sync-failure calls: sync=%d remove=%v", h.dirSyncCalls, h.removeCalls)
		}
	})

	t.Run("absent target created during publication is preserved", func(t *testing.T) {
		h := newPrivateArtifactFaultHarness()
		h.linkErr = os.ErrExist
		result, err := installPrivateReplaceWithOperations(h.operations(), "/parent/output", []byte("payload"))
		if err == nil || !errors.Is(err, os.ErrExist) {
			t.Fatalf("intervening-target error = %v", err)
		}
		assertPrivateArtifactResult(t, result, privateArtifactReplaceExisting, false, privateArtifactCleanupComplete, privateArtifactDirectorySyncNotAttempted)
		if len(h.replaceCalls) != 0 {
			t.Fatalf("replace called for initially absent target: %v", h.replaceCalls)
		}
	})

	t.Run("create-only exposes existing target failure without cleanup", func(t *testing.T) {
		h := newPrivateArtifactFaultHarness()
		h.linkErr = os.ErrExist
		result, err := publishPrivateNewWithOperations(h.operations(), "/parent/output", []byte("payload"))
		if err == nil || !errors.Is(err, os.ErrExist) {
			t.Fatalf("existing-target error = %v", err)
		}
		assertPrivateArtifactResult(t, result, privateArtifactCreateOnly, false, privateArtifactCleanupComplete, privateArtifactDirectorySyncNotAttempted)
		if len(h.removeCalls) != 1 {
			t.Fatalf("existing target temporary cleanup calls = %v", h.removeCalls)
		}
	})

	t.Run("replace accepts a regular target and reaches rename", func(t *testing.T) {
		dir := t.TempDir()
		regular := filepath.Join(dir, "regular")
		if err := os.WriteFile(regular, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(regular)
		if err != nil {
			t.Fatal(err)
		}
		h := newPrivateArtifactFaultHarness()
		h.lstatInfo, h.lstatErr = info, nil
		result, err := installPrivateReplaceWithOperations(h.operations(), "/parent/output", []byte("payload"))
		if runtime.GOOS == "windows" {
			if err == nil || result.Replacement != privateArtifactReplacementUnsupported {
				t.Fatalf("Windows existing-target result = %#v / %v", result, err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if result.Replacement != privateArtifactReplacementComplete {
			t.Fatalf("replacement status = %s, want complete", result.Replacement)
		}
		if len(h.replaceCalls) != 1 {
			t.Fatalf("replace calls = %v", h.replaceCalls)
		}
	})
}

func TestPrivateArtifactGuardedExchangePreservesInterveningTarget(t *testing.T) {
	if !privateArtifactReplaceExistingSupported {
		t.Skip("guarded exchange is unsupported on this platform")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "artifact")
	temp := filepath.Join(dir, ".staged")
	if err := os.WriteFile(target, []byte("expected-old"), 0o600); err != nil {
		t.Fatal(err)
	}
	expected, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(temp, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	intervening := filepath.Join(dir, "intervening")
	if err := os.WriteFile(intervening, []byte("intervening"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(intervening, target); err != nil {
		t.Fatal(err)
	}
	published, cleanup, mutated, err := replacePrivateArtifactExisting(temp, target, expected)
	if err == nil || published || cleanup != privateArtifactCleanupNotRequired {
		t.Fatalf("guarded replace = published %v cleanup %s err %v", published, cleanup, err)
	}
	if !mutated {
		t.Fatal("guarded replace did not report the rolled-back namespace mutation")
	}
	assertPrivateArtifactFile(t, target, "intervening")
	assertPrivateArtifactFile(t, temp, "new")

	if err := os.Remove(temp); err != nil {
		t.Fatal(err)
	}
	expected, err = os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(temp, []byte("newer"), 0o600); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(dir, "protected")
	if err := os.WriteFile(protected, []byte("protected"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protected, target); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	published, cleanup, mutated, err = replacePrivateArtifactExisting(temp, target, expected)
	if err == nil || published || cleanup != privateArtifactCleanupNotRequired {
		t.Fatalf("symlink-swap replace = published %v cleanup %s err %v", published, cleanup, err)
	}
	if !mutated {
		t.Fatal("symlink-swap replace did not report the rolled-back namespace mutation")
	}
	info, statErr := os.Lstat(target)
	if statErr != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("intervening symlink was not preserved: info=%v err=%v", info, statErr)
	}
	assertPrivateArtifactFile(t, protected, "protected")
	assertPrivateArtifactFile(t, temp, "newer")
}

func assertPrivateArtifactPlatformResult(t *testing.T, result privateArtifactInstallResult, mode privateArtifactMode) {
	t.Helper()
	wantDirectorySync := privateArtifactDirectorySyncComplete
	if runtime.GOOS == "windows" {
		wantDirectorySync = privateArtifactDirectorySyncUnsupported
	}
	cleanup := privateArtifactCleanupComplete
	assertPrivateArtifactResult(t, result, mode, true, cleanup, wantDirectorySync)
}

func assertPrivateArtifactResult(
	t *testing.T,
	result privateArtifactInstallResult,
	mode privateArtifactMode,
	published bool,
	cleanup privateArtifactCleanup,
	directorySync privateArtifactDirectorySync,
) {
	t.Helper()
	if result.Mode != mode || result.Published != published || result.Cleanup != cleanup || result.DirectorySync != directorySync {
		t.Fatalf("result = %#v, want mode=%s published=%v cleanup=%s directorySync=%s", result, mode, published, cleanup, directorySync)
	}
}

func assertPrivateArtifactFile(t *testing.T, path, contents string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != contents {
		t.Fatalf("contents = %q, want %q", raw, contents)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("mode = %v, want regular file", info.Mode())
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("permissions = %04o, want 0600", info.Mode().Perm())
	}
}

var (
	_ io.Writer   = (*privateArtifactFaultFile)(nil)
	_ os.FileInfo = privateArtifactTestFileInfo{}
)

type privateArtifactTestFileInfo struct{ mode os.FileMode }

func (f privateArtifactTestFileInfo) Name() string       { return "fixture" }
func (f privateArtifactTestFileInfo) Size() int64        { return 0 }
func (f privateArtifactTestFileInfo) Mode() os.FileMode  { return f.mode }
func (f privateArtifactTestFileInfo) ModTime() time.Time { return time.Time{} }
func (f privateArtifactTestFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f privateArtifactTestFileInfo) Sys() any           { return nil }

func TestPrivateArtifactInstallNonRegularFaultClassification(t *testing.T) {
	for _, test := range []struct {
		name string
		mode os.FileMode
	}{
		{"directory", os.ModeDir | 0o700},
		{"symlink", os.ModeSymlink | 0o777},
		{"named pipe", os.ModeNamedPipe | 0o600},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newPrivateArtifactFaultHarness()
			h.lstatInfo = privateArtifactTestFileInfo{mode: test.mode}
			h.lstatErr = nil
			result, err := installPrivateReplaceWithOperations(h.operations(), "/parent/output", []byte("payload"))
			if err == nil || !strings.Contains(err.Error(), "non-regular") {
				t.Fatalf("non-regular error = %v", err)
			}
			assertPrivateArtifactResult(t, result, privateArtifactReplaceExisting, false, privateArtifactCleanupNotRequired, privateArtifactDirectorySyncNotAttempted)
			if len(h.replaceCalls) != 0 || len(h.removeCalls) != 0 {
				t.Fatalf("non-regular mutation calls: replace=%v remove=%v", h.replaceCalls, h.removeCalls)
			}
		})
	}
}
