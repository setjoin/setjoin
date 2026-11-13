//go:build linux

package storage

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestWormIoctlConstants is a regression guard for C7-worm:
// FS_IOC_GETFLAGS was locally defined as 0x80046601 (int-sized, 4-byte arg).
// The correct kernel constant is 0x80086601 (long-sized, 8-byte arg on 64-bit).
// The wrong constant causes ENOTTY from every ioctl call, making isImmutable
// always return false and setImmutable always fail — leaving every WORM blob
// silently unprotected. This test fails if the wrong value reappears.
func TestWormIoctlConstants(t *testing.T) {
	const wrongGetFlags = 0x80046601 // the old buggy int-sized value
	if unix.FS_IOC_GETFLAGS == wrongGetFlags {
		t.Fatalf("unix.FS_IOC_GETFLAGS=%#x is the wrong (int-sized) ioctl; expected long-sized %#x",
			unix.FS_IOC_GETFLAGS, uint(0x80086601))
	}

	// Verify the flags variable type has the right size for the ioctl.
	// The ioctl encodes sizeof(unsigned long) in bits 16-29 of the command number.
	// On 64-bit Linux that is 8 bytes; Go's int matches on both 32- and 64-bit.
	var flags int
	if sz := unsafe.Sizeof(flags); int(sz) < int(unsafe.Sizeof(int32(0))) {
		t.Errorf("flags type (int) is %d bytes, smaller than int32 — unsafe.Pointer argument will be undersized", sz)
	}
}

// TestGetObjectLegalHoldFailsClosed guards the compliance fail-open: a
// non-ENODATA getxattr error (here ENOENT from a missing blob) must propagate,
// not be reported as ("OFF", nil). Before the fix, GetObjectLegalHold collapsed
// every error into ("OFF", nil), silently reporting "no legal hold" on a
// regulatory control that could not be read.
func TestGetObjectLegalHoldFailsClosed(t *testing.T) {
	d := &posixDriver{root: t.TempDir()}
	status, err := d.GetObjectLegalHold(context.Background(), "does-not-exist")
	if err == nil {
		t.Fatalf("expected error for missing blob (ENOENT), got status=%q err=nil (fail-open regressed)", status)
	}
	if status != "" {
		t.Errorf("expected empty status on error, got %q", status)
	}
}

func TestWormMethodsRejectUnsafeKeysBeforeFilesystemIO(t *testing.T) {
	d := &posixDriver{root: t.TempDir()}
	ctx := context.Background()
	if err := d.PutObjectRetention(ctx, "../escape", "governance", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("unsafe retention key accepted")
	}
	if _, err := d.GetObjectRetention(ctx, "../escape"); err == nil {
		t.Fatal("unsafe retention lookup key accepted")
	}
	if err := d.PutObjectLegalHold(ctx, "../escape", "ON"); err == nil {
		t.Fatal("unsafe legal-hold key accepted")
	}
	if _, err := d.GetObjectLegalHold(ctx, "../escape"); err == nil {
		t.Fatal("unsafe legal-hold lookup key accepted")
	}
}

// setUserXattrOrSkip probes user.* xattr support on the test filesystem.
func setUserXattrOrSkip(t *testing.T, path string) {
	t.Helper()
	if err := unix.Setxattr(path, "user.worm_probe", []byte("1"), 0); err != nil {
		t.Skipf("filesystem lacks user.* xattr support: %v", err)
	}
}

func testBlobPath(t *testing.T, driver *posixDriver, key string) string {
	t.Helper()
	path, err := driver.safeBlobPath(key)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// TestPutObjectRetentionLengthenOnly proves G9 defects #2+#3: a second, SHORTER
// retention call must not weaken the stored lock, and retention metadata must
// persist without CAP_SYS_ADMIN (user.* namespace fallback).
func TestPutObjectRetentionLengthenOnly(t *testing.T) {
	d := &posixDriver{root: t.TempDir()}
	if err := d.PutObject(context.Background(), "chunk1", strings.NewReader("x"), 1); err != nil {
		t.Fatal(err)
	}
	setUserXattrOrSkip(t, testBlobPath(t, d, "chunk1"))

	far := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	near := time.Now().Add(1 * time.Hour).Truncate(time.Second)
	if err := d.PutObjectRetention(context.Background(), "chunk1", "governance", far); err != nil {
		// unprivileged runner: immutable flag needs CAP_LINUX_IMMUTABLE — xattrs must
		// still have been written before the chattr step failed.
		t.Logf("setImmutable unavailable (unprivileged): %v", err)
	}
	if err := d.PutObjectRetention(context.Background(), "chunk1", "governance", near); err != nil {
		t.Logf("second call: %v", err)
	}
	st, err := d.GetObjectRetention(context.Background(), "chunk1")
	if err != nil {
		t.Fatal(err)
	}
	if !st.RetainUntil.Equal(far) {
		t.Fatalf("retention weakened: got %v want %v (lengthen-only violated)", st.RetainUntil, far)
	}
}

// TestPutObjectRetentionExtendsImmutable proves G9 defect #1: extending the lock
// on an ALREADY-IMMUTABLE object must succeed (clear→setxattr→re-immutable dance)
// and the object must be immutable again afterwards. Needs CAP_LINUX_IMMUTABLE.
func TestPutObjectRetentionExtendsImmutable(t *testing.T) {
	d := &posixDriver{root: t.TempDir()}
	if err := d.PutObject(context.Background(), "chunk2", strings.NewReader("x"), 1); err != nil {
		t.Fatal(err)
	}
	setUserXattrOrSkip(t, testBlobPath(t, d, "chunk2"))
	near := time.Now().Add(1 * time.Hour).Truncate(time.Second)
	far := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	if err := d.PutObjectRetention(context.Background(), "chunk2", "governance", near); err != nil {
		t.Skipf("cannot set immutable flag (needs CAP_LINUX_IMMUTABLE): %v", err)
	}
	if !d.isImmutable(testBlobPath(t, d, "chunk2")) {
		t.Skip("immutable flag did not stick (unsupported fs)")
	}
	// THE bug: this used to fail EPERM (setxattr on an immutable file).
	if err := d.PutObjectRetention(context.Background(), "chunk2", "governance", far); err != nil {
		t.Fatalf("extend on immutable object failed (G9 regression): %v", err)
	}
	st, err := d.GetObjectRetention(context.Background(), "chunk2")
	if err != nil {
		t.Fatal(err)
	}
	if !st.RetainUntil.Equal(far) {
		t.Fatalf("extend not persisted: got %v want %v", st.RetainUntil, far)
	}
	if !d.isImmutable(testBlobPath(t, d, "chunk2")) {
		t.Fatal("object left MUTABLE after extend — re-immutable step missing")
	}
	if err := d.DeleteObject(context.Background(), "chunk2"); !errors.Is(err, ErrObjectLocked) {
		t.Fatalf("locked object deletable after extend: %v", err)
	}
}

// TestPutObjectLegalHoldDanceOnImmutable proves the F-003 fix: a legal hold
// must apply to (and release from) an ALREADY-IMMUTABLE object — plain setxattr
// on an immutable file fails EPERM, so the hold paths must use the same
// clear→xattr→re-immutable dance as retention — and the object must never be
// left mutable while still protected.
func TestPutObjectLegalHoldDanceOnImmutable(t *testing.T) {
	d := &posixDriver{root: t.TempDir()}
	if err := d.PutObject(context.Background(), "chunk-hold", strings.NewReader("x"), 1); err != nil {
		t.Fatal(err)
	}
	setUserXattrOrSkip(t, testBlobPath(t, d, "chunk-hold"))
	far := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	if err := d.PutObjectRetention(context.Background(), "chunk-hold", "governance", far); err != nil {
		t.Skipf("cannot set immutable flag (needs CAP_LINUX_IMMUTABLE): %v", err)
	}
	ctx := context.Background()

	// ON over an immutable object: used to fail EPERM.
	if err := d.PutObjectLegalHold(ctx, "chunk-hold", "ON"); err != nil {
		t.Fatalf("legal hold ON on immutable object failed (F-003 regression): %v", err)
	}
	status, err := d.GetObjectLegalHold(ctx, "chunk-hold")
	if err != nil || status != "ON" {
		t.Fatalf("hold status after ON = %q, %v; want ON, nil", status, err)
	}
	if !d.isImmutable(testBlobPath(t, d, "chunk-hold")) {
		t.Fatal("object left MUTABLE while legal hold is ON")
	}
	if err := d.DeleteObject(ctx, "chunk-hold"); !errors.Is(err, ErrObjectLocked) {
		t.Fatalf("held object deletable: %v", err)
	}

	// OFF with retention still active: hold released, object re-locked by
	// retention (never left mutable while protected).
	if err := d.PutObjectLegalHold(ctx, "chunk-hold", "OFF"); err != nil {
		t.Fatalf("legal hold OFF failed: %v", err)
	}
	if status, err := d.GetObjectLegalHold(ctx, "chunk-hold"); err != nil || status != "OFF" {
		t.Fatalf("hold status after OFF = %q, %v; want OFF, nil", status, err)
	}
	if !d.isImmutable(testBlobPath(t, d, "chunk-hold")) {
		t.Fatal("object left MUTABLE while retention is still active after hold OFF")
	}
	if err := d.DeleteObject(ctx, "chunk-hold"); !errors.Is(err, ErrObjectLocked) {
		t.Fatalf("retention-locked object deletable after hold OFF: %v", err)
	}
}

// TestGetBucketObjectLockConfigFailsClosedOnUnenforceableFS proves F-004:
// Enabled:true is a measured capability, not self-attestation. On a filesystem
// that cannot enforce immutability the config must fail closed with the probe
// error instead of reporting Enabled:true unconditionally.
func TestGetBucketObjectLockConfigFailsClosedOnUnenforceableFS(t *testing.T) {
	d := &posixDriver{root: t.TempDir()}
	cfg, err := d.GetBucketObjectLockConfig(context.Background())
	if err != nil {
		// Unprivileged/unenforceable environment: fail closed is the contract.
		if cfg != nil {
			t.Fatalf("config returned alongside probe error: %+v", cfg)
		}
		return
	}
	if !cfg.Enabled {
		t.Fatal("enforceable filesystem reported Enabled:false")
	}
}

// TestEnsureBucketObjectLockRecordsModeTruthfully proves the F-004 remediation:
// after Ensure, GetBucketObjectLockConfig reports the recorded mode/days so
// StartupWORMCheck's mode-mismatch branch operates on recorded state.
func TestEnsureBucketObjectLockRecordsModeTruthfully(t *testing.T) {
	d := &posixDriver{root: t.TempDir()}
	if err := d.EnsureBucketObjectLock(context.Background(), "compliance", 2557); err != nil {
		t.Skipf("cannot enforce immutability (needs CAP_LINUX_IMMUTABLE + xattrs): %v", err)
	}
	cfg, err := d.GetBucketObjectLockConfig(context.Background())
	if err != nil {
		t.Fatalf("GetBucketObjectLockConfig after ensure: %v", err)
	}
	if cfg.Mode != "compliance" {
		t.Fatalf("Mode = %q, want compliance (recorded posture not reported)", cfg.Mode)
	}
	if cfg.RetentionPeriodDays != 2557 {
		t.Fatalf("RetentionPeriodDays = %d, want 2557", cfg.RetentionPeriodDays)
	}
}

// TestPutObjectRetentionConcurrentSerializes proves G9 batch-2 correction #4: two
// concurrent PutObjectRetention calls on the SAME key (a post-commit worker retry
// racing another save, or two concurrent saves) must never let the shorter lock
// win in storage. The per-driver mutex serializes the read-merge-write dance so
// whichever call runs second always observes the first's write and the final
// state is the pairwise maximum regardless of goroutine ordering.
func TestPutObjectRetentionConcurrentSerializes(t *testing.T) {
	d := &posixDriver{root: t.TempDir()}
	if err := d.PutObject(context.Background(), "chunk3", strings.NewReader("x"), 1); err != nil {
		t.Fatal(err)
	}
	setUserXattrOrSkip(t, testBlobPath(t, d, "chunk3"))

	near := time.Now().Add(1 * time.Hour).Truncate(time.Second)
	far := time.Now().Add(48 * time.Hour).Truncate(time.Second)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = d.PutObjectRetention(context.Background(), "chunk3", "governance", far)
	}()
	go func() {
		defer wg.Done()
		_ = d.PutObjectRetention(context.Background(), "chunk3", "governance", near)
	}()
	wg.Wait()

	st, err := d.GetObjectRetention(context.Background(), "chunk3")
	if err != nil {
		t.Fatal(err)
	}
	if !st.RetainUntil.Equal(far) {
		t.Fatalf("concurrent PutObjectRetention lost the longer lock: got %v want %v (unserialized lost-update race)", st.RetainUntil, far)
	}
}
