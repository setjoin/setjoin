//go:build linux

package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ── WORM via Linux immutable flag ──

func (d *posixDriver) isImmutable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }() // read-only descriptor: close carries no durability semantics
	// ponytail: FS_IMMUTABLE_FL is not in golang.org/x/sys/unix; keep local.
	const FS_IMMUTABLE_FL = 0x00000010
	var flags int // unsigned long on kernel side; int matches on 64-bit and 32-bit
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.FS_IOC_GETFLAGS, uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return false
	}
	return flags&FS_IMMUTABLE_FL != 0
}

func (d *posixDriver) setImmutable(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // read-only descriptor: close carries no durability semantics
	const FS_IMMUTABLE_FL = 0x00000010
	var flags int
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.FS_IOC_GETFLAGS, uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return fmt.Errorf("posix: get flags: %w", errno)
	}
	flags |= FS_IMMUTABLE_FL
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.FS_IOC_SETFLAGS, uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return fmt.Errorf("posix: chattr +i: %w", errno)
	}
	return nil
}

func (d *posixDriver) clearImmutable(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // read-only descriptor: close carries no durability semantics
	const FS_IMMUTABLE_FL = 0x00000010
	var flags int
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.FS_IOC_GETFLAGS, uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return fmt.Errorf("posix: get flags: %w", errno)
	}
	flags &^= FS_IMMUTABLE_FL
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.FS_IOC_SETFLAGS, uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return fmt.Errorf("posix: chattr -i: %w", errno)
	}
	return nil
}

// xattr namespace fallback (G9 defect #3): trusted.* needs CAP_SYS_ADMIN; a
// deployment running with only CAP_LINUX_IMMUTABLE falls back to user.*.
// Reads check trusted.* FIRST so pre-fix locks keep working.
var wormXattrNamespaces = [2]string{"trusted.", "user."}

func setWormXattr(path, name string, value []byte) error {
	var firstErr error
	for _, ns := range wormXattrNamespaces {
		err := unix.Setxattr(path, ns+name, value, 0)
		if err == nil {
			return nil
		}
		if firstErr == nil {
			firstErr = err
		}
		if !errors.Is(err, unix.EPERM) {
			return fmt.Errorf("posix: setxattr %s%s: %w", ns, name, err)
		}
	}
	return fmt.Errorf("posix: setxattr %s (both namespaces): %w", name, firstErr)
}

func getWormXattr(path, name string) ([]byte, error) {
	var lastErr error
	for _, ns := range wormXattrNamespaces {
		sz, err := unix.Getxattr(path, ns+name, nil)
		if err != nil {
			lastErr = err
			continue
		}
		data := make([]byte, sz)
		if _, err := unix.Getxattr(path, ns+name, data); err != nil {
			return nil, fmt.Errorf("posix: getxattr %s%s value: %w", ns, name, err)
		}
		return data, nil
	}
	return nil, lastErr // ENODATA when unset in both namespaces
}

// removeWormXattr clears name from whichever namespace holds it; ENODATA in
// both namespaces (already unset) is success.
func removeWormXattr(path, name string) error {
	var lastErr error
	for _, ns := range wormXattrNamespaces {
		if err := unix.Removexattr(path, ns+name); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr != nil && !errors.Is(lastErr, unix.ENODATA) {
		return fmt.Errorf("posix: removexattr %s: %w", name, lastErr)
	}
	return nil
}

// PutObjectRetention applies WORM retention with lengthen-only semantics (G9):
// read existing → merge via resolveRetentionUpgrade (retain-until only lengthens,
// mode only hardens) → if already covered, no-op → clear immutable → setxattr →
// ALWAYS re-set immutable (deferred; runs on the error path too — a WORM object
// must never be left mutable because a metadata write failed).
//
// wormMu serializes the whole read-merge-write dance (batch-2 correction #4): the
// clear-immutable/setxattr/re-immutable sequence is not atomic at the syscall
// level, so unserialized concurrent calls (a worker retry racing another save)
// could interleave and let a shorter lock win in storage.
func (d *posixDriver) PutObjectRetention(ctx context.Context, key, mode string, retainUntil time.Time) error {
	d.wormMu.Lock()
	defer d.wormMu.Unlock()

	path, err := d.safeBlobPath(key)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("posix: retention stat: %w", err)
	}
	cur, err := d.GetObjectRetention(ctx, key) // getxattr works on immutable files
	if err != nil {
		return fmt.Errorf("posix: retention read-before-write: %w", err)
	}
	newMode, newUntil, apply := resolveRetentionUpgrade(cur.Mode, cur.RetainUntil, mode, retainUntil)
	if !apply {
		// Existing lock already covers the request. Belt-and-braces: ensure the
		// immutable flag is actually set (a pre-fix partial write may have left
		// xattrs without the flag).
		if !d.isImmutable(path) {
			return d.setImmutable(path)
		}
		return nil
	}
	wasImmutable := d.isImmutable(path)
	if wasImmutable {
		if err := d.clearImmutable(path); err != nil {
			return fmt.Errorf("posix: retention unlock-for-extend: %w", err)
		}
	}
	xerr := setWormXattr(path, "retain_until", []byte(newUntil.Format(time.RFC3339)))
	if xerr == nil {
		xerr = setWormXattr(path, "retention_mode", []byte(newMode))
	}
	// Re-immutable UNCONDITIONALLY (fresh objects get locked here too).
	if ierr := d.setImmutable(path); ierr != nil {
		if xerr != nil {
			return fmt.Errorf("posix: retention write failed (%v) AND re-lock failed: %w", xerr, ierr)
		}
		return fmt.Errorf("posix: chattr +i after retention write: %w", ierr)
	}
	if xerr != nil {
		return fmt.Errorf("posix: retention xattr (object re-locked at old terms): %w", xerr)
	}
	return nil
}

func (d *posixDriver) GetObjectRetention(_ context.Context, key string) (*RetentionStatus, error) {
	path, err := d.safeBlobPath(key)
	if err != nil {
		return nil, err
	}
	data, err := getWormXattr(path, "retain_until")
	if err != nil {
		if errors.Is(err, unix.ENODATA) {
			return &RetentionStatus{}, nil
		}
		return nil, fmt.Errorf("posix: getxattr: %w", err)
	}
	retainUntil, err := time.Parse(time.RFC3339, string(data))
	if err != nil {
		return nil, fmt.Errorf("posix: parse retain_until: %w", err)
	}
	mode, _ := getWormXattr(path, "retention_mode")
	return &RetentionStatus{
		Mode:        string(mode),
		RetainUntil: retainUntil,
	}, nil
}

func (d *posixDriver) PutObjectLegalHold(_ context.Context, key, status string) error {
	d.wormMu.Lock()
	defer d.wormMu.Unlock()

	path, err := d.safeBlobPath(key)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("posix: legal hold stat: %w", err)
	}

	held, err := d.hasLegalHold(path)
	if err != nil {
		return fmt.Errorf("posix: legal hold read-before-write: %w", err)
	}
	if (status == "ON" && held) || (status == "OFF" && !held) {
		// Belt-and-braces (mirrors PutObjectRetention): an ON hold keeps the
		// object immutable even if a pre-fix partial write left it unlocked.
		if status == "ON" && !d.isImmutable(path) {
			return d.setImmutable(path)
		}
		return nil
	}

	// Same dance as PutObjectRetention: a plain xattr write on an immutable
	// file fails with EPERM, so clear the flag first and ALWAYS restore it
	// while the object must stay protected — a hold must never leave the
	// object mutable because a metadata step failed.
	wasImmutable := d.isImmutable(path)
	if wasImmutable {
		if err := d.clearImmutable(path); err != nil {
			return fmt.Errorf("posix: legal hold unlock-for-write: %w", err)
		}
	}
	var xerr error
	if status == "ON" {
		xerr = setWormXattr(path, "legal_hold", []byte("1"))
	} else {
		xerr = removeWormXattr(path, "legal_hold")
	}
	// Re-lock unconditionally on ON; on OFF only while an active retention
	// term remains (a hold-less, retention-less object returns to its mutable
	// baseline).
	if status == "ON" || d.hasActiveRetention(path) {
		if ierr := d.setImmutable(path); ierr != nil {
			if xerr != nil {
				return fmt.Errorf("posix: legal hold write failed (%v) AND re-lock failed: %w", xerr, ierr)
			}
			return fmt.Errorf("posix: chattr +i after legal hold write: %w", ierr)
		}
	}
	if xerr != nil {
		return fmt.Errorf("posix: legal hold xattr: %w", xerr)
	}
	return nil
}

// hasLegalHold reads the hold xattr at path: true when set, false when unset
// (ENODATA), and the error otherwise — callers fail closed on read faults.
func (d *posixDriver) hasLegalHold(path string) (bool, error) {
	_, err := getWormXattr(path, "legal_hold")
	if err == nil {
		return true, nil
	}
	if errors.Is(err, unix.ENODATA) {
		return false, nil
	}
	return false, fmt.Errorf("posix: getxattr legal_hold: %w", err)
}

// hasActiveRetention reports whether the object still carries an unexpired
// retention term. Unreadable/corrupt metadata fails toward "locked" so
// uncertainty can never leave a WORM object mutable; ENODATA (no term) is the
// only trusted "no".
func (d *posixDriver) hasActiveRetention(path string) bool {
	data, err := getWormXattr(path, "retain_until")
	if err != nil {
		return !errors.Is(err, unix.ENODATA)
	}
	until, err := time.Parse(time.RFC3339, string(data))
	if err != nil {
		return true
	}
	return until.After(time.Now())
}

func (d *posixDriver) GetObjectLegalHold(_ context.Context, key string) (string, error) {
	path, err := d.safeBlobPath(key)
	if err != nil {
		return "", err
	}
	held, err := d.hasLegalHold(path)
	if err != nil {
		return "", err
	}
	if held {
		return "ON", nil
	}
	return "OFF", nil
}

// wormEnforcementProbe failures mean the filesystem can neither take the
// immutable flag nor WORM xattrs, so this backend cannot honor WORM at all
// and every lock-config operation must fail closed with the concrete errno.
// Enforcement capability is a host/filesystem property, so the probe runs
// once per process (mutex-free via sync.Once) on a scratch file under the
// bucket root.
var (
	wormProbeOnce sync.Once
	wormProbeErr  error
)

// probeWormEnforcement verifies, exactly once, that this filesystem can
// actually enforce immutability: FS_IOC_SETFLAGS (+i) on a probe file plus a
// WORM-namespace xattr write. GetBucketObjectLockConfig and
// EnsureBucketObjectLock gate on it so a backend on a filesystem without
// immutable-flag or xattr support self-reports instead of self-attesting.
func (d *posixDriver) probeWormEnforcement() error {
	wormProbeOnce.Do(func() {
		if err := os.MkdirAll(d.root, 0o700); err != nil {
			wormProbeErr = fmt.Errorf("posix: worm enforcement probe mkdir: %w", err)
			return
		}
		probe := filepath.Join(d.root, ".worm-enforcement-probe")
		if err := os.WriteFile(probe, nil, 0o600); err != nil {
			wormProbeErr = fmt.Errorf("posix: worm enforcement probe create: %w", err)
			return
		}
		defer func() { _ = os.Remove(probe) }()
		if err := d.setImmutable(probe); err != nil {
			wormProbeErr = fmt.Errorf("posix: worm enforcement probe (immutable flag unavailable): %w", err)
			return
		}
		// Undo the flag before removal; a leftover immutable probe file would
		// wedge the next boot's probe.
		if err := d.clearImmutable(probe); err != nil {
			wormProbeErr = fmt.Errorf("posix: worm enforcement probe cleanup: %w", err)
			return
		}
		if err := setWormXattr(probe, "probe", []byte("1")); err != nil {
			wormProbeErr = fmt.Errorf("posix: worm enforcement probe (xattr namespace unavailable): %w", err)
		}
	})
	return wormProbeErr
}

func (d *posixDriver) EnsureBucketObjectLock(_ context.Context, mode string, retentionDays int) error {
	if err := d.EnsureBucket(context.Background()); err != nil {
		return err
	}
	// Fail closed when the filesystem cannot enforce immutability instead of
	// reporting a WORM mandate as satisfied on an uneforceable backend.
	if err := d.probeWormEnforcement(); err != nil {
		return err
	}
	// Record the enforced lock posture on the bucket root so
	// GetBucketObjectLockConfig reports truthfully (StartupWORMCheck's
	// mode-mismatch branch works against recorded state, not a constant).
	if err := setWormXattr(d.root, "lock_mode", []byte(mode)); err != nil {
		return fmt.Errorf("posix: record lock_mode: %w", err)
	}
	if err := setWormXattr(d.root, "lock_retention_days", []byte(strconv.Itoa(retentionDays))); err != nil {
		return fmt.Errorf("posix: record lock_retention_days: %w", err)
	}
	return nil
}

func (d *posixDriver) GetBucketObjectLockConfig(_ context.Context) (*BucketLockConfig, error) {
	// Enabled:true is a measured capability here, not self-attestation.
	if err := d.probeWormEnforcement(); err != nil {
		return nil, err
	}
	cfg := &BucketLockConfig{Enabled: true}
	// Mode/days are what EnsureBucketObjectLock recorded; ENODATA (never
	// ensured) leaves Mode empty, which fails StartupWORMCheck's mismatch
	// branch closed exactly as before.
	if mode, err := getWormXattr(d.root, "lock_mode"); err == nil {
		cfg.Mode = string(mode)
	}
	if days, err := getWormXattr(d.root, "lock_retention_days"); err == nil {
		if n, perr := strconv.Atoi(string(days)); perr == nil {
			cfg.RetentionPeriodDays = n
		}
	}
	return cfg, nil
}
