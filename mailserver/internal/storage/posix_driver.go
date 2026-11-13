package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"sync"
)

// posixDriver stores blobs as files under a single root directory.
// Blobs are sharded by SHA-256 prefix (2-char subdirectory) to avoid
// single-directory file limits. WORM is implemented via Linux immutable
// flag (chattr +i, Veeam Hardened Repository model).
type posixDriver struct {
	root string

	// wormMu serializes PutObjectRetention (G9 batch-2 correction #4): the
	// read-existing→merge→clear-immutable→setxattr→re-immutable dance is not
	// atomic at the syscall level, so two concurrent calls on the same (or
	// different) chunks could interleave and let a shorter lock win in
	// storage while the DB's GREATEST mark-applied records the longer one.
	// ponytail: single mutex, keyed map if contention shows.
	wormMu sync.Mutex
}

// NewPOSIXDriver creates a POSIX filesystem storage driver.
// root is the base directory (e.g., /data/blobs). It is created if absent.
func NewPOSIXDriver(root string) (Driver, error) {
	if root == "" {
		return nil, fmt.Errorf("posix: root path required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("posix: resolve root: %w", err)
	}
	return &posixDriver{root: abs}, nil
}

// ── Path helpers ──

const maxPOSIXObjectKeyBytes = 1024

func validatePOSIXObjectKey(key string) error {
	if key == "" || len(key) > maxPOSIXObjectKeyBytes || strings.ContainsRune(key, '\x00') ||
		strings.Contains(key, `\`) || strings.HasPrefix(key, "/") ||
		pathpkg.Clean(key) != key || key == "." || key == ".." || strings.HasPrefix(key, "../") {
		return fmt.Errorf("posix: invalid object key")
	}
	return nil
}

func (d *posixDriver) safeBlobPath(key string) (string, error) {
	if err := validatePOSIXObjectKey(key); err != nil {
		return "", err
	}
	shard := key
	if len(shard) > 2 {
		shard = shard[:2]
	}
	resolved := filepath.Join(d.root, shard, filepath.FromSlash(key))
	rel, err := filepath.Rel(d.root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("posix: object key escapes storage root")
	}
	return resolved, nil
}

func (d *posixDriver) rejectSymlinkComponents(resolved string, includeLeaf bool) error {
	rel, err := filepath.Rel(d.root, resolved)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("posix: object path escapes storage root")
	}
	parts := strings.Split(rel, string(filepath.Separator))
	current := d.root
	for index, part := range parts {
		if index == len(parts)-1 && !includeLeaf {
			break
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if os.IsNotExist(statErr) {
			return nil
		}
		if statErr != nil {
			return fmt.Errorf("posix: inspect confined object path: %w", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("posix: symbolic links are not allowed in object paths")
		}
		if index < len(parts)-1 && !info.IsDir() {
			return fmt.Errorf("posix: object parent is not a directory")
		}
	}
	return nil
}

// ── Core operations ──

func (d *posixDriver) PutObject(_ context.Context, key string, data io.Reader, _ int64) error {
	final, err := d.safeBlobPath(key)
	if err != nil {
		return err
	}
	if err := d.rejectSymlinkComponents(final, false); err != nil {
		return err
	}
	dir := filepath.Dir(final)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("posix: mkdir %s: %w", dir, err)
	}
	if err := d.rejectSymlinkComponents(final, false); err != nil {
		return err
	}

	// Atomic write: temp file + rename.
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("posix: create temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { os.Remove(tmpPath) }

	if _, err := io.Copy(tmp, data); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("posix: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("posix: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("posix: close temp: %w", err)
	}

	if err := os.Rename(tmpPath, final); err != nil {
		cleanup()
		return fmt.Errorf("posix: rename %s -> %s: %w", tmpPath, final, err)
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("posix: fsync destination directory: %w", err)
	}
	return nil
}

func (d *posixDriver) GetObject(_ context.Context, key string) (io.ReadCloser, error) {
	path, err := d.safeBlobPath(key)
	if err != nil {
		return nil, err
	}
	if err := d.rejectSymlinkComponents(path, true); err != nil {
		return nil, err
	}
	f, err := os.Open(path) //nolint:gosec // G304: validated below the configured root and every existing component is non-symlink
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("posix: object not found: %s", key)
		}
		return nil, fmt.Errorf("posix: open %s: %w", key, err)
	}
	return f, nil
}

func (d *posixDriver) DeleteObject(_ context.Context, key string) error {
	path, err := d.safeBlobPath(key)
	if err != nil {
		return err
	}
	if err := d.rejectSymlinkComponents(path, true); err != nil {
		return err
	}
	if d.isImmutable(path) {
		return ErrObjectLocked
	}
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return nil // idempotent
		}
		return fmt.Errorf("posix: remove %s: %w", key, err)
	}
	return nil
}

func (d *posixDriver) CopyObject(_ context.Context, _, srcKey, _, dstKey string) error {
	srcPath, err := d.safeBlobPath(srcKey)
	if err != nil {
		return err
	}
	if err := d.rejectSymlinkComponents(srcPath, true); err != nil {
		return err
	}
	dstPath, err := d.safeBlobPath(dstKey)
	if err != nil {
		return err
	}
	if err := d.rejectSymlinkComponents(dstPath, false); err != nil {
		return err
	}
	dstDir := filepath.Dir(dstPath)
	if err := os.MkdirAll(dstDir, 0750); err != nil {
		return fmt.Errorf("posix: mkdir %s: %w", dstDir, err)
	}
	if err := d.rejectSymlinkComponents(dstPath, false); err != nil {
		return err
	}
	src, err := os.Open(srcPath) //nolint:gosec // G304: path is the trusted storage root joined with a content-addressed blob key, not user input
	if err != nil {
		return fmt.Errorf("posix: open src: %w", err)
	}
	tmp, err := os.CreateTemp(dstDir, ".tmp-*")
	if err != nil {
		_ = src.Close()
		return fmt.Errorf("posix: create temp: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := io.Copy(tmp, src); err != nil {
		_ = src.Close()
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("posix: copy: %w", err)
	}
	if err := src.Close(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("posix: close source: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("posix: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("posix: close temp: %w", err)
	}

	if err := os.Rename(tmpPath, dstPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("posix: rename: %w", err)
	}
	if err := syncDirectory(dstDir); err != nil {
		return fmt.Errorf("posix: fsync destination directory: %w", err)
	}
	return nil
}

func syncDirectory(dir string) error {
	f, err := os.Open(dir) //nolint:gosec // G304: callers pass a validated storage-root descendant or a process-created destination
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (d *posixDriver) StatObject(ctx context.Context, key string) (*ObjectInfo, error) {
	return d.HeadObject(ctx, key)
}

func (d *posixDriver) HeadObject(_ context.Context, key string) (*ObjectInfo, error) {
	path, err := d.safeBlobPath(key)
	if err != nil {
		return nil, err
	}
	if err := d.rejectSymlinkComponents(path, true); err != nil {
		return nil, err
	}
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("posix: not found: %s", key)
		}
		return nil, fmt.Errorf("posix: stat: %w", err)
	}
	return &ObjectInfo{
		Key:          key,
		Size:         fi.Size(),
		LastModified: fi.ModTime(),
	}, nil
}

func (d *posixDriver) ListObjects(_ context.Context, prefix string) ([]ObjectInfo, error) {
	var results []ObjectInfo
	err := filepath.Walk(d.root, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		// Use filename as key — shard directories are an implementation detail.
		key := fi.Name()
		if !strings.HasPrefix(key, prefix) {
			return nil
		}
		results = append(results, ObjectInfo{
			Key:          key,
			Size:         fi.Size(),
			LastModified: fi.ModTime(),
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("posix: walk: %w", err)
	}
	return results, nil
}

func (d *posixDriver) EnsureBucket(_ context.Context) error {
	return os.MkdirAll(d.root, 0750)
}

func (d *posixDriver) BucketExists(_ context.Context) (bool, error) {
	fi, err := os.Stat(d.root)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return fi.IsDir(), nil
}

func (d *posixDriver) RootPath() string { return d.root }

func (d *posixDriver) ProviderName() string { return "posix" }
func (d *posixDriver) Endpoint() string     { return d.root }

func (d *posixDriver) Ping(_ context.Context) error {
	_, err := os.Stat(d.root)
	return err
}
