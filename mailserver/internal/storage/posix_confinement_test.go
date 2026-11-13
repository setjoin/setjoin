package storage

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPOSIXDriverRejectsUnconfinedObjectKeysBeforeIO(t *testing.T) {
	driverAny, err := NewPOSIXDriver(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	driver := driverAny.(*posixDriver)
	ctx := context.Background()
	for _, key := range []string{"", "../escape", "/absolute", "blobs/../../escape", "a//b", `a\..\b`} {
		t.Run(key, func(t *testing.T) {
			if _, err := driver.safeBlobPath(key); err == nil {
				t.Fatal("unsafe key resolved")
			}
			if err := driver.PutObject(ctx, key, bytes.NewReader([]byte("x")), 1); err == nil {
				t.Fatal("unsafe put succeeded")
			}
			if _, err := driver.GetObject(ctx, key); err == nil {
				t.Fatal("unsafe get succeeded")
			}
			if _, err := driver.HeadObject(ctx, key); err == nil {
				t.Fatal("unsafe head succeeded")
			}
			if err := driver.DeleteObject(ctx, key); err == nil {
				t.Fatal("unsafe delete succeeded")
			}
			if err := driver.CopyObject(ctx, "", key, "", "safe"); err == nil {
				t.Fatal("unsafe source copy succeeded")
			}
			if err := driver.CopyObject(ctx, "", "safe", "", key); err == nil {
				t.Fatal("unsafe destination copy succeeded")
			}
		})
	}
}

func TestPOSIXDriverConfinesShortAndNestedKeys(t *testing.T) {
	root := t.TempDir()
	driverAny, err := NewPOSIXDriver(root)
	if err != nil {
		t.Fatal(err)
	}
	driver := driverAny.(*posixDriver)
	ctx := context.Background()
	for _, key := range []string{"a", "blobs/abcdef"} {
		if err := driver.PutObject(ctx, key, bytes.NewReader([]byte(key)), int64(len(key))); err != nil {
			t.Fatalf("put %q: %v", key, err)
		}
		r, err := driver.GetObject(ctx, key)
		if err != nil {
			t.Fatalf("get %q: %v", key, err)
		}
		got, readErr := io.ReadAll(r)
		closeErr := r.Close()
		if readErr != nil || closeErr != nil || string(got) != key {
			t.Fatalf("round trip %q: got=%q read=%v close=%v", key, got, readErr, closeErr)
		}
		path, err := driver.safeBlobPath(key)
		if err != nil {
			t.Fatal(err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == ".." || filepath.IsAbs(rel) {
			t.Fatalf("key %q escaped root: path=%q rel=%q err=%v", key, path, rel, err)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("stored key %q missing: %v", key, err)
		}
	}
}

func TestPOSIXDriverRejectsSymlinkedObjectPaths(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	driverAny, err := NewPOSIXDriver(root)
	if err != nil {
		t.Fatal(err)
	}
	driver := driverAny.(*posixDriver)
	ctx := context.Background()

	if err := os.Symlink(outside, filepath.Join(root, "ab")); err != nil {
		t.Fatal(err)
	}
	if err := driver.PutObject(ctx, "abcdef", bytes.NewReader([]byte("escape")), 6); err == nil {
		t.Fatal("put followed a symlinked shard")
	}
	if _, err := os.Stat(filepath.Join(outside, "abcdef")); !os.IsNotExist(err) {
		t.Fatalf("put escaped storage root: %v", err)
	}

	if err := os.Remove(filepath.Join(root, "ab")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "ab"), 0o750); err != nil {
		t.Fatal(err)
	}
	outsideObject := filepath.Join(outside, "object")
	if err := os.WriteFile(outsideObject, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideObject, filepath.Join(root, "ab", "abcdef")); err != nil {
		t.Fatal(err)
	}
	if _, err := driver.GetObject(ctx, "abcdef"); err == nil {
		t.Fatal("get followed a symlinked object")
	}
	if _, err := driver.HeadObject(ctx, "abcdef"); err == nil {
		t.Fatal("head followed a symlinked object")
	}
	if err := driver.DeleteObject(ctx, "abcdef"); err == nil {
		t.Fatal("delete accepted a symlinked object")
	}
	if got, err := os.ReadFile(outsideObject); err != nil || string(got) != "outside" {
		t.Fatalf("outside object changed: got=%q err=%v", got, err)
	}
}

func TestPOSIXDriverCopyListHeadDeleteAndFilesystemFailures(t *testing.T) {
	root := filepath.Join(t.TempDir(), "objects")
	driverAny, err := NewPOSIXDriver(root)
	if err != nil {
		t.Fatal(err)
	}
	driver := driverAny.(*posixDriver)
	ctx := context.Background()
	if exists, err := driver.BucketExists(ctx); err != nil || exists {
		t.Fatalf("pre-create exists=%v err=%v", exists, err)
	}
	if err := driver.EnsureBucket(ctx); err != nil {
		t.Fatal(err)
	}
	if exists, err := driver.BucketExists(ctx); err != nil || !exists {
		t.Fatalf("post-create exists=%v err=%v", exists, err)
	}
	if err := driver.PutObject(ctx, "source", strings.NewReader("payload"), 7); err != nil {
		t.Fatal(err)
	}
	if err := driver.CopyObject(ctx, "ignored", "source", "ignored", "copy"); err != nil {
		t.Fatal(err)
	}
	info, err := driver.HeadObject(ctx, "copy")
	if err != nil || info.Key != "copy" || info.Size != 7 {
		t.Fatalf("head=%+v err=%v", info, err)
	}
	if stat, err := driver.StatObject(ctx, "copy"); err != nil || stat.Size != info.Size {
		t.Fatalf("stat=%+v err=%v", stat, err)
	}
	listed, err := driver.ListObjects(ctx, "cop")
	if err != nil || len(listed) != 1 || listed[0].Key != "copy" {
		t.Fatalf("listed=%+v err=%v", listed, err)
	}
	if err := driver.DeleteObject(ctx, "copy"); err != nil {
		t.Fatal(err)
	}
	if err := driver.DeleteObject(ctx, "copy"); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
	if _, err := driver.GetObject(ctx, "missing"); err == nil {
		t.Fatal("missing object opened")
	}
	if _, err := driver.HeadObject(ctx, "missing"); err == nil {
		t.Fatal("missing object headed")
	}
	if err := driver.CopyObject(ctx, "", "missing", "", "destination"); err == nil {
		t.Fatal("missing copy source accepted")
	}
	if err := driver.rejectSymlinkComponents(root, false); err == nil {
		t.Fatal("storage root accepted as an object path")
	}
	if err := syncDirectory(filepath.Join(root, "missing")); err == nil {
		t.Fatal("missing directory fsync accepted")
	}
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if _, err := driver.ListObjects(ctx, ""); err == nil {
		t.Fatal("missing root walked successfully")
	}
}

func TestPOSIXDriverRejectsRegularFileAsShardParent(t *testing.T) {
	root := t.TempDir()
	driverAny, err := NewPOSIXDriver(root)
	if err != nil {
		t.Fatal(err)
	}
	driver := driverAny.(*posixDriver)
	if err := os.WriteFile(filepath.Join(root, "ab"), []byte("not-a-directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := driver.PutObject(context.Background(), "abcdef", strings.NewReader("x"), 1); err == nil {
		t.Fatal("regular shard parent accepted")
	}
}
