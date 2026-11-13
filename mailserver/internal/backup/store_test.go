package backup

import (
	"context"
	"io"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/storage"
)

func TestBackupStore_SatisfiedByDriver(t *testing.T) {
	d, err := storage.NewDriver(storage.DriverConfig{Provider: "posix", Bucket: t.TempDir()})
	if err != nil {
		t.Fatalf("NewDriver: %v", err)
	}
	var _ BackupStore = d // subset proof
}

// fakeStore is a minimal in-memory BackupStore proving the engine compiles
// and runs against the narrow interface (no full storage.Driver needed). It
// implements the FULL BackupStore, including no-op retention ops, so it is a
// true BackupStore.
type fakeStore struct{ objs map[string][]byte }

func (f *fakeStore) HeadObject(_ context.Context, key string) (*storage.ObjectInfo, error) {
	b, ok := f.objs[key]
	if !ok {
		return nil, io.EOF
	}
	return &storage.ObjectInfo{Key: key, Size: int64(len(b))}, nil
}

func (f *fakeStore) GetObject(_ context.Context, _ string) (io.ReadCloser, error) {
	return io.NopCloser(io.MultiReader()), nil
}

func (f *fakeStore) PutObject(_ context.Context, key string, _ io.Reader, _ int64) error {
	if f.objs == nil {
		f.objs = map[string][]byte{}
	}
	f.objs[key] = []byte{}
	return nil
}

func (f *fakeStore) DeleteObject(_ context.Context, key string) error {
	delete(f.objs, key)
	return nil
}

func (f *fakeStore) ProviderName() string { return "fake" }

func (f *fakeStore) PutObjectRetention(_ context.Context, _, _ string, _ time.Time) error {
	return storage.ErrRetentionNotSupported
}

func (f *fakeStore) GetObjectRetention(_ context.Context, _ string) (*storage.RetentionStatus, error) {
	return nil, storage.ErrRetentionNotSupported
}

func (f *fakeStore) PutObjectLegalHold(_ context.Context, _, _ string) error {
	return storage.ErrRetentionNotSupported
}

func (f *fakeStore) GetObjectLegalHold(_ context.Context, _ string) (string, error) {
	return "OFF", storage.ErrRetentionNotSupported
}

func TestNewEngine_AcceptsBackupStore(t *testing.T) {
	var p, b BackupStore = &fakeStore{}, &fakeStore{}
	e := NewEngine(nil, p, b, nil, context.Background())
	if e == nil {
		t.Fatal("NewEngine returned nil")
	}
}
