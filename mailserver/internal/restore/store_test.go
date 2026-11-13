package restore

import (
	"context"
	"io"
	"testing"

	"setjoin.com/mailserver/internal/storage"
)

func TestRestoreStore_SatisfiedByDriver(t *testing.T) {
	d, err := storage.NewDriver(storage.DriverConfig{Provider: "posix", Bucket: t.TempDir()})
	if err != nil {
		t.Fatalf("NewDriver: %v", err)
	}
	var _ RestoreStore = d // subset proof
}

// fakeStore is a minimal in-memory RestoreStore (exactly Head/Get/Put) proving
// the engine compiles and runs against the narrow interface.
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

func TestNewEngine_AcceptsRestoreStore(t *testing.T) {
	var p, b RestoreStore = &fakeStore{}, &fakeStore{}
	e := NewEngine(nil, p, b, nil)
	if e == nil {
		t.Fatal("NewEngine returned nil")
	}
}
