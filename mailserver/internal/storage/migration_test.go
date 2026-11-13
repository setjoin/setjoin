package storage

import (
	"context"
	"io"
	"testing"
)

// fakeMover implements ONLY the blobMover methods, proving the migration
// orchestrator no longer requires a full Driver.
type fakeMover struct{ objs map[string][]byte }

func (f *fakeMover) ProviderName() string { return "fake" }

func (f *fakeMover) HeadObject(_ context.Context, key string) (*ObjectInfo, error) {
	b, ok := f.objs[key]
	if !ok {
		return nil, io.EOF
	}
	return &ObjectInfo{Key: key, Size: int64(len(b))}, nil
}

func (f *fakeMover) GetObject(_ context.Context, _ string) (io.ReadCloser, error) {
	return io.NopCloser(io.MultiReader()), nil
}

func (f *fakeMover) PutObject(_ context.Context, key string, _ io.Reader, _ int64) error {
	if f.objs == nil {
		f.objs = map[string][]byte{}
	}
	f.objs[key] = []byte{}
	return nil
}

func (f *fakeMover) DeleteObject(_ context.Context, key string) error {
	delete(f.objs, key)
	return nil
}

func TestNewMigration_AcceptsBlobMover(t *testing.T) {
	var src, dst blobMover = &fakeMover{}, &fakeMover{}
	m := NewMigration(nil, src, dst, nil)
	if m == nil {
		t.Fatal("NewMigration returned nil")
	}
}
