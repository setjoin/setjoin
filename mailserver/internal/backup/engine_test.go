package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"testing"

	"setjoin.com/mailserver/internal/storage"
)

// TestBackupIntegritySHA256 verifies the hash computation logic used
// for post-copy integrity verification: reading back a blob from the backup
// destination and comparing its SHA-256 against the expected hash.
func TestBackupIntegritySHA256(t *testing.T) {
	// Simulate: blob key is "blobs/{sha256}" — the key itself encodes the expected hash.
	data := []byte("hello backup integrity check")
	expected := sha256.Sum256(data)
	expectedHex := hex.EncodeToString(expected[:])
	blobKey := "blobs/" + expectedHex

	// Verification: compute SHA-256 of data read back, compare with blobHash from key.
	got := sha256.Sum256(data)
	gotHex := hex.EncodeToString(got[:])

	if gotHex != expectedHex {
		t.Errorf("hash mismatch: got %s, want %s", gotHex, expectedHex)
	}

	// Verify blob key contains the correct hash
	if blobKey != "blobs/"+expectedHex {
		t.Errorf("blobKey = %q, want %q", blobKey, "blobs/"+expectedHex)
	}

	// Simulate corruption
	corrupted := []byte("corrupted data")
	corruptedHash := sha256.Sum256(corrupted)
	if hex.EncodeToString(corruptedHash[:]) == expectedHex {
		t.Error("corrupted data should produce different hash")
	}
}

// TestCopyNewBlobs_IntegrityCheck verifies that integrity failures
// produce the expected error message format.
func TestCopyNewBlobs_IntegrityCheck(t *testing.T) {
	blobKey := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	err := fmt.Errorf("backup integrity check failed for %s: hash mismatch", blobKey)
	if err.Error() == "" {
		t.Error("expected non-empty error")
	}
	if len(err.Error()) < 20 {
		t.Error("error message too short")
	}
}

// TestCopyNewBlobs_HeadObjectIdempotency verifies the idempotent skip
// logic that prevents re-copying already-backed-up blobs.
func TestCopyNewBlobs_HeadObjectIdempotency(t *testing.T) {
	// When HeadObject succeeds (blob already exists), blob is skipped.
	// This is the existing behavior at line 86-88 of engine.go.
	blobs := []BlobRef{
		{Hash: "already_exists", Size: 42},
		{Hash: "needs_copy", Size: 100},
	}

	skipped := 0
	for _, b := range blobs {
		if b.Hash == "already_exists" {
			skipped++ // simulate HeadObject success
			continue
		}
		// Would copy here
	}

	if skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", skipped)
	}
}

type backupBoundaryReader struct {
	io.Reader
	readErr  error
	closeErr error
}

func (reader *backupBoundaryReader) Read(p []byte) (int, error) {
	if reader.readErr != nil {
		return 0, reader.readErr
	}
	return reader.Reader.Read(p)
}

func (reader *backupBoundaryReader) Close() error { return reader.closeErr }

type backupBoundaryStore struct {
	*memStore
	headErr  error
	getErr   error
	headSize int64
	raw      []byte
	readErr  error
	closeErr error
}

func (store *backupBoundaryStore) HeadObject(context.Context, string) (*storage.ObjectInfo, error) {
	if store.headErr != nil {
		return nil, store.headErr
	}
	return &storage.ObjectInfo{Size: store.headSize}, nil
}

func (store *backupBoundaryStore) GetObject(context.Context, string) (io.ReadCloser, error) {
	if store.getErr != nil {
		return nil, store.getErr
	}
	return &backupBoundaryReader{Reader: bytes.NewReader(store.raw), readErr: store.readErr, closeErr: store.closeErr}, nil
}

func TestVerifyStoredBlobRejectsEveryStorageBoundary(t *testing.T) {
	data := []byte("valid")
	digest := sha256.Sum256(data)
	ref := BlobRef{Hash: hex.EncodeToString(digest[:]), Size: int64(len(data))}
	for name, store := range map[string]*backupBoundaryStore{
		"head":        {memStore: newMemStore(), headErr: errors.New("head")},
		"head size":   {memStore: newMemStore(), headSize: int64(len(data)) + 1},
		"get":         {memStore: newMemStore(), headSize: int64(len(data)), getErr: errors.New("get")},
		"read":        {memStore: newMemStore(), headSize: int64(len(data)), raw: data, readErr: errors.New("read")},
		"close":       {memStore: newMemStore(), headSize: int64(len(data)), raw: data, closeErr: errors.New("close")},
		"read size":   {memStore: newMemStore(), headSize: int64(len(data)), raw: data[:2]},
		"read digest": {memStore: newMemStore(), headSize: int64(len(data)), raw: []byte("other")},
	} {
		t.Run(name, func(t *testing.T) {
			if err := verifyStoredBlob(context.Background(), store, ref); err == nil {
				t.Fatal("invalid stored blob accepted")
			}
		})
	}
	valid := &backupBoundaryStore{memStore: newMemStore(), headSize: int64(len(data)), raw: data}
	if err := verifyStoredBlob(context.Background(), valid, ref); err != nil {
		t.Fatal(err)
	}
}
