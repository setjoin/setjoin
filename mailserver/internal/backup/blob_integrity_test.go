package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"testing"

	"setjoin.com/mailserver/internal/storage"
)

type integrityStore struct {
	objects       map[string][]byte
	corruptWrites bool
	reads         int
}

func newIntegrityStore() *integrityStore                             { return &integrityStore{objects: map[string][]byte{}} }
func (s *integrityStore) ProviderName() string                       { return "test" }
func (s *integrityStore) DeleteObject(context.Context, string) error { return nil }
func (s *integrityStore) HeadObject(_ context.Context, key string) (*storage.ObjectInfo, error) {
	b, ok := s.objects[key]
	if !ok {
		return nil, fmt.Errorf("missing %s", key)
	}
	return &storage.ObjectInfo{Key: key, Size: int64(len(b))}, nil
}
func (s *integrityStore) GetObject(_ context.Context, key string) (io.ReadCloser, error) {
	s.reads++
	b, ok := s.objects[key]
	if !ok {
		return nil, fmt.Errorf("missing %s", key)
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}
func (s *integrityStore) PutObject(_ context.Context, key string, r io.Reader, _ int64) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if s.corruptWrites && len(b) > 0 {
		b = append([]byte(nil), b...)
		b[0] ^= 0xff
	}
	s.objects[key] = b
	return nil
}

func blobFixture(data []byte) BlobRef {
	sum := sha256.Sum256(data)
	return BlobRef{Hash: hex.EncodeToString(sum[:]), Size: int64(len(data))}
}

func TestCopyNewBlobsRepairsSameSizeCorruptionAndVerifiesDigest(t *testing.T) {
	ctx := context.Background()
	data := []byte("verified backup bytes")
	ref := blobFixture(data)
	primary := newIntegrityStore()
	primary.objects["blobs/"+ref.Hash] = data
	backup := newIntegrityStore()
	backup.objects["blobs/"+ref.Hash] = bytes.Repeat([]byte("x"), len(data))

	engine := &Engine{primary: primary, backup: backup}
	copied, skipped, errs := engine.CopyNewBlobs(ctx, []BlobRef{ref})
	if len(errs) != 0 || copied != 1 || skipped != 0 {
		t.Fatalf("copied=%d skipped=%d errs=%v", copied, skipped, errs)
	}
	if !bytes.Equal(backup.objects["blobs/"+ref.Hash], data) {
		t.Fatal("same-size corrupt destination was not repaired")
	}
	if backup.reads < 2 {
		t.Fatalf("destination was not hashed before skip and after write; reads=%d", backup.reads)
	}
}

func TestCopyNewBlobsRejectsPostWriteHashMismatch(t *testing.T) {
	data := []byte("expected bytes")
	ref := blobFixture(data)
	primary := newIntegrityStore()
	primary.objects["blobs/"+ref.Hash] = data
	backup := newIntegrityStore()
	backup.corruptWrites = true

	engine := &Engine{primary: primary, backup: backup}
	copied, _, errs := engine.CopyNewBlobs(context.Background(), []BlobRef{ref})
	if copied != 0 || len(errs) != 1 {
		t.Fatalf("copied=%d errs=%v", copied, errs)
	}
}

func TestCopyNewBlobsRejectsMalformedInventoryBeforeStorage(t *testing.T) {
	primary := newIntegrityStore()
	backup := newIntegrityStore()
	engine := &Engine{primary: primary, backup: backup}
	copied, skipped, errs := engine.CopyNewBlobs(context.Background(), []BlobRef{{Hash: "../escape", Size: 1}})
	if copied != 0 || skipped != 0 || len(errs) != 1 || primary.reads != 0 || backup.reads != 0 {
		t.Fatalf("copied=%d skipped=%d errs=%v primaryReads=%d backupReads=%d", copied, skipped, errs, primary.reads, backup.reads)
	}
}

// TestReplicateToBackupRepairsSameSizeCorruptReplica pins the replica's
// verify-before-skip discipline (D-MAILSERVER-INTERNAL-BACKUP-F-002): a
// SAME-SIZE corrupt replica object must not be skipped as parity — it is
// digest-verified, fails, and is re-copied from the backup, mirroring
// CopyNewBlobs' repair of the same corruption on the primary path. A verified
// mirror is still skipped without a re-read.
func TestReplicateToBackupRepairsSameSizeCorruptReplica(t *testing.T) {
	data := []byte("replica parity bytes")
	ref := blobFixture(data)

	backup := newIntegrityStore()
	backup.objects["blobs/"+ref.Hash] = data

	// Corrupt replica: same size, different bytes — the exact case the old
	// size-only HEAD-skip silently accepted.
	replica := newIntegrityStore()
	replica.objects["blobs/"+ref.Hash] = bytes.Repeat([]byte("y"), len(data))

	e := &Engine{backup: backup, replica: replica, logger: testLogger()}
	e.replicateToBackup([]BlobRef{ref}, BackupResult{Timestamp: "testts"})

	if !bytes.Equal(replica.objects["blobs/"+ref.Hash], data) {
		t.Fatal("same-size corrupt replica object was not repaired")
	}
	if replica.reads < 2 {
		t.Fatalf("replica was not hashed before skip and after write; reads=%d", replica.reads)
	}
}

// TestReplicateToBackupSkipsVerifiedReplicaWithoutRecopy is the control: a
// digest-verified same-size replica object is skipped — the verification must
// not turn the mirror into an unconditional full re-copy.
func TestReplicateToBackupSkipsVerifiedReplicaWithoutRecopy(t *testing.T) {
	data := []byte("verified replica bytes")
	ref := blobFixture(data)

	backup := newIntegrityStore()
	backup.objects["blobs/"+ref.Hash] = data
	replica := newIntegrityStore()
	replica.objects["blobs/"+ref.Hash] = data

	e := &Engine{backup: backup, replica: replica, logger: testLogger()}
	e.replicateToBackup([]BlobRef{ref}, BackupResult{Timestamp: "testts"})

	if !bytes.Equal(replica.objects["blobs/"+ref.Hash], data) {
		t.Fatal("verified replica object was modified")
	}
	if replica.reads != 1 {
		t.Fatalf("verified replica should be read exactly once for the pre-skip digest, reads=%d", replica.reads)
	}
}
