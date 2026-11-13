package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"setjoin.com/mailserver/internal/storage"
)

// testLogger is a quiet (error-level) logger for the backup unit tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// memStore is an in-memory BackupStore for exercising the manifest-emission path
// without a real S3/SeaweedFS. putErr lets a test inject a write failure on a
// specific key to assert the commit-ordering / fail behavior.
type memStore struct {
	mu        sync.Mutex
	objs      map[string][]byte
	putErr    map[string]error
	deleteErr map[string]error
}

func newMemStore() *memStore {
	return &memStore{objs: map[string][]byte{}, putErr: map[string]error{}, deleteErr: map[string]error{}}
}

func (m *memStore) HeadObject(_ context.Context, key string) (*storage.ObjectInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objs[key]
	if !ok {
		return nil, fmt.Errorf("not found: %s", key)
	}
	return &storage.ObjectInfo{Key: key, Size: int64(len(b))}, nil
}

func (m *memStore) GetObject(_ context.Context, key string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objs[key]
	if !ok {
		return nil, fmt.Errorf("not found: %s", key)
	}
	return io.NopCloser(strings.NewReader(string(b))), nil
}

func (m *memStore) PutObject(_ context.Context, key string, data io.Reader, _ int64) error {
	if e := m.putErr[key]; e != nil {
		return e
	}
	b, err := io.ReadAll(data)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.objs[key] = b
	m.mu.Unlock()
	return nil
}

func (m *memStore) DeleteObject(_ context.Context, key string) error {
	if e := m.deleteErr[key]; e != nil {
		return e
	}
	m.mu.Lock()
	delete(m.objs, key)
	m.mu.Unlock()
	return nil
}

func (m *memStore) ProviderName() string { return "mem" }

func (m *memStore) get(key string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objs[key]
	return b, ok
}

// TestBuildBlobManifest covers the pure manifest contract: hash set, count, and
// total size, with type "incr".
func TestBuildBlobManifest(t *testing.T) {
	blobs := []BlobRef{{Hash: "aaa", Size: 10}, {Hash: "bbb", Size: 32}, {Hash: "ccc", Size: 8}}
	m := BuildBlobManifest(blobs, "20260621T030000Z")

	if m.Type != "incr" {
		t.Errorf("Type = %q, want incr", m.Type)
	}
	if m.Count != 3 {
		t.Errorf("Count = %d, want 3", m.Count)
	}
	if m.TotalSize != 50 {
		t.Errorf("TotalSize = %d, want 50", m.TotalSize)
	}
	if len(m.Hashes) != 3 || m.Hashes[0] != "aaa" || m.Hashes[2] != "ccc" {
		t.Errorf("Hashes = %v, want [aaa bbb ccc]", m.Hashes)
	}
	if m.Timestamp != "20260621T030000Z" {
		t.Errorf("Timestamp = %q", m.Timestamp)
	}

	// Empty snapshot → zero-value manifest, not nil hashes (round-trips as []).
	empty := BuildBlobManifest(nil, "t")
	if empty.Count != 0 || empty.TotalSize != 0 || empty.Hashes == nil {
		t.Errorf("empty manifest = %+v, want count 0 / size 0 / non-nil hashes", empty)
	}
}

// TestWriteManifests_AllArtifacts asserts writeManifests writes every expected
// object, that the latest pointer matches the timestamped index, and that the
// index records the right sizes.
func TestWriteManifests_AllArtifacts(t *testing.T) {
	store := newMemStore()
	e := &Engine{backup: store}
	blobs := []BlobRef{{Hash: "h1", Size: 100}, {Hash: "h2", Size: 200}}
	cfg := []byte(`{"k":"v"}`)
	ts := "20260621T030000Z"

	res, err := e.writeManifests(context.Background(), blobs, cfg, ts)
	if err != nil {
		t.Fatalf("writeManifests: %v", err)
	}

	for _, key := range []string{
		"manifests/incr-" + ts + ".json",
		"config-" + ts + ".json",
		"config.json",
		"backup-manifest-" + ts + ".json",
		"backup-manifest.json",
	} {
		if _, ok := store.get(key); !ok {
			t.Errorf("expected object %q written", key)
		}
	}

	// The latest pointer must be byte-identical to the timestamped index.
	latest, _ := store.get("backup-manifest.json")
	stamped, _ := store.get("backup-manifest-" + ts + ".json")
	if string(latest) != string(stamped) {
		t.Errorf("backup-manifest.json must equal backup-manifest-%s.json", ts)
	}

	// The index records config + blob sizes.
	var idx BackupManifest
	if err := json.Unmarshal(latest, &idx); err != nil {
		t.Fatalf("unmarshal index: %v", err)
	}
	if idx.ConfigSize != int64(len(cfg)) {
		t.Errorf("ConfigSize = %d, want %d", idx.ConfigSize, len(cfg))
	}
	if idx.BlobCount != 2 || idx.BlobTotalSize != 300 {
		t.Errorf("index blob stats = %d/%d, want 2/300", idx.BlobCount, idx.BlobTotalSize)
	}
	if res.ConfigSize != int64(len(cfg)) || res.BlobTotalSize != 300 {
		t.Errorf("result = %+v, want config %d / total 300", res, len(cfg))
	}

	// config.json holds the raw export.
	gotCfg, _ := store.get("config.json")
	if string(gotCfg) != string(cfg) {
		t.Errorf("config.json = %q, want %q", gotCfg, cfg)
	}
}

func TestSignedManifestDetectsTamper(t *testing.T) {
	store := newMemStore()
	e := &Engine{backup: store}
	keyFile := filepath.Join(t.TempDir(), "backup-signing-key")
	if err := os.WriteFile(keyFile, []byte(strings.Repeat("11", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigureSigningKey(keyFile); err != nil {
		t.Fatal(err)
	}
	if _, err := e.writeManifests(context.Background(), nil, []byte(`{"safe":true}`), "20260621T030000Z"); err != nil {
		t.Fatal(err)
	}
	raw, _ := store.get("backup-manifest.json")
	var manifest BackupManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if err := VerifyEmbeddedManifest(manifest); err != nil {
		t.Fatalf("valid signed manifest rejected: %v", err)
	}
	manifest.ConfigSize++
	if err := VerifyEmbeddedManifest(manifest); err == nil {
		t.Fatal("tampered signed manifest accepted")
	}
}

func TestVerifyEmbeddedManifestRejectsInvalidSignatureMetadata(t *testing.T) {
	legacy := BackupManifest{}
	if err := VerifyEmbeddedManifest(legacy); err != nil {
		t.Fatalf("legacy manifest rejected: %v", err)
	}
	for name, manifest := range map[string]BackupManifest{
		"incomplete":     {SchemaVersion: 1, Signature: "x"},
		"bad public key": {SchemaVersion: 1, Signature: "x", SigningPublicKey: "not-base64", SigningKeyID: "id"},
		"key id":         {SchemaVersion: 1, Signature: "x", SigningPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", SigningKeyID: "wrong"},
		"signature":      {SchemaVersion: 1, Signature: "not-base64", SigningPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", SigningKeyID: "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := VerifyEmbeddedManifest(manifest); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
}

func TestConfigureSigningKeyRejectsUnsafeAndMalformedFiles(t *testing.T) {
	e := &Engine{}
	if err := e.ConfigureSigningKey(""); err == nil {
		t.Fatal("empty signing key path accepted")
	}
	if err := e.ConfigureSigningKey(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing signing key accepted")
	}
	dir := t.TempDir()
	if err := e.ConfigureSigningKey(dir); err == nil {
		t.Fatal("directory signing key accepted")
	}
	unsafe := filepath.Join(t.TempDir(), "unsafe")
	if err := os.WriteFile(unsafe, []byte(strings.Repeat("11", 32)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigureSigningKey(unsafe); err == nil {
		t.Fatal("world-readable signing key accepted")
	}
	unreadable := filepath.Join(t.TempDir(), "unreadable")
	if err := os.WriteFile(unreadable, []byte(strings.Repeat("11", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigureSigningKey(unreadable); err == nil {
		t.Fatal("unreadable signing key accepted")
	}
	malformed := filepath.Join(t.TempDir(), "malformed")
	if err := os.WriteFile(malformed, []byte("not-hex"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigureSigningKey(malformed); err == nil {
		t.Fatal("malformed signing key accepted")
	}
}

// TestWriteManifests_CommitPointNotWrittenOnFailure asserts that if an earlier
// artifact fails, the latest pointer (the commit point) is never written — so
// restore won't pick up a partial backup.
func TestWriteManifests_CommitPointNotWrittenOnFailure(t *testing.T) {
	store := newMemStore()
	store.putErr["backup-manifest-20260621T030000Z.json"] = fmt.Errorf("disk full")
	e := &Engine{backup: store}

	_, err := e.writeManifests(context.Background(), []BlobRef{{Hash: "h1", Size: 1}}, []byte(`{}`), "20260621T030000Z")
	if err == nil {
		t.Fatal("expected error when the index write fails")
	}
	if _, ok := store.get("backup-manifest.json"); ok {
		t.Error("backup-manifest.json (commit point) must NOT be written when the index write failed")
	}
}

// TestCopyNewBlobs_SizeMismatchNotSkipped: a backup blob that exists but is the
// WRONG size (truncated by an interrupted prior put) must NOT be HEAD-skipped — it
// must be re-copied, else the run completes listing a corrupt blob.
func TestCopyNewBlobs_SizeMismatchNotSkipped(t *testing.T) {
	primary := newMemStore()
	backupStore := newMemStore()
	full := []byte("the full blob content")
	ref := blobFixture(full)
	key := "blobs/" + ref.Hash
	primary.objs[key] = full
	backupStore.objs[key] = []byte("trunc") // present but truncated

	e := &Engine{primary: primary, backup: backupStore, logger: testLogger()}
	copied, skipped, errs := e.CopyNewBlobs(context.Background(), []BlobRef{ref})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, a size-mismatched backup blob must NOT be skipped", skipped)
	}
	if copied != 1 {
		t.Errorf("copied = %d, want 1 (the truncated blob re-copied)", copied)
	}
	if got, _ := backupStore.get(key); string(got) != string(full) {
		t.Errorf("backup blob not repaired: got %q", got)
	}
}

// TestCopyNewBlobs_CorrectSizeSkipped: a backup blob present with the RIGHT size
// IS skipped (idempotency preserved).
func TestCopyNewBlobs_CorrectSizeSkipped(t *testing.T) {
	primary := newMemStore()
	backupStore := newMemStore()
	content := []byte("matching content")
	ref := blobFixture(content)
	key := "blobs/" + ref.Hash
	primary.objs[key] = content
	backupStore.objs[key] = content

	e := &Engine{primary: primary, backup: backupStore, logger: testLogger()}
	copied, skipped, _ := e.CopyNewBlobs(context.Background(), []BlobRef{ref})
	if skipped != 1 || copied != 0 {
		t.Errorf("skipped=%d copied=%d, want the correctly-sized blob skipped", skipped, copied)
	}
}

// TestReplicateToBackup_MirrorsBlobsAndManifests asserts the replica receives the
// run's blobs + manifest artifacts, that an already-present replica blob is
// HEAD-skipped, and that a replica write error is best-effort (never panics /
// never blocks the rest).
func TestReplicateToBackup_MirrorsBlobsAndManifests(t *testing.T) {
	backupStore := newMemStore()
	replica := newMemStore()
	ts := "20260621T030000Z"

	// Seed the backup with two blobs + the manifest artifacts a real run wrote.
	ref1 := blobFixture([]byte("blob-one"))
	ref2 := blobFixture([]byte("blob-two"))
	key1, key2 := "blobs/"+ref1.Hash, "blobs/"+ref2.Hash
	backupStore.objs[key1] = []byte("blob-one")
	backupStore.objs[key2] = []byte("blob-two")
	for _, k := range []string{
		"manifests/incr-" + ts + ".json", "config-" + ts + ".json", "config.json",
		"backup-manifest-" + ts + ".json", "backup-manifest.json",
	} {
		backupStore.objs[k] = []byte(`{"x":1}`)
	}
	// h1 already on the replica → must be HEAD-skipped (and a write error on it
	// would prove it was NOT skipped).
	replica.objs[key1] = []byte("blob-one")
	replica.putErr[key1] = fmt.Errorf("must not be written — should be skipped")

	e := &Engine{backup: backupStore, replica: replica, logger: testLogger()}
	e.replicateToBackup(
		[]BlobRef{ref1, ref2},
		BackupResult{Timestamp: ts},
	)

	// h2 mirrored; h1 left as the pre-existing copy (skipped, not overwritten).
	if got, ok := replica.get(key2); !ok || string(got) != "blob-two" {
		t.Errorf("replica blobs/h2 = %q (ok=%v), want blob-two", got, ok)
	}
	// All five manifest artifacts mirrored.
	for _, k := range []string{
		"manifests/incr-" + ts + ".json", "config-" + ts + ".json", "config.json",
		"backup-manifest-" + ts + ".json", "backup-manifest.json",
	} {
		if _, ok := replica.get(k); !ok {
			t.Errorf("replica missing mirrored manifest %q", k)
		}
	}
}

// TestReplicateToBackup_WrongSizeReplicaBlobRecopied: a replica blob present but
// the WRONG size (a once-truncated mirror) must be re-copied, not HEAD-skipped —
// consistent with the primary CopyNewBlobs size check.
func TestReplicateToBackup_WrongSizeReplicaBlobRecopied(t *testing.T) {
	backupStore := newMemStore()
	replica := newMemStore()
	full := []byte("the full replica content")
	ref := blobFixture(full)
	key := "blobs/" + ref.Hash
	backupStore.objs[key] = full
	replica.objs[key] = []byte("trunc") // present but wrong size

	e := &Engine{backup: backupStore, replica: replica, logger: testLogger()}
	e.replicateToBackup([]BlobRef{ref}, BackupResult{Timestamp: "t"})

	if got, _ := replica.get(key); string(got) != string(full) {
		t.Errorf("a wrong-size replica blob must be re-copied, got %q", got)
	}
}

// TestReplicateToBackup_BestEffortOnError asserts a replica blob-write failure
// does not stop the manifests from being mirrored (best-effort, non-fatal).
func TestReplicateToBackup_BestEffortOnError(t *testing.T) {
	backupStore := newMemStore()
	replica := newMemStore()
	ts := "20260621T030000Z"
	ref := blobFixture([]byte("blob-one"))
	key := "blobs/" + ref.Hash
	backupStore.objs[key] = []byte("blob-one")
	backupStore.objs["backup-manifest.json"] = []byte(`{"ok":1}`)
	replica.putErr[key] = fmt.Errorf("replica down")

	e := &Engine{backup: backupStore, replica: replica, logger: testLogger()}
	e.replicateToBackup([]BlobRef{ref}, BackupResult{Timestamp: ts})

	// The blob failed, but the manifest copy still proceeded.
	if _, ok := replica.get("backup-manifest.json"); !ok {
		t.Error("a replica blob error must not stop manifest mirroring (best-effort)")
	}
}
