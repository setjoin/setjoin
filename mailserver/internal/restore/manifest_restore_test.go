package restore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/backup"
	"setjoin.com/mailserver/internal/storage"
	"setjoin.com/shared/testsupport"
)

// sha256hex returns the lowercase hex SHA-256 of data — the blob key convention.
func sha256hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// restoreTestPool returns a pool to the test DB, skipping if DB_DSN is unset.
func restoreTestPool(t *testing.T) *pgxpool.Pool {
	return testsupport.OpenTestPool(t)
}

func rtLogger() *slog.Logger {
	return testsupport.TestLogger()
}

// memRestoreStore is an in-memory RestoreStore holding real content (the
// package's existing fakeStore returns empty readers, unusable for content). It
// records every key passed to Head/Get so a test can assert a key was NEVER
// accessed (proving a path-traversal guard fired before any store call).
type memRestoreStore struct {
	objs          map[string][]byte
	accessed      map[string]bool
	corruptWrites bool
	// manifestGetErr, when set, makes GetObject fail for backup-manifest.json —
	// the transient storage-outcome the restore engine must fail closed on
	// instead of silently skipping manifest verification (occ_902b7cb5).
	manifestGetErr error
}

func newMemRestoreStore() *memRestoreStore {
	return &memRestoreStore{objs: map[string][]byte{}, accessed: map[string]bool{}}
}

// installLegacyManifest binds a legacy (schema_version 0, unsigned — the exact
// shape VerifyEmbeddedManifest admits) manifest for configJSON into the store,
// mirroring what every complete backup run writes: writeManifests commits
// backup-manifest.json last as the run's commit point, so a config.json under
// test always carries its integrity metadata.
func installLegacyManifest(t *testing.T, store *memRestoreStore, configJSON []byte) {
	t.Helper()
	digest := sha256.Sum256(configJSON)
	raw, err := json.Marshal(backup.BackupManifest{
		Timestamp:    "20260101T000000Z",
		ConfigSize:   int64(len(configJSON)),
		ConfigSHA256: hex.EncodeToString(digest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	store.objs["backup-manifest.json"] = raw
}

func (m *memRestoreStore) HeadObject(_ context.Context, key string) (*storage.ObjectInfo, error) {
	m.accessed[key] = true
	b, ok := m.objs[key]
	if !ok {
		return nil, fmt.Errorf("not found: %s", key)
	}
	return &storage.ObjectInfo{Key: key, Size: int64(len(b))}, nil
}

func (m *memRestoreStore) GetObject(_ context.Context, key string) (io.ReadCloser, error) {
	m.accessed[key] = true
	if key == "backup-manifest.json" && m.manifestGetErr != nil {
		return nil, m.manifestGetErr
	}
	b, ok := m.objs[key]
	if !ok {
		return nil, fmt.Errorf("not found: %s", key)
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (m *memRestoreStore) PutObject(_ context.Context, key string, data io.Reader, _ int64) error {
	b, err := io.ReadAll(data)
	if err != nil {
		return err
	}
	if m.corruptWrites && len(b) > 0 {
		b = append([]byte(nil), b...)
		b[0] ^= 0xff
	}
	m.objs[key] = b
	return nil
}

// TestDownloadManifest_ReturnsParsedIndex: DownloadManifest fetches
// backup-manifest.json from the backup store and parses it into the
// backup.BackupManifest the writer produced.
func TestDownloadManifest_ReturnsParsedIndex(t *testing.T) {
	backupStore := newMemRestoreStore()
	want := backup.BackupManifest{
		Timestamp:     "20260621T030000Z",
		ConfigSize:    42,
		BlobCount:     3,
		BlobTotalSize: 1000,
		BlobManifest:  backup.Manifest{Type: "incr", Count: 3, Hashes: []string{"a", "b", "c"}, TotalSize: 1000},
	}
	raw, _ := json.Marshal(want)
	backupStore.objs["backup-manifest.json"] = raw

	e := NewEngine(nil, newMemRestoreStore(), backupStore, rtLogger())
	got, err := e.DownloadManifest(context.Background())
	if err != nil {
		t.Fatalf("DownloadManifest: %v", err)
	}
	if got.Timestamp != want.Timestamp || got.BlobCount != 3 || got.BlobTotalSize != 1000 {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if got.BlobManifest.Count != 3 || len(got.BlobManifest.Hashes) != 3 {
		t.Errorf("blob manifest = %+v, want 3 hashes", got.BlobManifest)
	}
}

// TestDownloadManifest_MissingIsError: a missing backup-manifest.json is a clear
// error (corrupt/empty backup), not a nil manifest.
func TestDownloadManifest_MissingIsError(t *testing.T) {
	e := NewEngine(nil, newMemRestoreStore(), newMemRestoreStore(), rtLogger())
	if _, err := e.DownloadManifest(context.Background()); err == nil {
		t.Fatal("expected an error when backup-manifest.json is absent")
	}
}

func TestDownloadManifestRejectsInvalidEmbeddedSignature(t *testing.T) {
	store := newMemRestoreStore()
	raw, _ := json.Marshal(backup.BackupManifest{SchemaVersion: 1, Signature: "incomplete"})
	store.objs["backup-manifest.json"] = raw
	e := NewEngine(nil, newMemRestoreStore(), store, rtLogger())
	if _, err := e.DownloadManifest(context.Background()); err == nil || !strings.Contains(err.Error(), "verify backup-manifest.json") {
		t.Fatalf("signature error = %v", err)
	}
}

func TestRestoreConfigRejectsManifestContentMismatchBeforeDatabaseWrite(t *testing.T) {
	store := newMemRestoreStore()
	store.objs["config.json"] = []byte(`{"feature.test":{"value":"true"}}`)
	manifest, _ := json.Marshal(backup.BackupManifest{ConfigSize: 1, ConfigSHA256: strings.Repeat("0", 64)})
	store.objs["backup-manifest.json"] = manifest
	e := NewEngine(nil, newMemRestoreStore(), store, rtLogger())
	if _, err := e.RestoreConfig(context.Background()); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("content mismatch error = %v", err)
	}
}

func TestRestoreConfigPropagatesInvalidManifestBeforeDatabaseWrite(t *testing.T) {
	store := newMemRestoreStore()
	store.objs["config.json"] = []byte(`{}`)
	manifest, _ := json.Marshal(backup.BackupManifest{SchemaVersion: 1, Signature: "incomplete"})
	store.objs["backup-manifest.json"] = manifest
	e := NewEngine(nil, newMemRestoreStore(), store, rtLogger())
	if _, err := e.RestoreConfig(context.Background()); err == nil || !strings.Contains(err.Error(), "verify backup-manifest.json") {
		t.Fatalf("invalid manifest error = %v", err)
	}
}

// TestRestoreConfigFailsClosedWhenManifestLookupErrors (occ_902b7cb5): a
// TRANSIENT manifest lookup failure (storage outage, throttling) must fail the
// restore — it used to be indistinguishable from "no manifest" and silently
// skipped verification entirely. The canary key proves nothing reached
// system_config.
func TestRestoreConfigFailsClosedWhenManifestLookupErrors(t *testing.T) {
	pool := restoreTestPool(t)
	ctx := context.Background()
	const key = "backup.restore_lookup_error_test"
	raw, _ := json.Marshal(map[string]backup.ConfigEntry{key: {Value: `"must-not-apply"`}})

	backupStore := newMemRestoreStore()
	backupStore.objs["config.json"] = raw
	backupStore.manifestGetErr = fmt.Errorf("seaweedfs: 503 backend unavailable")
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key = $1`, key)
		_, _ = pool.Exec(ctx, `DELETE FROM restore_config_quarantine WHERE config_key = $1`, key)
	})

	e := NewEngine(pool, newMemRestoreStore(), backupStore, rtLogger())
	_, err := e.RestoreConfig(ctx)
	if err == nil || !strings.Contains(err.Error(), "backup-manifest.json") {
		t.Fatalf("RestoreConfig error = %v, want a fail-closed manifest lookup error", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM system_config WHERE key = $1`, key).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("a failed manifest lookup must not restore any configuration")
	}
}

// TestRestoreConfigFailsClosedWhenManifestAbsent (occ_902b7cb5): a backup
// holding config.json WITHOUT backup-manifest.json is an incomplete or tampered
// run (writeManifests commits the manifest last as the run's commit point), so
// restore refuses instead of applying unverified configuration — the exact
// silent-restore leg this occurrence sealed.
func TestRestoreConfigFailsClosedWhenManifestAbsent(t *testing.T) {
	pool := restoreTestPool(t)
	ctx := context.Background()
	const key = "backup.restore_manifest_absent_test"
	raw, _ := json.Marshal(map[string]backup.ConfigEntry{key: {Value: `"must-not-apply"`}})

	backupStore := newMemRestoreStore()
	backupStore.objs["config.json"] = raw
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key = $1`, key)
		_, _ = pool.Exec(ctx, `DELETE FROM restore_config_quarantine WHERE config_key = $1`, key)
	})

	e := NewEngine(pool, newMemRestoreStore(), backupStore, rtLogger())
	_, err := e.RestoreConfig(ctx)
	if err == nil || !strings.Contains(err.Error(), "backup-manifest.json") {
		t.Fatalf("RestoreConfig error = %v, want a manifest-required failure", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM system_config WHERE key = $1`, key).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("a manifest-less backup must not restore any configuration")
	}
}

// TestRestoreConfig_RoundTripsExport: RestoreConfig reads config.json (the
// system_config export the backup wrote) and upserts it back into system_config,
// round-tripping the jsonb value byte-for-byte (symmetric with ExportConfig).
func TestRestoreConfig_RoundTripsExport(t *testing.T) {
	pool := restoreTestPool(t)
	ctx := context.Background()
	const key = "feature.restore_roundtrip_test"
	// config.json mirrors ExportConfig: each value is the jsonb's text form.
	// `"restored-value"` is a JSON string scalar.
	cfg := map[string]backup.ConfigEntry{key: {Value: `"restored-value"`}}
	raw, _ := json.Marshal(cfg)
	backupStore := newMemRestoreStore()
	backupStore.objs["config.json"] = raw
	installLegacyManifest(t, backupStore, raw)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key = $1`, key) })

	e := NewEngine(pool, newMemRestoreStore(), backupStore, rtLogger())
	n, err := e.RestoreConfig(ctx)
	if err != nil {
		t.Fatalf("RestoreConfig: %v", err)
	}
	if n < 1 {
		t.Errorf("restored %d keys, want >= 1", n)
	}

	// Read back as a string (as ExportConfig does) — must equal the exported form.
	var got string
	if err := pool.QueryRow(ctx, `SELECT value FROM system_config WHERE key = $1`, key).Scan(&got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got != `"restored-value"` {
		t.Errorf("round-trip value = %q, want %q", got, `"restored-value"`)
	}
}

// TestRestoreFromManifest_RestoresOnlyMissing: given a manifest, restore fetches
// (SHA-256 verified) the blobs absent from primary and skips those present.
func TestRestoreFromManifest_RestoresOnlyMissing(t *testing.T) {
	present := []byte("already-in-primary")
	missing := []byte("needs-restoring-from-backup")
	hPresent := sha256hex(present)
	hMissing := sha256hex(missing)

	primary := newMemRestoreStore()
	primary.objs["blobs/"+hPresent] = present // present in primary
	backupStore := newMemRestoreStore()
	backupStore.objs["blobs/"+hPresent] = present
	backupStore.objs["blobs/"+hMissing] = missing // only this one is missing in primary

	manifest := &backup.BackupManifest{
		BlobCount:    2,
		BlobManifest: backup.Manifest{Hashes: []string{hPresent, hMissing}, Count: 2},
	}
	e := NewEngine(nil, primary, backupStore, rtLogger())
	restored, errs := e.RestoreFromManifest(context.Background(), manifest)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if restored != 1 {
		t.Errorf("restored = %d, want 1 (only the missing blob)", restored)
	}
	if got, ok := primary.objs["blobs/"+hMissing]; !ok || string(got) != string(missing) {
		t.Errorf("missing blob not restored to primary: ok=%v", ok)
	}
}

// TestRestoreMissingBlobs_RejectsNonCanonicalHash: an attacker-controlled manifest
// hash that isn't a canonical 64-char lowercase hex SHA-256 (e.g. a path-traversal
// payload) must be rejected BEFORE any store key is built/accessed — the POSIX
// driver's filepath.Join would otherwise escape the blob root.
func TestRestoreMissingBlobs_RejectsNonCanonicalHash(t *testing.T) {
	backupStore := newMemRestoreStore()
	primary := newMemRestoreStore()
	e := NewEngine(nil, primary, backupStore, rtLogger())

	traversal := "../../../../etc/passwd"
	restored, errs := e.RestoreMissingBlobs(context.Background(), []string{traversal, "NOTHEXUPPER", "short"})
	if restored != 0 {
		t.Errorf("restored = %d, want 0 (no non-canonical hash restored)", restored)
	}
	if len(errs) == 0 {
		t.Error("a non-canonical hash must produce an error")
	}
	if backupStore.accessed["blobs/"+traversal] {
		t.Error("the traversal key must NEVER be accessed on the backup store")
	}
}

// TestRestoreFromManifest_RejectsTraversalHash: the same guard at the manifest
// level — a traversal hash is not even HEAD-probed on primary.
func TestRestoreFromManifest_RejectsTraversalHash(t *testing.T) {
	primary := newMemRestoreStore()
	backupStore := newMemRestoreStore()
	e := NewEngine(nil, primary, backupStore, rtLogger())
	traversal := "../../../../etc/passwd"
	manifest := &backup.BackupManifest{BlobCount: 1, BlobManifest: backup.Manifest{Hashes: []string{traversal}, Count: 1}}

	restored, errs := e.RestoreFromManifest(context.Background(), manifest)
	if restored != 0 || len(errs) == 0 {
		t.Errorf("restored=%d errs=%d, want 0 restored + an error", restored, len(errs))
	}
	if primary.accessed["blobs/"+traversal] {
		t.Error("the traversal key must NEVER be HEAD-probed on primary")
	}
}

// TestRestoreFromManifest_CorruptBlobIsError: a backup blob whose content doesn't
// match its hash (corruption) is rejected, not written to primary.
func TestRestoreFromManifest_CorruptBlobIsError(t *testing.T) {
	good := []byte("good content")
	h := sha256hex(good)
	backupStore := newMemRestoreStore()
	backupStore.objs["blobs/"+h] = []byte("CORRUPTED — does not match the hash")
	primary := newMemRestoreStore()

	manifest := &backup.BackupManifest{BlobCount: 1, BlobManifest: backup.Manifest{Hashes: []string{h}, Count: 1}}
	e := NewEngine(nil, primary, backupStore, rtLogger())
	restored, errs := e.RestoreFromManifest(context.Background(), manifest)
	if restored != 0 {
		t.Errorf("restored = %d, want 0 (corrupt blob rejected)", restored)
	}
	if len(errs) == 0 {
		t.Error("expected an error for the SHA-256 mismatch")
	}
	if _, ok := primary.objs["blobs/"+h]; ok {
		t.Error("a corrupt blob must NOT be written to primary")
	}
}

func TestRestoreFromManifestRejectsInventoryCountMismatch(t *testing.T) {
	data := []byte("one")
	h := sha256hex(data)
	backupStore := newMemRestoreStore()
	backupStore.objs["blobs/"+h] = data
	primary := newMemRestoreStore()
	e := NewEngine(nil, primary, backupStore, rtLogger())

	restored, errs := e.RestoreFromManifest(context.Background(), &backup.BackupManifest{
		BlobCount: 2, BlobManifest: backup.Manifest{Count: 1, Hashes: []string{h}},
	})
	if restored != 0 || len(errs) != 1 || len(primary.objs) != 0 {
		t.Fatalf("restored=%d errs=%v primary=%v", restored, errs, primary.objs)
	}
}

func TestRestoreMissingBlobsRejectsCorruptDestinationWrite(t *testing.T) {
	data := []byte("source is valid")
	h := sha256hex(data)
	backupStore := newMemRestoreStore()
	backupStore.objs["blobs/"+h] = data
	primary := newMemRestoreStore()
	primary.corruptWrites = true
	e := NewEngine(nil, primary, backupStore, rtLogger())

	restored, errs := e.RestoreMissingBlobs(context.Background(), []string{h})
	if restored != 0 || len(errs) != 1 {
		t.Fatalf("restored=%d errs=%v", restored, errs)
	}
}

type fakeIntegrityRows struct {
	rows      [][]any
	index     int
	scanErrAt int
	finalErr  error
}

func (r *fakeIntegrityRows) Next() bool { r.index++; return r.index <= len(r.rows) }
func (r *fakeIntegrityRows) Scan(dest ...any) error {
	i := r.index - 1
	if i == r.scanErrAt {
		return errors.New("scan failed")
	}
	*dest[0].(*string) = r.rows[i][0].(string)
	*dest[1].(*int64) = r.rows[i][1].(int64)
	return nil
}
func (r *fakeIntegrityRows) Err() error { return r.finalErr }

func TestScanIntegrityRefsFailsClosedOnScanAndCursorErrors(t *testing.T) {
	valid := sha256hex([]byte("valid"))
	for name, rows := range map[string]*fakeIntegrityRows{
		"scan":   {rows: [][]any{{valid, int64(5)}}, scanErrAt: 0},
		"cursor": {rows: [][]any{{valid, int64(5)}}, scanErrAt: -1, finalErr: errors.New("cursor failed")},
		"hash":   {rows: [][]any{{"../escape", int64(5)}}, scanErrAt: -1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := scanIntegrityRefs(rows); err == nil {
				t.Fatal("integrity inventory error was swallowed")
			}
		})
	}
}

type restoreBoundaryReader struct {
	io.Reader
	readErr  error
	closeErr error
}

func (reader *restoreBoundaryReader) Read(p []byte) (int, error) {
	if reader.readErr != nil {
		return 0, reader.readErr
	}
	return reader.Reader.Read(p)
}

func (reader *restoreBoundaryReader) Close() error { return reader.closeErr }

type restoreBoundaryStore struct {
	raw                []byte
	head               *storage.ObjectInfo
	headErr            error
	getErr             error
	putErr             error
	readErr            error
	closeErr           error
	getCalls           int
	secondRaw          []byte
	returnNilHead      bool
	closeErrAfterFirst bool
	putObjects         map[string][]byte
}

func (store *restoreBoundaryStore) HeadObject(_ context.Context, key string) (*storage.ObjectInfo, error) {
	if store.headErr != nil {
		return nil, store.headErr
	}
	if store.returnNilHead {
		return nil, nil
	}
	if store.head != nil {
		return store.head, nil
	}
	return &storage.ObjectInfo{Key: key, Size: int64(len(store.raw))}, nil
}

func (store *restoreBoundaryStore) GetObject(_ context.Context, _ string) (io.ReadCloser, error) {
	store.getCalls++
	if store.getErr != nil {
		return nil, store.getErr
	}
	raw := store.raw
	if store.getCalls > 1 && store.secondRaw != nil {
		raw = store.secondRaw
	}
	closeErr := store.closeErr
	if store.closeErrAfterFirst && store.getCalls == 1 {
		closeErr = nil
	}
	return &restoreBoundaryReader{Reader: bytes.NewReader(raw), readErr: store.readErr, closeErr: closeErr}, nil
}

func (store *restoreBoundaryStore) PutObject(_ context.Context, key string, data io.Reader, _ int64) error {
	if store.putErr != nil {
		return store.putErr
	}
	raw, err := io.ReadAll(data)
	if err == nil && store.putObjects != nil {
		store.putObjects[key] = raw
	}
	return err
}

func TestReadBoundedAndClosePropagatesAllReaderBoundaries(t *testing.T) {
	for name, fixture := range map[string]struct {
		reader io.ReadCloser
		limit  int64
	}{
		"read":  {reader: &restoreBoundaryReader{Reader: bytes.NewReader(nil), readErr: errors.New("read")}, limit: 10},
		"close": {reader: &restoreBoundaryReader{Reader: bytes.NewReader([]byte("ok")), closeErr: errors.New("close")}, limit: 10},
		"limit": {reader: io.NopCloser(bytes.NewReader([]byte("too long"))), limit: 2},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readBoundedAndClose(fixture.reader, fixture.limit); err == nil {
				t.Fatal("reader boundary failure accepted")
			}
		})
	}
	if raw, err := readBoundedAndClose(io.NopCloser(strings.NewReader("ok")), 2); err != nil || string(raw) != "ok" {
		t.Fatalf("raw=%q err=%v", raw, err)
	}
}

func TestVerifyBlobDigestRejectsMetadataReaderSizeAndContentFailures(t *testing.T) {
	data := []byte("valid")
	hash := sha256hex(data)
	for name, candidate := range map[string]struct {
		hash  string
		size  int64
		store RestoreStore
	}{
		"hash":          {hash: "bad", size: int64(len(data)), store: &restoreBoundaryStore{raw: data}},
		"size metadata": {hash: hash, size: -1, store: &restoreBoundaryStore{raw: data}},
		"get":           {hash: hash, size: int64(len(data)), store: &restoreBoundaryStore{getErr: errors.New("get")}},
		"read":          {hash: hash, size: int64(len(data)), store: &restoreBoundaryStore{raw: data, readErr: errors.New("read")}},
		"close":         {hash: hash, size: int64(len(data)), store: &restoreBoundaryStore{raw: data, closeErr: errors.New("close")}},
		"size":          {hash: hash, size: int64(len(data)) + 1, store: &restoreBoundaryStore{raw: data}},
		"digest":        {hash: hash, size: int64(len(data)), store: &restoreBoundaryStore{raw: []byte("other")}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := verifyBlobDigest(context.Background(), candidate.store, candidate.hash, candidate.size); err == nil {
				t.Fatal("invalid blob accepted")
			}
		})
	}
}

func TestRestoreManifestNilDuplicateAndCorruptPrimaryBoundaries(t *testing.T) {
	data := []byte("valid")
	hash := sha256hex(data)
	backupStore := newMemRestoreStore()
	backupStore.objs["blobs/"+hash] = data
	primary := newMemRestoreStore()
	engine := NewEngine(nil, primary, backupStore, rtLogger())
	if restored, errs := engine.RestoreFromManifest(context.Background(), nil); restored != 0 || len(errs) != 1 {
		t.Fatalf("nil manifest restored=%d errs=%v", restored, errs)
	}
	duplicate := &backup.BackupManifest{BlobCount: 2, BlobManifest: backup.Manifest{Count: 2, Hashes: []string{hash, hash}}}
	if _, errs := engine.RestoreFromManifest(context.Background(), duplicate); len(errs) == 0 {
		t.Fatal("duplicate manifest accepted")
	}
	primary.objs["blobs/"+hash] = []byte("bad!!")
	single := &backup.BackupManifest{BlobCount: 1, BlobManifest: backup.Manifest{Count: 1, Hashes: []string{hash}}}
	if restored, errs := engine.RestoreFromManifest(context.Background(), single); restored != 1 || len(errs) != 0 {
		t.Fatalf("corrupt primary recovery restored=%d errs=%v", restored, errs)
	}
}

func TestRestoreMissingBlobsPropagatesSourceAndDestinationBoundaries(t *testing.T) {
	data := []byte("valid")
	hash := sha256hex(data)
	tests := map[string]struct {
		backup  RestoreStore
		primary RestoreStore
	}{
		"head":        {backup: &restoreBoundaryStore{headErr: errors.New("head")}, primary: newMemRestoreStore()},
		"nil head":    {backup: &restoreBoundaryStore{returnNilHead: true}, primary: newMemRestoreStore()},
		"put":         {backup: &restoreBoundaryStore{raw: data}, primary: &restoreBoundaryStore{putErr: errors.New("put")}},
		"second size": {backup: &restoreBoundaryStore{raw: data, secondRaw: []byte("x")}, primary: newMemRestoreStore()},
		"copy close":  {backup: &restoreBoundaryStore{raw: data, closeErr: errors.New("close"), closeErrAfterFirst: true}, primary: newMemRestoreStore()},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			restored, errs := NewEngine(nil, tt.primary, tt.backup, rtLogger()).RestoreMissingBlobs(context.Background(), []string{hash})
			if restored != 0 || len(errs) == 0 {
				t.Fatalf("restored=%d errs=%v", restored, errs)
			}
		})
	}
}

func TestScanIntegrityRefsAcceptsValidRowsAndRejectsNegativeSize(t *testing.T) {
	valid := sha256hex([]byte("valid"))
	refs, err := scanIntegrityRefs(&fakeIntegrityRows{rows: [][]any{{valid, int64(5)}}, scanErrAt: -1})
	if err != nil || len(refs) != 1 || refs[0].Hash != valid {
		t.Fatalf("refs=%v err=%v", refs, err)
	}
	if _, err := scanIntegrityRefs(&fakeIntegrityRows{rows: [][]any{{valid, int64(-1)}}, scanErrAt: -1}); err == nil {
		t.Fatal("negative blob size accepted")
	}
}

func TestRestoreConfigIsAtomic(t *testing.T) {
	pool := restoreTestPool(t)
	ctx := context.Background()
	const validKey = "backup.restore_atomic_a_valid"
	const invalidKey = "backup.restore_atomic_z_invalid"
	_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key = ANY($1)`, []string{validKey, invalidKey})
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key = ANY($1)`, []string{validKey, invalidKey})
	})

	cfg := map[string]backup.ConfigEntry{
		validKey:   {Value: `"would-have-committed"`},
		invalidKey: {Value: `not-json`},
	}
	raw, _ := json.Marshal(cfg)
	backupStore := newMemRestoreStore()
	backupStore.objs["config.json"] = raw
	installLegacyManifest(t, backupStore, raw)
	e := NewEngine(pool, newMemRestoreStore(), backupStore, rtLogger())
	if _, err := e.RestoreConfig(ctx); err == nil {
		t.Fatal("invalid config row did not fail restore")
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM system_config WHERE key = $1`, validKey).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("config restore committed a prefix before a later failure")
	}
}

func TestVerifyIntegrityClassifiesMissingSizeDigestAndPresentBlobs(t *testing.T) {
	pool := restoreTestPool(t)
	ctx := context.Background()
	type priorRef struct {
		hash  string
		count int64
	}
	rows, err := pool.Query(ctx, `SELECT sha256,ref_count FROM blobs WHERE ref_count>0`)
	if err != nil {
		t.Fatal(err)
	}
	var prior []priorRef
	for rows.Next() {
		var ref priorRef
		if err := rows.Scan(&ref.hash, &ref.count); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		prior = append(prior, ref)
	}
	rows.Close()
	if _, err := pool.Exec(ctx, `UPDATE blobs SET ref_count=0 WHERE ref_count>0`); err != nil {
		t.Fatal(err)
	}
	present := []byte("present")
	sizeMismatch := []byte("size-mismatch")
	digestMismatch := []byte("digest-mismatch")
	missing := []byte("missing")
	hashes := []string{sha256hex(present), sha256hex(sizeMismatch), sha256hex(digestMismatch), sha256hex(missing)}
	for index, hash := range hashes {
		contents := [][]byte{present, sizeMismatch, digestMismatch, missing}[index]
		if _, err := pool.Exec(ctx, `INSERT INTO blobs (sha256,minio_ref,size_bytes,content_type,ref_count)
			VALUES ($1,$1,$2,'application/octet-stream',1)
			ON CONFLICT (sha256) DO UPDATE SET size_bytes=EXCLUDED.size_bytes,ref_count=1`, hash, len(contents)); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM blobs WHERE sha256=ANY($1)`, hashes)
		for _, ref := range prior {
			_, _ = pool.Exec(ctx, `UPDATE blobs SET ref_count=$2 WHERE sha256=$1`, ref.hash, ref.count)
		}
	})
	primary := newMemRestoreStore()
	primary.objs["blobs/"+hashes[0]] = present
	primary.objs["blobs/"+hashes[1]] = []byte("x")
	primary.objs["blobs/"+hashes[2]] = bytes.Repeat([]byte("x"), len(digestMismatch))
	report, err := NewEngine(pool, primary, newMemRestoreStore(), rtLogger()).VerifyIntegrity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.Total != 4 || report.Present != 1 || len(report.Missing) != 1 || len(report.Corrupt) != 2 {
		t.Fatalf("report=%+v", report)
	}
}

// TestRestoreConfig_QuarantinesEncryptedValue: recovery never imports encrypted
// credentials directly because they are bound to the source installation's key.
func TestRestoreConfig_QuarantinesEncryptedValue(t *testing.T) {
	pool := restoreTestPool(t)
	ctx := context.Background()
	const key = "backup.restore_encflag_test"
	cfg := map[string]backup.ConfigEntry{key: {Value: `{"_enc":"ciphertext"}`, Encrypted: true}}
	raw, _ := json.Marshal(cfg)
	backupStore := newMemRestoreStore()
	backupStore.objs["config.json"] = raw
	installLegacyManifest(t, backupStore, raw)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key = $1`, key)
		_, _ = pool.Exec(ctx, `DELETE FROM restore_config_quarantine WHERE config_key = $1`, key)
	})

	e := NewEngine(pool, newMemRestoreStore(), backupStore, rtLogger())
	if _, err := e.RestoreConfig(ctx); err != nil {
		t.Fatalf("RestoreConfig: %v", err)
	}
	var systemCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM system_config WHERE key = $1`, key).Scan(&systemCount); err != nil {
		t.Fatal(err)
	}
	if systemCount != 0 {
		t.Fatalf("encrypted restore applied %d system_config rows, want 0", systemCount)
	}
	var disposition string
	var encrypted bool
	if err := pool.QueryRow(ctx,
		`SELECT disposition, encrypted FROM restore_config_quarantine WHERE config_key = $1 ORDER BY id DESC LIMIT 1`,
		key).Scan(&disposition, &encrypted); err != nil {
		t.Fatalf("read quarantine: %v", err)
	}
	if disposition != "rotate" || !encrypted {
		t.Fatalf("quarantine disposition=%q encrypted=%v, want rotate/true", disposition, encrypted)
	}
}

// TestStartRestoreJob_SingleFlight: only one restore may run at a time. The first
// StartRestoreJob succeeds; a second, while it's still running, is rejected.
func TestStartRestoreJob_SingleFlight(t *testing.T) {
	pool := restoreTestPool(t)
	ctx := context.Background()
	e := NewEngine(pool, newMemRestoreStore(), newMemRestoreStore(), rtLogger())

	id1, err := e.StartRestoreJob(ctx, "full")
	if err != nil {
		t.Fatalf("first StartRestoreJob: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM restore_jobs WHERE id = $1`, id1) })
	if id1 == 0 {
		t.Fatal("expected a nonzero job id")
	}

	if _, err2 := e.StartRestoreJob(ctx, "full"); err2 == nil {
		t.Error("a second restore must be rejected while one is running (single-flight)")
	}
}

// TestStartRestoreJob_AllowedAfterCompletion: once the running job completes, a
// new restore is allowed.
func TestStartRestoreJob_AllowedAfterCompletion(t *testing.T) {
	pool := restoreTestPool(t)
	ctx := context.Background()
	e := NewEngine(pool, newMemRestoreStore(), newMemRestoreStore(), rtLogger())

	id1, err := e.StartRestoreJob(ctx, "config")
	if err != nil {
		t.Fatalf("first StartRestoreJob: %v", err)
	}
	// Complete it.
	_, _ = pool.Exec(ctx, `UPDATE restore_jobs SET status = 'completed', completed_at = now() WHERE id = $1`, id1)

	id2, err := e.StartRestoreJob(ctx, "config")
	if err != nil {
		t.Errorf("after completion a new restore should be allowed: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM restore_jobs WHERE id = ANY($1)`, []int64{id1, id2}) })
}

// TestFinishRestoreJob_MarksCompletedAndReleases: finishing with no error marks
// the job completed (+ completed_at) and releases the single-flight slot.
func TestFinishRestoreJob_MarksCompletedAndReleases(t *testing.T) {
	pool := restoreTestPool(t)
	ctx := context.Background()
	e := NewEngine(pool, newMemRestoreStore(), newMemRestoreStore(), rtLogger())

	id, err := e.StartRestoreJob(ctx, "full")
	if err != nil {
		t.Fatalf("StartRestoreJob: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM restore_jobs WHERE id = $1`, id) })

	if err := e.FinishRestoreJob(ctx, id, nil); err != nil {
		t.Fatalf("FinishRestoreJob: %v", err)
	}
	var status string
	var completedAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT status, completed_at FROM restore_jobs WHERE id = $1`, id).Scan(&status, &completedAt); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if status != "completed" {
		t.Errorf("status = %q, want completed", status)
	}
	if completedAt == nil {
		t.Error("completed_at should be set")
	}

	// The slot is released — a new restore is allowed.
	id2, err := e.StartRestoreJob(ctx, "full")
	if err != nil {
		t.Errorf("slot not released after completion: %v", err)
	}
	_, _ = pool.Exec(ctx, `DELETE FROM restore_jobs WHERE id = $1`, id2)
}

// TestFinishRestoreJob_RecordsFailure: finishing with an error marks the job
// failed and records the message in error_log.
func TestFinishRestoreJob_RecordsFailure(t *testing.T) {
	pool := restoreTestPool(t)
	ctx := context.Background()
	e := NewEngine(pool, newMemRestoreStore(), newMemRestoreStore(), rtLogger())

	id, err := e.StartRestoreJob(ctx, "config")
	if err != nil {
		t.Fatalf("StartRestoreJob: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM restore_jobs WHERE id = $1`, id) })

	if err := e.FinishRestoreJob(ctx, id, errors.New("pg_restore exploded")); err != nil {
		t.Fatalf("FinishRestoreJob: %v", err)
	}
	var status string
	var errlog []byte
	if err := pool.QueryRow(ctx, `SELECT status, error_log FROM restore_jobs WHERE id = $1`, id).Scan(&status, &errlog); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if status != "failed" {
		t.Errorf("status = %q, want failed", status)
	}
	if !strings.Contains(string(errlog), "pg_restore exploded") {
		t.Errorf("error_log = %s, want it to contain the failure", errlog)
	}
}

// TestRestoreConfig_UpsertsExisting: restoring over an existing key overwrites it
// (a restore is authoritative).
func TestRestoreConfig_UpsertsExisting(t *testing.T) {
	pool := restoreTestPool(t)
	ctx := context.Background()
	const key = "feature.restore_upsert_test"
	_, _ = pool.Exec(ctx, `INSERT INTO system_config (key, value) VALUES ($1, '"old"'::jsonb)
		ON CONFLICT (key) DO UPDATE SET value = '"old"'::jsonb`, key)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key = $1`, key) })

	backupStore := newMemRestoreStore()
	raw, _ := json.Marshal(map[string]backup.ConfigEntry{key: {Value: `"new"`}})
	backupStore.objs["config.json"] = raw
	installLegacyManifest(t, backupStore, raw)

	e := NewEngine(pool, newMemRestoreStore(), backupStore, rtLogger())
	if _, err := e.RestoreConfig(ctx); err != nil {
		t.Fatalf("RestoreConfig: %v", err)
	}
	var got string
	_ = pool.QueryRow(ctx, `SELECT value FROM system_config WHERE key = $1`, key).Scan(&got)
	if got != `"new"` {
		t.Errorf("after restore value = %q, want %q (overwrite)", got, `"new"`)
	}
}
