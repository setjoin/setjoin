package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"testing"
)

// ── fakes ────────────────────────────────────────────────────────────────

// reconMover is an in-memory blobMover with fault-injection points for the
// interruption/reconciliation contract tests.
type reconMover struct {
	objs        map[string][]byte
	getErr      map[string]error
	putErr      map[string]error
	putTruncate map[string]int // store only the first N bytes (interrupted write)
	puts        []string
	deletes     []string
}

func newReconMover() *reconMover {
	return &reconMover{
		objs:        map[string][]byte{},
		getErr:      map[string]error{},
		putErr:      map[string]error{},
		putTruncate: map[string]int{},
	}
}

func (m *reconMover) ProviderName() string { return "recon" }

func (m *reconMover) HeadObject(_ context.Context, key string) (*ObjectInfo, error) {
	b, ok := m.objs[key]
	if !ok {
		return nil, io.EOF
	}
	return &ObjectInfo{Key: key, Size: int64(len(b))}, nil
}

func (m *reconMover) GetObject(_ context.Context, key string) (io.ReadCloser, error) {
	if err := m.getErr[key]; err != nil {
		return nil, err
	}
	b, ok := m.objs[key]
	if !ok {
		return nil, io.EOF
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (m *reconMover) PutObject(_ context.Context, key string, r io.Reader, _ int64) error {
	if err := m.putErr[key]; err != nil {
		return err
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if n := m.putTruncate[key]; n > 0 && n < len(b) {
		b = b[:n] // simulate an interrupted/truncated write that still "succeeds"
	}
	m.objs[key] = b
	m.puts = append(m.puts, key)
	return nil
}

func (m *reconMover) DeleteObject(_ context.Context, key string) error {
	delete(m.objs, key)
	m.deletes = append(m.deletes, key)
	return nil
}

// reconRows is a backfillRows fake over (sha256, size_bytes) pairs.
type reconRows struct {
	keys  []string
	sizes []int64
	i     int
}

func (r *reconRows) Next() bool { return r.i < len(r.keys) }

func (r *reconRows) Scan(dest ...any) error {
	*dest[0].(*string) = r.keys[r.i]
	*dest[1].(*int64) = r.sizes[r.i]
	r.i++
	return nil
}

func (r *reconRows) Err() error { return nil }

// ── helpers ──────────────────────────────────────────────────────────────

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func reconLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ── tests ────────────────────────────────────────────────────────────────

// TestMigrationCopyRows_SkipRequiresIntegrity pins the reconciliation contract:
// the target-skip path requires size AND content verification (read-back hash
// against the content-addressed key) — never the old HeadObject existence-only
// skip that kept partial objects from interrupted runs in place.
func TestMigrationCopyRows_SkipRequiresIntegrity(t *testing.T) {
	key := sha256Hex("alpha-blob")
	src := newReconMover()
	src.objs[key] = []byte("alpha-blob")

	t.Run("verified object is skipped without a re-copy", func(t *testing.T) {
		target := newReconMover()
		target.objs[key] = []byte("alpha-blob")
		m := NewMigration(nil, src, target, reconLogger())
		mig, failed, err := m.copyRows(context.Background(), &reconRows{keys: []string{key}, sizes: []int64{10}}, 0)
		if err != nil || len(failed) != 0 || mig != 1 {
			t.Fatalf("copyRows = (%d, %v, %v), want (1, none, nil)", mig, failed, err)
		}
		if len(target.puts) != 0 {
			t.Fatalf("verified object was re-copied: %v", target.puts)
		}
	})

	t.Run("truncated partial object is re-copied", func(t *testing.T) {
		target := newReconMover()
		target.objs[key] = []byte("alpha") // interrupted earlier run: size mismatch
		m := NewMigration(nil, src, target, reconLogger())
		mig, failed, err := m.copyRows(context.Background(), &reconRows{keys: []string{key}, sizes: []int64{10}}, 0)
		if err != nil || len(failed) != 0 || mig != 1 {
			t.Fatalf("copyRows = (%d, %v, %v), want (1, none, nil)", mig, failed, err)
		}
		if len(target.puts) != 1 {
			t.Fatalf("partial object was not re-copied (puts=%v)", target.puts)
		}
		if got := string(target.objs[key]); got != "alpha-blob" {
			t.Fatalf("target content = %q, want full object", got)
		}
	})

	t.Run("same-size wrong content is re-copied", func(t *testing.T) {
		target := newReconMover()
		target.objs[key] = []byte("alpha-bbbx") // 10 bytes, corrupted content
		m := NewMigration(nil, src, target, reconLogger())
		mig, failed, err := m.copyRows(context.Background(), &reconRows{keys: []string{key}, sizes: []int64{10}}, 0)
		if err != nil || len(failed) != 0 || mig != 1 {
			t.Fatalf("copyRows = (%d, %v, %v), want (1, none, nil)", mig, failed, err)
		}
		if len(target.puts) != 1 {
			t.Fatalf("corrupted object was not re-copied (puts=%v)", target.puts)
		}
	})
}

// TestMigrationCopyRows_TransferErrorsEnumerated proves per-object failures do
// not abort the run and are ENUMERATED for reconciliation (never a convergence
// claim).
func TestMigrationCopyRows_TransferErrorsEnumerated(t *testing.T) {
	keyA, keyB, keyC := sha256Hex("a"), sha256Hex("b"), sha256Hex("c")
	src := newReconMover()
	src.objs[keyA], src.objs[keyB], src.objs[keyC] = []byte("a"), []byte("b"), []byte("c")
	src.getErr[keyB] = context.DeadlineExceeded // source read failure

	target := newReconMover()
	target.putErr[keyC] = context.DeadlineExceeded // target write failure

	m := NewMigration(nil, src, target, reconLogger())
	mig, failed, err := m.copyRows(context.Background(),
		&reconRows{keys: []string{keyA, keyB, keyC}, sizes: []int64{1, 1, 1}}, 0)

	if err != nil {
		t.Fatalf("per-object failures must not abort the run: %v", err)
	}
	if mig != 1 {
		t.Fatalf("migrated = %d, want 1", mig)
	}
	if len(failed) != 2 || failed[0] != keyB || failed[1] != keyC {
		t.Fatalf("failed enumeration = %v, want [%s %s] in order", failed, keyB, keyC)
	}
}

// TestMigrationCopyRows_TruncatedTargetWriteDetected pins the post-copy
// read-back: a write that "succeeds" but lands truncated/corrupted on the
// target is detected by size/content integrity, the partial object is deleted,
// and the key is enumerated — not counted as migrated.
func TestMigrationCopyRows_TruncatedTargetWriteDetected(t *testing.T) {
	key := sha256Hex("interrupted-write-blob")
	src := newReconMover()
	src.objs[key] = []byte("interrupted-write-blob")

	target := newReconMover()
	target.putTruncate[key] = 4 // silently store only a prefix

	m := NewMigration(nil, src, target, reconLogger())
	mig, failed, err := m.copyRows(context.Background(), &reconRows{keys: []string{key}, sizes: []int64{22}}, 0)
	if err != nil {
		t.Fatalf("copyRows: %v", err)
	}
	if mig != 0 {
		t.Fatalf("migrated = %d, want 0 (integrity failure must not count)", mig)
	}
	if len(failed) != 1 || failed[0] != key {
		t.Fatalf("failed enumeration = %v, want [%s]", failed, key)
	}
	if len(target.deletes) != 1 || target.deletes[0] != key {
		t.Fatalf("partial object was not deleted from target (deletes=%v)", target.deletes)
	}
	if _, ok := target.objs[key]; ok {
		t.Fatal("unverified partial object still present on target")
	}
}

// TestMigrationCopyRows_SourceCorruptionDetected pins the stream-hash leg: if
// the bytes read from the source do not hash to the content-addressed key, the
// corrupt copy is deleted from the target and the key enumerated.
func TestMigrationCopyRows_SourceCorruptionDetected(t *testing.T) {
	key := sha256Hex("expected-content") // rows claim this key
	src := newReconMover()
	src.objs[key] = []byte("expected-CONTENT") // same size, different bytes

	target := newReconMover()
	m := NewMigration(nil, src, target, reconLogger())
	mig, failed, err := m.copyRows(context.Background(), &reconRows{keys: []string{key}, sizes: []int64{16}}, 0)
	if err != nil {
		t.Fatalf("copyRows: %v", err)
	}
	if mig != 0 || len(failed) != 1 || failed[0] != key {
		t.Fatalf("(migrated, failed) = (%d, %v), want (0, [%s])", mig, failed, key)
	}
	if len(target.deletes) != 1 {
		t.Fatalf("corrupt target copy was not deleted (deletes=%v)", target.deletes)
	}
}

// TestMigrationCopyRows_CancellationStopsBetweenRows keeps the accepted-work
// drain property: a cancelled context stops the loop promptly with the partial
// count and the context error.
func TestMigrationCopyRows_CancellationStopsBetweenRows(t *testing.T) {
	keys := []string{sha256Hex("1"), sha256Hex("2"), sha256Hex("3")}
	src := newReconMover()
	for i, k := range keys {
		src.objs[k] = []byte{byte(i + 1)}
	}
	target := newReconMover()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before any row is accepted

	m := NewMigration(nil, src, target, reconLogger())
	mig, failed, err := m.copyRows(ctx, &reconRows{keys: keys, sizes: []int64{1, 1, 1}}, 0)
	if err != context.Canceled {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if mig != 0 || failed != nil {
		t.Fatalf("(migrated, failed) = (%d, %v), want (0, nil)", mig, failed)
	}
}

// TestMigrationCopyRows_CleanRunEnumeratesNothing is the positive control.
func TestMigrationCopyRows_CleanRunEnumeratesNothing(t *testing.T) {
	contents := []string{"blob-one", "blob-two", "blob-three", "blob-four"}
	src := newReconMover()
	keys := make([]string, len(contents))
	sizes := make([]int64, len(contents))
	for i, c := range contents {
		keys[i] = sha256Hex(c)
		sizes[i] = int64(len(c))
		src.objs[keys[i]] = []byte(c)
	}
	target := newReconMover()

	m := NewMigration(nil, src, target, reconLogger())
	mig, failed, err := m.copyRows(context.Background(), &reconRows{keys: keys, sizes: sizes}, 0)
	if err != nil || len(failed) != 0 || mig != int64(len(contents)) {
		t.Fatalf("copyRows = (%d, %v, %v), want (%d, none, nil)", mig, failed, err, len(contents))
	}
	for i, k := range keys {
		if got := string(target.objs[k]); got != contents[i] {
			t.Fatalf("target[%d] = %q, want %q", i, got, contents[i])
		}
	}
}
