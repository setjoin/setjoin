package mailrecovery

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// scriptedChunkDB sequences QueryRow results for putChunk:
// 1. session/item SELECT, 2. existing-chunk SELECT, 3. the record reducer,
// 4. the raced-record probe introduced by shared-object-delete-on-raced-record.
type scriptedChunkDB struct {
	results []pgx.Row
	calls   int
}

func (db *scriptedChunkDB) QueryRow(context.Context, string, ...any) pgx.Row {
	db.calls++
	if len(db.results) == 0 {
		return errRow{err: errors.New("unexpected QueryRow call")}
	}
	r := db.results[0]
	db.results = db.results[1:]
	return r
}

func (db *scriptedChunkDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected Query")
}

type errRow struct{ err error }

func (r errRow) Scan(...any) error { return r.err }

type scanFunc func(...any) error

func (f scanFunc) Scan(dest ...any) error { return f(dest...) }

type recordingStore struct {
	putCalls    int
	removeCalls int
	removedKeys []string
}

func (s *recordingStore) Put(context.Context, string, io.Reader, int64, string) error {
	s.putCalls++
	return nil
}

func (s *recordingStore) Get(context.Context, string) (io.ReadCloser, error) {
	return nil, errors.New("unexpected get")
}

func (s *recordingStore) Remove(_ context.Context, key string) error {
	s.removeCalls++
	s.removedKeys = append(s.removedKeys, key)
	return nil
}

func putChunkHarness(t *testing.T, db *scriptedChunkDB, store *recordingStore) *Handler {
	t.Helper()
	return &Handler{
		db:     db,
		store:  store,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:    func() time.Time { return time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC) },
	}
}

var putChunkCommonResults = []pgx.Row{
	// 1. session/item state: uploading, not expired, offset 0, size 5.
	scanFunc(func(dest ...any) error {
		incident := dest[0].(*uuid.UUID)
		*incident = uuid.MustParse("11111111-1111-4111-8111-111111111111")
		*(dest[1].(*int64)) = 0            // next_offset
		*(dest[2].(*int64)) = 5            // declared_size
		*(dest[3].(*string)) = "uploading" // item status
		*(dest[4].(*string)) = "uploading" // session status
		*(dest[5].(*time.Time)) = time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
		return nil
	}),
	// 2. existing chunk: absent.
	errRow{err: pgx.ErrNoRows},
	// 3. the record reducer: fails.
	errRow{err: errors.New("synthetic reducer failure")},
}

func TestPutChunkRacedCommittedRecordKeepsObject(t *testing.T) {
	// The reducer failed, but the probe finds a COMMITTED row (a raced
	// identical upload shares the content-addressed key): the object must be
	// KEPT, or the raced upload's committed record would be wedged.
	db := &scriptedChunkDB{results: append(append([]pgx.Row{}, putChunkCommonResults...),
		scanFunc(func(dest ...any) error {
			*(dest[0].(*string)) = "recovery-quarantine/shared-key"
			return nil
		}),
	)}
	store := &recordingStore{}
	handler := putChunkHarness(t, db, store)

	err := handler.putChunk(context.Background(), 7,
		uuid.MustParse("22222222-2222-4222-8222-222222222222"), "item-1",
		"bytes 0-4/5", strings.NewReader("hello"))
	var rf reducerFailure
	if !errors.As(err, &rf) {
		t.Fatalf("expected reducerFailure, got %v", err)
	}
	if store.removeCalls != 0 {
		t.Fatalf("Remove called %d times despite a committed raced record; removed=%v",
			store.removeCalls, store.removedKeys)
	}
}

func TestPutChunkUnreferencedObjectIsRemoved(t *testing.T) {
	// The reducer failed AND the probe proves no row was committed: the just-
	// uploaded object is an orphan and the compensating Remove must still fire.
	db := &scriptedChunkDB{results: append(append([]pgx.Row{}, putChunkCommonResults...),
		errRow{err: pgx.ErrNoRows},
	)}
	store := &recordingStore{}
	handler := putChunkHarness(t, db, store)

	err := handler.putChunk(context.Background(), 7,
		uuid.MustParse("22222222-2222-4222-8222-222222222222"), "item-1",
		"bytes 0-4/5", strings.NewReader("hello"))
	if !errors.As(err, &reducerFailure{}) {
		t.Fatalf("expected reducerFailure, got %v", err)
	}
	if store.removeCalls != 1 {
		t.Fatalf("Remove calls = %d, want 1 (orphan cleanup)", store.removeCalls)
	}
}

func TestPutChunkProbeErrorKeepsObject(t *testing.T) {
	// Probe failure leaves the commit state unknown: keep the object (the
	// dangerous direction is deletion) and let residue reaping own orphans.
	db := &scriptedChunkDB{results: append(append([]pgx.Row{}, putChunkCommonResults...),
		errRow{err: errors.New("probe db failure")},
	)}
	store := &recordingStore{}
	handler := putChunkHarness(t, db, store)

	err := handler.putChunk(context.Background(), 7,
		uuid.MustParse("22222222-2222-4222-8222-222222222222"), "item-1",
		"bytes 0-4/5", strings.NewReader("hello"))
	if !errors.As(err, &reducerFailure{}) {
		t.Fatalf("expected reducerFailure, got %v", err)
	}
	if store.removeCalls != 0 {
		t.Fatalf("Remove called %d times on an unknown commit state", store.removeCalls)
	}
}
