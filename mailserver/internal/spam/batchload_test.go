package spam

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// countingSource is a ModelSource fake that counts LoadModel calls and hands
// out fresh untrained models (or a fixed error / disabled sentinel).
type countingSource struct {
	mu     sync.Mutex
	loads  int
	users  map[int64]bool
	errFor map[int64]error
}

func newCountingSource() *countingSource {
	return &countingSource{users: map[int64]bool{}, errFor: map[int64]error{}}
}

func (c *countingSource) LoadModel(_ context.Context, userID int64) (*Model, error) {
	c.mu.Lock()
	c.loads++
	c.users[userID] = true
	err := c.errFor[userID]
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return newUserModel(userID), nil
}

func (c *countingSource) loadCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.loads
}

// recordingSink is a BatchStatsSink fake capturing gauge deltas.
type recordingSink struct {
	mu       sync.Mutex
	loads    int64
	releases int64
	bytes    int64
}

func (r *recordingSink) recordBatchLoad(residentBytes int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loads++
	r.bytes += residentBytes
}

func (r *recordingSink) recordBatchRelease(residentBytes int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.releases++
	r.bytes -= residentBytes
}

func TestBatchScorerOneLoadPerBatchPerUser(t *testing.T) {
	src := newCountingSource()
	b := NewBatchScorer(src, DefaultBatchLoadSize)
	ctx := context.Background()

	raw := []byte("Subject: hi\r\n\r\nbody")
	for i := 0; i < 5; i++ {
		if _, err := b.Score(ctx, 42, raw); err != nil {
			t.Fatalf("Score %d: %v", i, err)
		}
	}
	if got := src.loadCount(); got != 1 {
		t.Fatalf("loads = %d, want 1 (one model load per batch per user)", got)
	}
	stats := b.Stats()
	if stats.Loads != 1 || stats.Hits != 4 {
		t.Fatalf("Stats = %+v, want Loads=1 Hits=4", stats)
	}
	if stats.ResidentModels != 1 || stats.ResidentBytes == 0 {
		t.Fatalf("Stats = %+v, want one resident model with nonzero bytes", stats)
	}
	// A second user in the same batch gets its own single load.
	if _, err := b.Score(ctx, 7, raw); err != nil {
		t.Fatalf("Score user 7: %v", err)
	}
	if got := src.loadCount(); got != 2 {
		t.Fatalf("loads after second user = %d, want 2", got)
	}
	if stats = b.Stats(); stats.ResidentModels != 2 {
		t.Fatalf("ResidentModels = %d, want 2", stats.ResidentModels)
	}
}

func TestBatchScorerBoundaryStartsFreshBatch(t *testing.T) {
	src := newCountingSource()
	const limit = 3
	b := NewBatchScorer(src, limit)
	ctx := context.Background()
	raw := []byte("Subject: hi\r\n\r\nbody")

	// Fill the batch: 3 calls, one load.
	for i := 0; i < limit; i++ {
		if _, err := b.Score(ctx, 42, raw); err != nil {
			t.Fatalf("Score %d: %v", i, err)
		}
	}
	if got := src.loadCount(); got != 1 {
		t.Fatalf("loads within batch = %d, want 1", got)
	}
	// The (limit+1)-th scored delivery must reload: the batch rotated.
	if _, err := b.Score(ctx, 42, raw); err != nil {
		t.Fatalf("Score past boundary: %v", err)
	}
	if got := src.loadCount(); got != 2 {
		t.Fatalf("loads after boundary = %d, want 2 (batch rotated at limit)", got)
	}
	if stats := b.Stats(); stats.ResidentModels != 1 {
		t.Fatalf("ResidentModels after boundary = %d, want 1 (old batch released)", stats.ResidentModels)
	}
}

func TestBatchScorerResetReleasesResidentModels(t *testing.T) {
	src := newCountingSource()
	sink := &recordingSink{}
	b := NewBatchScorer(src, DefaultBatchLoadSize)
	// Wire the sink the production PGModelStore path uses (source-implemented);
	// countingSource deliberately does not satisfy BatchStatsSink.
	if _, ok := any(src).(BatchStatsSink); ok {
		t.Fatal("countingSource must not satisfy BatchStatsSink")
	}
	b.sink = sink

	ctx := context.Background()
	raw := []byte("Subject: hi\r\n\r\nbody")
	if _, err := b.Score(ctx, 42, raw); err != nil {
		t.Fatalf("Score: %v", err)
	}
	before := b.Stats()
	if sink.loads != 1 || sink.bytes != before.ResidentBytes {
		t.Fatalf("sink after load: loads=%d bytes=%d, want 1/%d", sink.loads, sink.bytes, before.ResidentBytes)
	}
	b.Reset()
	after := b.Stats()
	if after.ResidentModels != 0 || after.ResidentBytes != 0 {
		t.Fatalf("Stats after Reset = %+v, want empty resident set (before: %+v)", after, before)
	}
	if sink.releases != 1 {
		t.Fatalf("sink releases=%d, want 1", sink.releases)
	}
	if sink.bytes != 0 {
		t.Fatalf("sink byte accounting = %d, want 0 (load/release symmetric)", sink.bytes)
	}
	// Lifetime counters survive the reset.
	if after.Loads != 1 {
		t.Fatalf("Loads after Reset = %d, want 1", after.Loads)
	}
}

func TestBatchScorerLoadErrorNotCachedNotScored(t *testing.T) {
	src := newCountingSource()
	src.errFor[99] = ErrModelDisabled
	b := NewBatchScorer(src, DefaultBatchLoadSize)
	ctx := context.Background()
	raw := []byte("Subject: hi\r\n\r\nbody")

	for i := 0; i < 3; i++ {
		score, err := b.Score(ctx, 99, raw)
		if !errors.Is(err, ErrModelDisabled) {
			t.Fatalf("Score %d: err = %v, want ErrModelDisabled", i, err)
		}
		if score != 0 {
			t.Fatalf("Score %d on load error = %v, want 0 (nothing scored)", i, score)
		}
	}
	if got := src.loadCount(); got != 3 {
		t.Fatalf("loads = %d, want 3 (errors retry per call, never cached)", got)
	}
	if stats := b.Stats(); stats.ResidentModels != 0 {
		t.Fatalf("Stats = %+v, want nothing cached", stats)
	}
	if b.calls != 0 {
		t.Fatalf("batched calls = %d, want 0 (failed loads score nothing and count nothing)", b.calls)
	}
	// A failed load must not consume the batch window: the next good user
	// still gets a full batch.
	for i := 0; i < DefaultBatchLoadSize; i++ {
		if _, err := b.Score(ctx, 42, raw); err != nil {
			t.Fatalf("Score user 42 call %d: %v", i, err)
		}
	}
	if got := src.loadCount(); got != 4 {
		t.Fatalf("loads = %d, want 4 (one fresh load for user 42's full batch)", got)
	}
}

func TestBatchScorerZeroLimitUsesDefault(t *testing.T) {
	b := NewBatchScorer(newCountingSource(), 0)
	if b.limit != DefaultBatchLoadSize {
		t.Fatalf("limit = %d, want %d", b.limit, DefaultBatchLoadSize)
	}
}

// TestBatchScorerConcurrentScores is the race sanity lane: run with -race.
func TestBatchScorerConcurrentScores(t *testing.T) {
	src := newCountingSource()
	b := NewBatchScorer(src, DefaultBatchLoadSize)
	ctx := context.Background()
	raw := []byte("Subject: hi\r\n\r\nbody")

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			userID := int64(g%4) + 1
			for i := 0; i < 20; i++ {
				if _, err := b.Score(ctx, userID, raw); err != nil {
					t.Errorf("Score: %v", err)
					return
				}
				_ = b.Stats()
			}
		}(g)
	}
	wg.Wait()
	if got := src.loadCount(); got < 1 || got > 8+8*int(DefaultBatchLoadSize) {
		t.Fatalf("loads = %d outside the plausible bounded range", got)
	}
}

func TestPGModelStoreBatchLoadStats(t *testing.T) {
	s := &PGModelStore{}
	if stats := s.BatchLoadStats(); stats != (BatchLoadStats{}) {
		t.Fatalf("fresh store stats = %+v, want zero", stats)
	}
	s.recordBatchLoad(24000000)
	s.recordBatchLoad(24000000)
	s.recordBatchRelease(24000000)
	stats := s.BatchLoadStats()
	if stats.Loads != 2 || stats.Hits != 0 || stats.ResidentModels != 1 || stats.ResidentBytes != 24000000 {
		t.Fatalf("stats = %+v, want Loads=2 ResidentModels=1 ResidentBytes=24000000", stats)
	}
}

func TestModelResidentBytesMatchesFTR2Layout(t *testing.T) {
	m := NewModel(DefaultFeatureSize)
	want := int64(8 + DefaultFeatureSize*3*8)
	if got := m.ResidentBytes(); got != want {
		t.Fatalf("ResidentBytes = %d, want %d", got, want)
	}
	blob, err := m.Save()
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if int64(len(blob)) != want {
		t.Fatalf("serialized size %d != ResidentBytes %d", len(blob), want)
	}
}

func TestLogBatchLoadPostureWarnsOnEnable(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	LogBatchLoadPosture(logger, true)
	warned := buf.String()
	if !strings.Contains(warned, "INCREASES MEMORY FOOTPRINT") {
		t.Fatalf("enabled posture did not warn about memory footprint; got: %s", warned)
	}
	if !strings.Contains(warned, "held resident") {
		t.Fatalf("warning does not describe resident models; got: %s", warned)
	}

	buf.Reset()
	LogBatchLoadPosture(logger, false)
	disabled := buf.String()
	if !strings.Contains(disabled, "per-message model loads") {
		t.Fatalf("disabled posture line missing; got: %s", disabled)
	}
	if strings.Contains(disabled, "WARN") {
		t.Fatalf("disabled posture must not warn; got: %s", disabled)
	}
}
