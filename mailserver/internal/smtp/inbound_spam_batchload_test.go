package smtp

import (
	"context"
	"errors"
	"sync"
	"testing"

	"setjoin.com/mailserver/internal/spam"
	"setjoin.com/shared/toggle"
)

// fakeSpamSource counts LoadModel calls so the tests can pin the exact load
// strategy the delivery path uses under each feature.spam_model_batch_load
// state (owner decision A6).
type fakeSpamSource struct {
	mu    sync.Mutex
	loads int
	err   error
}

func (f *fakeSpamSource) LoadModel(_ context.Context, _ int64) (*spam.Model, error) {
	f.mu.Lock()
	f.loads++
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	// A keyed model whose tables are tiny (featSize 1) keeps Score cheap; the
	// score value itself is asserted via Model.Score parity below.
	return spam.NewModel(1), nil
}

func (f *fakeSpamSource) loadCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loads
}

func batchLoadConnState(t *testing.T, flags map[string]bool, src *fakeSpamSource) *inConnState {
	t.Helper()
	return &inConnState{
		srv: &InboundServer{
			toggles:   toggle.NewTestFlags(flags),
			spamStore: src,
		},
	}
}

// TestScoreFTRLToggleOffLoadsPerCall pins the byte-identical old behavior:
// with feature.spam_model_batch_load OFF every scoring call performs its own
// LoadModel+Score and no batch scorer is ever created (nothing resident
// across calls).
func TestScoreFTRLToggleOffLoadsPerCall(t *testing.T) {
	src := &fakeSpamSource{}
	c := batchLoadConnState(t, map[string]bool{
		toggle.FeatureMLSpam:             true,
		toggle.FeatureSpamModelBatchLoad: false, // registry default is ON — OFF must be explicit
	}, src)
	ctx := context.Background()
	data := []byte("Subject: s\r\n\r\nbody")

	const calls = 5
	for i := 0; i < calls; i++ {
		score, err := c.scoreFTRL(ctx, 42, data)
		if err != nil {
			t.Fatalf("scoreFTRL %d: %v", i, err)
		}
		// Parity with the historical path: the score is exactly
		// LoadModel(...).Score(data) for the same model.
		want := spam.NewModel(1).Score(data)
		if score != want {
			t.Fatalf("scoreFTRL %d = %v, want per-call LoadModel+Score value %v", i, score, want)
		}
	}
	if got := src.loadCount(); got != calls {
		t.Fatalf("loads = %d, want %d (one load per call when OFF)", got, calls)
	}
	if c.spamBatch != nil {
		t.Fatal("batch scorer must never be created while the toggle is OFF")
	}
}

// TestScoreFTRLToggleOnLoadsOncePerBatch pins the A6 behavior: N scoring
// calls for the same user within one batch perform exactly one model load,
// with the rest served from the resident model.
func TestScoreFTRLToggleOnLoadsOncePerBatch(t *testing.T) {
	src := &fakeSpamSource{}
	c := batchLoadConnState(t, map[string]bool{
		toggle.FeatureMLSpam: true,
		// toggle.FeatureSpamModelBatchLoad absent -> registry default ON.
	}, src)
	ctx := context.Background()
	data := []byte("Subject: s\r\n\r\nbody")

	const calls = 10
	for i := 0; i < calls; i++ {
		if _, err := c.scoreFTRL(ctx, 42, data); err != nil {
			t.Fatalf("scoreFTRL %d: %v", i, err)
		}
	}
	if got := src.loadCount(); got != 1 {
		t.Fatalf("loads = %d, want 1 (one model load per batch)", got)
	}
	if c.spamBatch == nil {
		t.Fatal("batch scorer must be created while the toggle is ON")
	}
	stats := c.spamBatch.Stats()
	if stats.Hits != calls-1 || stats.Loads != 1 {
		t.Fatalf("batch stats = %+v, want Loads=1 Hits=%d", stats, calls-1)
	}
}

// TestScoreFTRLToggleOnBatchBoundaryReloads pins the batch bound: after
// DefaultBatchLoadSize scored deliveries the connection's next scoring call
// starts a fresh batch (one reload), keeping both staleness and the resident
// set bounded.
func TestScoreFTRLToggleOnBatchBoundaryReloads(t *testing.T) {
	src := &fakeSpamSource{}
	c := batchLoadConnState(t, map[string]bool{
		toggle.FeatureMLSpam:             true,
		toggle.FeatureSpamModelBatchLoad: true,
	}, src)
	ctx := context.Background()
	data := []byte("Subject: s\r\n\r\nbody")

	for i := 0; i < spam.DefaultBatchLoadSize; i++ {
		if _, err := c.scoreFTRL(ctx, 42, data); err != nil {
			t.Fatalf("scoreFTRL %d: %v", i, err)
		}
	}
	if got := src.loadCount(); got != 1 {
		t.Fatalf("loads within first batch = %d, want 1", got)
	}
	if _, err := c.scoreFTRL(ctx, 42, data); err != nil {
		t.Fatalf("scoreFTRL past boundary: %v", err)
	}
	if got := src.loadCount(); got != 2 {
		t.Fatalf("loads after boundary = %d, want 2 (batch rotated)", got)
	}
}

// TestScoreFTRLToggleOnErrorSurfaces pins the shared error contract: a load
// error (including the ErrModelDisabled scoring opt-out) returns the error on
// BOTH toggle paths and scores nothing.
func TestScoreFTRLToggleOnErrorSurfaces(t *testing.T) {
	for _, batchOn := range []bool{false, true} {
		src := &fakeSpamSource{err: spam.ErrModelDisabled}
		flags := map[string]bool{
			toggle.FeatureMLSpam:             true,
			toggle.FeatureSpamModelBatchLoad: batchOn,
		}
		c := batchLoadConnState(t, flags, src)
		score, err := c.scoreFTRL(context.Background(), 42, []byte("x"))
		if !errors.Is(err, spam.ErrModelDisabled) {
			t.Fatalf("batchOn=%v: err = %v, want ErrModelDisabled", batchOn, err)
		}
		if score != 0 {
			t.Fatalf("batchOn=%v: score = %v, want 0", batchOn, score)
		}
	}
}
