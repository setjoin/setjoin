package spam

import (
	"context"
	"log/slog"
	"sync"
)

// DefaultBatchLoadSize bounds one scoring batch, in scored deliveries
// (owner decision A6 / SPAM-007). While feature.spam_model_batch_load is ON,
// a batch scorer holds each touched user's model resident across the batch:
// one LoadModel per user per batch instead of load/score/discard per recipient
// per message. After the limit is reached the next scoring call releases the
// batch's resident models and starts a fresh batch, so both the load
// amortization window and the resident-model set stay bounded.
const DefaultBatchLoadSize = 50

// ModelSource is the scoring-side load surface (PGModelStore). It carries the
// LoadModel outcome contract verbatim: cold start yields a fresh model with a
// nil error; ErrModelDisabled and any load fault yield (nil, err) — batch
// loading never converts an error into a silently-fresh score.
type ModelSource interface {
	LoadModel(ctx context.Context, userID int64) (*Model, error)
}

// BatchStatsSink receives resident-model gauge updates from a BatchScorer so
// the process-wide footprint stays observable (admin spam dashboard). The
// sink is optional; test sources may omit it.
type BatchStatsSink interface {
	recordBatchLoad(residentBytes int64)
	recordBatchRelease(residentBytes int64)
}

// BatchLoadStats reports cumulative and gauge counters for batch model
// loading. Loads/Hits are lifetime totals; ResidentModels/ResidentBytes are
// the current footprint of models held across active batches (the
// memory-footprint surface the toggle's warning log points at).
type BatchLoadStats struct {
	Loads          int64 // model loads issued to the store (batch path only)
	Hits           int64 // scoring calls served from an already-resident model
	ResidentModels int64 // models currently held resident across active batches
	ResidentBytes  int64 // approximate bytes of the currently resident models
}

// BatchScorer amortizes per-user model loads across one bounded delivery
// scoring batch. It is the feature.spam_model_batch_load implementation for
// the delivery path (internal/smtp applyPerUserSpam): one connection's
// delivery loop is the natural batch grouping, bounded at
// DefaultBatchLoadSize scored deliveries.
//
// Semantics relative to per-call LoadModel+Score:
//
//   - The first scoring call for a user in a batch loads once; further calls
//     for the same user reuse the resident model (Hits). A model the trainer
//     saves mid-batch is therefore seen only after the batch boundary — the
//     bounded-staleness trade the toggle accepts. OFF (the old path) reloads
//     per call and never holds models across messages.
//   - Resident footprint is bounded: at most min(batch limit, distinct
//     recipients) user models per active connection, released at the batch
//     boundary or when the connection closes (Reset). Each user model is
//     ~24 MB at DefaultFeatureSize (3 float64 tables of 2^20) — the
//     memory-footprint increase the toggle's warning log declares.
//   - Load errors keep the per-call contract: (0, err) is returned, nothing
//     is cached, and the call does not count toward the batch (it scored
//     nothing). A disabled or faulted user retries on its next delivery.
type BatchScorer struct {
	source ModelSource
	sink   BatchStatsSink
	limit  int

	mu     sync.Mutex
	models map[int64]*Model
	calls  int   // scored deliveries in the current batch
	bytes  int64 // resident bytes held in the current batch
	loads  int64 // lifetime
	hits   int64 // lifetime
}

// NewBatchScorer builds a batch scorer over source. limit <= 0 selects
// DefaultBatchLoadSize. If source also implements BatchStatsSink (the
// production PGModelStore does), resident-footprint gauges flow to it.
func NewBatchScorer(source ModelSource, limit int) *BatchScorer {
	if limit <= 0 {
		limit = DefaultBatchLoadSize
	}
	b := &BatchScorer{
		source: source,
		limit:  limit,
		models: make(map[int64]*Model),
	}
	if sink, ok := source.(BatchStatsSink); ok {
		b.sink = sink
	}
	return b
}

// Score returns the FTRL spam probability for raw under userID's model,
// loading the model once per batch. Error semantics mirror ModelSource
// (i.e. PGModelStore.LoadModel) exactly: any load error — including the
// ErrModelDisabled scoring opt-out — returns (0, err) and scores nothing.
func (b *BatchScorer) Score(ctx context.Context, userID int64, raw []byte) (float64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.calls >= b.limit {
		b.dropLocked()
	}
	m, cached := b.models[userID]
	if !cached {
		var err error
		m, err = b.source.LoadModel(ctx, userID)
		if err != nil {
			return 0, err
		}
		b.models[userID] = m
		b.loads++
		rb := m.ResidentBytes()
		b.bytes += rb
		if b.sink != nil {
			b.sink.recordBatchLoad(rb)
		}
	} else {
		b.hits++
	}
	b.calls++
	return m.Score(raw), nil
}

// Reset releases the batch's resident models (returning their bytes to the
// process-wide gauge) and starts a fresh batch. Call when the delivery loop
// the scorer belongs to ends, so the resident gauge never outlives its
// connection. Lifetime Loads/Hits survive the reset.
func (b *BatchScorer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dropLocked()
}

func (b *BatchScorer) dropLocked() {
	if b.sink != nil && b.bytes > 0 {
		b.sink.recordBatchRelease(b.bytes)
	}
	b.models = make(map[int64]*Model)
	b.calls = 0
	b.bytes = 0
}

// Stats reports this scorer's lifetime load/hit counters and its current
// resident footprint.
func (b *BatchScorer) Stats() BatchLoadStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return BatchLoadStats{
		Loads:          b.loads,
		Hits:           b.hits,
		ResidentModels: int64(len(b.models)),
		ResidentBytes:  b.bytes,
	}
}

// BatchLoadStats returns the process-wide batch-loading counters across every
// batch scorer wired to this store: lifetime loads/hits and the current
// resident model count/bytes (the admin-dashboard footprint surface).
func (s *PGModelStore) BatchLoadStats() BatchLoadStats {
	return BatchLoadStats{
		Loads:          s.batchLoadsTotal.Load(),
		Hits:           s.batchHitsTotal.Load(),
		ResidentModels: s.batchResidentModels.Load(),
		ResidentBytes:  s.batchResidentBytes.Load(),
	}
}

func (s *PGModelStore) recordBatchLoad(residentBytes int64) {
	s.batchLoadsTotal.Add(1)
	s.batchResidentModels.Add(1)
	s.batchResidentBytes.Add(residentBytes)
}

func (s *PGModelStore) recordBatchRelease(residentBytes int64) {
	s.batchResidentModels.Add(-1)
	s.batchResidentBytes.Add(-residentBytes)
}

// BatchLoadEnabledWarning is the operator-facing memory-footprint warning
// (owner decision A6): emitted at startup whenever
// feature.spam_model_batch_load resolves ON and on every enabling
// config_changed flip. Batch loading trades per-message model loads for a
// resident working set, and operators must never gain the performance win
// silently.
const BatchLoadEnabledWarning = "spam model batch loading ENABLED (feature.spam_model_batch_load) — INCREASES MEMORY FOOTPRINT: models for the scoring batch are held resident (~24 MB per user model at the default 2^20 feature size, up to 50 models per active inbound connection); a model trained mid-batch is seen by scoring only after the batch boundary. Disable the toggle to restore per-message model loads"

// LogBatchLoadPosture emits the toggle's posture log: the BatchLoadEnabledWarning
// warning when batch loading is enabled, otherwise an informational note that
// the historical per-message load path is active. Called at startup and from
// the config_changed observer on flips of the toggle.
func LogBatchLoadPosture(logger *slog.Logger, enabled bool) {
	if logger == nil {
		logger = slog.Default()
	}
	if enabled {
		logger.Warn(BatchLoadEnabledWarning)
		return
	}
	logger.Info("spam model batch loading disabled (feature.spam_model_batch_load) — per-message model loads (historical behavior)")
}
