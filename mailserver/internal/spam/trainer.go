package spam

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// trainEvent is a single training signal from PostgreSQL NOTIFY.
//
// MessageID and UserID are int64: spam_train_notify() emits both via
// json_build_object on BIGINT columns, i.e. unquoted JSON numbers. A `string`
// MessageID made encoding/json reject EVERY payload, silently killing the whole
// ML auto-training pipeline.
type trainEvent struct {
	UserID    int64 `json:"user_id"`
	MessageID int64 `json:"message_id"`
	IsSpam    bool  `json:"is_spam"` // true = moved to Junk, false = moved from Junk to Inbox
}

// batchCollector buffers training events, deduplicates, and limits batch size.
type batchCollector struct {
	mu        sync.Mutex
	pending   map[int64]trainEvent // keyed by messageID
	maxBatch  int
	window    time.Duration
	lastFlush time.Time
}

func newBatchCollector(window time.Duration) *batchCollector {
	return &batchCollector{
		pending:  make(map[int64]trainEvent),
		maxBatch: 100,
		window:   window,
	}
}

// add stores the whole event (incl. UserID) keyed by messageID. Threading the
// full struct is load-bearing: flushAndTrain groups by ev.UserID, so dropping
// UserID here attributed every event to user 0 (a nonexistent user).
func (b *batchCollector) add(ev trainEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	existing, ok := b.pending[ev.MessageID]
	if ok {
		// If the label flipped (Junk → Inbox or Inbox → Junk), remove entirely.
		if existing.IsSpam != ev.IsSpam {
			delete(b.pending, ev.MessageID)
			return
		}
		// Same label repeated — update timestamp but don't duplicate.
	}
	b.pending[ev.MessageID] = ev
}

func (b *batchCollector) flush() []trainEvent {
	b.mu.Lock()
	defer b.mu.Unlock()

	n := len(b.pending)
	if n > b.maxBatch {
		n = b.maxBatch
	}
	events := make([]trainEvent, 0, n)
	// ponytail: leftover events stay keyed in the map for the next flush; no separate overflow queue needed.
	for id, ev := range b.pending {
		if len(events) >= b.maxBatch {
			break
		}
		events = append(events, ev)
		delete(b.pending, id) // safe: deleting the current key mid-range is defined behavior in Go
	}
	b.lastFlush = time.Now()
	return events
}

// Trainer listens for spam training events and periodically trains user models.
type Trainer struct {
	logger    *slog.Logger
	store     ModelStore
	collector *batchCollector
	events    chan trainEvent
	stop      chan struct{}
}

// ModelStore abstracts model persistence (implemented by the DB layer).
// LoadModelForTraining/SaveModel carry the optimistic-concurrency snapshot
// (expect) that fences persistence against interleaved reset/disable/competing
// saves — see PGModelStore.SaveModel.
type ModelStore interface {
	LoadModelForTraining(ctx context.Context, userID int64) (*Model, []byte, error)
	SaveModel(ctx context.Context, userID int64, data []byte, expect []byte) error
	FetchMessage(ctx context.Context, userID int64, messageID int64) ([]byte, error)
}

// NewTrainer creates a trainer with the given batch window.
func NewTrainer(store ModelStore, logger *slog.Logger) *Trainer {
	return &Trainer{
		logger:    logger,
		store:     store,
		collector: newBatchCollector(30 * time.Second),
		events:    make(chan trainEvent, 1000),
		stop:      make(chan struct{}),
	}
}

// Enqueue adds a training event from a NOTIFY payload.
// Safe to call from the NOTIFY dispatcher goroutine.
func (t *Trainer) Enqueue(userID int64, messageID int64, isSpam bool) {
	select {
	case t.events <- trainEvent{UserID: userID, MessageID: messageID, IsSpam: isSpam}:
	default:
		t.logger.Warn("spam trainer event queue full, dropping event",
			"user_id", userID, "message_id", messageID)
	}
}

// Start begins the background training loop.
func (t *Trainer) Start(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	t.logger.Info("spam trainer started", "batch_window", "30s", "max_batch", 100)

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.stop:
			return
		case ev := <-t.events:
			t.collector.add(ev)
		case <-ticker.C:
			t.flushAndTrain(ctx)
		}
	}
}

// flushAndTrain groups events by user, loads models, trains, and saves.
// This is the core training loop — called every 30s by the ticker.
//
// Semantics of user_spam_model state this loop implements are the ADOPTED
// ROOT POLICY of the approved med-shard3-016 remediation
// (retired-docs:zcode-security-deep/handoff/sj-glm-sec-20260909-003-triage/
// medium-packages-corrected.jsonl, row med-shard3-016), not an open question:
//
//   - Scoring opt-out (disabled = TRUE): the disabled flag is honored in BOTH
//     scoring and trainer gating. LoadModelForTraining returns
//     ErrModelDisabled and this loop refuses the user: no FetchMessage, no
//     Train, no SaveModel — a disabled model is neither scored nor rebuilt.
//     Even without the load-time refusal, SaveModel's fence would refuse any
//     write reaching a disabled row. Events already flushed for that window
//     are dropped, not requeued.
//   - Model reset (admin ResetModel / prune_spam DELETE the row): a
//     destructive wipe the trainer never silently undoes. The trainer has no
//     persisted sample store, so wiped weights cannot come back: the
//     optimistic persistence fence (SaveModel's snapshot CAS) refuses a save
//     whose loaded row vanished or changed mid-batch, so pre-reset weights
//     are never reinserted. A rowless user's next events train a FRESH model
//     (sample_count restarts at the INSERT arm) whose knowledge is limited to
//     post-wipe events, and every successful save is logged ("spam trainer:
//     model updated") — no rebuild is silent.
//   - Training consent (a user stopping their own mail from training the
//     model): an UNRESOLVED PRODUCT DECISION, deliberately separate from the
//     two policies above and NOT implemented here. Today any user with
//     feature.ml_spam enabled has Spam-tag moves train their own per-user
//     model; DisableModel is an admin-controlled scoring opt-out, not user
//     consent. Surfaced for an explicit product call before any consent
//     mechanism is claimed.
func (t *Trainer) flushAndTrain(ctx context.Context) {
	events := t.collector.flush()
	if len(events) == 0 {
		return
	}

	t.logger.Info("spam trainer: batch training", "events", len(events))

	// Group by user.
	byUser := make(map[int64][]trainEvent)
	for _, ev := range events {
		byUser[ev.UserID] = append(byUser[ev.UserID], ev)
	}

	for userID, userEvents := range byUser {
		model, expect, err := t.store.LoadModelForTraining(ctx, userID)
		if errors.Is(err, ErrModelDisabled) {
			// Adopted policy — disablement gates training: skip without
			// touching the disabled row (no rebuild, no counter bumps).
			t.logger.Info("spam trainer: model disabled, skipping user",
				"user_id", userID, "events_skipped", len(userEvents))
			continue
		}
		if err != nil {
			// Load fault or corrupt/unsealed blob, surfaced by the store:
			// refuse to train. Training a batch onto an unverified fresh model
			// and upserting it would destructively overwrite the persisted
			// weights with near-empty ones.
			t.logger.Error("spam trainer: load model failed", "user_id", userID, "error", err)
			continue
		}

		trained := 0
		for _, ev := range userEvents {
			raw, err := t.store.FetchMessage(ctx, userID, ev.MessageID)
			if err != nil {
				t.logger.Warn("spam trainer: fetch message failed, skipping",
					"user_id", userID, "message_id", ev.MessageID, "error", err)
				continue
			}
			model.Train(raw, ev.IsSpam)
			trained++
		}

		if trained == 0 {
			continue
		}

		data, err := model.Save()
		if err != nil {
			t.logger.Error("spam trainer: save model failed", "user_id", userID, "error", err)
			continue
		}
		if err := t.store.SaveModel(ctx, userID, data, expect); err != nil {
			if errors.Is(err, ErrSaveFenced) {
				// Interleaved reset/disable/competing save: the batch is
				// dropped — persisting would resurrect wiped weights or
				// overwrite a newly disabled model. The next window reloads.
				t.logger.Warn("spam trainer: model state changed during training, batch dropped (fenced)",
					"user_id", userID, "trained", trained)
				continue
			}
			t.logger.Error("spam trainer: persist model failed", "user_id", userID, "error", err)
			continue
		}

		t.logger.Info("spam trainer: model updated", "user_id", userID, "trained", trained)
	}
}

// Stop gracefully shuts down the trainer.
func (t *Trainer) Stop() {
	close(t.stop)
}

// ParseNotifyPayload extracts a trainEvent from a pg_notify payload.
func ParseNotifyPayload(payload string) (trainEvent, error) {
	var ev trainEvent
	if err := json.Unmarshal([]byte(payload), &ev); err != nil {
		return trainEvent{}, err
	}
	return ev, nil
}
