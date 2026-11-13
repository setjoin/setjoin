// Package mailboxlifecycle drains durable post-commit mailbox effects.
// Reducers remain authoritative for claims and database-local mutations; this
// worker only performs bounded peripheral I/O and acknowledges its lease.
package mailboxlifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/mediaevict"
	"setjoin.com/shared/pgxutil"
	wh "setjoin.com/shared/webhook"
)

const (
	drainInterval = 5 * time.Second
	drainBatch    = 100
)

type DurableWebhook interface {
	EnqueueDurable(ctx context.Context, event wh.CloudEvent) error
}

// settlementRecorder is a test-only sink: when a Worker carries one, effect
// settlement calls (per-target ack, complete, fail) are recorded instead of
// issued, so tests can prove fail-path selection and the absence of
// acknowledgements without a database. Production constructors leave it nil
// and every settlement reaches the pool exactly as before.
type settlementRecorder struct {
	fail           []settlementCall
	complete       []string
	targetComplete []string
}

type settlementCall struct {
	effectID string
	detail   string
}

type Worker struct {
	pool        pgxutil.WorkerPool
	rooms       mediaevict.ParticipantRemover
	webhooks    DurableWebhook
	logger      *slog.Logger
	id          string
	settlements *settlementRecorder
	// clock is a test-only seam: nil in production, where the eviction runs
	// on the system clock. Tests thread a fake clock so they can observe an
	// established in-loop wait before cancelling.
	clock mediaevict.Clock
}

func NewWorker(pool pgxutil.WorkerPool, rooms mediaevict.ParticipantRemover, webhooks DurableWebhook, logger *slog.Logger) *Worker {
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{pool: pool, rooms: rooms, webhooks: webhooks, logger: logger,
		id: "mailbox-lifecycle-" + uuid.NewString()}
}

func (w *Worker) Run(ctx context.Context) {
	w.drain(ctx)
	w.drainPurges(ctx)
	ticker := time.NewTicker(drainInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.drain(ctx)
			w.drainPurges(ctx)
		}
	}
}

type purge struct {
	RequestID   string `json:"purgeRequestId"`
	MailboxID   string `json:"mailboxId"`
	ActorIDText string `json:"actorUserId"`
	OperationID string `json:"operationId"`
	RequestHash string `json:"requestDigest"`
	Attempt     int    `json:"attempt"`
	Blocked     bool   `json:"blocked"`
	ActorID     int64  `json:"-"`
}

func (w *Worker) drainPurges(ctx context.Context) {
	for i := 0; i < drainBatch; i++ {
		p, ok, err := w.claimPurge(ctx)
		if err != nil {
			if ctx.Err() == nil {
				w.logger.Warn("mailbox purge claim failed", "error", err)
			}
			return
		}
		if !ok {
			return
		}
		if p.Blocked {
			w.logger.Warn("mailbox purge blocked by retention authority", "purge_request_id", p.RequestID,
				"mailbox_id", p.MailboxID)
			continue
		}
		var receipt []byte
		err = w.pool.QueryRow(ctx, `SELECT mailbox_purge_execute($1,$2::uuid,$3::uuid,$4)`,
			p.ActorID, p.RequestID, p.OperationID, p.RequestHash).Scan(&receipt)
		if err == nil {
			continue
		}
		if _, failErr := w.pool.Exec(ctx, `SELECT mailbox_purge_fail($1,$2::uuid,$3)`,
			w.id, p.RequestID, err.Error()); failErr != nil && ctx.Err() == nil {
			w.logger.Warn("mailbox purge failure recording failed", "purge_request_id", p.RequestID,
				"error", failErr)
		}
		if ctx.Err() == nil {
			w.logger.Warn("mailbox purge execution failed", "purge_request_id", p.RequestID,
				"attempt", p.Attempt, "error", err)
		}
	}
}

func (w *Worker) claimPurge(ctx context.Context) (purge, bool, error) {
	var raw []byte
	err := w.pool.QueryRow(ctx, `SELECT mailbox_purge_claim($1,$2)`, w.id, 600).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && len(raw) == 0) {
		return purge{}, false, nil
	}
	if err != nil {
		return purge{}, false, err
	}
	var p purge
	if err := json.Unmarshal(raw, &p); err != nil {
		return purge{}, false, fmt.Errorf("decode mailbox purge claim: %w", err)
	}
	if p.Blocked {
		if _, err := uuid.Parse(p.RequestID); err != nil {
			return purge{}, false, errors.New("blocked mailbox purge claim is invalid")
		}
		return p, true, nil
	}
	actorID, err := parsePositiveID(p.ActorIDText)
	if err != nil || p.Attempt < 1 || p.Attempt > 20 || len(p.RequestHash) != 64 {
		return purge{}, false, errors.New("claimed mailbox purge is invalid")
	}
	if _, err := uuid.Parse(p.RequestID); err != nil {
		return purge{}, false, errors.New("claimed mailbox purge request id is invalid")
	}
	if _, err := uuid.Parse(p.OperationID); err != nil {
		return purge{}, false, errors.New("claimed mailbox purge operation id is invalid")
	}
	p.ActorID = actorID
	return p, true, nil
}

type target struct {
	Room       string     `json:"room"`
	Identity   string     `json:"identity"`
	EvictUntil *time.Time `json:"evictUntil"`
}

type event struct {
	ID   string          `json:"id"`
	Type string          `json:"type"`
	Time time.Time       `json:"time"`
	Data json.RawMessage `json:"data"`
}

type effect struct {
	ID          int64    `json:"-"`
	IDText      string   `json:"effectId"`
	OperationID string   `json:"operationId"`
	Kind        string   `json:"kind"`
	Attempt     int      `json:"attempt"`
	Targets     []target `json:"targets"`
	Event       *event   `json:"event"`
}

func (w *Worker) drain(ctx context.Context) {
	for i := 0; i < drainBatch; i++ {
		e, ok, err := w.claim(ctx)
		if err != nil {
			if ctx.Err() == nil {
				w.logger.Warn("mailbox lifecycle effect claim failed", "error", err)
			}
			return
		}
		if !ok {
			return
		}
		w.settle(ctx, e)
	}
}

// settle routes one claimed effect exactly as drain always has: a
// processing failure is failed, success is completed.
func (w *Worker) settle(ctx context.Context, e effect) {
	if err := w.process(ctx, e); err != nil {
		w.fail(ctx, e, err)
		return
	}
	if err := w.complete(ctx, e); err != nil && ctx.Err() == nil {
		w.logger.Warn("mailbox lifecycle effect completion failed", "effect_id", e.ID, "error", err)
	}
}

func (w *Worker) claim(ctx context.Context) (effect, bool, error) {
	var raw []byte
	err := w.pool.QueryRow(ctx, `SELECT mailbox_lifecycle_effect_claim($1,$2)`, w.id, 600).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && len(raw) == 0) {
		return effect{}, false, nil
	}
	if err != nil {
		return effect{}, false, err
	}
	var e effect
	if err := json.Unmarshal(raw, &e); err != nil {
		return effect{}, false, fmt.Errorf("decode mailbox lifecycle effect: %w", err)
	}
	parsed, err := parsePositiveID(e.IDText)
	if err != nil || e.OperationID == "" || e.Kind == "" || e.Attempt < 1 || e.Attempt > 20 {
		return effect{}, false, errors.New("claimed mailbox lifecycle effect is invalid")
	}
	e.ID = parsed
	return e, true, nil
}

func parsePositiveID(value string) (int64, error) {
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid positive id")
	}
	return id, nil
}

func (w *Worker) process(ctx context.Context, e effect) error {
	switch e.Kind {
	case "revoke_sessions", "revoke_delegates", "notify_clients":
		_, err := w.pool.Exec(ctx, `SELECT mailbox_lifecycle_effect_apply($1,$2)`, w.id, e.ID)
		return err
	case "evict_media":
		if len(e.Targets) > 0 && w.rooms == nil {
			return errors.New("LiveKit is not configured")
		}
		for _, target := range e.Targets {
			if err := mediaevict.EvictParticipantThroughClock(ctx, w.rooms, target.Room, target.Identity, target.EvictUntil, w.clock); err != nil {
				return err
			}
			if err := w.ackTarget(ctx, e, target); err != nil {
				return err
			}
		}
		return nil
	case "lifecycle_webhook":
		if e.Event == nil || e.Event.ID == "" || e.Event.Type == "" {
			return errors.New("mailbox lifecycle webhook payload is missing")
		}
		if w.webhooks == nil {
			return errors.New("webhook dispatcher is not configured")
		}
		return w.webhooks.EnqueueDurable(ctx, wh.CloudEvent{
			SpecVersion: "1.0", ID: e.Event.ID, Source: "mailserver/lifecycle",
			Type: e.Event.Type, Time: e.Event.Time.UTC().Format(time.RFC3339Nano),
			DataContentType: "application/json", Data: e.Event.Data,
		})
	default:
		return fmt.Errorf("unknown mailbox lifecycle effect kind %q", e.Kind)
	}
}

// ackTarget records one evicted target with its per-target acknowledgement.
func (w *Worker) ackTarget(ctx context.Context, e effect, t target) error {
	if w.settlements != nil {
		w.settlements.targetComplete = append(w.settlements.targetComplete, t.Room+"/"+t.Identity)
		return nil
	}
	_, err := w.pool.Exec(ctx, `SELECT mailbox_lifecycle_effect_target_complete($1,$2,$3,$4)`,
		w.id, e.ID, t.Room, t.Identity)
	return err
}

func (w *Worker) complete(ctx context.Context, e effect) error {
	if e.Kind != "evict_media" && e.Kind != "lifecycle_webhook" {
		return nil
	}
	if w.settlements != nil {
		w.settlements.complete = append(w.settlements.complete, e.IDText)
		return nil
	}
	_, err := w.pool.Exec(ctx, `SELECT mailbox_lifecycle_effect_complete($1,$2)`, w.id, e.ID)
	return err
}

func (w *Worker) fail(ctx context.Context, e effect, effectErr error) {
	if w.settlements != nil {
		w.settlements.fail = append(w.settlements.fail,
			settlementCall{effectID: e.IDText, detail: effectErr.Error()})
		return
	}
	if _, err := w.pool.Exec(ctx, `SELECT mailbox_lifecycle_effect_fail($1,$2,$3)`,
		w.id, e.ID, effectErr.Error()); err != nil && ctx.Err() == nil {
		w.logger.Warn("mailbox lifecycle effect failure recording failed", "effect_id", e.ID, "error", err)
	}
	if ctx.Err() == nil {
		w.logger.Warn("mailbox lifecycle effect failed", "effect_id", e.ID, "kind", e.Kind,
			"attempt", e.Attempt, "error", effectErr)
	}
}
