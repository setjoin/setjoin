// Package identitytransition drains durable post-commit identity effects.
// Database identity state is authoritative; LiveKit and notices converge by
// bounded retry even when the feature toggle is later disabled.
package identitytransition

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/mediaevict"
	"setjoin.com/shared/pgxutil"
)

const (
	interval  = 5 * time.Second
	batchSize = 100
	// maxSessionEvictionAttempts is the bounded-retry cap for persistently
	// failing session evictions, matching the package contract. With the 60s
	// backoff cap this gives roughly fifty minutes of active retries before
	// the intent is dead-lettered (parked with completed_at left NULL while
	// last_error and attempt_count stay as durable evidence).
	maxSessionEvictionAttempts = 60
)

// settlementRecorder is a test-only sink: when a Worker carries one, effect
// settlement calls (per-target ack, complete, fail) are recorded instead of
// issued and mediaTargets serves cannedTargets, so tests can prove fail-path
// selection and the absence of acknowledgements without a database.
// Production constructors leave it nil and every settlement reaches the pool
// exactly as before.
type settlementRecorder struct {
	fail           []settlementCall
	complete       []string
	targetComplete []string
	cannedTargets  []mediaTarget
}

type settlementCall struct {
	effectID string
	detail   string
}

type Worker struct {
	pool        pgxutil.WorkerPool
	rooms       mediaevict.ParticipantRemover
	logger      *slog.Logger
	workerID    string
	settlements *settlementRecorder
	// clock is a test-only seam: nil in production, where the eviction runs
	// on the system clock. Tests thread a fake clock so they can observe an
	// established in-loop wait before cancelling.
	clock mediaevict.Clock
}

func NewWorker(pool pgxutil.WorkerPool, rooms mediaevict.ParticipantRemover, logger *slog.Logger) *Worker {
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{
		pool:     pool,
		rooms:    rooms,
		logger:   logger,
		workerID: "identity-transition-" + uuid.NewString(),
	}
}

func (w *Worker) Run(ctx context.Context) {
	w.drain(ctx)
	w.drainSessionEvictions(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.drain(ctx)
			w.drainSessionEvictions(ctx)
		}
	}
}

type effect struct {
	transitionID string
	effectID     string
	kind         string
	attempts     int
}

func (w *Worker) drain(ctx context.Context) {
	drainClaimed(ctx, w.logger, batchSize, "identity transition effect claim failed", w.claim, w.settle)
}

// drainClaimed claims up to limit items and settles each one, stopping on
// the first claim error, an empty claim, or cancellation; a claim failure
// while the context is already cancelled stays silent.
func drainClaimed[T any](
	ctx context.Context,
	logger *slog.Logger,
	limit int,
	claimFailure string,
	claim func(context.Context) (T, bool, error),
	settle func(context.Context, T),
) {
	for i := 0; i < limit; i++ {
		item, ok, err := claim(ctx)
		if err != nil {
			if ctx.Err() == nil {
				logger.Warn(claimFailure, "error", err)
			}
			return
		}
		if !ok {
			return
		}
		settle(ctx, item)
	}
}

// settle routes one claimed effect exactly as drain always has: a
// processing failure is failed, success is completed.
func (w *Worker) settle(ctx context.Context, e effect) {
	if err := w.process(ctx, e); err != nil {
		w.fail(ctx, e, err)
		return
	}
	w.complete(ctx, e)
}

func (w *Worker) claim(ctx context.Context) (effect, bool, error) {
	var raw []byte
	err := w.pool.QueryRow(ctx,
		`SELECT identity_transition_effect_claim($1,$2)`,
		w.workerID, 120,
	).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && len(raw) == 0) {
		return effect{}, false, nil
	}
	if err != nil {
		return effect{}, false, err
	}
	var claimed struct {
		TransitionID string `json:"transitionId"`
		EffectID     string `json:"effectId"`
		Kind         string `json:"kind"`
		AttemptCount int    `json:"attemptCount"`
	}
	if err := json.Unmarshal(raw, &claimed); err != nil {
		return effect{}, false, fmt.Errorf("decode claimed identity transition effect: %w", err)
	}
	if _, err := uuid.Parse(claimed.TransitionID); err != nil {
		return effect{}, false, fmt.Errorf("claimed identity transition has invalid transition id")
	}
	if _, err := uuid.Parse(claimed.EffectID); err != nil {
		return effect{}, false, fmt.Errorf("claimed identity transition has invalid effect id")
	}
	if claimed.Kind == "" || claimed.AttemptCount < 1 || claimed.AttemptCount > 20 {
		return effect{}, false, fmt.Errorf("claimed identity transition effect is invalid")
	}
	return effect{
		transitionID: claimed.TransitionID,
		effectID:     claimed.EffectID,
		kind:         claimed.Kind,
		attempts:     claimed.AttemptCount,
	}, true, nil
}

func (w *Worker) process(ctx context.Context, e effect) error {
	baseKind, rollback := transitionEffectKind(e.kind)
	switch baseKind {
	case "auth_sessions":
		return nil
	case "subscriber_notice":
		state := "committed"
		if rollback {
			state = "rollback_committed"
		}
		_, err := w.pool.Exec(ctx, `SELECT app_notify(
			'identity_transition',
			jsonb_build_object(
				'transitionId',$1::text,'state',$2::text
			)::text
		)`, e.transitionID, state)
		return err
	case "livekit_sessions":
		targets, err := w.mediaTargets(ctx, e)
		if err != nil {
			return err
		}
		if len(targets) == 0 {
			return nil
		}
		if w.rooms == nil {
			return errors.New("LiveKit is not configured")
		}
		return w.evictTargets(ctx, e, targets)
	default:
		return fmt.Errorf("unknown effect kind %q", e.kind)
	}
}

// mediaTarget is one pending LiveKit eviction of a claimed effect.
type mediaTarget struct {
	key        string
	evictUntil *time.Time
}

// mediaTargets loads the unfinished targets of a livekit effect.
func (w *Worker) mediaTargets(ctx context.Context, e effect) ([]mediaTarget, error) {
	if w.settlements != nil && w.settlements.cannedTargets != nil {
		return w.settlements.cannedTargets, nil
	}
	rows, err := w.pool.Query(ctx, `
		SELECT target_key,evict_until FROM identity_transition_effect_targets
		 WHERE transition_id=$1::uuid AND effect_kind=$2
		   AND completed_at IS NULL ORDER BY target_key
	`, e.transitionID, e.kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	targets := make([]mediaTarget, 0)
	for rows.Next() {
		var target mediaTarget
		if err := rows.Scan(&target.key, &target.evictUntil); err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return targets, nil
}

// evictTargets kicks each pending target through its horizon and
// acknowledges it; the first failure aborts the remaining targets.
func (w *Worker) evictTargets(ctx context.Context, e effect, targets []mediaTarget) error {
	for _, target := range targets {
		room, identity, ok := strings.Cut(target.key, "|")
		if !ok {
			return fmt.Errorf("invalid LiveKit target")
		}
		if err := mediaevict.EvictParticipantThroughClock(
			ctx, w.rooms, room, identity, target.evictUntil, w.clock,
		); err != nil {
			return err
		}
		if err := w.ackTarget(ctx, e, target.key); err != nil {
			return err
		}
	}
	return nil
}

// ackTarget marks one evicted target complete.
func (w *Worker) ackTarget(ctx context.Context, e effect, targetKey string) error {
	if w.settlements != nil {
		w.settlements.targetComplete = append(w.settlements.targetComplete, targetKey)
		return nil
	}
	_, err := w.pool.Exec(ctx, `
		UPDATE identity_transition_effect_targets
		   SET completed_at=statement_timestamp(),last_error=NULL
		 WHERE transition_id=$1::uuid AND effect_kind=$2
		   AND target_key=$3
	`, e.transitionID, e.kind, targetKey)
	return err
}

type sessionEviction struct {
	id         int64
	room       string
	identity   string
	retryUntil time.Time
	attempts   int
}

func (w *Worker) drainSessionEvictions(ctx context.Context) {
	drainClaimed(ctx, w.logger, batchSize, "identity session eviction claim failed", w.claimSessionEviction, w.processSessionEviction)
}

func (w *Worker) claimSessionEviction(
	ctx context.Context,
) (sessionEviction, bool, error) {
	var intent sessionEviction
	err := w.pool.QueryRow(ctx, `
		UPDATE identity_session_eviction_intents
		   SET attempt_count=attempt_count+1,
		       last_attempt_at=statement_timestamp(),
		       next_attempt_at=statement_timestamp()+interval '2 minutes'
		 WHERE id=(
		       SELECT id FROM identity_session_eviction_intents
		        WHERE completed_at IS NULL
		          AND next_attempt_at<=statement_timestamp()
		        ORDER BY next_attempt_at,id
		        FOR UPDATE SKIP LOCKED
		        LIMIT 1
		 )
		 RETURNING id,room_name,identity,retry_until,attempt_count
	`).Scan(
		&intent.id, &intent.room, &intent.identity,
		&intent.retryUntil, &intent.attempts,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return sessionEviction{}, false, nil
	}
	if err != nil {
		return sessionEviction{}, false, err
	}
	return intent, true, nil
}

func (w *Worker) processSessionEviction(ctx context.Context, in sessionEviction) {
	var removeErr error
	if w.rooms == nil {
		removeErr = errors.New("LiveKit is not configured")
	} else {
		removeErr = w.rooms.RemoveParticipant(ctx, in.room, in.identity)
	}
	now := time.Now()
	succeeded := removeErr == nil || mediaevict.ParticipantNotFound(removeErr)
	if succeeded && !now.Before(in.retryUntil) {
		if _, err := w.pool.Exec(ctx, `
			UPDATE identity_session_eviction_intents
			   SET completed_at=statement_timestamp(),
			       next_attempt_at=statement_timestamp(),last_error=NULL
			 WHERE id=$1`, in.id); err != nil && ctx.Err() == nil {
			w.logger.Warn("identity session eviction completion failed",
				"intent_id", in.id, "error", err)
		}
		return
	}

	delay := 5 * time.Second
	lastError := ""
	if !succeeded {
		delay = min(time.Duration(max(in.attempts, 1))*5*time.Second, time.Minute)
		lastError = removeErr.Error()

		// Bounded-retry cap: a persistently failing eviction must not retry
		// forever. Dead-letter it past every claim window, keeping
		// completed_at NULL with last_error and attempt_count as durable
		// admin-visible evidence, and surface the exhaustion loudly.
		if in.attempts >= maxSessionEvictionAttempts {
			if _, err := w.pool.Exec(ctx, `
				UPDATE identity_session_eviction_intents
				   SET next_attempt_at='infinity',
				       last_error=NULLIF($2,'')
				 WHERE id=$1`, in.id, lastError,
			); err != nil && ctx.Err() == nil {
				w.logger.Warn("identity session eviction dead-letter failed",
					"intent_id", in.id, "error", err)
				// Fall through to the ordinary reschedule below so the row
				// stays due and dead-lettering is retried next cycle.
			} else if err == nil {
				w.logger.Error("identity session eviction intent exhausted, dead-lettered",
					"intent_id", in.id, "room", in.room, "identity", in.identity,
					"attempts", in.attempts, "last_error", lastError)
				return
			}
		}
	}
	if _, err := w.pool.Exec(ctx, `
		UPDATE identity_session_eviction_intents
		   SET next_attempt_at=statement_timestamp()+make_interval(secs=>$2),
		       last_error=NULLIF($3,'')
		 WHERE id=$1`, in.id, int(delay/time.Second), lastError,
	); err != nil && ctx.Err() == nil {
		w.logger.Warn("identity session eviction reschedule failed",
			"intent_id", in.id, "error", err)
	}
	if !succeeded && ctx.Err() == nil {
		w.logger.Warn("identity session eviction failed",
			"intent_id", in.id, "room", in.room, "identity", in.identity,
			"attempt", in.attempts, "retry_in", delay, "error", removeErr)
	}
}

func transitionEffectKind(kind string) (base string, rollback bool) {
	const prefix = "rollback_"
	if strings.HasPrefix(kind, prefix) {
		return strings.TrimPrefix(kind, prefix), true
	}
	return kind, false
}

func (w *Worker) complete(ctx context.Context, e effect) {
	if w.settlements != nil {
		w.settlements.complete = append(w.settlements.complete, e.effectID)
		return
	}
	if _, err := w.pool.Exec(ctx,
		`SELECT identity_transition_effect_complete($1,$2::uuid,$3::uuid,NULL)`,
		w.workerID, e.transitionID, e.effectID,
	); err != nil && ctx.Err() == nil {
		w.logger.Warn("identity transition effect completion failed", "error", err)
	}
}

func (w *Worker) fail(ctx context.Context, e effect, effectErr error) {
	if w.settlements != nil {
		w.settlements.fail = append(w.settlements.fail,
			settlementCall{effectID: e.effectID, detail: "effect_failed"})
		return
	}
	if _, err := w.pool.Exec(ctx,
		`SELECT identity_transition_effect_fail($1,$2::uuid,$3::uuid,$4,NULL)`,
		w.workerID, e.transitionID, e.effectID, "effect_failed",
	); err != nil && ctx.Err() == nil {
		w.logger.Warn("identity transition effect failure recording failed", "error", err)
	}
	if ctx.Err() == nil {
		w.logger.Warn("identity transition effect failed",
			"transition_id", e.transitionID, "kind", e.kind,
			"attempt", e.attempts, "error", effectErr)
	}
}
