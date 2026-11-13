// Package guestlifecycle reconciles Guest Accounts G5 expiry and live Meet
// eviction. Database state is authoritative; LiveKit is a retryable peripheral.
package guestlifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/twitchtv/twirp"

	"setjoin.com/shared/pgxutil"
)

const (
	evictionInterval = 5 * time.Second
	expiryInterval   = time.Hour
	claimLease       = 30 * time.Second
	batchSize        = 100
	// maxEvictionAttempts bounds how often a persistently failing eviction is
	// rescheduled before the intent is dead-lettered (parked beyond every
	// claim window with completed_at left NULL). With the 5m backoff cap this
	// gives roughly four hours of retries before parking.
	maxEvictionAttempts = 60
)

// ParticipantRemover is the narrow DES-011 peripheral seam G5 needs.
type ParticipantRemover interface {
	RemoveParticipant(ctx context.Context, room, identity string) error
}

// Worker expires due guests through guest_set_status and drains durable exact
// LiveKit participant targets. It runs independently of feature toggles so a
// flip cannot strand authority committed before the flip.
type Worker struct {
	pool   pgxutil.WorkerPool
	rooms  ParticipantRemover
	logger *slog.Logger
	now    func() time.Time
}

// NewWorker creates the unconditional lifecycle worker. A nil rooms seam still
// runs expiry; SFU intents remain durable until a configured gateway drains them.
func NewWorker(pool pgxutil.WorkerPool, rooms ParticipantRemover, logger *slog.Logger) *Worker {
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{pool: pool, rooms: rooms, logger: logger, now: time.Now}
}

// Run starts expiry and eviction reconciliation and exits on ctx cancellation.
func (w *Worker) Run(ctx context.Context) {
	w.logger.Info("guest lifecycle worker started", "eviction_interval", evictionInterval, "expiry_interval", expiryInterval)
	w.expireDue(ctx)
	w.drain(ctx, nil)

	evictionTicker := time.NewTicker(evictionInterval)
	expiryTicker := time.NewTicker(expiryInterval)
	defer evictionTicker.Stop()
	defer expiryTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("guest lifecycle worker stopped")
			return
		case <-evictionTicker.C:
			w.drain(ctx, nil)
		case <-expiryTicker.C:
			w.expireDue(ctx)
			// Do not wait for the next eviction tick after the sweep committed:
			// expiry just enqueued exact SFU targets and should attempt them now.
			w.drain(ctx, nil)
		}
	}
}

// DrainUser performs the post-commit immediate eviction attempt for one guest.
// Failure is returned for logging only; the durable worker remains authoritative
// for convergence and the caller must never roll back the committed disable.
func (w *Worker) DrainUser(ctx context.Context, userID int64) error {
	if userID <= 0 {
		return errors.New("guest lifecycle: positive user id required")
	}
	if w.rooms == nil {
		return errors.New("guest lifecycle: LiveKit is not configured")
	}
	return w.drainBatch(ctx, &userID)
}

func (w *Worker) expireDue(ctx context.Context) {
	var count int
	if err := w.pool.QueryRow(ctx, `SELECT guest_expire_due(500)`).Scan(&count); err != nil {
		if ctx.Err() == nil {
			w.logger.Warn("guest lifecycle: expiry sweep failed", "error", err)
		}
		return
	}
	if count > 0 {
		w.logger.Info("guest lifecycle: expired due guests", "count", count)
	}
}

func (w *Worker) drain(ctx context.Context, userID *int64) {
	if w.rooms == nil {
		return
	}
	if err := w.drainBatch(ctx, userID); err != nil && ctx.Err() == nil {
		w.logger.Warn("guest lifecycle: eviction drain failed", "error", err)
	}
}

func (w *Worker) drainBatch(ctx context.Context, userID *int64) error {
	for i := 0; i < batchSize; i++ {
		intent, ok, err := w.claimOne(ctx, userID)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		w.processOne(ctx, intent)
	}
	return nil
}

type intent struct {
	id           int64
	room         string
	identity     string
	transitionAt time.Time
	retryUntil   time.Time
	attempts     int
}

func (w *Worker) claimOne(ctx context.Context, userID *int64) (intent, bool, error) {
	var out intent
	err := w.pool.QueryRow(ctx, `
		UPDATE guest_live_eviction_intents
		   SET attempt_count = attempt_count + 1,
		       last_attempt_at = now(),
		       next_attempt_at = now() + make_interval(secs => $2)
		 WHERE id = (
		       SELECT id FROM guest_live_eviction_intents
		        WHERE completed_at IS NULL
		          AND next_attempt_at <= now()
		          AND ($1::bigint IS NULL OR guest_user_id = $1)
		        ORDER BY next_attempt_at, id
		        FOR UPDATE SKIP LOCKED
		        LIMIT 1
		 )
		 RETURNING id, room_name::text, identity, transition_at, retry_until, attempt_count`,
		userID, int(claimLease/time.Second),
	).Scan(&out.id, &out.room, &out.identity, &out.transitionAt, &out.retryUntil, &out.attempts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return intent{}, false, nil
		}
		return intent{}, false, fmt.Errorf("claim guest live eviction: %w", err)
	}
	return out, true, nil
}

func (w *Worker) processOne(ctx context.Context, in intent) {
	err := w.rooms.RemoveParticipant(ctx, in.room, in.identity)
	now := w.now()
	absent := participantAbsent(err)

	if (err == nil || absent) && !now.Before(in.retryUntil) {
		if _, markErr := w.pool.Exec(ctx, `
			UPDATE guest_live_eviction_intents
			   SET completed_at=now(), next_attempt_at=now(), last_error=NULL
			 WHERE id=$1`, in.id); markErr != nil && ctx.Err() == nil {
			w.logger.Warn("guest lifecycle: mark eviction complete failed", "intent_id", in.id, "error", markErr)
		}
		return
	}

	delay := successRetryDelay(in.transitionAt, now)
	lastError := ""
	if err != nil && !absent {
		delay = failureRetryDelay(in.attempts)
		lastError = err.Error()

		// Dead-letter: a persistently failing intent must not retry forever.
		// Park it past every claim window while keeping completed_at NULL,
		// last_error and attempt_count as durable admin-visible evidence.
		if in.attempts >= maxEvictionAttempts {
			if _, markErr := w.pool.Exec(ctx, `
				UPDATE guest_live_eviction_intents
				   SET next_attempt_at='infinity',
				       last_error=NULLIF($2,'')
				 WHERE id=$1`, in.id, lastError); markErr != nil && ctx.Err() == nil {
				w.logger.Warn("guest lifecycle: dead-letter eviction failed",
					"intent_id", in.id, "error", markErr)
				// Fall through to the ordinary reschedule below so the row
				// stays due and the dead-lettering is retried next cycle.
			} else if markErr == nil {
				w.logger.Error("guest lifecycle: eviction intent exhausted, dead-lettered",
					"intent_id", in.id, "room", in.room, "identity", in.identity,
					"attempts", in.attempts, "last_error", lastError)
				return
			}
		}
	}
	if _, markErr := w.pool.Exec(ctx, `
		UPDATE guest_live_eviction_intents
		   SET next_attempt_at=now()+make_interval(secs => $2),
		       last_error=NULLIF($3,'')
		 WHERE id=$1`, in.id, int(delay/time.Second), lastError); markErr != nil && ctx.Err() == nil {
		w.logger.Warn("guest lifecycle: reschedule eviction failed", "intent_id", in.id, "error", markErr)
	}
	if err != nil && !absent && ctx.Err() == nil {
		w.logger.Warn("guest lifecycle: RemoveParticipant failed",
			"intent_id", in.id, "room", in.room, "identity", in.identity,
			"attempt", in.attempts, "retry_in", delay, "error", err)
	}
}

func participantAbsent(err error) bool {
	if err == nil {
		return false
	}
	var twerr twirp.Error
	return errors.As(err, &twerr) && twerr.Code() == twirp.NotFound
}

func successRetryDelay(transitionAt, now time.Time) time.Duration {
	if now.Sub(transitionAt) < 5*time.Minute {
		return 10 * time.Second
	}
	return time.Minute
}

func failureRetryDelay(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	shift := attempts - 1
	if shift > 9 {
		shift = 9
	}
	d := time.Second * time.Duration(1<<shift)
	if d > 5*time.Minute {
		return 5 * time.Minute
	}
	return d
}
