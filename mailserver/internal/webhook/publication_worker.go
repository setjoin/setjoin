package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"setjoin.com/shared/pgxutil"
)

const (
	publicationPollInterval = 5 * time.Second
	publicationClaimLimit   = 100
	publicationPruneEvery   = 12 * time.Hour
)

type publicationClaim struct {
	ID           int64  `json:"id"`
	EventID      string `json:"event_id"`
	AttemptCount int    `json:"attempt_count"`
}

// PublicationWorker drains committed publication residue unconditionally. The
// feature flag is checked only by the enrollment reducer, never in this loop.
type PublicationWorker struct {
	pool       pgxutil.WorkerPool
	dispatcher *Dispatcher
	logger     *slog.Logger
	workerID   uuid.UUID
	lastPrune  time.Time
}

func NewPublicationWorker(pool pgxutil.WorkerPool, dispatcher *Dispatcher, logger *slog.Logger) *PublicationWorker {
	if logger == nil {
		logger = slog.Default()
	}
	return &PublicationWorker{pool: pool, dispatcher: dispatcher, logger: logger, workerID: uuid.New()}
}

func (w *PublicationWorker) Run(ctx context.Context) {
	w.drain(ctx)
	ticker := time.NewTicker(publicationPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.drain(ctx)
		}
	}
}

func (w *PublicationWorker) drain(ctx context.Context) {
	var raw []byte
	if err := w.pool.QueryRow(ctx, `SELECT webhook_publication_claim($1,$2)`,
		w.workerID, publicationClaimLimit).Scan(&raw); err != nil {
		if ctx.Err() == nil {
			w.logger.Warn("webhook publication claim failed", "error", err)
		}
		return
	}
	var claims []publicationClaim
	if err := json.Unmarshal(raw, &claims); err != nil {
		w.logger.Warn("webhook publication claim decode failed", "error", err)
		return
	}
	for _, claim := range claims {
		if claim.ID <= 0 || claim.EventID == "" || claim.AttemptCount < 1 || claim.AttemptCount > 12 {
			w.logger.Warn("webhook publication returned invalid claim")
			continue
		}
		var fanout int
		err := w.pool.QueryRow(ctx, `SELECT webhook_publication_fanout($1,$2)`,
			claim.ID, w.workerID).Scan(&fanout)
		if err == nil {
			var completed bool
			err = w.pool.QueryRow(ctx, `SELECT webhook_publication_complete($1,$2,true,NULL)`,
				claim.ID, w.workerID).Scan(&completed)
			if err == nil && !completed {
				err = fmt.Errorf("publication lease lost before completion")
			}
		}
		if err != nil {
			bounded := err.Error()
			if len(bounded) > 2048 {
				bounded = bounded[:2048]
			}
			_, finishErr := w.pool.Exec(ctx,
				`SELECT webhook_publication_complete($1,$2,false,$3)`, claim.ID, w.workerID, bounded)
			if finishErr != nil && ctx.Err() == nil {
				w.logger.Warn("webhook publication failure recording failed", "publication_id", claim.ID, "error", finishErr)
			}
			continue
		}
		w.dispatcher.DeliverPendingEvent(ctx, claim.EventID)
	}

	if w.lastPrune.IsZero() || time.Since(w.lastPrune) >= publicationPruneEvery {
		if _, err := w.pool.Exec(ctx, `SELECT webhook_publication_prune(30,500)`); err != nil && ctx.Err() == nil {
			w.logger.Warn("webhook publication prune failed", "error", err)
		} else if err == nil {
			w.lastPrune = time.Now()
		}
	}
}
