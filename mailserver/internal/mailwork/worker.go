// Package mailwork drains the reducer-owned shared-mail work outbox. The Go
// worker owns only bounded scheduling and retry; recipient authorization,
// preference/DND/rate policy, receipts, metrics and notifications remain in
// PostgreSQL transactions.
package mailwork

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"setjoin.com/shared/pgxutil"
	wh "setjoin.com/shared/webhook"
)

const (
	pollInterval = 5 * time.Second
	claimLimit   = 100
)

type Worker struct {
	pool     pgxutil.WorkerPool
	logger   *slog.Logger
	webhooks webhookEnqueuer
}

type webhookEnqueuer interface {
	EnqueueDurable(context.Context, wh.CloudEvent) error
}

func NewWorker(pool pgxutil.WorkerPool, logger *slog.Logger, webhooks ...webhookEnqueuer) *Worker {
	if logger == nil {
		logger = slog.Default()
	}
	w := &Worker{pool: pool, logger: logger}
	if len(webhooks) > 0 {
		w.webhooks = webhooks[0]
	}
	return w
}

type claim struct {
	ID       int64          `json:"id"`
	EventID  string         `json:"event_id"`
	Consumer string         `json:"consumer_kind"`
	Attempts int            `json:"attempts"`
	Payload  map[string]any `json:"payload"`
}

func (w *Worker) Run(ctx context.Context) {
	w.drain(ctx)
	ticker := time.NewTicker(pollInterval)
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

func (w *Worker) drain(ctx context.Context) {
	if _, err := w.pool.Exec(ctx, `SELECT mail_work_sla_scan($1)`, claimLimit); err != nil && ctx.Err() == nil {
		w.logger.Warn("mail-work SLA scan failed", "error", err)
	}
	if _, err := w.pool.Exec(ctx, `SELECT mail_work_digest_dispatch($1)`, claimLimit); err != nil && ctx.Err() == nil {
		w.logger.Warn("mail-work digest dispatch failed", "error", err)
	}
	var raw []byte
	if err := w.pool.QueryRow(ctx, `SELECT mail_work_outbox_claim($1,$2)`,
		[]string{"push", "digest", "metric", "webhook", "task", "chat", "drive"}, claimLimit).Scan(&raw); err != nil {
		if ctx.Err() == nil {
			w.logger.Warn("mail-work outbox claim failed", "error", err)
		}
		return
	}
	var claims []claim
	if err := json.Unmarshal(raw, &claims); err != nil {
		w.logger.Warn("mail-work outbox claim decode failed", "error", err)
		return
	}
	for _, item := range claims {
		if item.ID <= 0 || item.Attempts < 1 || item.Attempts > 100 || !validConsumer(item.Consumer) {
			w.logger.Warn("mail-work outbox returned an invalid claim")
			// Settle-before-skip (S12-RETRY-POISON): an invalid claim that is
			// only logged stays a claimed row forever — permanently unsettled
			// poison. Record the rejection through the same finish reducer the
			// dispatch-failure path uses so the row reaches a terminal state.
			// A non-positive id cannot address any row, so only log there.
			if item.ID > 0 {
				if _, finishErr := w.pool.Exec(ctx,
					`SELECT mail_work_outbox_finish($1,false,NULL,$2)`,
					item.ID, "invalid claim rejected by worker",
				); finishErr != nil && ctx.Err() == nil {
					w.logger.Warn("mail-work outbox invalid-claim settlement failed",
						"outbox_id", item.ID, "error", finishErr)
				}
			}
			continue
		}
		var receipt []byte
		var err error
		if item.Consumer == "webhook" {
			err = w.dispatchWebhook(ctx, item)
			if err == nil {
				receipt, _ = json.Marshal(map[string]any{"outboxId": item.ID, "eventId": item.EventID, "outcome": "enqueued"})
			}
		} else if item.Consumer == "task" || item.Consumer == "chat" || item.Consumer == "drive" {
			err = w.pool.QueryRow(ctx, `SELECT mail_work_outbox_dispatch_internal($1)`, item.ID).Scan(&receipt)
		} else {
			err = w.pool.QueryRow(ctx, `SELECT mail_work_outbox_dispatch_local($1)`, item.ID).Scan(&receipt)
		}
		if err == nil {
			_, err = w.pool.Exec(ctx, `SELECT mail_work_outbox_finish($1,true,$2::jsonb,NULL)`, item.ID, receipt)
		} else {
			_, finishErr := w.pool.Exec(ctx, `SELECT mail_work_outbox_finish($1,false,NULL,$2)`, item.ID, boundedError(err))
			if finishErr != nil && ctx.Err() == nil {
				w.logger.Warn("mail-work outbox failure recording failed", "outbox_id", item.ID, "error", finishErr)
			}
		}
		if err != nil && ctx.Err() == nil {
			w.logger.Warn("mail-work outbox dispatch failed", "outbox_id", item.ID,
				"consumer", item.Consumer, "attempt", item.Attempts, "error", err)
		}
	}
}

func validConsumer(consumer string) bool {
	switch consumer {
	case "push", "digest", "metric", "webhook", "task", "chat", "drive":
		return true
	default:
		return false
	}
}

func (w *Worker) dispatchWebhook(ctx context.Context, item claim) error {
	if w.webhooks == nil {
		return errors.New("mail-work webhook dispatcher unavailable")
	}
	eventType, _ := item.Payload["eventType"].(string)
	mapped := map[string]string{
		"claimed": wh.EventMailWorkClaimed, "assigned": wh.EventMailWorkAssigned,
		"reassigned": wh.EventMailWorkAssigned, "handed_off": wh.EventMailWorkHandedOff,
		"completed": wh.EventMailWorkCompleted, "sla_breached": wh.EventMailWorkSLABreached,
	}[eventType]
	if mapped == "" {
		return errors.New("mail-work webhook event is not approved")
	}
	safe := map[string]any{"mailboxId": item.Payload["mailboxId"], "threadId": item.Payload["threadId"],
		"eventId": item.EventID, "eventType": eventType, "generation": item.Payload["generation"]}
	event := wh.NewCloudEvent("urn:setjoin:mailwork", mapped, safe)
	event.ID = item.EventID
	return w.webhooks.EnqueueDurable(ctx, event)
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	value := err.Error()
	if len(value) > 2048 {
		return value[:2048]
	}
	return value
}
