package admin

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/httputil"
)

type QueueHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

func NewQueueHandler(pool *pgxpool.Pool, logger *slog.Logger) *QueueHandler {
	return &QueueHandler{pool: pool, logger: logger}
}

// Summary returns quick stats about the outbound queue.
func (h *QueueHandler) Summary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var pending, deferred, bouncedToday, stuck int
	var oldestMinutes float64

	// One round-trip with FILTERed aggregates: a single error path so a DB
	// failure surfaces as 500 instead of silently returning all-zero stats.
	err := h.pool.QueryRow(ctx, `
		SELECT
		  COUNT(*) FILTER (WHERE status = 'pending'),
		  COUNT(*) FILTER (WHERE status = 'deferred'),
		  COUNT(*) FILTER (WHERE status = 'bounced' AND delivered_at > now() - interval '24 hours'),
		  COUNT(*) FILTER (WHERE attempt_count >= 10 AND status IN ('deferred','pending')),
		  COALESCE(EXTRACT(EPOCH FROM (now() - MIN(queued_at) FILTER (WHERE status IN ('pending','deferred'))))/60, 0)
		FROM outbound_queue`,
	).Scan(&pending, &deferred, &bouncedToday, &stuck, &oldestMinutes)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "queue summary failed", err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"pending":       pending,
		"deferred":      deferred,
		"bouncedToday":  bouncedToday,
		"stuck":         stuck,
		"oldestMinutes": fmt.Sprintf("%.0f min", oldestMinutes),
	})
}

// mapQueueStatus translates a UI tab id to a real outbound_queue WHERE clause.
// The webmail tabs use operator vocabulary ('failed'/'held') that does NOT exist
// in outbound_queue.status (pending/sending/delivered/bounced/deferred). Returns
// the clause and whether the tab value should be bound as $1 (only for tabs that
// ARE real status values). An empty clause means "no filter" (all).
func mapQueueStatus(tab string) (clause string, bindArg bool) {
	switch tab {
	case "", "all":
		return "", false
	case "failed":
		return "status = 'bounced'", false
	case "held":
		return "attempt_count >= 10 AND status IN ('deferred','pending')", false
	default:
		return "status = $1", true
	}
}

// List returns paginated queue items.
func (h *QueueHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	status := r.URL.Query().Get("status")
	limit, offset := httputil.ParseLimitOffset(r, 50, 200)

	var rows pgx.Rows
	var err error

	clause, bindArg := mapQueueStatus(status)
	baseSelect := `SELECT id, message_id, from_addr, rcpt_addrs, status, attempt_count,
	        next_attempt_at, last_error, queued_at, mailbox_id
	 FROM outbound_queue`
	if clause == "" {
		rows, err = h.pool.Query(ctx,
			baseSelect+` ORDER BY queued_at DESC LIMIT $1 OFFSET $2`,
			limit, offset,
		)
	} else if bindArg {
		rows, err = h.pool.Query(ctx,
			baseSelect+` WHERE `+clause+` ORDER BY queued_at DESC LIMIT $2 OFFSET $3`,
			status, limit, offset,
		)
	} else {
		rows, err = h.pool.Query(ctx,
			baseSelect+` WHERE `+clause+` ORDER BY queued_at DESC LIMIT $1 OFFSET $2`,
			limit, offset,
		)
	}
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "queue list failed", err)
		return
	}
	defer rows.Close()

	out := []map[string]interface{}{}
	for rows.Next() {
		var id, attemptCount int
		var msgID, from, status string
		var rcpts []string
		var nextAt, queuedAt time.Time
		var lastError *string
		var mbID *int64
		if err := rows.Scan(&id, &msgID, &from, &rcpts, &status, &attemptCount, &nextAt, &lastError, &queuedAt, &mbID); err != nil {
			continue
		}
		errStr := ""
		if lastError != nil {
			errStr = *lastError
		}
		out = append(out, map[string]interface{}{
			"id":            id,
			"messageId":     msgID,
			"fromAddr":      from,
			"recipients":    rcpts,
			"status":        status,
			"attemptCount":  attemptCount,
			"nextAttemptAt": nextAt,
			"lastError":     errStr,
			"queuedAt":      queuedAt,
			"mailboxId":     mbID,
		})
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

// ForceRetry resets a deferred item back to pending for immediate retry.
func (h *QueueHandler) ForceRetry(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := httputil.ParseIDPath(w, r, "id", "invalid queue id")
	if !ok {
		return
	}

	ct, err := h.pool.Exec(ctx,
		`UPDATE outbound_queue SET status = 'pending', next_attempt_at = now()
		 WHERE id = $1 AND status IN ('deferred','pending')`, id,
	)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "queue retry failed", err)
		return
	}
	if ct.RowsAffected() == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "item not found or not retriable"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Bounce marks an item as bounced, stopping further retries.
func (h *QueueHandler) Bounce(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := httputil.ParseIDPath(w, r, "id", "invalid queue id")
	if !ok {
		return
	}

	ct, err := h.pool.Exec(ctx,
		`UPDATE outbound_queue SET status = 'bounced', delivered_at = now()
		 WHERE id = $1`, id,
	)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "queue bounce failed", err)
		return
	}
	if ct.RowsAffected() == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "item not found"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
