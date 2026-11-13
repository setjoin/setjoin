package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
)

// JobsHandler serves the Background Jobs console (U6): a cross-tenant operator
// read surface over the bespoke Postgres queues, via the F3 shared read
// interface (get_queue_summary / list_queue / queue_status_normalized). It runs
// on workerPool (BYPASSRLS) per the established admin precedent — the queues
// span all mailboxes, so a per-tenant GUC would hide rows. workerPool aliases
// pool until DB_WORKER_DSN is set (INERT, flip-safe). RBAC (queue.read /
// queue.write) is enforced by middleware in main.go, not the handler.
type JobsHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

func NewJobsHandler(workerPool pgxutil.WorkerPool, logger *slog.Logger) *JobsHandler {
	return &JobsHandler{pool: workerPool.Pool, logger: logger}
}

// knownQueues is the set the F3 reducers accept. An unknown queue is a 400.
var knownQueues = map[string]bool{"journal": true, "outbound": true, "scheduled": true, "bulk_role": true}

// Summary returns the normalized {active,failed,dead,done,total} counts for one
// queue. GET /admin/jobs/{queue}/summary
func (h *JobsHandler) Summary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	queue := r.PathValue("queue")
	if !knownQueues[queue] {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "unknown queue"})
		return
	}
	var active, failed, dead, done, total int
	err := h.pool.QueryRow(ctx,
		`SELECT active, failed, dead, done, total FROM get_queue_summary($1)`, queue,
	).Scan(&active, &failed, &dead, &done, &total)
	if err != nil {
		h.logger.Error("jobs summary failed", "queue", queue, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]int{
		"active": active,
		"failed": failed,
		"dead":   dead,
		"done":   done,
		"total":  total,
	})
}

// List returns paginated normalized rows for one queue, optionally filtered by
// normalized status. GET /admin/jobs/{queue}?status=&limit=&offset=
func (h *JobsHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	queue := r.PathValue("queue")
	if !knownQueues[queue] {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "unknown queue"})
		return
	}
	status := r.URL.Query().Get("status")
	limit, offset := httputil.ParseLimitOffset(r, 50, 200)

	rows, err := h.pool.Query(ctx,
		`SELECT item FROM list_queue($1, $2, $3, $4)`, queue, status, limit, offset,
	)
	if err != nil {
		h.logger.Error("jobs list failed", "queue", queue, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
		return
	}
	defer rows.Close()

	out := []json.RawMessage{}
	for rows.Next() {
		var item []byte
		if err := rows.Scan(&item); err != nil {
			continue
		}
		out = append(out, json.RawMessage(item))
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// RetryJournal re-pends a dead-lettered journal_queue row. Idempotent: the
// reducer's WHERE status='dead' guard returns 0 affected for a missing/non-dead
// row, which we surface as 404. POST /admin/jobs/journal/{id}/retry
func (h *JobsHandler) RetryJournal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := httputil.ParseIDPath(w, r, "id", "invalid job id")
	if !ok {
		return
	}
	var affected int
	if err := h.pool.QueryRow(ctx,
		`SELECT repend_dead_journal_row($1)`, id,
	).Scan(&affected); err != nil {
		h.logger.Error("jobs journal retry failed", "id", id, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
		return
	}
	if affected == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "row not found or not dead-lettered"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
