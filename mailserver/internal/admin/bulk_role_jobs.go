package admin

import (
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// BulkRoleJobsHandler serves the bulk_role job detail and retry endpoints.
// Uses pool (same as RolesHandler — admin data, no per-tenant RLS needed).
type BulkRoleJobsHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

func NewBulkRoleJobsHandler(pool *pgxpool.Pool, logger *slog.Logger) *BulkRoleJobsHandler {
	return &BulkRoleJobsHandler{pool: pool, logger: logger}
}

// JobDetail returns the full bulk_role_jobs row as JSON, including results.
// GET /admin/jobs/bulk_role/{id}
func (h *BulkRoleJobsHandler) JobDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := httputil.ParseIDPath(w, r, "id", "invalid job id")
	if !ok {
		return
	}
	var row []byte
	err := h.pool.QueryRow(ctx,
		`SELECT row_to_json(b) FROM bulk_role_jobs b WHERE id = $1`, id,
	).Scan(&row)
	if err != nil || row == nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "job not found"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(row)
}

// RetryJob re-queues a failed bulk_role_jobs row WITHOUT resetting processed or
// results — the worker resumes from processed (O2 resume semantics).
// POST /admin/jobs/bulk_role/{id}/retry
func (h *BulkRoleJobsHandler) RetryJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := httputil.ParseIDPath(w, r, "id", "invalid job id")
	if !ok {
		return
	}

	var returnedID int64
	err := h.pool.QueryRow(ctx,
		`UPDATE bulk_role_jobs SET status='queued', error=NULL, updated_at=now()
		 WHERE id=$1 AND status='error' RETURNING id`,
		id,
	).Scan(&returnedID)
	if err != nil {
		// ponytail: pgx returns pgx.ErrNoRows on 0 rows; that means either not-found or not-error status → 409
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusConflict, Detail: "job not found or not in error state"})
		return
	}

	// Audit log the retry (mirrors admin_roles.go pattern).
	claims := auth.UserFromContext(ctx)
	var actorID int64
	if claims != nil {
		actorID = claims.UserID
	}
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: actorID, Action: "bulk_role_job_retry", TargetType: "bulk_role_job", TargetID: &id,
		IP: httputil.ClientIP(r), Tier: "core",
	})

	w.WriteHeader(http.StatusNoContent)
}
