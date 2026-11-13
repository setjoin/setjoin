package admin

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/sql/dbschema"
	"setjoin.com/shared/httputil"
)

type SystemHandler struct {
	pool    *pgxpool.Pool
	minio   *minio.Client
	bucket  string
	logger  *slog.Logger
	startAt time.Time
	pid     int
	ctx     context.Context
}

func NewSystemHandler(pool *pgxpool.Pool, minioClient *minio.Client, bucket string, logger *slog.Logger, ctx context.Context) *SystemHandler {
	return &SystemHandler{
		pool: pool, minio: minioClient, bucket: bucket,
		logger: logger, startAt: time.Now(), pid: os.Getpid(), ctx: ctx,
	}
}

func (h *SystemHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "running",
		"pid":        h.pid,
		"uptime_sec": int(time.Since(h.startAt).Seconds()),
		"goroutines": runtime.NumGoroutine(),
		"memory_mb":  mem.Alloc / 1024 / 1024,
		"started_at": h.startAt.Format(time.RFC3339),
	})
}

func (h *SystemHandler) Health(w http.ResponseWriter, r *http.Request) {
	h.GetStatus(w, r)
}

// Backup enqueues a backup run. The INSERT fires trg_backup_runs_notify →
// pg_notify('backup_run', id) → the backup worker (started in main.go when
// BACKUP_PROVIDER is configured) executes it. If no worker is configured, the
// row stays 'pending' and is drained whenever a worker comes up — manual and
// scheduled backups share this one enqueue path.
func (h *SystemHandler) Backup(w http.ResponseWriter, r *http.Request) {
	var runID int64
	if err := h.pool.QueryRow(r.Context(),
		`INSERT INTO backup_runs (status) VALUES ('pending') RETURNING id`,
	).Scan(&runID); err != nil {
		h.logger.Error("backup: enqueue failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to enqueue backup")
		return
	}
	httputil.WriteJSON(w, http.StatusAccepted, map[string]interface{}{"status": "enqueued", "run_id": runID})
}

// backupRun is the JSON shape ListBackups returns for one row. Nullable counts +
// timestamps are pointers so a still-running ('pending'/'running') row reports
// null rather than a zero that reads as "0 blobs copied".
type backupRun struct {
	ID                int64      `json:"id"`
	Status            string     `json:"status"`
	BlobCount         *int       `json:"blob_count"`
	BlobTotalSize     *int64     `json:"blob_total_size"`
	ConfigSize        *int64     `json:"config_size"`
	ManifestTimestamp *string    `json:"manifest_timestamp"`
	BlobsCopied       *int       `json:"blobs_copied"`
	BlobsSkipped      *int       `json:"blobs_skipped"`
	StartedAt         *time.Time `json:"started_at"`
	CompletedAt       *time.Time `json:"completed_at"`
	CreatedAt         time.Time  `json:"created_at"`
}

// ListBackups returns the 50 most recent backup runs, newest first.
func (h *SystemHandler) ListBackups(w http.ResponseWriter, r *http.Request) {
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, status, blob_count, blob_total_size, config_size,
		        manifest_timestamp, blobs_copied, blobs_skipped,
		        started_at, completed_at, created_at
		 FROM backup_runs ORDER BY created_at DESC, id DESC LIMIT 50`)
	if err != nil {
		h.logger.Error("backup: list failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to list backups")
		return
	}
	defer rows.Close()

	out := []backupRun{}
	for rows.Next() {
		var b backupRun
		if err := rows.Scan(&b.ID, &b.Status, &b.BlobCount, &b.BlobTotalSize, &b.ConfigSize,
			&b.ManifestTimestamp, &b.BlobsCopied, &b.BlobsSkipped,
			&b.StartedAt, &b.CompletedAt, &b.CreatedAt); err != nil {
			h.logger.Error("backup: list scan failed", "error", err)
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to read backups")
			return
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("backup: list rows error", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to read backups")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

func (h *SystemHandler) DownloadBackup(w http.ResponseWriter, r *http.Request) {
	httputil.WriteProblemStatus(w, http.StatusNotImplemented, "download not yet implemented")
}

func (h *SystemHandler) DeleteBackup(w http.ResponseWriter, r *http.Request) {
	httputil.WriteProblemStatus(w, http.StatusNotImplemented, "delete not yet implemented")
}

// SchemaVersionStatus returns the current DATABASE SCHEMA VERSION compared to
// the version this binary expects. (Named for the schema-version concept, not
// the unrelated mailbox/data-import "migration".) "expected" + "pending" come
// from mailserver/sql/dbschema (the embedded V<NNN>__*.sql files) — the SAME
// source the gateway's refuse-to-start guard and `mailctl schema` use, so the
// three never disagree.
func (h *SystemHandler) SchemaVersionStatus(w http.ResponseWriter, r *http.Request) {
	expectedVersion := dbschema.ExpectedVersion()

	var current int
	if h.pool != nil {
		// Shared read: returns 0 for an unbaselined DB but surfaces any other DB
		// fault as an error — so a transient failure is reported as 500, NOT
		// masqueraded as "current=0, everything pending" (which is what a genuinely
		// empty DB looks like and could send an operator to re-run the baseline).
		v, err := dbschema.ReadCurrentVersion(r.Context(), h.pool)
		if err != nil {
			httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
				"error": "schema-version query failed: " + err.Error(),
			})
			return
		}
		current = v
	}

	pending := make([]string, 0)
	for _, m := range dbschema.Pending(current) {
		pending = append(pending, m.Name)
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"current":    current,
		"expected":   expectedVersion,
		"up_to_date": current >= expectedVersion,
		"pending":    pending,
	})
}

func (h *SystemHandler) Version(w http.ResponseWriter, r *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"version": "v2.1.3"})
}
