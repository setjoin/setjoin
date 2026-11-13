package admin

import (
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/storage"
	"setjoin.com/shared/httputil"
)

// StorageMigrateHandler adapts the process-lifetime storage Migrator to the
// admin HTTP surface (AR-01 "one lifetime owner"): parse → Migrator call →
// Problem-JSON. It holds no per-request Migration instances — the Migrator
// owns execution, cancellation and recovery, and the DB stays the read model
// for status. Run contexts derive from the service lifecycle inside the
// Migrator, never from the requests served here.
type StorageMigrateHandler struct {
	migrator    *storage.Migrator
	pool        *pgxpool.Pool // list read model only
	logger      *slog.Logger
	minioClient *minio.Client // current storage
	bucket      string
	accessKey   string // S3 access key for target driver creation
	secretKey   string // S3 secret key for target driver creation
	endpoint    string // target storage endpoint
	provider    string // default target provider from env
}

// NewStorageMigrateHandler creates a storage migration admin handler over the
// process Migrator.
func NewStorageMigrateHandler(migrator *storage.Migrator, pool *pgxpool.Pool, minioClient *minio.Client, bucket string, logger *slog.Logger) *StorageMigrateHandler {
	return &StorageMigrateHandler{
		migrator: migrator, pool: pool, logger: logger, minioClient: minioClient, bucket: bucket,
		accessKey: os.Getenv("STORAGE_ACCESS_KEY"),
		secretKey: os.Getenv("STORAGE_SECRET_KEY"),
		endpoint:  os.Getenv("STORAGE_ENDPOINT"),
		provider:  os.Getenv("STORAGE_PROVIDER"),
	}
}

// Status returns the current storage provider and health.
func (h *StorageMigrateHandler) Status(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// minio's BucketExists returns (exists bool, err error): the BOOL is the
	// health/existence signal. The previous assignment captured the error as
	// `healthy`, projecting a marshaled error object (or null) instead of a
	// boolean into the response.
	healthy, _ := h.minioClient.BucketExists(ctx, h.bucket)
	exists, _ := h.minioClient.BucketExists(ctx, h.bucket)

	resp := map[string]any{
		"provider": "s3",
		"endpoint": h.minioClient.EndpointURL().String(),
		"healthy":  healthy,
		"bucket":   exists,
	}
	httputil.WriteJSON(w, http.StatusOK, resp)
}

// migrationSourceDriver wraps the shared blob client as a storage.Driver for
// the migration SOURCE leg. The client's EndpointURL carries the scheme that
// reflects its configured S3_SECURE posture; NewS3HotDriver resolves transport
// TLS from it (https:// → TLS, http:// loopback → plaintext, anything else
// fail-closed). A remote-plaintext shared client therefore refuses to start a
// migration instead of silently leaking blob traffic (D-…-STORAGE-F-001).
func migrationSourceDriver(mc *minio.Client, accessKey, secretKey, bucket string) (storage.Driver, error) {
	return storage.NewS3HotDriver(mc.EndpointURL().String(), accessKey, secretKey, bucket, false)
}

// StartMigrate begins a cross-driver blob migration.
func (h *StorageMigrateHandler) StartMigrate(w http.ResponseWriter, r *http.Request) {
	targetProvider := r.URL.Query().Get("target")
	if targetProvider == "" {
		targetProvider = h.provider
	}
	if targetProvider == "" || targetProvider == "s3" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "target provider required and must differ from current"})
		return
	}

	// Create target driver from stored config.
	targetDriver, err := storage.NewDriver(storage.DriverConfig{
		Provider:  targetProvider,
		Endpoint:  h.endpoint,
		Bucket:    h.bucket,
		AccessKey: h.accessKey,
		SecretKey: h.secretKey,
	})
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "failed to create target driver: " + err.Error()})
		return
	}

	// Wrap the minio client as a Driver for the migration SOURCE. The
	// scheme-ful endpoint URL of the already-configured shared client drives
	// the TLS posture (storage.ResolveEndpointTLS), so the source honors
	// S3_SECURE instead of the historical hardcoded plaintext
	// (D-MAILSERVER-INTERNAL-STORAGE-F-001).
	sourceDriver, err := migrationSourceDriver(h.minioClient, h.accessKey, h.secretKey, h.bucket)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "failed to create source driver: " + err.Error()})
		return
	}
	// Admit through the process Migrator: the durable INSERT runs on the
	// request context, while the run itself derives from the service
	// lifecycle (AR01-1) — this request returning can never kill the worker.
	id, err := h.migrator.Start(r.Context(), sourceDriver, targetDriver)
	if err != nil {
		if errors.Is(err, storage.ErrAdmissionClosed) {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusServiceUnavailable, Detail: "migration admission is closed — service shutdown in progress"})
			return
		}
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "failed to start migration: " + err.Error()})
		return
	}

	httputil.WriteJSON(w, http.StatusAccepted, map[string]any{"id": id, "status": "started"})
}

// MigrateStatus returns the state of a migration by ID. The DB read model is
// served by the Migrator — no dummy Migration instance is constructed.
func (h *StorageMigrateHandler) MigrateStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid migration id"})
		return
	}

	status, err := h.migrator.Status(ctx, id)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "migration not found"})
		return
	}
	httputil.WriteJSON(w, http.StatusOK, status)
}

// MigrateCancel cancels a running migration through the Migrator's bounded
// handshake, mapping the typed outcomes to Problem-JSON: unknown → 404,
// terminal/cutover or no-live-run rows → 409 (the row is unchanged), an
// expired drain → 503 (ownership retained; the caller retries or polls
// status).
func (h *StorageMigrateHandler) MigrateCancel(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid migration id"})
		return
	}

	if err := h.migrator.Cancel(r.Context(), id); err != nil {
		switch {
		case errors.Is(err, storage.ErrUnknownMigration):
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "migration not found"})
		case errors.Is(err, storage.ErrNotCancellable):
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusConflict, Detail: err.Error()})
		case errors.Is(err, storage.ErrNotRunning):
			// Transitional row, but no live run in this process: local absence
			// cannot authorize mutating another executor's row (AR01-2).
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusConflict, Detail: err.Error()})
		case errors.Is(err, storage.ErrDrainTimeout):
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusServiceUnavailable, Detail: err.Error()})
		default:
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: err.Error()})
		}
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

// ListMigrations returns the last 20 migrations.
func (h *StorageMigrateHandler) ListMigrations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT id, source_driver, target_driver, status, COALESCE(total_blobs, 0), COALESCE(migrated, 0), started_at, completed_at
		 FROM storage_migrations ORDER BY started_at DESC LIMIT 20`)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "query failed"})
		return
	}
	defer rows.Close()

	results, err := readStorageMigrationRows(rows)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "query failed"})
		return
	}
	httputil.WriteJSON(w, http.StatusOK, results)
}

// A failed row or cursor invalidates the whole read model. The caller owns
// Close and does not publish any rows before this function succeeds.
func readStorageMigrationRows(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]map[string]any, error) {
	results := []map[string]any{}
	for rows.Next() {
		var id, total, migrated int64
		var source, target, status string
		var started, completed interface{}
		if err := rows.Scan(&id, &source, &target, &status, &total, &migrated, &started, &completed); err != nil {
			return nil, err
		}
		item := map[string]any{
			"id": id, "source": source, "target": target, "status": status,
			"total": total, "migrated": migrated, "started": started,
		}
		if completed != nil {
			item["completed"] = completed
		}
		if total > 0 {
			item["progress_pct"] = float64(migrated) * 100 / float64(total)
		}
		results = append(results, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}
