package admin

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/restore"
	"setjoin.com/mailserver/internal/storage"
	"setjoin.com/shared/httputil"
)

// dbQuerier abstracts pgxpool.Pool.QueryRow for testing.
// *pgxpool.Pool satisfies this automatically.
type dbQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// SetupHandler serves the first-boot setup and restore wizard.
type SetupHandler struct {
	pool   *pgxpool.Pool
	db     dbQuerier // for mocking in tests; in production db == pool
	logger *slog.Logger

	// primary is the PRIMARY blob store (SeaweedFS/MinIO) restore writes blobs TO.
	// Built from cfg.S3* at startup. When the primary driver could not be built
	// it is nil and the restore endpoints return 503 (never panic).
	primary restore.RestoreStore

	// backupFactory builds the BACKUP store (restore source) from the request.
	// Production uses backupDriverFromRequest (a real S3/OSS driver); tests inject
	// an in-memory store so the restore execution path is exercised without S3.
	backupFactory func(restoreRequest) (restore.RestoreStore, error)
}

const restoreFinalizeTimeout = 15 * time.Second

func restoreFinalizeContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), restoreFinalizeTimeout)
}

// NewSetupHandler creates a new setup handler. primary is the live primary blob
// store (where restore writes blobs); pass nil when it could not be constructed —
// the restore endpoints then return a clear 503 instead of panicking.
func NewSetupHandler(pool *pgxpool.Pool, primary restore.RestoreStore, logger *slog.Logger) *SetupHandler {
	return &SetupHandler{
		pool:    pool,
		db:      pool,
		logger:  logger,
		primary: primary,
		backupFactory: func(req restoreRequest) (restore.RestoreStore, error) {
			return backupDriverFromRequest(req)
		},
	}
}

// CreateInitialAdmin is retained only as a fail-closed compatibility method for
// packages that constructed SetupHandler directly. No route registers it.
func (h *SetupHandler) CreateInitialAdmin(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

// ── SetupStatus ─────────────────────────────────────────────────────────

// SetupStatus handles GET /setup/status.
// Returns {"initialized": true} if any users exist, false otherwise.
func (h *SetupHandler) SetupStatus(w http.ResponseWriter, r *http.Request) {
	var count int
	if err := h.db.QueryRow(r.Context(), `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		h.logger.Error("setup-status: user count check failed", "error", err)
		httputil.WriteJSON(w, http.StatusOK, map[string]bool{"initialized": true})
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]bool{"initialized": count > 0})
}

// ── Restore endpoints (existing) ────────────────────────────────────────

// restoreRequest is the JSON body for POST /setup/restore and POST /setup/preflight.
type restoreRequest struct {
	Provider   string   `json:"provider"`
	Endpoint   string   `json:"endpoint"`
	Region     string   `json:"region"`
	Bucket     string   `json:"bucket"`
	AccessKey  string   `json:"access_key"`
	SecretKey  string   `json:"secret_key"`
	VolumePath string   `json:"volume_path"`
	Type       string   `json:"type"`             // "full", "config", or "blobs"
	Hashes     []string `json:"hashes,omitempty"` // explicit blob hashes (used when type=="blobs")
}

func (r restoreRequest) validate() error {
	if r.Bucket == "" {
		return fmt.Errorf("bucket is required")
	}
	if r.AccessKey == "" {
		return fmt.Errorf("access_key is required")
	}
	if r.SecretKey == "" {
		return fmt.Errorf("secret_key is required")
	}
	if r.Type != "full" && r.Type != "config" && r.Type != "blobs" {
		return fmt.Errorf("type must be 'full', 'config', or 'blobs'")
	}
	return nil
}

// preflightResponse is returned by POST /setup/preflight — a preview of the
// backup the operator is about to restore.
type preflightResponse struct {
	Timestamp     string   `json:"timestamp"`
	BlobCount     int      `json:"blob_count"`
	BlobTotalSize int64    `json:"blob_total_size_bytes"`
	ConfigSize    int64    `json:"config_size_bytes"`
	UserCount     int      `json:"user_count"`
	DomainCount   int      `json:"domain_count"`
	Warnings      []string `json:"warnings"`
}

// restoreResponse is returned by POST /setup/restore on a completed restore.
type restoreResponse struct {
	Status             string   `json:"status"`
	RestoreJobID       int64    `json:"restore_job_id"`
	RestoredConfigKeys int      `json:"restored_config_keys"`
	RestoredBlobs      int      `json:"restored_blobs"`
	Errors             []string `json:"errors"`
}

// backupDriverFromRequest builds the BACKUP storage driver (the source the
// restore reads from) from the request fields.
//
// TLS posture (D-MAILSERVER-INTERNAL-STORAGE-F-001): the request-supplied
// endpoint resolves through storage.ResolveEndpointTLS — a remote backup
// target MUST state an explicit https:// scheme (or the caller's storage
// driver Secure field); scheme-less non-loopback and http:// non-loopback
// endpoints are rejected fail-closed, and loopback HTTP remains available for
// local restore rehearsal.
func backupDriverFromRequest(req restoreRequest) (storage.Driver, error) {
	return storage.NewDriver(storage.DriverConfig{
		Provider:  req.Provider,
		Endpoint:  req.Endpoint,
		Region:    req.Region,
		Bucket:    req.Bucket,
		AccessKey: req.AccessKey,
		SecretKey: req.SecretKey,
	})
}

// userCount returns the number of users in the system. The no-users check is the
// safety rail for both restore endpoints: a restore must NEVER run against a
// populated system.
func (h *SetupHandler) userCount(ctx context.Context) (int, error) {
	var count int
	err := h.db.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

// PreFlight handles POST /setup/preflight — downloads the backup manifest from
// the operator-supplied backup target and returns a preview (timestamp, blob
// count/size, config size) plus the current user/domain counts. 409 if the
// system already has users; 400 if the manifest is missing/corrupt.
func (h *SetupHandler) PreFlight(w http.ResponseWriter, r *http.Request) {
	var req restoreRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := req.validate(); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "Invalid restore configuration. Check the required fields.")
		return
	}

	// Safety rail: a restore/preflight must never run against a populated system.
	count, err := h.userCount(r.Context())
	if err != nil {
		h.logger.Error("preflight: user count check failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal error")
		return
	}
	if count > 0 {
		httputil.WriteProblemStatus(w, http.StatusConflict, "Setup already completed")
		return
	}

	if h.primary == nil {
		httputil.WriteProblemStatus(w, http.StatusServiceUnavailable, "restore unavailable: primary storage not configured")
		return
	}

	backupStore, err := h.backupFactory(req)
	if err != nil {
		h.logger.Error("preflight: backup driver init failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "failed to connect to backup provider")
		return
	}

	engine := restore.NewEngine(h.pool, h.primary, backupStore, h.logger)
	manifest, err := engine.DownloadManifest(r.Context())
	if err != nil {
		h.logger.Warn("preflight: manifest download failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "backup manifest missing or unreadable")
		return
	}

	// Current system counts (a fresh system in setup mode reports 0/0).
	var domainCount int
	if err := h.pool.QueryRow(r.Context(), "SELECT COUNT(*) FROM domains").Scan(&domainCount); err != nil {
		h.logger.Warn("preflight: domain count failed", "error", err)
	}

	httputil.WriteJSON(w, http.StatusOK, preflightResponse{
		Timestamp:     manifest.Timestamp,
		BlobCount:     manifest.BlobCount,
		BlobTotalSize: manifest.BlobTotalSize,
		ConfigSize:    manifest.ConfigSize,
		UserCount:     count,
		DomainCount:   domainCount,
		Warnings:      []string{},
	})
}

// StartRestore handles POST /setup/restore — a SYNCHRONOUS disaster-recovery
// operation (the operator's CLI blocks until it completes). It claims the single
// restore slot, restores config and/or blobs per the request type, and records
// the outcome on the restore_jobs row. 409 if the system has users OR a restore
// is already running; 500 on a hard failure.
func (h *SetupHandler) StartRestore(w http.ResponseWriter, r *http.Request) {
	var req restoreRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := req.validate(); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "Invalid restore configuration. Check the required fields.")
		return
	}

	// Safety rail: a restore must NEVER run against a populated system.
	count, err := h.userCount(r.Context())
	if err != nil {
		h.logger.Error("restore: user count check failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal error")
		return
	}
	if count > 0 {
		httputil.WriteProblemStatus(w, http.StatusConflict, "Setup already completed")
		return
	}

	if h.primary == nil {
		httputil.WriteProblemStatus(w, http.StatusServiceUnavailable, "restore unavailable: primary storage not configured")
		return
	}

	backupStore, err := h.backupFactory(req)
	if err != nil {
		h.logger.Error("restore: backup driver init failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "failed to connect to backup provider")
		return
	}

	engine := restore.NewEngine(h.pool, h.primary, backupStore, h.logger)

	// Single-flight: claim the one restore slot. If another restore holds it, 409.
	jobID, err := engine.StartRestoreJob(r.Context(), req.Type)
	if err != nil {
		h.logger.Warn("restore: could not claim restore slot", "error", err)
		httputil.WriteProblemStatus(w, http.StatusConflict, "a restore is already in progress")
		return
	}

	// Always release the slot + record the outcome, success or failure.
	var retErr error
	defer func() {
		finishCtx, cancel := restoreFinalizeContext(r.Context())
		defer cancel()
		if ferr := engine.FinishRestoreJob(finishCtx, jobID, retErr); ferr != nil {
			h.logger.Error("restore: finish job failed", "error", ferr, "job_id", jobID)
		}
	}()

	resp, hardErr := h.runRestore(r.Context(), engine, req)
	resp.RestoreJobID = jobID
	if hardErr != nil {
		retErr = hardErr
		h.logger.Error("restore: hard failure", "error", hardErr, "job_id", jobID)
		resp.Status = "failed"
		if resp.Errors == nil {
			resp.Errors = []string{}
		}
		httputil.WriteJSON(w, http.StatusInternalServerError, resp)
		return
	}

	resp.Status = "completed"
	if resp.Errors == nil {
		resp.Errors = []string{}
	}
	// Per-blob errors are reported in the body but are not, by themselves, a hard
	// failure — record them on the job too so the operator sees a partial result.
	if len(resp.Errors) > 0 {
		retErr = fmt.Errorf("%d restore error(s); first: %s", len(resp.Errors), resp.Errors[0])
	}
	httputil.WriteJSON(w, http.StatusOK, resp)
}

// runRestore executes the config/blob restore steps for the request type and
// aggregates the result. A returned non-nil error is a HARD failure (the whole
// restore could not proceed — e.g. config.json unreadable, or the blob manifest
// could not be downloaded); per-blob errors are collected into resp.Errors.
func (h *SetupHandler) runRestore(ctx context.Context, engine *restore.Engine, req restoreRequest) (restoreResponse, error) {
	var resp restoreResponse
	resp.Errors = []string{}

	if req.Type == "config" || req.Type == "full" {
		n, err := engine.RestoreConfig(ctx)
		if err != nil {
			return resp, fmt.Errorf("restore config: %w", err)
		}
		resp.RestoredConfigKeys = n
	}

	if req.Type == "blobs" || req.Type == "full" {
		var restored int
		var errs []error
		if len(req.Hashes) > 0 {
			restored, errs = engine.RestoreMissingBlobs(ctx, req.Hashes)
		} else {
			manifest, err := engine.DownloadManifest(ctx)
			if err != nil {
				return resp, fmt.Errorf("download manifest: %w", err)
			}
			restored, errs = engine.RestoreFromManifest(ctx, manifest)
		}
		resp.RestoredBlobs = restored
		for _, e := range errs {
			resp.Errors = append(resp.Errors, e.Error())
		}
	}

	return resp, nil
}
