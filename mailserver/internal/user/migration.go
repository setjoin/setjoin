package user

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/migration"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/permissions"
)

// maxMigrationUploadBytes bounds the total request body for ICS/VCF uploads,
// preventing memory exhaustion from an oversized multipart request.
const maxMigrationUploadBytes = 64 << 20 // 64 MiB

// m365ConsentStateTTL is how long a server-issued M365 consent authorization
// stays consumable. Short window: the admin completes Microsoft's consent
// screen and lands back on the callback within minutes.
const m365ConsentStateTTL = 10 * time.Minute

// maxIMAPTestConnectionDuration bounds the whole self-service IMAP connection
// test (dial + TLS handshake + LOGIN + LIST). The connector sets dial and
// handshake deadlines, but post-handshake command I/O against a caller-named
// server is the connector's per-command concern (mailserver/internal/migration,
// er5-s15 lane); without a handler-side bound a hostile source server that
// completes the handshake and then answers nothing pins a goroutine and socket
// per request for as long as the caller keeps the HTTP connection open.
// Var (not const) so tests can shorten the bound.
var maxIMAPTestConnectionDuration = 30 * time.Second

// migrationOneActivePerUserConstraint is the partial UNIQUE index
// (migration_one_active_per_user, V001) that admits at most one active
// migration job per user. Insert failures carrying this constraint are the
// concurrency-admission verdict, not an internal error.
const migrationOneActivePerUserConstraint = "migration_one_active_per_user"

// isActiveJobAdmissionRejection reports whether err is the per-user
// one-active-job admission verdict (unique violation on the partial index).
func isActiveJobAdmissionRejection(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == "23505" && pgErr.ConstraintName == migrationOneActivePerUserConstraint
}

// clientFacingScheme resolves the scheme the CLIENT used, mirroring the CSRF
// middleware's expectedScheme (shared/middleware/csrf.go, introduced with the
// scheme+host+port tuple fix): the gateway strips client-supplied
// X-Forwarded-* before re-deriving them (authproxy.New), so a single well-formed
// X-Forwarded-Proto token is the client-facing scheme; direct deployments fall
// back to the connection TLS state. Used to set the Secure attribute on the
// M365 OAuth state cookie so the cookie is Secure behind the supported
// TLS-terminating proxy (r.TLS is nil there) while plain-HTTP dev keeps the
// cookie functional.
func clientFacingScheme(r *http.Request) string {
	switch p := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))); p {
	case "http", "https":
		return p
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// MigrationHandler serves the migration API (user self-service + admin).
type MigrationHandler struct {
	orch   *migration.Orchestrator
	pool   *pgxpool.Pool
	logger *slog.Logger

	// verifyM365Tenant proves a candidate tenant config actually works BEFORE
	// anything is persisted by the consent callback (verify-before-persist).
	// Injectable so security tests can drive both outcomes without network;
	// the constructor installs the real Graph connector check.
	verifyM365Tenant func(ctx context.Context, cfg migration.MigrationM365Config) error

	// testIMAPConnection runs the self-service IMAP connection test under the
	// handler-imposed deadline. Injectable for the same reason as
	// verifyM365Tenant: the deadline wiring (ctx.Deadline inside the call) is
	// assertable without a network-reaching hostile server.
	testIMAPConnection func(ctx context.Context, cfg migration.IMAPConfig) error
}

// NewMigrationHandler creates a new MigrationHandler.
func NewMigrationHandler(orch *migration.Orchestrator, pool *pgxpool.Pool, logger *slog.Logger) *MigrationHandler {
	return &MigrationHandler{
		orch:               orch,
		pool:               pool,
		logger:             logger,
		verifyM365Tenant:   verifyM365TenantConnection,
		testIMAPConnection: testIMAPConnectionReal,
	}
}

// testIMAPConnectionReal is the production connection-test body: the real IMAP
// connector driven by the caller's (deadline-bounded) context.
func testIMAPConnectionReal(ctx context.Context, cfg migration.IMAPConfig) error {
	return migration.NewIMAPConnector(cfg).TestConnection(ctx)
}

// verifyM365TenantConnection is the production verifier: build the real M365
// Graph connector for the candidate config and exercise it.
func verifyM365TenantConnection(ctx context.Context, cfg migration.MigrationM365Config) error {
	conn, err := migration.NewM365Connector(ctx, cfg)
	if err != nil {
		return err
	}
	return conn.TestConnection(ctx)
}

// ── User endpoints ──────────────────────────────────────────────────────

// StartMigration creates and starts a new migration job.
func (h *MigrationHandler) StartMigration(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Target entry for bulk migration (e.g. impersonation).
	type migrationTarget struct {
		SourceEmail string `json:"sourceEmail"`
		TargetEmail string `json:"targetEmail"`
	}

	var req struct {
		SourceType       string               `json:"sourceType"`
		ConflictStrategy string               `json:"conflictStrategy"`
		IMAPConfig       migration.IMAPConfig `json:"imapConfig,omitempty"`
		Config           json.RawMessage      `json:"config,omitempty"`
		Targets          []migrationTarget    `json:"targets,omitempty"`
		// No authMode field: bulk/impersonation jobs are rejected below, and
		// per-job impersonation principals are never accepted on this route.
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.Targets) > 0 {
		// Bulk/impersonation migration (importing into someone else's mailbox)
		// is an admin operation with its own gated surface (POST
		// /admin/migration/start). This self-service route only ever acts on
		// the caller's own mailbox — never accept targets here.
		httputil.WriteProblemStatus(w, http.StatusForbidden, "bulk/impersonation migration is an admin operation; use the admin migration API")
		return
	}
	if req.SourceType == "" {
		req.SourceType = "imap"
	}
	if req.ConflictStrategy == "" {
		req.ConflictStrategy = "skip"
	}

	encKey := h.orch.EncryptionKey()

	// ── EWS path ──────────────────────────────────────────────────────
	if req.SourceType == "ews" {
		if len(req.Config) == 0 {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "config is required for EWS migration")
			return
		}
		var ewsCfg migration.MigrationEWSConfig
		if err := json.Unmarshal(req.Config, &ewsCfg); err != nil {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid EWS config JSON")
			return
		}
		if ewsCfg.ServerURL == "" {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "config.serverURL is required for EWS migration")
			return
		}
		if ewsCfg.ImpersonateAs != "" {
			// Impersonation acts AS another mailbox using the shared service
			// account — it is an admin-only capability. Reject (do not
			// silently strip) so the caller knows the field is not honored
			// on the self-service path; the admin API derives the principal
			// from the verified source mailbox instead.
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "impersonation is admin-only; remove impersonateAs from migration config")
			return
		}
		// The migration egress allowlist is administrator-owned: it reaches
		// a connector only through the admin global source profile. Reject
		// (do not silently strip) caller-manufactured private-network
		// exceptions, with and without a global profile; the connector
		// factory enforces the same rule fail-closed when the persisted
		// job is reconstructed on start/resume/dial.
		if err := migration.RejectUserSuppliedPrivatePolicy(ewsCfg.PrivateHosts, ewsCfg.PrivateCIDRs); err != nil {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, err.Error())
			return
		}
		// Self-service credential boundary: the job must carry the CALLER'S
		// OWN complete credentials. The shared service account's global
		// username/password is never inherited on this path — a URL-only
		// request would otherwise authenticate as the service account with no
		// impersonation selector and read the SHARED account's mailbox into
		// the caller's mailbox. Required regardless of whether a global EWS
		// profile exists; the ewsFactory merge enforces the same rule
		// fail-closed at connector construction (MigrationJobConfig.SelfService).
		if ewsCfg.Username == "" || ewsCfg.Password == "" {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "self-service EWS migration requires your own username and password")
			return
		}
		useGlobal := h.hasGlobalSourceConfig(r.Context(), "ews")

		if len(req.Targets) == 0 {
			// Single-job: migrate current user.
			jobCfg := migration.MigrationJobConfig{
				SourceType:    "ews",
				UseGlobalAuth: useGlobal,
				SelfService:   migration.CredentialProvenance(true),
				EWS:           &ewsCfg,
			}
			sourceConfigEnc, err := migration.EncryptConfigAny(jobCfg, encKey)
			if err != nil {
				h.logger.Error("encrypt migration config", "error", err)
				httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal error")
				return
			}
			mailboxID := h.getUserMailboxID(r.Context(), claims.UserID)
			if mailboxID == 0 {
				httputil.WriteProblemStatus(w, http.StatusBadRequest, "no mailbox found for user")
				return
			}
			jobID, err := h.insertMigrationJob(r.Context(), claims.UserID, req.SourceType,
				sourceConfigEnc, mailboxID, req.ConflictStrategy)
			if err != nil {
				// The one-active-job-per-user admission verdict (partial UNIQUE
				// index migration_one_active_per_user) is a 409, never a 500:
				// the caller already has an admitted worker, so this request
				// must stop instead of stacking another one.
				if isActiveJobAdmissionRejection(err) {
					httputil.WriteProblemStatus(w, http.StatusConflict, "an active migration job already exists; cancel it or wait for it to finish")
					return
				}
				h.logger.Error("insert migration job", "error", err)
				httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to create job")
				return
			}
			if err := h.orch.StartJob(r.Context(), jobID); err != nil {
				h.logger.Error("start migration job", "job_id", jobID, "error", err)
				httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to start job")
				return
			}
			httputil.WriteJSON(w, http.StatusCreated, map[string]interface{}{
				"id":     jobID,
				"status": "pending",
			})
			return
		}

		// Bulk targets are rejected at the top of this handler (impersonation
		// migration is an admin-only surface, POST /admin/migration/start), so
		// there is deliberately no per-target job branch here: the self-service
		// path never writes a per-job impersonation principal.
	}

	// ── M365 path ─────────────────────────────────────────────────────
	if req.SourceType == "m365" {
		useGlobal := h.hasGlobalSourceConfig(r.Context(), "m365")
		if !useGlobal {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "M365 global config not found — admin must configure it first")
			return
		}

		if len(req.Targets) == 0 {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "targets[] is required for M365 migration (at least one source email)")
			return
		}

		var jobIDs []int64
		for _, tgt := range req.Targets {
			jobCfg := migration.MigrationJobConfig{
				SourceType:    "m365",
				UseGlobalAuth: true,
				SelfService:   migration.CredentialProvenance(true),
			}
			sourceConfigEnc, err := migration.EncryptConfigAny(jobCfg, encKey)
			if err != nil {
				h.logger.Error("encrypt m365 job config", "error", err)
				continue
			}

			mailboxID := h.getMailboxIDByEmail(r.Context(), tgt.TargetEmail)
			if mailboxID == 0 {
				h.logger.Warn("migration: no mailbox for target email", "email", tgt.TargetEmail)
				continue
			}

			jobID, err := h.insertMigrationJob(r.Context(), claims.UserID, req.SourceType,
				sourceConfigEnc, mailboxID, req.ConflictStrategy)
			if err != nil {
				// Admission is a hard stop, not a per-target footnote: once the
				// one-active-job constraint rejects a target, no further job is
				// created and no worker is started for this request.
				if isActiveJobAdmissionRejection(err) {
					h.logger.Warn("migration: concurrency admission rejected; stopping target fan-out", "targets_done", len(jobIDs))
					break
				}
				h.logger.Error("insert migration job", "error", err)
				continue
			}
			jobIDs = append(jobIDs, jobID)
		}

		if len(jobIDs) == 0 {
			httputil.WriteProblemStatus(w, http.StatusConflict, "an active migration job already exists; cancel it or wait for it to finish")
			return
		}

		for _, jobID := range jobIDs {
			if err := h.orch.StartJob(r.Context(), jobID); err != nil {
				h.logger.Error("start migration job", "job_id", jobID, "error", err)
			}
		}

		httputil.WriteJSON(w, http.StatusCreated, map[string]interface{}{
			"ids":    jobIDs,
			"status": "pending",
		})
		return
	}

	// ── IMAP / ICS / VCF path (existing behaviour) ────────────────────
	mailboxID := h.getUserMailboxID(r.Context(), claims.UserID)
	if mailboxID == 0 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "no mailbox found for user")
		return
	}

	var sourceConfigEnc []byte
	if migration.ContainsSourceType(req.SourceType, "imap") {
		cfg := req.IMAPConfig
		if cfg.Host == "" {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "imapConfig.host is required for IMAP migration")
			return
		}
		// Administrator-owned allowlist (same rule as the EWS path above):
		// per-job private-network exceptions are rejected at ingress.
		if err := migration.RejectUserSuppliedPrivatePolicy(cfg.PrivateHosts, cfg.PrivateCIDRs); err != nil {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, err.Error())
			return
		}
		useGlobal := h.hasGlobalSourceConfig(r.Context(), "imap")
		jobCfg := migration.MigrationJobConfig{
			SourceType:    "imap",
			UseGlobalAuth: useGlobal,
			SelfService:   migration.CredentialProvenance(true),
			IMAP:          &cfg,
		}
		var err error
		sourceConfigEnc, err = migration.EncryptConfigAny(jobCfg, encKey)
		if err != nil {
			h.logger.Error("encrypt migration config", "error", err)
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal error")
			return
		}
	}

	var jobID int64
	err := h.pool.QueryRow(r.Context(), `
		INSERT INTO migration_jobs (user_id, source_type, source_config_enc, target_mailbox_id, conflict_strategy, status)
		VALUES ($1, $2, $3, $4, $5, 'pending')
		RETURNING id`,
		claims.UserID, req.SourceType, sourceConfigEnc, mailboxID, req.ConflictStrategy,
	).Scan(&jobID)
	if err != nil {
		// Same admission rule as the EWS path: the per-user one-active-job
		// constraint is the concurrency gate — surface 409 and stop.
		if isActiveJobAdmissionRejection(err) {
			httputil.WriteProblemStatus(w, http.StatusConflict, "an active migration job already exists; cancel it or wait for it to finish")
			return
		}
		h.logger.Error("insert migration job", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to create job")
		return
	}

	if err := h.orch.StartJob(r.Context(), jobID); err != nil {
		h.logger.Error("start migration job", "job_id", jobID, "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to start job")
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, map[string]interface{}{
		"id":     jobID,
		"status": "pending",
	})
}

// GetMigrationStatus returns the status of the user's current migration job.
func (h *MigrationHandler) GetMigrationStatus(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var row struct {
		ID               int64
		SourceType       string
		Status           string
		ConflictStrategy string
		Progress         []byte
		ErrorLog         []byte
		StartedAt        *string
		CompletedAt      *string
		CreatedAt        string
	}
	err := h.pool.QueryRow(r.Context(), `
		SELECT id, source_type, status, conflict_strategy, progress, error_log, 
		       to_char(started_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
		       to_char(completed_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
		       to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		FROM migration_jobs
		WHERE user_id = $1 AND status != 'completed'
		ORDER BY created_at DESC LIMIT 1`,
		claims.UserID,
	).Scan(&row.ID, &row.SourceType, &row.Status, &row.ConflictStrategy,
		&row.Progress, &row.ErrorLog, &row.StartedAt, &row.CompletedAt, &row.CreatedAt)
	if err != nil {
		httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{"status": "none"})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"id":                row.ID,
		"source_type":       row.SourceType,
		"status":            row.Status,
		"conflict_strategy": row.ConflictStrategy,
		"progress":          json.RawMessage(row.Progress),
		"error_log":         json.RawMessage(row.ErrorLog),
		"started_at":        row.StartedAt,
		"completed_at":      row.CompletedAt,
		"created_at":        row.CreatedAt,
	})
}

// CancelMigration cancels the user's running migration job.
func (h *MigrationHandler) CancelMigration(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var jobID int64
	err := h.pool.QueryRow(r.Context(), `
		SELECT id FROM migration_jobs
		WHERE user_id = $1 AND status IN ('pending','testing','fetching','importing','paused')
		ORDER BY created_at DESC LIMIT 1`,
		claims.UserID,
	).Scan(&jobID)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "no active migration job")
		return
	}

	if err := h.orch.CancelJob(jobID); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to cancel job")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// TestIMAPConnection validates IMAP credentials without creating a job.
func (h *MigrationHandler) TestIMAPConnection(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var cfg migration.IMAPConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	// The connection test dials the caller-named origin under the shared SSRF
	// policy layer, so the allowlist content itself is administrator-owned:
	// reject caller-manufactured private-network exceptions instead of
	// building a connector that honors them.
	if err := migration.RejectUserSuppliedPrivatePolicy(cfg.PrivateHosts, cfg.PrivateCIDRs); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, err.Error())
		return
	}

	// Bound the whole test (dial + handshake + LOGIN + LIST). The connector's
	// dial and TLS-handshake deadlines do not extend to post-handshake command
	// I/O, so without this bound a hostile source server that goes quiet after
	// the handshake pins one goroutine + socket per request for as long as the
	// caller holds the HTTP connection open.
	ctx, cancel := context.WithTimeout(r.Context(), maxIMAPTestConnectionDuration)
	defer cancel()

	if err := h.testIMAPConnection(ctx, cfg); err != nil {
		h.logger.Warn("migration imap test connection failed", "error", err)
		httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
			"success": false,
			"error":   "Could not connect to the source server. Verify the server address and credentials.",
		})
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// UploadMigrationFiles handles ICS/VCF file uploads for migration.
func (h *MigrationHandler) UploadMigrationFiles(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	jobIDStr := r.URL.Query().Get("job_id")
	jobID, err := strconv.ParseInt(jobIDStr, 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid job_id")
		return
	}

	var ownerID int64
	err = h.pool.QueryRow(r.Context(), `SELECT user_id FROM migration_jobs WHERE id = $1`, jobID).Scan(&ownerID)
	if err != nil || ownerID != claims.UserID {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "migration job not found")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxMigrationUploadBytes)
	//nolint:gosec // G120: total body bounded by the MaxBytesReader above (maxMigrationUploadBytes).
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "failed to parse multipart form")
		return
	}

	data := &migration.UploadData{}
	if icsFile, _, err := r.FormFile("ics"); err == nil {
		data.ICS, _ = io.ReadAll(icsFile)
		icsFile.Close()
	}
	if vcfFile, _, err := r.FormFile("vcf"); err == nil {
		data.VCF, _ = io.ReadAll(vcfFile)
		vcfFile.Close()
	}

	if data.ICS == nil && data.VCF == nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "no ICS or VCF file provided")
		return
	}

	h.orch.StoreUpload(r.Context(), jobID, data)
	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"ics_size": len(data.ICS),
		"vcf_size": len(data.VCF),
	})
}

// PauseMigration pauses the user's running migration job.
func (h *MigrationHandler) PauseMigration(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	var jobID int64
	err := h.pool.QueryRow(r.Context(), `
		SELECT id FROM migration_jobs
		WHERE user_id = $1 AND status IN ('fetching','importing')
		ORDER BY created_at DESC LIMIT 1`,
		claims.UserID,
	).Scan(&jobID)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "no active migration job")
		return
	}
	if err := h.orch.PauseJob(jobID); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to pause job")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// ResumeMigration resumes the user's paused migration job.
func (h *MigrationHandler) ResumeMigration(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	var jobID int64
	err := h.pool.QueryRow(r.Context(), `
		SELECT id FROM migration_jobs
		WHERE user_id = $1 AND status = 'paused'
		ORDER BY created_at DESC LIMIT 1`,
		claims.UserID,
	).Scan(&jobID)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "no paused migration job")
		return
	}
	if err := h.orch.ResumeJob(jobID); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to resume job")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// DeleteMigrationHistory deletes completed/cancelled/failed migration jobs for the user.
func (h *MigrationHandler) DeleteMigrationHistory(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	result, err := h.pool.Exec(r.Context(), `
		DELETE FROM migration_jobs
		WHERE user_id = $1 AND status IN ('completed','cancelled','failed')`,
		claims.UserID,
	)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "delete failed")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"deleted": result.RowsAffected(),
	})
}

// ── Admin endpoints ─────────────────────────────────────────────────────

// AdminListJobs lists all migration jobs (filterable).
func (h *MigrationHandler) AdminListJobs(w http.ResponseWriter, r *http.Request) {
	statusFilter := r.URL.Query().Get("status")
	userFilter := r.URL.Query().Get("user_id")

	query := `SELECT id, user_id, source_type, status, conflict_strategy, progress, error_log, 
	               to_char(started_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
	               to_char(completed_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
	               to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
	        FROM migration_jobs WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if statusFilter != "" {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, statusFilter)
		argIdx++
	}
	if userFilter != "" {
		query += fmt.Sprintf(" AND user_id = $%d", argIdx)
		args = append(args, userFilter)
		argIdx++
	}
	query += " ORDER BY created_at DESC LIMIT 100"

	rows, err := h.pool.Query(r.Context(), query, args...)
	if err != nil {
		h.logger.Error("admin list migration jobs", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	type jobRow struct {
		ID               int64           `json:"id"`
		UserID           int64           `json:"user_id"`
		SourceType       string          `json:"source_type"`
		Status           string          `json:"status"`
		ConflictStrategy string          `json:"conflict_strategy"`
		Progress         json.RawMessage `json:"progress"`
		ErrorLog         json.RawMessage `json:"error_log"`
		StartedAt        *string         `json:"started_at"`
		CompletedAt      *string         `json:"completed_at"`
		CreatedAt        string          `json:"created_at"`
	}

	jobs := []jobRow{}
	for rows.Next() {
		var j jobRow
		if err := rows.Scan(&j.ID, &j.UserID, &j.SourceType, &j.Status, &j.ConflictStrategy,
			&j.Progress, &j.ErrorLog, &j.StartedAt, &j.CompletedAt, &j.CreatedAt); err != nil {
			continue
		}
		jobs = append(jobs, j)
	}
	httputil.WriteJSON(w, http.StatusOK, jobs)
}

// AdminGetJob returns detail for a single migration job.
func (h *MigrationHandler) AdminGetJob(w http.ResponseWriter, r *http.Request) {
	jobID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid job id")
		return
	}

	var row struct {
		ID               int64
		UserID           int64
		SourceType       string
		Status           string
		ConflictStrategy string
		Progress         []byte
		ErrorLog         []byte
		StartedAt        *string
		CompletedAt      *string
		CreatedAt        string
	}
	err = h.pool.QueryRow(r.Context(), `
		SELECT id, user_id, source_type, status, conflict_strategy, progress, error_log,
		       to_char(started_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
		       to_char(completed_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
		       to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		FROM migration_jobs WHERE id = $1`, jobID,
	).Scan(&row.ID, &row.UserID, &row.SourceType, &row.Status, &row.ConflictStrategy,
		&row.Progress, &row.ErrorLog, &row.StartedAt, &row.CompletedAt, &row.CreatedAt)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "job not found")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"id":                row.ID,
		"user_id":           row.UserID,
		"source_type":       row.SourceType,
		"status":            row.Status,
		"conflict_strategy": row.ConflictStrategy,
		"progress":          json.RawMessage(row.Progress),
		"error_log":         json.RawMessage(row.ErrorLog),
		"started_at":        row.StartedAt,
		"completed_at":      row.CompletedAt,
		"created_at":        row.CreatedAt,
	})
}

// AdminCancelJob cancels any migration job.
func (h *MigrationHandler) AdminCancelJob(w http.ResponseWriter, r *http.Request) {
	jobID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid job id")
		return
	}
	if err := h.orch.CancelJob(jobID); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to cancel job")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// AdminRetryJob retries a failed/cancelled migration job.
func (h *MigrationHandler) AdminRetryJob(w http.ResponseWriter, r *http.Request) {
	jobID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid job id")
		return
	}
	if err := h.orch.StartJob(r.Context(), jobID); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to retry job")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// AdminPauseJob pauses any migration job.
func (h *MigrationHandler) AdminPauseJob(w http.ResponseWriter, r *http.Request) {
	jobID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid job id")
		return
	}
	if err := h.orch.PauseJob(jobID); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to pause job")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// AdminResumeJob resumes any paused migration job.
func (h *MigrationHandler) AdminResumeJob(w http.ResponseWriter, r *http.Request) {
	jobID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid job id")
		return
	}
	if err := h.orch.ResumeJob(jobID); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to resume job")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// AdminDeleteJob deletes any migration job.
func (h *MigrationHandler) AdminDeleteJob(w http.ResponseWriter, r *http.Request) {
	jobID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid job id")
		return
	}
	result, err := h.pool.Exec(r.Context(), `DELETE FROM migration_jobs WHERE id = $1`, jobID)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if result.RowsAffected() == 0 {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "job not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Global source config endpoints ──────────────────────────────────────

// SaveGlobalIMAPConfig stores the global IMAP defaults.
func (h *MigrationHandler) SaveGlobalIMAPConfig(w http.ResponseWriter, r *http.Request) {
	var cfg migration.GlobalIMAPConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if cfg.Host == "" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "host is required")
		return
	}
	if cfg.Port == 0 {
		cfg.Port = 993
	}
	if cfg.TLSMode == "" {
		cfg.TLSMode = "tls"
	}
	// Webmail tls_mode normalization: the admin console's SSL checkbox sends
	// the legacy value "ssl", which the IMAP connector's dialer does not
	// implement (its implicit-TLS mode is "tls"). Normalize at save time so a
	// stored profile is dialable instead of failing every later job with
	// "unsupported IMAP TLS mode".
	if cfg.TLSMode == "ssl" {
		cfg.TLSMode = "tls"
	}
	// Save-time validation: the profile is only stored when it would build a
	// working, policy-safe connector — TLS mode implemented by the dialer and
	// a compilable private-network policy (loopback/link-local/metadata stay
	// permanently blocked, never allowlistable).
	if err := migration.ValidateGlobalIMAPProfile(cfg); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, err.Error())
		return
	}
	raw, _ := json.Marshal(cfg)
	_, err := h.pool.Exec(r.Context(),
		`INSERT INTO system_config (key, value) VALUES ('imap.defaults', $1)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		string(raw))
	if err != nil {
		h.logger.Error("save global imap config", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "save failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SaveGlobalEWSConfig stores the global EWS configuration.
func (h *MigrationHandler) SaveGlobalEWSConfig(w http.ResponseWriter, r *http.Request) {
	var cfg migration.GlobalEWSConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if cfg.ServerURL == "" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "serverURL is required")
		return
	}
	if cfg.Username == "" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "username is required")
		return
	}
	if cfg.AuthMode == "" {
		// Impersonation lets the service account act AS any source mailbox —
		// it requires explicit administrator opt-in, never an implicit
		// default. Empty saves get per_user; already-stored configs are
		// left untouched (no migration).
		cfg.AuthMode = migration.EWSAuthModePerUser
	}
	// Save-time validation: apply the same policy + URL checks the connector
	// factory enforces at construction (compilable private-network policy with
	// permanent denials intact, https server URL acceptable under that policy)
	// so an unusable profile is rejected here instead of failing every job
	// that later inherits it.
	if err := migration.ValidateGlobalEWSProfile(cfg); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, err.Error())
		return
	}

	systemKey, _ := migration.DeriveKey(h.orch.EncryptionRoot(), "system")
	enc, err := migration.EncryptConfigAny(cfg, systemKey)
	if err != nil {
		h.logger.Error("encrypt global ews config", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "encryption failed")
		return
	}
	wrapper := map[string]string{"_enc": base64.StdEncoding.EncodeToString(enc)}
	raw, _ := json.Marshal(wrapper)
	_, err = h.pool.Exec(r.Context(),
		`INSERT INTO system_config (key, value, encrypted) VALUES ('ews.global', $1, TRUE)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, encrypted = TRUE, updated_at = now()`,
		string(raw))
	if err != nil {
		h.logger.Error("save global ews config", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "save failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SaveGlobalM365Config stores the M365 app credentials.
func (h *MigrationHandler) SaveGlobalM365Config(w http.ResponseWriter, r *http.Request) {
	var cfg migration.MigrationM365Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if cfg.ClientID == "" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "client_id is required")
		return
	}
	if cfg.ClientSecret == "" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "client_secret is required")
		return
	}

	systemKey, _ := migration.DeriveKey(h.orch.EncryptionRoot(), "system")
	enc, err := migration.EncryptConfigAny(cfg, systemKey)
	if err != nil {
		h.logger.Error("encrypt m365 config", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "encryption failed")
		return
	}
	wrapper := map[string]string{"_enc": base64.StdEncoding.EncodeToString(enc)}
	raw, _ := json.Marshal(wrapper)
	_, err = h.pool.Exec(r.Context(),
		`INSERT INTO system_config (key, value, encrypted) VALUES ('m365.app', $1, TRUE)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, encrypted = TRUE, updated_at = now()`,
		string(raw))
	if err != nil {
		h.logger.Error("save m365 config", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "save failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetGlobalSourceConfig returns the global config for a source type (secrets redacted).
func (h *MigrationHandler) GetGlobalSourceConfig(w http.ResponseWriter, r *http.Request) {
	sourceType := r.PathValue("type")

	keyMap := map[string]string{
		"imap": "imap.defaults",
		"ews":  "ews.global",
		"m365": "m365.app",
	}
	configKey, ok := keyMap[sourceType]
	if !ok {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "unknown source type")
		return
	}

	var value []byte
	var encrypted bool
	err := h.pool.QueryRow(r.Context(),
		`SELECT value, encrypted FROM system_config WHERE key = $1`, configKey,
	).Scan(&value, &encrypted)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "config not found")
		return
	}

	if sourceType == "imap" && len(value) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.Write(value)
		return
	}

	if encrypted {
		var wrapper struct {
			Enc string `json:"_enc"`
		}
		if err := json.Unmarshal(value, &wrapper); err != nil {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "invalid encrypted config")
			return
		}
		encBytes, err := base64.StdEncoding.DecodeString(wrapper.Enc)
		if err != nil {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "invalid encrypted data")
			return
		}
		systemKey, _ := migration.DeriveKey(h.orch.EncryptionRoot(), "system")
		switch sourceType {
		case "ews":
			var cfg migration.GlobalEWSConfig
			if err := migration.DecryptConfigAny(encBytes, systemKey, &cfg); err == nil {
				cfg.Password = ""
				httputil.WriteJSON(w, http.StatusOK, cfg)
				return
			}
		case "m365":
			var cfg migration.MigrationM365Config
			if err := migration.DecryptConfigAny(encBytes, systemKey, &cfg); err == nil {
				cfg.ClientSecret = ""
				httputil.WriteJSON(w, http.StatusOK, cfg)
				return
			}
		}
	}

	httputil.WriteProblemStatus(w, http.StatusNotFound, "config not found")
}

// DeleteGlobalSourceConfig clears the global config for a source type.
func (h *MigrationHandler) DeleteGlobalSourceConfig(w http.ResponseWriter, r *http.Request) {
	sourceType := r.PathValue("type")
	keyMap := map[string]string{
		"imap": "imap.defaults",
		"ews":  "ews.global",
		"m365": "m365.app",
	}
	configKey, ok := keyMap[sourceType]
	if !ok {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "unknown source type")
		return
	}
	_, err := h.pool.Exec(r.Context(),
		`DELETE FROM system_config WHERE key = $1`, configKey)
	if err != nil {
		h.logger.Error("delete global config", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "delete failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// M365Connect redirects the admin to the Microsoft admin consent page.
//
// It mints a SERVER-SIDE, expiring, SINGLE-USE consent authorization
// (m365_consent_states, V234) bound to the authenticated admin, and puts its
// random token in the OAuth state. The callback consumes that row before
// trusting the consent result, so the state is unforgeable: the
// cookie/query-equality check below is only defense in depth —
// authorization is the server-side row, not any caller-supplied value.
func (h *MigrationHandler) M365Connect(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	cloud := r.URL.Query().Get("cloud")
	if cloud == "" {
		cloud = "global"
	}
	if cloud != "global" && cloud != "china" {
		http.Error(w, "unknown cloud", http.StatusBadRequest)
		return
	}

	systemKey, _ := migration.DeriveKey(h.orch.EncryptionRoot(), "system")
	var raw json.RawMessage
	var encrypted bool
	err := h.pool.QueryRow(r.Context(),
		`SELECT value, encrypted FROM system_config WHERE key = 'm365.app'`,
	).Scan(&raw, &encrypted)
	if err != nil || !encrypted {
		http.Error(w, "M365 config not found — save client ID and secret first", http.StatusBadRequest)
		return
	}
	var wrapper struct {
		Enc string `json:"_enc"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		http.Error(w, "failed to parse M365 config", http.StatusInternalServerError)
		return
	}
	encBytes, _ := base64.StdEncoding.DecodeString(wrapper.Enc)
	var cfg migration.MigrationM365Config
	if err := migration.DecryptConfigAny(encBytes, systemKey, &cfg); err != nil {
		http.Error(w, "failed to read M365 config", http.StatusInternalServerError)
		return
	}

	authBase := "https://login.microsoftonline.com"
	if cloud == "china" {
		authBase = "https://login.chinacloudapi.cn"
	}

	// Mint the server-bound consent authorization through its owning reducer:
	// a 32-byte random token stored server-side, owned by THIS admin, expiring
	// after a short window (expiry stamped from the database clock). The same
	// reducer call prunes this actor's spent/expired rows so abandoned consent
	// attempts cannot accumulate. RunUserScoped supplies the FORCE-RLS actor
	// GUC; the reducer itself binds every statement to p_actor (R1/R3).
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		http.Error(w, "failed to generate state token", http.StatusInternalServerError)
		return
	}
	stateToken := hex.EncodeToString(stateBytes)
	err = dbscope.RunUserScoped(r.Context(), h.pool, claims.UserID, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(),
			`SELECT m365_consent_state_mint($1, $2, $3, $4)`,
			claims.UserID, stateToken, cloud, int(m365ConsentStateTTL.Seconds()))
		return err
	})
	if err != nil {
		h.logger.Error("mint m365 consent state", "error", err)
		http.Error(w, "failed to start consent flow", http.StatusInternalServerError)
		return
	}
	// Secure follows the client-facing scheme (sanitized X-Forwarded-Proto with
	// connection-TLS fallback, mirroring the CSRF middleware's expectedScheme):
	// behind the supported TLS-terminating proxy r.TLS is nil, and the previous
	// r.TLS-only gate sent the OAuth state bearer cookie without Secure.
	//nolint:gosec // G124: HttpOnly + SameSite set; Secure derives from the client-facing scheme (proxy XFP or connection TLS).
	http.SetCookie(w, &http.Cookie{
		Name:     "m365_oauth_state",
		Value:    stateToken,
		Path:     "/admin/migration/m365",
		MaxAge:   int(m365ConsentStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   clientFacingScheme(r) == "https",
		SameSite: http.SameSiteLaxMode,
	})

	redirectURI := fmt.Sprintf("https://%s/admin/migration/m365/callback", r.Host)
	consentURL := fmt.Sprintf(
		"%s/organizations/adminconsent?client_id=%s&redirect_uri=%s&state=%s",
		authBase, cfg.ClientID, url.QueryEscape(redirectURI), url.QueryEscape(stateToken),
	)
	http.Redirect(w, r, consentURL, http.StatusFound)
}

// M365Callback handles the OAuth admin consent callback.
//
// Authorization model (D-MAILSERVER-INTERNAL-USER-F-002 remediation): the
// callback is an authenticated, mail.pipeline-gated mutation. The only
// accepted credential for the consent itself is the SERVER-SIDE consent
// authorization minted by M365Connect for THIS admin (m365_consent_states,
// V234), consumed atomically on first use. A matching cookie/query state pair
// without such a row is worthless — equality of two caller-owned values is
// not authentication. The tenant id is persisted only AFTER the candidate
// connection verifies, together with the consent-completion audit row.
func (h *MigrationHandler) M365Callback(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	// Mutation-specific permission BEFORE any state consumption or config
	// write — mirrors the requireMailPipeline middleware on this route (the
	// handler-side check keeps the ordering guarantee at the seam that owns
	// the write).
	if !claims.HasPermission(permissions.PermMailPipeline) {
		httputil.WriteProblemStatus(w, http.StatusForbidden, "mail.pipeline permission required")
		return
	}

	// Defense-in-depth CSRF check against the connect-issued cookie. On
	// mismatch, never log the state material itself: the pending state is the
	// bearer secret for this consent, and echoing it would turn every log
	// line into a disclosure channel.
	stateCookie, csrfErr := r.Cookie("m365_oauth_state")
	state := r.URL.Query().Get("state")
	if csrfErr != nil || state == "" || stateCookie.Value != state {
		h.clearM365StateCookie(w, r)
		if csrfErr != nil {
			h.logger.Warn("m365 callback: missing state cookie")
		} else {
			h.logger.Warn("m365 callback: state mismatch")
		}
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}
	h.clearM365StateCookie(w, r)

	adminConsent := r.URL.Query().Get("admin_consent")
	tenantID := r.URL.Query().Get("tenant")
	errorDesc := r.URL.Query().Get("error_description")

	if adminConsent != "True" || tenantID == "" {
		msg := "Admin consent was not granted"
		if errorDesc != "" {
			msg = errorDesc
		}
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	// Consume the server-issued consent authorization through its owning
	// reducer: SINGLE-USE, bound to the authenticated admin, and dead once
	// expired — one atomic UPDATE, so concurrent callbacks for the same state
	// have exactly one winner. An actor-bound predicate (R1/R3) scopes the
	// mutation even before the RLS policy does. BZ002 → fabricated, replayed,
	// or expired state.
	var cloud string
	err := dbscope.RunUserScoped(r.Context(), h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(),
			`SELECT m365_consent_state_consume($1, $2)`,
			claims.UserID, state,
		).Scan(&cloud)
	})
	if err != nil {
		h.logger.Warn("m365 callback: consent state rejected",
			"reason", "no unconsumed, unexpired server-side consent authorization for the caller")
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}

	systemKey, _ := migration.DeriveKey(h.orch.EncryptionRoot(), "system")
	var raw json.RawMessage
	var encrypted bool
	err = h.pool.QueryRow(r.Context(),
		`SELECT value, encrypted FROM system_config WHERE key = 'm365.app'`,
	).Scan(&raw, &encrypted)
	if err != nil || !encrypted {
		http.Error(w, "M365 config not found", http.StatusBadRequest)
		return
	}
	var wrapper struct {
		Enc string `json:"_enc"`
	}
	json.Unmarshal(raw, &wrapper)
	encBytes, _ := base64.StdEncoding.DecodeString(wrapper.Enc)

	var cfg migration.MigrationM365Config
	if err := migration.DecryptConfigAny(encBytes, systemKey, &cfg); err != nil {
		http.Error(w, "failed to read M365 config", http.StatusInternalServerError)
		return
	}

	// Candidate config — nothing below persists until verification succeeds.
	cfg.TenantID = tenantID
	cfg.Cloud = cloud

	// Verify-before-persist: the tenant binding is written ONLY after the
	// candidate connection actually works. A failed verification persists
	// nothing (the consent state is already spent — restart the flow).
	if err := h.verifyM365Tenant(r.Context(), cfg); err != nil {
		h.logger.Warn("m365 callback: tenant connection verification failed")
		http.Error(w, fmt.Sprintf("M365 test connection failed: %v", err), http.StatusInternalServerError)
		return
	}

	reEnc, err := migration.EncryptConfigAny(cfg, systemKey)
	if err != nil {
		http.Error(w, "failed to store tenant ID", http.StatusInternalServerError)
		return
	}
	newWrapper := map[string]string{"_enc": base64.StdEncoding.EncodeToString(reEnc)}
	rawNew, _ := json.Marshal(newWrapper)

	// Persist the verified tenant binding and the consent-completion audit
	// row through the owning reducer in ONE transaction: either both land or
	// neither does. The reducer hard-codes the 'm365.app' key and routes the
	// audit row through the audit_write choke point; the tier stays computed
	// here (audit.TierForPerm) as the single source of truth.
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		http.Error(w, "failed to save config", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if _, err := tx.Exec(r.Context(),
		`SELECT m365_consent_complete($1, $2, $3, $4)`,
		claims.UserID, string(rawNew),
		fmt.Sprintf("tenant=%s cloud=%s", tenantID, cloud),
		audit.TierForPerm(permissions.PermMailPipeline)); err != nil {
		h.logger.Error("m365 consent completion", "error", err)
		http.Error(w, "failed to save config", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		http.Error(w, "failed to save config", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/migration?m365_connected=true", http.StatusFound)
}

// clearM365StateCookie clears the m365_oauth_state cookie with the same
// attribute set used to issue it (Secure from the client-facing scheme so the
// clear matches the issued cookie behind a TLS-terminating proxy as well as on
// direct TLS; plain-HTTP dev keeps working).
func (h *MigrationHandler) clearM365StateCookie(w http.ResponseWriter, r *http.Request) {
	//nolint:gosec // G124: HttpOnly + SameSite set; Secure derives from the client-facing scheme to match the issued cookie.
	http.SetCookie(w, &http.Cookie{Name: "m365_oauth_state", Value: "", MaxAge: -1, Path: "/admin/migration/m365", HttpOnly: true, Secure: clientFacingScheme(r) == "https", SameSite: http.SameSiteLaxMode})
}

// ── Helpers ──────────────────────────────────────────────────────────────

// hasGlobalSourceConfig returns true if a global config exists for the given source type.
func (h *MigrationHandler) hasGlobalSourceConfig(ctx context.Context, sourceType string) bool {
	keyMap := map[string]string{
		"imap": "imap.defaults",
		"ews":  "ews.global",
		"m365": "m365.app",
	}
	configKey, ok := keyMap[sourceType]
	if !ok {
		return false
	}
	var exists bool
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM system_config WHERE key = $1)`, configKey,
	).Scan(&exists)
	return exists
}

func (h *MigrationHandler) getUserMailboxID(ctx context.Context, userID int64) int64 {
	var id int64
	_ = h.pool.QueryRow(ctx, `SELECT id FROM mailboxes WHERE user_id = $1 LIMIT 1`, userID).Scan(&id)
	return id
}

// getMailboxIDByEmail looks up a mailbox ID by the owner's email address.
func (h *MigrationHandler) getMailboxIDByEmail(ctx context.Context, email string) int64 {
	var id int64
	_ = h.pool.QueryRow(ctx,
		`SELECT m.id FROM mailboxes m
		 JOIN users u ON m.user_id = u.id
		 WHERE u.email = $1 LIMIT 1`, email).Scan(&id)
	return id
}

// insertMigrationJob creates a pending migration job row and returns its ID.
func (h *MigrationHandler) insertMigrationJob(ctx context.Context, userID int64,
	sourceType string, sourceConfigEnc []byte, mailboxID int64, conflictStrategy string) (int64, error) {
	var jobID int64
	err := h.pool.QueryRow(ctx, `
		INSERT INTO migration_jobs (user_id, source_type, source_config_enc, target_mailbox_id, conflict_strategy, status)
		VALUES ($1, $2, $3, $4, $5, 'pending')
		RETURNING id`,
		userID, sourceType, sourceConfigEnc, mailboxID, conflictStrategy,
	).Scan(&jobID)
	return jobID, err
}
