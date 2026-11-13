// Package mailrecovery implements the bounded HTTP translation and quarantine
// byte plane for client-assisted recovery. PostgreSQL reducers remain the sole
// authority for incident lifecycle and mailbox mutation.
package mailrecovery

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/auth"
	servercontinuity "setjoin.com/mailserver/internal/continuity"
	sharedcontinuity "setjoin.com/shared/continuity"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/toggle"
)

const maxJSONBody = 1 << 20

type queryDB interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

type MalwareScanner interface {
	Scan([]byte) (string, error)
}

type Handler struct {
	db         queryDB
	store      objectStore
	continuity *servercontinuity.Service
	toggles    *toggle.FeatureFlags
	scanner    MalwareScanner
	logger     *slog.Logger
	now        func() time.Time
}

func NewHandler(pool *pgxpool.Pool, minioClient *minio.Client, bucket string, toggles *toggle.FeatureFlags,
	continuity *servercontinuity.Service, scanner MalwareScanner, logger *slog.Logger) *Handler {
	var store objectStore
	if minioClient != nil && bucket != "" {
		store = minioStore{client: minioClient, bucket: bucket}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{db: pool, store: store, continuity: continuity, toggles: toggles, scanner: scanner, logger: logger, now: time.Now}
}

// RunCleanup reaps expired sessions and their exact quarantine chunk objects.
// It runs independent of feature enablement so disabling intake never strands
// residue accepted while the flag was on.
func (h *Handler) RunCleanup(ctx context.Context) {
	if h == nil || h.db == nil || h.store == nil {
		return
	}
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		h.cleanupTerminalChunks(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (h *Handler) cleanupTerminalChunks(ctx context.Context) {
	var expired int
	if err := h.db.QueryRow(ctx, `SELECT mail_recovery_uploads_expire()`).Scan(&expired); err != nil && !errors.Is(err, context.Canceled) {
		h.logger.Warn("recovery upload expiry failed", "error", err)
		return
	}
	rows, err := h.db.Query(ctx, `
		SELECT chunk.session_id,chunk.item_id,chunk.start_offset,chunk.object_key
		  FROM mail_recovery_upload_chunks chunk
		  JOIN mail_recovery_upload_sessions session ON session.id=chunk.session_id
		 WHERE session.status IN ('quarantined','deduplicated','rejected','aborted','expired')
		 ORDER BY chunk.created_at LIMIT 256`)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			h.logger.Warn("recovery chunk cleanup scan failed", "error", err)
		}
		return
	}
	type cleanupItem struct {
		sessionID uuid.UUID
		itemID    string
		offset    int64
		key       string
	}
	items := make([]cleanupItem, 0, 256)
	for rows.Next() {
		var item cleanupItem
		if err := rows.Scan(&item.sessionID, &item.itemID, &item.offset, &item.key); err != nil {
			h.logger.Warn("recovery chunk cleanup row invalid", "error", err)
			continue
		}
		items = append(items, item)
	}
	rows.Close()
	for _, item := range items {
		if err := h.store.Remove(ctx, item.key); err != nil {
			h.logger.Warn("recovery chunk cleanup deferred", "key", item.key, "error", err)
			continue
		}
		var removed bool
		if err := h.db.QueryRow(ctx, `SELECT mail_recovery_chunk_cleanup_complete($1,$2,$3,$4)`,
			item.sessionID, item.itemID, item.offset, item.key).Scan(&removed); err != nil {
			h.logger.Warn("recovery chunk cleanup acknowledgement failed", "key", item.key, "error", err)
		}
	}
}

func (h *Handler) enabled() bool {
	return h != nil && h.db != nil && h.store != nil && h.continuity != nil && h.toggles != nil &&
		h.toggles.IsEnabled(toggle.FeatureUpgradeRecoveryIntake)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid recovery request")
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "recovery request must contain exactly one JSON object")
		return false
	}
	return true
}

func claimsForRecovery(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil || claims.UserID <= 0 {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return nil, false
	}
	return claims, true
}

func exactReason(w http.ResponseWriter, r *http.Request, reason string) bool {
	reason = strings.TrimSpace(reason)
	if len(reason) < 8 || len(reason) > 1024 || strings.ContainsAny(reason, "\r\n\x00") ||
		strings.TrimSpace(r.Header.Get("X-Audit-Reason")) != reason {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "body reason must exactly match X-Audit-Reason and contain 8-1024 safe characters")
		return false
	}
	return true
}

func exactIdempotency(w http.ResponseWriter, r *http.Request, value string) (uuid.UUID, bool) {
	if value == "" || strings.TrimSpace(r.Header.Get("Idempotency-Key")) != value {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "body idempotencyKey must exactly match Idempotency-Key")
		return uuid.Nil, false
	}
	id, err := uuid.Parse(value)
	if err != nil || id == uuid.Nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid recovery idempotency key")
		return uuid.Nil, false
	}
	return id, true
}

func parsePositiveDecimal(value string) (int64, error) {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 || strconv.FormatInt(parsed, 10) != value {
		return 0, errors.New("invalid positive decimal")
	}
	return parsed, nil
}

func validIncidentEvidence(evidence map[string]string, mailboxIDs []int64) bool {
	if len(evidence) < 1 || len(evidence) > 100 || len(evidence) != len(mailboxIDs) {
		return false
	}
	scope := make(map[string]struct{}, len(mailboxIDs))
	for _, mailboxID := range mailboxIDs {
		key := strconv.FormatInt(mailboxID, 10)
		if _, duplicate := scope[key]; duplicate {
			return false
		}
		scope[key] = struct{}{}
		value, ok := evidence[key]
		if !ok || len(value) != 64 || value != strings.ToLower(value) {
			return false
		}
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 32 {
			return false
		}
	}
	return true
}

func validIncidentExpiry(now, expiresAt time.Time) bool {
	return !expiresAt.IsZero() && expiresAt.After(now) && !expiresAt.After(now.Add(7*24*time.Hour))
}

func parseUUIDPath(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	value, err := uuid.Parse(r.PathValue(name))
	if err != nil || value == uuid.Nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid recovery identifier")
		return uuid.Nil, false
	}
	return value, true
}

func (h *Handler) queryRaw(w http.ResponseWriter, r *http.Request, status int, query string, args ...any) {
	if h == nil || h.db == nil {
		httputil.WriteProblemStatus(w, http.StatusServiceUnavailable, "recovery control plane unavailable")
		return
	}
	var raw json.RawMessage
	if err := h.db.QueryRow(r.Context(), query, args...).Scan(&raw); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "recovery control operation failed")
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func (h *Handler) requireEnabled(w http.ResponseWriter) bool {
	if !h.enabled() {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "client-assisted recovery is disabled")
		return false
	}
	return true
}

func (h *Handler) AdminList(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsForRecovery(w, r)
	if !ok || !h.requireEnabled(w) {
		return
	}
	limit := 50
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 100 {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid recovery list limit")
			return
		}
		limit = parsed
	}
	var before *time.Time
	if value := r.URL.Query().Get("before"); value != "" {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid recovery list cursor")
			return
		}
		before = &parsed
	}
	status := r.URL.Query().Get("status")
	if status != "" && status != "open" && status != "closed" && status != "expired" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid recovery incident status")
		return
	}
	var statusArg any
	if status != "" {
		statusArg = status
	}
	h.queryRaw(w, r, http.StatusOK, `SELECT mail_recovery_incident_list($1,$2,$3,$4)`, claims.UserID, limit, before, statusArg)
}

func (h *Handler) UserIncidents(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsForRecovery(w, r)
	if !ok || !h.requireEnabled(w) {
		return
	}
	h.queryRaw(w, r, http.StatusOK, `SELECT mail_recovery_user_incident_list($1)`, claims.UserID)
}

func (h *Handler) AdminSignals(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsForRecovery(w, r)
	if !ok || !h.requireEnabled(w) {
		return
	}
	limit := 100
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 100 {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid continuity signal limit")
			return
		}
		limit = parsed
	}
	h.queryRaw(w, r, http.StatusOK, `SELECT continuity_admin_status($1,$2)`, claims.UserID, limit)
}

func (h *Handler) AdminArtifacts(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsForRecovery(w, r)
	if !ok || !h.requireEnabled(w) {
		return
	}
	incidentID, ok := parseUUIDPath(w, r, "id")
	if !ok {
		return
	}
	limit := 100
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 100 {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid recovery artifact limit")
			return
		}
		limit = parsed
	}
	h.queryRaw(w, r, http.StatusOK, `SELECT mail_recovery_artifact_list($1,$2,$3)`, claims.UserID, incidentID, limit)
}

func (h *Handler) AdminOpen(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsForRecovery(w, r)
	if !ok || !h.requireEnabled(w) {
		return
	}
	var req struct {
		IncidentID       string            `json:"incidentId"`
		MailboxIDs       []string          `json:"mailboxIds"`
		Evidence         map[string]string `json:"evidence"`
		MinimumTimeline  string            `json:"minimumTimeline"`
		MaximumTimeline  string            `json:"maximumTimeline"`
		ExpiresAt        time.Time         `json:"expiresAt"`
		Reason           string            `json:"reason"`
		ApprovalRequired bool              `json:"approvalRequired"`
		IdempotencyKey   string            `json:"idempotencyKey"`
	}
	if !decodeJSON(w, r, &req) || !exactReason(w, r, req.Reason) {
		return
	}
	incidentID, incidentErr := uuid.Parse(req.IncidentID)
	idempotency, idemOK := exactIdempotency(w, r, req.IdempotencyKey)
	minTimeline, minErr := parsePositiveDecimal(req.MinimumTimeline)
	maxTimeline, maxErr := parsePositiveDecimal(req.MaximumTimeline)
	if incidentErr != nil || incidentID == uuid.Nil || !idemOK || minErr != nil || maxErr != nil || maxTimeline < minTimeline ||
		len(req.MailboxIDs) == 0 || len(req.MailboxIDs) > 100 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid recovery incident scope")
		return
	}
	mailboxIDs := make([]int64, 0, len(req.MailboxIDs))
	for _, value := range req.MailboxIDs {
		id, err := parsePositiveDecimal(value)
		if err != nil {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid recovery mailbox id")
			return
		}
		mailboxIDs = append(mailboxIDs, id)
	}
	now := h.now()
	if !validIncidentEvidence(req.Evidence, mailboxIDs) || !validIncidentExpiry(now, req.ExpiresAt) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid recovery incident evidence or expiry")
		return
	}
	binding, strong := recoveryStepUpBinding(claims, incidentID, now)
	if !strong {
		httputil.WriteProblemStatus(w, http.StatusForbidden, "fresh AAL2 step-up with two verified factors is required")
		return
	}
	evidence, _ := json.Marshal(req.Evidence)
	h.queryRaw(w, r, http.StatusCreated,
		`SELECT mail_recovery_incident_open($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,$10,$11)`,
		claims.UserID, incidentID, mailboxIDs, evidence, minTimeline, maxTimeline, req.ExpiresAt,
		strings.TrimSpace(req.Reason), req.ApprovalRequired, binding[:], idempotency)
}

type adminIncidentMutationKind uint8

const (
	adminIncidentApprove adminIncidentMutationKind = iota
	adminIncidentClose
)

func (h *Handler) adminIncidentMutation(w http.ResponseWriter, r *http.Request, mutation adminIncidentMutationKind) {
	claims, ok := claimsForRecovery(w, r)
	if !ok || !h.requireEnabled(w) {
		return
	}
	incidentID, ok := parseUUIDPath(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if !decodeJSON(w, r, &req) || !exactReason(w, r, req.Reason) {
		return
	}
	var query string
	switch mutation {
	case adminIncidentApprove:
		query = `SELECT mail_recovery_incident_approve($1,$2,$3)`
	case adminIncidentClose:
		query = `SELECT mail_recovery_incident_close($1,$2,$3)`
	default:
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "unsupported recovery incident mutation")
		return
	}
	h.queryRaw(w, r, http.StatusOK, query, claims.UserID, incidentID, strings.TrimSpace(req.Reason))
}

func (h *Handler) AdminApprove(w http.ResponseWriter, r *http.Request) {
	h.adminIncidentMutation(w, r, adminIncidentApprove)
}

func (h *Handler) AdminClose(w http.ResponseWriter, r *http.Request) {
	h.adminIncidentMutation(w, r, adminIncidentClose)
}

func (h *Handler) AdminAccept(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsForRecovery(w, r)
	if !ok || !h.requireEnabled(w) {
		return
	}
	quarantineID, ok := parseUUIDPath(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Resolution string `json:"resolution"`
		Reason     string `json:"reason"`
	}
	if !decodeJSON(w, r, &req) || !exactReason(w, r, req.Reason) {
		return
	}
	if req.Resolution != "accept" && req.Resolution != "accept_fork" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid recovery resolution")
		return
	}
	h.queryRaw(w, r, http.StatusOK, `SELECT mail_recovery_artifact_ingest($1,$2,$3,$4)`,
		claims.UserID, quarantineID, req.Resolution, strings.TrimSpace(req.Reason))
}

func (h *Handler) BeginUpload(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsForRecovery(w, r)
	if !ok || !h.requireEnabled(w) {
		return
	}
	var req struct {
		SessionID        string                         `json:"sessionId"`
		IncidentID       string                         `json:"incidentId"`
		AccountID        string                         `json:"accountId"`
		DeviceID         string                         `json:"deviceId"`
		ArtifactIdentity string                         `json:"artifactIdentity"`
		Eligibility      string                         `json:"eligibility"`
		Receipt          sharedcontinuity.SignedReceipt `json:"receipt"`
		Inventory        []InventoryItem                `json:"inventory"`
		ConsentedAt      time.Time                      `json:"consentedAt"`
		IdempotencyKey   string                         `json:"idempotencyKey"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	sessionID, sessionErr := uuid.Parse(req.SessionID)
	incidentID, incidentErr := uuid.Parse(req.IncidentID)
	deviceID, deviceErr := uuid.Parse(req.DeviceID)
	mailboxID, mailboxErr := parsePositiveDecimal(req.AccountID)
	idempotency, idemOK := exactIdempotency(w, r, req.IdempotencyKey)
	if sessionErr != nil || incidentErr != nil || deviceErr != nil || mailboxErr != nil || !idemOK ||
		sessionID == uuid.Nil || incidentID == uuid.Nil || deviceID == uuid.Nil ||
		(req.Eligibility != "received" && req.Eligibility != "sent-terminal") {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid recovery upload identity")
		return
	}
	if err := verifyOffer(h.continuity, req.Receipt, req.AccountID, h.now()); err != nil {
		h.logger.Warn("recovery receipt rejected", "error", err, "user", claims.UserID)
		httputil.WriteProblemStatus(w, http.StatusForbidden, "recovery receipt verification failed")
		return
	}
	eligibility, err := signedEligibility(req.Receipt, req.Eligibility)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := verifyArtifactIdentity(req.Receipt, req.ArtifactIdentity); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := validateInventory(req.Receipt, req.Inventory); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, err.Error())
		return
	}
	receiptJSON, _ := json.Marshal(req.Receipt)
	inventoryJSON, _ := json.Marshal(req.Inventory)
	h.queryRaw(w, r, http.StatusCreated,
		`SELECT mail_recovery_upload_begin($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10,$11)`,
		claims.UserID, sessionID, incidentID, mailboxID, deviceID, req.ArtifactIdentity, eligibility,
		receiptJSON, inventoryJSON, req.ConsentedAt, idempotency)
}

func (h *Handler) PutChunk(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsForRecovery(w, r)
	if !ok || !h.requireEnabled(w) {
		return
	}
	sessionID, ok := parseUUIDPath(w, r, "sessionId")
	if !ok {
		return
	}
	if err := h.putChunk(r.Context(), claims.UserID, sessionID, r.PathValue("itemId"), r.Header.Get("Content-Range"), r.Body); err != nil {
		h.writeOperationError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) CommitItem(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsForRecovery(w, r)
	if !ok || !h.requireEnabled(w) {
		return
	}
	sessionID, ok := parseUUIDPath(w, r, "sessionId")
	if !ok {
		return
	}
	result, err := h.commitItem(r.Context(), claims.UserID, sessionID, r.PathValue("itemId"))
	if err != nil {
		h.writeOperationError(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, result)
}

func (h *Handler) Finalize(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsForRecovery(w, r)
	if !ok || !h.requireEnabled(w) {
		return
	}
	sessionID, ok := parseUUIDPath(w, r, "sessionId")
	if !ok {
		return
	}
	result, err := h.finalize(r.Context(), claims.UserID, sessionID)
	if err != nil {
		h.writeOperationError(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, result)
}

func (h *Handler) Abort(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsForRecovery(w, r)
	if !ok || !h.requireEnabled(w) {
		return
	}
	sessionID, ok := parseUUIDPath(w, r, "sessionId")
	if !ok {
		return
	}
	var raw json.RawMessage
	if err := h.db.QueryRow(r.Context(), `SELECT mail_recovery_upload_abort($1,$2)`, claims.UserID, sessionID).Scan(&raw); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "recovery upload abort failed")
		}
		return
	}
	var result struct {
		ObjectKeys []string `json:"objectKeys"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "recovery upload abort result was invalid")
		return
	}
	for _, key := range result.ObjectKeys {
		if err := h.store.Remove(r.Context(), key); err != nil {
			h.logger.Warn("aborted recovery chunk cleanup deferred", "key", key, "error", err)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ForkConsent(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsForRecovery(w, r)
	if !ok || !h.requireEnabled(w) {
		return
	}
	quarantineID, ok := parseUUIDPath(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		DeviceID string `json:"deviceId"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	deviceID, err := uuid.Parse(req.DeviceID)
	if err != nil || deviceID == uuid.Nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid recovery device id")
		return
	}
	h.queryRaw(w, r, http.StatusOK, `SELECT mail_recovery_fork_consent($1,$2,$3)`, claims.UserID, quarantineID, deviceID)
}

func (h *Handler) writeOperationError(w http.ResponseWriter, r *http.Request, err error) {
	var reducer reducerFailure
	if errors.As(err, &reducer) && reducererr.WriteClassified(w, r, reducer.err) {
		return
	}
	h.logger.Warn("mail recovery operation failed", "error", err)
	httputil.WriteProblemStatus(w, http.StatusBadRequest, "mail recovery operation failed")
}
