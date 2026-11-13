package admin

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/reducererr"
)

func (h *IdentityHandler) identityRuntimeArgs() []any {
	return []any{
		h.runtime.ExpectedSchemaVersion,
		h.runtime.WorkerDSNReady,
		h.runtime.OwnerDSNReady,
		h.runtime.DirectDSNReady,
		h.runtime.AuthserverConfigured,
		h.sourceSecrets != nil,
	}
}

func (h *IdentityHandler) IdentityDoctor(w http.ResponseWriter, r *http.Request) {
	if !requireUnscopedIdentityAdmin(w, r) || !h.requireIdentityWorker(w) {
		return
	}
	sourceKey := strings.TrimSpace(r.URL.Query().Get("source"))
	if sourceKey != "" && !validIdentitySourceKey(sourceKey) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid identity source key")
		return
	}
	args := append(h.identityRuntimeArgs(), nullableString(sourceKey))
	var raw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(), `
		SELECT identity_doctor($1,$2,$3,$4,$5,$6,$7)
	`, args...).Scan(&raw); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError,
				"identity doctor failed")
		}
		return
	}
	writeIdentityRawJSON(w, r, http.StatusOK, raw, "")
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func (h *IdentityHandler) IdentityInventoryExport(w http.ResponseWriter, r *http.Request) {
	if !requireUnscopedIdentityAdmin(w, r, permissions.PermAuditExport) ||
		!h.requireIdentityWorker(w) {
		return
	}
	var raw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(),
		`SELECT identity_inventory_export()`).Scan(&raw); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError,
				"identity inventory export failed")
		}
		return
	}
	sum := sha256.Sum256(raw)
	w.Header().Set("Content-Disposition",
		`attachment; filename="setjoin-identity-inventory.json"`)
	w.Header().Set("Digest", "sha-256="+base64.StdEncoding.EncodeToString(sum[:]))
	writeIdentityRawJSON(w, r, http.StatusOK, raw, hex.EncodeToString(sum[:]))
}

func identityJobID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || id == uuid.Nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid identity job id")
		return uuid.Nil, false
	}
	return id, true
}

func (h *IdentityHandler) IdentityJob(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	if !requireAnyUnscopedIdentityAdmin(
		w, r,
		permissions.PermAuditExport,
		permissions.PermIdentityWrite,
		permissions.PermSystemUpgrade,
	) {
		return
	}
	id, ok := identityJobID(w, r)
	if !ok || !h.requireIdentityWorker(w) {
		return
	}
	var raw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(),
		`SELECT identity_job_read($1,$2)`, claims.UserID, id).Scan(&raw); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity job read failed")
		return
	}
	if len(raw) == 0 || string(raw) == "null" {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "identity job not found")
		return
	}
	var state struct {
		Kind     string `json:"kind"`
		Terminal bool   `json:"terminal"`
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity job returned an invalid response")
		return
	}
	if !identityJobPermission(claims, state.Kind) {
		httputil.WriteProblemStatus(w, http.StatusForbidden,
			"identity job permission is no longer held")
		return
	}
	if !state.Terminal {
		w.Header().Set("Retry-After", "2")
	}
	writeIdentityRawJSON(w, r, http.StatusOK, raw, "")
}

func identityJobPermission(claims *auth.Claims, kind string) bool {
	if claims == nil {
		return false
	}
	switch kind {
	case "diagnostics":
		return permissions.HasPermission(
			claims.GlobalPermissions, permissions.PermAuditExport,
		)
	case "upgrade_backfill", "cohort_preview":
		return permissions.HasPermission(
			claims.GlobalPermissions, permissions.PermSystemUpgrade,
		) && permissions.HasPermission(
			claims.GlobalPermissions, permissions.PermIdentityWrite,
		)
	default:
		return false
	}
}

func (h *IdentityHandler) requireIdentityJobPermission(
	w http.ResponseWriter,
	r *http.Request,
	claims *auth.Claims,
	id uuid.UUID,
) bool {
	if !requireAnyUnscopedIdentityAdmin(
		w, r,
		permissions.PermAuditExport,
		permissions.PermIdentityWrite,
		permissions.PermSystemUpgrade,
	) {
		return false
	}
	var raw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(),
		`SELECT identity_job_read($1,$2)`, claims.UserID, id).Scan(&raw); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity job permission check failed")
		return false
	}
	if len(raw) == 0 || string(raw) == "null" {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "identity job not found")
		return false
	}
	var state struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(raw, &state) != nil || !identityJobPermission(claims, state.Kind) {
		httputil.WriteProblemStatus(w, http.StatusForbidden,
			"identity job permission is no longer held")
		return false
	}
	return true
}

func (h *IdentityHandler) IdentityJobCancel(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	if !requireAnyUnscopedIdentityAdmin(
		w, r,
		permissions.PermAuditExport,
		permissions.PermIdentityWrite,
		permissions.PermSystemUpgrade,
	) {
		return
	}
	id, ok := identityJobID(w, r)
	if !ok || !h.requireIdentityWorker(w) {
		return
	}
	if !h.requireIdentityJobPermission(w, r, claims, id) {
		return
	}
	var raw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(),
		`SELECT identity_job_cancel($1,$2)`, claims.UserID, id).Scan(&raw); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError,
				"identity job cancel failed")
		}
		return
	}
	if len(raw) == 0 || string(raw) == "null" {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "identity job not found")
		return
	}
	writeIdentityRawJSON(w, r, http.StatusAccepted, raw, "")
}

func (h *IdentityHandler) IdentityJobResults(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	if !requireAnyUnscopedIdentityAdmin(
		w, r,
		permissions.PermAuditExport,
		permissions.PermIdentityWrite,
		permissions.PermSystemUpgrade,
	) {
		return
	}
	id, ok := identityJobID(w, r)
	if !ok || !h.requireIdentityWorker(w) {
		return
	}
	if !h.requireIdentityJobPermission(w, r, claims, id) {
		return
	}
	after := int64(0)
	if raw := r.URL.Query().Get("after"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 0 {
			httputil.WriteProblemStatus(w, http.StatusBadRequest,
				"invalid identity job result cursor")
			return
		}
		after = parsed
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			httputil.WriteProblemStatus(w, http.StatusBadRequest,
				"identity job result limit must be between 1 and 500")
			return
		}
		limit = parsed
	}
	var raw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(),
		`SELECT identity_job_results($1,$2,$3,$4)`,
		claims.UserID, id, after, limit).Scan(&raw); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError,
				"identity job results failed")
		}
		return
	}
	if len(raw) == 0 || string(raw) == "null" {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "identity job not found")
		return
	}
	writeIdentityRawJSON(w, r, http.StatusOK, raw, "")
}

type identityDiagnosticRequest struct {
	SourceKey      string `json:"sourceKey,omitempty"`
	TransitionID   string `json:"transitionId,omitempty"`
	SinceSeconds   int    `json:"sinceSeconds"`
	Reason         string `json:"reason"`
	IdempotencyKey string `json:"idempotencyKey"`
}

func (h *IdentityHandler) IdentityDiagnosticCreate(w http.ResponseWriter, r *http.Request) {
	var req identityDiagnosticRequest
	if !decodeIdentityJSON(w, r, &req, "invalid identity diagnostic request") {
		return
	}
	if !identityReasonMatches(w, r, req.Reason) {
		return
	}
	headerKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if headerKey != "" && req.IdempotencyKey != "" && headerKey != req.IdempotencyKey {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"Idempotency-Key must match body idempotencyKey")
		return
	}
	if headerKey != "" {
		req.IdempotencyKey = headerKey
	}
	key, keyErr := uuid.Parse(req.IdempotencyKey)
	var transitionID *uuid.UUID
	if req.TransitionID != "" {
		parsed, err := uuid.Parse(req.TransitionID)
		if err != nil || parsed == uuid.Nil {
			httputil.WriteProblemStatus(w, http.StatusBadRequest,
				"invalid identity transition id")
			return
		}
		transitionID = &parsed
	}
	if keyErr != nil || key == uuid.Nil ||
		((req.SourceKey == "") == (transitionID == nil)) ||
		(req.SourceKey != "" && !validIdentitySourceKey(req.SourceKey)) ||
		req.SinceSeconds < 1 || req.SinceSeconds > 86400 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"diagnostics requires one source or transition and a 1..86400 second range")
		return
	}
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	if !requireUnscopedIdentityAdmin(w, r, permissions.PermAuditExport) ||
		!h.requireIdentityWorker(w) {
		return
	}
	request := map[string]any{"sinceSeconds": req.SinceSeconds}
	var raw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(), `
		SELECT identity_job_create(
			$1,'diagnostics',$2,$3,$4,$5::jsonb,$6
		)
	`, claims.UserID, key, nullableString(req.SourceKey), transitionID,
		mustIdentityJSON(request), req.Reason).Scan(&raw); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError,
				"identity diagnostic creation failed")
		}
		return
	}
	var result struct {
		JobID string `json:"jobId"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || result.JobID == "" {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity diagnostic creation returned an invalid response")
		return
	}
	location := "/api/admin/identity/v2/diagnostics/" + result.JobID
	w.Header().Set("Location", location)
	w.Header().Set("Retry-After", "2")
	writeIdentityRawJSON(w, r, http.StatusAccepted, raw, "")
}

func mustIdentityJSON(value any) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

func (h *IdentityHandler) IdentityDiagnosticStatus(w http.ResponseWriter, r *http.Request) {
	h.IdentityJob(w, r)
}

func (h *IdentityHandler) IdentityDiagnosticDownload(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	if !requireUnscopedIdentityAdmin(w, r, permissions.PermAuditExport) {
		return
	}
	id, ok := identityJobID(w, r)
	if !ok || !h.requireIdentityWorker(w) {
		return
	}
	var statusRaw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(),
		`SELECT identity_job_read($1,$2)`, claims.UserID, id).Scan(&statusRaw); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity diagnostic status failed")
		return
	}
	if len(statusRaw) == 0 || string(statusRaw) == "null" {
		httputil.WriteProblemStatus(w, http.StatusNotFound,
			"identity diagnostic bundle not found")
		return
	}
	var status struct {
		Kind      string `json:"kind"`
		State     string `json:"state"`
		ExpiresAt string `json:"expiresAt"`
	}
	if json.Unmarshal(statusRaw, &status) != nil ||
		status.Kind != "diagnostics" {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity diagnostic status is invalid")
		return
	}
	expiresAt, parseErr := time.Parse(time.RFC3339Nano, status.ExpiresAt)
	if parseErr != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity diagnostic expiry is invalid")
		return
	}
	if status.State == "expired" || !expiresAt.After(time.Now()) {
		httputil.WriteProblemStatus(w, http.StatusGone,
			"identity diagnostic bundle has expired")
		return
	}
	if status.State != "completed" {
		httputil.WriteProblemStatus(w, http.StatusConflict,
			"identity diagnostic bundle is not ready")
		return
	}
	var artifact, digest []byte
	var manifestVersion string
	var downloadedExpiresAt time.Time
	if err := h.workerPool.QueryRow(r.Context(), `
		SELECT artifact,artifact_sha256,manifest_version,expires_at
		  FROM identity_diagnostic_download($1,$2)
	`, claims.UserID, id).Scan(
		&artifact, &digest, &manifestVersion, &downloadedExpiresAt,
	); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusNotFound,
				"identity diagnostic bundle not found")
		}
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition",
		`attachment; filename="setjoin-identity-diagnostic-`+id.String()+`.zip"`)
	w.Header().Set("X-Setjoin-Manifest-Version", manifestVersion)
	w.Header().Set("Digest", "sha-256="+base64.StdEncoding.EncodeToString(digest))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(artifact)
}

func (h *IdentityHandler) IdentityDiagnosticDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	if !decodeIdentityJSON(w, r, &req, "invalid diagnostic deletion request") {
		return
	}
	if !identityReasonMatches(w, r, req.Reason) {
		return
	}
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	if !requireUnscopedIdentityAdmin(w, r, permissions.PermAuditExport) {
		return
	}
	id, ok := identityJobID(w, r)
	if !ok || !h.requireIdentityWorker(w) {
		return
	}
	var found bool
	if err := h.workerPool.QueryRow(r.Context(),
		`SELECT identity_diagnostic_delete($1,$2,$3)`,
		claims.UserID, id, req.Reason).Scan(&found); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError,
				"identity diagnostic deletion failed")
		}
		return
	}
	// Idempotent deletion deliberately hides whether the job ever existed.
	w.WriteHeader(http.StatusNoContent)
}

func (h *IdentityHandler) IdentityUpgradePreflight(w http.ResponseWriter, r *http.Request) {
	if !requireUnscopedIdentityAdmin(
		w, r, permissions.PermIdentityWrite, permissions.PermSystemUpgrade,
	) || !h.requireIdentityWorker(w) {
		return
	}
	args := h.identityRuntimeArgs()
	var raw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(), `
		SELECT identity_upgrade_preflight($1,$2,$3,$4,$5,$6)
	`, args...).Scan(&raw); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity upgrade preflight failed")
		return
	}
	writeIdentityRawJSON(w, r, http.StatusOK, raw, "")
}

func (h *IdentityHandler) IdentityUpgradeBackfill(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action            string `json:"action"`
		PreflightChecksum string `json:"preflightChecksum,omitempty"`
		Reason            string `json:"reason,omitempty"`
		IdempotencyKey    string `json:"idempotencyKey,omitempty"`
	}
	if !decodeIdentityJSON(w, r, &req, "invalid identity backfill request") {
		return
	}
	if req.Action == "plan" {
		if !requireUnscopedIdentityAdmin(
			w, r, permissions.PermIdentityWrite, permissions.PermSystemUpgrade,
		) || !h.requireIdentityWorker(w) {
			return
		}
		args := h.identityRuntimeArgs()
		var raw json.RawMessage
		if err := h.workerPool.QueryRow(r.Context(), `
			SELECT identity_upgrade_preflight($1,$2,$3,$4,$5,$6)
		`, args...).Scan(&raw); err != nil {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError,
				"identity backfill plan failed")
			return
		}
		writeIdentityRawJSON(w, r, http.StatusOK, raw, "")
		return
	}
	if req.Action != "start" || !identityReasonMatches(w, r, req.Reason) {
		if req.Action != "start" {
			httputil.WriteProblemStatus(w, http.StatusBadRequest,
				"identity backfill action must be plan or start")
		}
		return
	}
	headerKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if headerKey != "" && req.IdempotencyKey != "" && headerKey != req.IdempotencyKey {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"Idempotency-Key must match body idempotencyKey")
		return
	}
	if headerKey != "" {
		req.IdempotencyKey = headerKey
	}
	key, err := uuid.Parse(req.IdempotencyKey)
	if err != nil || key == uuid.Nil || !validIdentityDigest(req.PreflightChecksum) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"identity backfill start requires checksum and idempotency UUID")
		return
	}
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	if !requireUnscopedIdentityAdmin(
		w, r, permissions.PermIdentityWrite, permissions.PermSystemUpgrade,
	) || !h.requireIdentityWorker(w) {
		return
	}
	args := append([]any{claims.UserID, req.PreflightChecksum, key, req.Reason},
		h.identityRuntimeArgs()...)
	var raw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(), `
		SELECT identity_upgrade_backfill_start(
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10
		)
	`, args...).Scan(&raw); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError,
				"identity backfill start failed")
		}
		return
	}
	var result struct {
		JobID string `json:"jobId"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || result.JobID == "" {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity backfill returned an invalid response")
		return
	}
	w.Header().Set("Location", "/api/admin/identity/v2/jobs/"+result.JobID)
	w.Header().Set("Retry-After", "2")
	writeIdentityRawJSON(w, r, http.StatusAccepted, raw, "")
}

func (h *IdentityHandler) IdentityUpgradeShadow(w http.ResponseWriter, r *http.Request) {
	sourceKey := strings.TrimSpace(r.URL.Query().Get("sourceKey"))
	if !validIdentitySourceKey(sourceKey) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"identity shadow check requires a valid sourceKey")
		return
	}
	if !requireUnscopedIdentityAdmin(
		w, r, permissions.PermIdentityWrite, permissions.PermSystemUpgrade,
	) || !h.requireIdentityWorker(w) {
		return
	}
	var raw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(),
		`SELECT identity_upgrade_shadow($1)`, sourceKey).Scan(&raw); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError,
				"identity shadow check failed")
		}
		return
	}
	writeIdentityRawJSON(w, r, http.StatusOK, raw, "")
}

func (h *IdentityHandler) IdentityUpgradeRetirementCheck(w http.ResponseWriter, r *http.Request) {
	if !requireUnscopedIdentityAdmin(
		w, r, permissions.PermIdentityWrite, permissions.PermSystemUpgrade,
	) || !h.requireIdentityWorker(w) {
		return
	}
	var raw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(),
		`SELECT identity_upgrade_retirement_check()`).Scan(&raw); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity retirement check failed")
		return
	}
	writeIdentityRawJSON(w, r, http.StatusOK, raw, "")
}
