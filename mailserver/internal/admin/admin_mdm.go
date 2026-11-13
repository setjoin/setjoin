package admin

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/mdm"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/genutil"
	"setjoin.com/shared/httputil"
)

// errLastGlobalPolicy is DeletePolicy's internal sentinel: it carries the
// "last global policy" conflict out of the dbscope.RunUserScoped transaction
// so the handler can answer 409 exactly as before the wrap.
var errLastGlobalPolicy = errors.New("mdm: cannot delete the last global policy")

// MDMHandler provides admin endpoints for mobile device management.
// All endpoints require admin authentication (enforced via middleware).
type MDMHandler struct {
	pool   *pgxpool.Pool
	engine *mdm.Engine
	logger *slog.Logger
}

// NewMDMHandler creates a new MDMHandler.
func NewMDMHandler(pool *pgxpool.Pool, logger *slog.Logger) *MDMHandler {
	return &MDMHandler{
		pool:   pool,
		engine: mdm.NewEngine(pool, logger),
		logger: logger,
	}
}

// ── Device endpoints ──────────────────────────────────────────────────────

// ListDevices handles GET /admin/mdm/devices.
// Returns devices visible to the caller. Supports query params: status, platform, user_id.
//
// Domain scope comes from the request context (middleware.DomainScopeFromContext,
// set by RequireAuth from claims.DomainScope) and is threaded into the engine so
// the visibility predicate runs in SQL: a domain-scoped admin sees only devices
// whose owning user is in their domain (mdm_device_state.user_id →
// users.domain_id). Global-scope admins (scope 0) are unchanged.
func (h *MDMHandler) ListDevices(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context()) // authz already enforced+audited by route middleware
	if h.pool == nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database not configured")
		return
	}

	domainScope := middleware.DomainScopeFromContext(r.Context())
	devices, err := h.engine.ListDevices(r.Context(), claims.UserID, true, domainScope)
	if err != nil {
		h.logger.Error("mdm: list devices failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to list devices")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"devices": devices,
		"total":   len(devices),
	})
}

// GetDevice handles GET /admin/mdm/devices/{device_id}.
//
// R1: the domain scope from the request context is folded into the SAME
// resolving SELECT — a scoped admin's WHERE carries the owner-derived predicate
// (user_id IN users of their domain), so an out-of-scope device is
// indistinguishable from a missing one (404).
func (h *MDMHandler) GetDevice(w http.ResponseWriter, r *http.Request) {
	// authz already enforced+audited by route middleware.
	if h.pool == nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database not configured")
		return
	}

	deviceIDStr := r.PathValue("device_id")
	deviceID, err := uuid.Parse(deviceIDStr)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid device_id")
		return
	}

	domainScope := middleware.DomainScopeFromContext(r.Context())
	// Query single device.
	//
	// V254 FORCE-RLS pairing (L2-C2 r1 item 2a): mdm_device_state is Posture A
	// — the read runs inside dbscope.RunUserScoped so the admin actor GUC
	// admits the self/admin-read arms. The in-statement domain-scope predicate
	// below remains the primary R1 authorization.
	var ds mdm.DeviceState
	query := `
		SELECT device_id, user_id, platform, device_name, os_version, app_version,
			passcode_set, passcode_compliant, encryption_enabled, jailbroken, jailbreak_method,
			compliance_status, non_compliance_reasons, grace_until,
			wipe_requested, COALESCE(wipe_level, ''), wipe_requested_at, wipe_acked_at,
			last_checkin_at, created_at, updated_at
		FROM mdm_device_state
		WHERE device_id = $1
	`
	var args []any = []any{deviceID}
	if domainScope > 0 {
		query += ` AND user_id IN (SELECT id FROM users WHERE domain_id = $2)`
		args = append(args, domainScope)
	}
	var adminUserID int64
	if claims := auth.UserFromContext(r.Context()); claims != nil {
		adminUserID = claims.UserID
	}
	err = dbscope.RunUserScoped(r.Context(), h.pool, adminUserID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), query, args...).Scan(
			&ds.DeviceID, &ds.UserID, &ds.Platform, &ds.DeviceName, &ds.OSVersion, &ds.AppVersion,
			&ds.PasscodeSet, &ds.PasscodeCompliant, &ds.EncryptionEnabled, &ds.Jailbroken, &ds.JailbreakMethod,
			&ds.ComplianceStatus, &ds.NonComplianceReasons, &ds.GraceUntil,
			&ds.WipeRequested, &ds.WipeLevel, &ds.WipeRequestedAt, &ds.WipeAckedAt,
			&ds.LastCheckinAt, &ds.CreatedAt, &ds.UpdatedAt,
		)
	})
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "device not found")
		return
	}
	if ds.NonComplianceReasons == nil {
		ds.NonComplianceReasons = []string{}
	}

	httputil.WriteJSON(w, http.StatusOK, ds)
}

// wipeTargetNotFound reports whether a RequestWipe ValidationError classifies
// as an invisible wipe target rather than an in-scope state conflict.
// Engine.RequestWipe (mapping mdm_device_wipe_arm's BZ053/BZ054 answers)
// returns exactly this field+message pair for an unknown OR out-of-scope
// device (fail-closed under the SAME scope predicate — no existence oracle);
// every other validation error is a state conflict on an in-scope device
// (executed / armed at another level / concurrent change) and stays a 409.
// The pairing is pinned by TestMDMDevices_DomainScope_Wipe so engine-side
// drift fails loudly.
func wipeTargetNotFound(verr *mdm.ValidationError) bool {
	return verr.Field == "device_id" && verr.Message == "device not found"
}

// TriggerWipe handles POST /admin/mdm/devices/{device_id}/wipe.
// Body: {"level": "account" | "device"}
//
// REDUCER-AUTHORITATIVE: the arm (state + core-tier audit row + durable
// device_events evidence + device_policy notify) is mdm_device_wipe_arm, one
// transaction. The admin's identity comes from the AUTH CONTEXT (R1/R2 —
// claims.UserID, never a request-owned body field) and rides with the client
// IP onto the durable audit row, so the destructive arm is attributable in the
// database, not just in ephemeral logs.
//
// The domain scope from the request context is threaded into the engine so the
// arm carries the owner-derived scope predicate in its WHERE (R3): a
// scoped admin can arm wipes only for in-scope devices. An invisible target —
// unknown or out-of-scope — is 404 "device not found", indistinguishable from
// missing (no existence oracle for out-of-scope callers); state conflicts on
// IN-SCOPE devices remain 409. The 202 response marks completion as
// "client-attested": wipe execution is reported by the device's own wipe_ack —
// it is NOT server-verified destruction.
func (h *MDMHandler) TriggerWipe(w http.ResponseWriter, r *http.Request) {
	// authz already enforced+audited by route middleware.
	claims := auth.UserFromContext(r.Context())
	deviceIDStr := r.PathValue("device_id")
	deviceID, err := uuid.Parse(deviceIDStr)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid device_id")
		return
	}

	var req struct {
		Level string `json:"level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.Level != mdm.WipeAccount && req.Level != mdm.WipeDevice {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "level must be 'account' or 'device'")
		return
	}

	if h.pool == nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database not configured")
		return
	}

	if err := h.engine.RequestWipe(r.Context(), deviceID, req.Level,
		middleware.DomainScopeFromContext(r.Context()), claims.UserID, httputil.ClientIP(r)); err != nil {
		if verr, ok := err.(*mdm.ValidationError); ok {
			if wipeTargetNotFound(verr) {
				// Unknown or out-of-scope device: 404, indistinguishable from
				// missing. Never a 409 — that would leak the device's state.
				httputil.WriteProblemStatus(w, http.StatusNotFound, "device not found")
				return
			}
			httputil.WriteJSON(w, http.StatusConflict, map[string]string{"error": verr.Message, "field": verr.Field})
			return
		}
		h.logger.Error("mdm: trigger wipe failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to trigger wipe")
		return
	}

	httputil.WriteJSON(w, http.StatusAccepted, map[string]string{
		"status":     "pending",
		"device_id":  deviceID.String(),
		"level":      req.Level,
		"completion": mdm.WipeCompletionClientAttested,
	})
}

// ── Policy endpoints ──────────────────────────────────────────────────────

// policyRequest is the JSON body for creating/updating a policy.
type policyRequest struct {
	Name                    *string `json:"name,omitempty"`
	Description             *string `json:"description,omitempty"`
	Priority                *int    `json:"priority,omitempty"`
	ScopeType               *string `json:"scope_type,omitempty"`
	ScopeID                 *int64  `json:"scope_id,omitempty"`
	Enabled                 *bool   `json:"enabled,omitempty"`
	PasscodeMinLength       *int    `json:"passcode_min_length,omitempty"`
	PasscodeComplexity      *string `json:"passcode_complexity,omitempty"`
	PasscodeMaxAgeDays      *int    `json:"passcode_max_age_days,omitempty"`
	PasscodeHistoryCount    *int    `json:"passcode_history_count,omitempty"`
	MaxFailedAttempts       *int    `json:"max_failed_attempts,omitempty"`
	InactivityLockMins      *int    `json:"inactivity_lock_mins,omitempty"`
	BlockScreenshots        *bool   `json:"block_screenshots,omitempty"`
	BlockCopyPaste          *bool   `json:"block_copy_paste,omitempty"`
	RequireDeviceEncryption *bool   `json:"require_device_encryption,omitempty"`
	MinOSVersionIOS         *string `json:"min_os_version_ios,omitempty"`
	MinOSVersionAndroid     *string `json:"min_os_version_android,omitempty"`
	JailbreakAction         *string `json:"jailbreak_action,omitempty"`
	HeartbeatIntervalSecs   *int    `json:"heartbeat_interval_secs,omitempty"`
	GracePeriodMins         *int    `json:"grace_period_mins,omitempty"`
}

func (p *policyRequest) validate() error {
	if p.Name != nil && *p.Name == "" {
		return &mdm.ValidationError{Field: "name", Message: "name cannot be empty"}
	}
	if p.ScopeType != nil && *p.ScopeType != mdm.ScopeGlobal && *p.ScopeType != mdm.ScopeGroup && *p.ScopeType != mdm.ScopeUser {
		return &mdm.ValidationError{Field: "scope_type", Message: "must be 'global', 'group', or 'user'"}
	}
	if p.PasscodeComplexity != nil && *p.PasscodeComplexity != mdm.PasscodeNone &&
		*p.PasscodeComplexity != mdm.PasscodeNumeric && *p.PasscodeComplexity != mdm.PasscodeAlphanumeric &&
		*p.PasscodeComplexity != mdm.PasscodeComplex {
		return &mdm.ValidationError{Field: "passcode_complexity", Message: "must be 'none', 'numeric', 'alphanumeric', or 'complex'"}
	}
	if p.JailbreakAction != nil && *p.JailbreakAction != mdm.JailbreakBlock &&
		*p.JailbreakAction != mdm.JailbreakQuarantine && *p.JailbreakAction != mdm.JailbreakWarnLog &&
		*p.JailbreakAction != mdm.JailbreakNone {
		return &mdm.ValidationError{Field: "jailbreak_action", Message: "must be 'block', 'quarantine', 'warn_log', or 'none'"}
	}
	if p.PasscodeMinLength != nil && *p.PasscodeMinLength < 0 {
		return &mdm.ValidationError{Field: "passcode_min_length", Message: "must be >= 0"}
	}
	return nil
}

// ListPolicies handles GET /admin/mdm/policies.
//
// V254 FORCE-RLS pairing (L2-C2 r2.3 (e)): mdm_policies is Posture C
// (perm-keyed admin arms on app.current_user_id) — the read runs inside
// dbscope.RunUserScoped so the actor GUC admits the arms; the route's
// requireMamRead middleware remains the primary gate.
func (h *MDMHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	// authz already enforced+audited by route middleware.
	if h.pool == nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database not configured")
		return
	}

	var adminUserID int64
	if claims := auth.UserFromContext(r.Context()); claims != nil {
		adminUserID = claims.UserID
	}
	type policyRow struct {
		ID        int64  `json:"id"`
		Name      string `json:"name"`
		Desc      string `json:"description"`
		Priority  int    `json:"priority"`
		ScopeType string `json:"scope_type"`
		ScopeID   int64  `json:"scope_id"`
		Enabled   bool   `json:"enabled"`
		mdm.Policy
	}
	var policies []policyRow
	err := dbscope.RunUserScoped(r.Context(), h.pool, adminUserID, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `
			SELECT id, name, description, priority, scope_type, COALESCE(scope_id, 0),
				enabled,
				passcode_min_length, passcode_complexity, passcode_max_age_days,
				passcode_history_count, max_failed_attempts, inactivity_lock_mins,
				block_screenshots, block_copy_paste, require_device_encryption,
				min_os_version_ios, min_os_version_android,
				jailbreak_action, heartbeat_interval_secs, grace_period_mins,
				created_at, updated_at
			FROM mdm_policies
			ORDER BY priority DESC
		`)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var p policyRow
			var created, updated interface{}
			if rows.Scan(&p.ID, &p.Name, &p.Desc, &p.Priority, &p.ScopeType, &p.ScopeID,
				&p.Enabled,
				&p.PasscodeMinLength, &p.PasscodeComplexity, &p.PasscodeMaxAgeDays,
				&p.PasscodeHistoryCount, &p.MaxFailedAttempts, &p.InactivityLockMins,
				&p.BlockScreenshots, &p.BlockCopyPaste, &p.RequireEncryption,
				&p.MinOSVersionIOS, &p.MinOSVersionAndroid,
				&p.JailbreakAction, &p.HeartbeatIntervalSecs, &p.GracePeriodMins,
				&created, &updated) == nil {
				policies = append(policies, p)
			}
		}
		return rows.Err()
	})
	if err != nil {
		h.logger.Error("mdm: list policies failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to list policies")
		return
	}
	if policies == nil {
		policies = []policyRow{}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"policies": policies,
		"total":    len(policies),
	})
}

// CreatePolicy handles POST /admin/mdm/policies.
func (h *MDMHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	// authz already enforced+audited by route middleware.
	var req policyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.Name == nil || *req.Name == "" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "name is required")
		return
	}

	if err := req.validate(); err != nil {
		if verr, ok := err.(*mdm.ValidationError); ok {
			httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": verr.Message, "field": verr.Field})
			return
		}
	}

	if h.pool == nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database not configured")
		return
	}

	// Build INSERT with defaults applied
	name := *req.Name
	desc := genutil.PtrOr(req.Description, "")
	priority := genutil.PtrOr(req.Priority, 0)
	scopeType := genutil.PtrOr(req.ScopeType, mdm.ScopeGlobal)
	var scopeID interface{}
	if req.ScopeID != nil {
		scopeID = *req.ScopeID
	}
	enabled := genutil.PtrOr(req.Enabled, true)
	passcodeMinLength := genutil.PtrOr(req.PasscodeMinLength, 6)
	passcodeComplexity := genutil.PtrOr(req.PasscodeComplexity, mdm.PasscodeNumeric)
	passcodeMaxAgeDays := genutil.PtrOr(req.PasscodeMaxAgeDays, 90)
	passcodeHistoryCount := genutil.PtrOr(req.PasscodeHistoryCount, 5)
	maxFailedAttempts := genutil.PtrOr(req.MaxFailedAttempts, 10)
	inactivityLockMins := genutil.PtrOr(req.InactivityLockMins, 5)
	blockScreenshots := genutil.PtrOr(req.BlockScreenshots, false)
	blockCopyPaste := genutil.PtrOr(req.BlockCopyPaste, false)
	requireEncryption := genutil.PtrOr(req.RequireDeviceEncryption, true)
	minOSVersionIOS := genutil.PtrOr(req.MinOSVersionIOS, "")
	minOSVersionAndroid := genutil.PtrOr(req.MinOSVersionAndroid, "")
	jailbreakAction := genutil.PtrOr(req.JailbreakAction, mdm.JailbreakQuarantine)
	heartbeatInterval := genutil.PtrOr(req.HeartbeatIntervalSecs, 3600)
	gracePeriodMins := genutil.PtrOr(req.GracePeriodMins, 60)

	var id int64
	var adminUserID int64
	if claims := auth.UserFromContext(r.Context()); claims != nil {
		adminUserID = claims.UserID
	}
	// V254 FORCE-RLS pairing (L2-C2 r2.3 (e)): Posture C write arm (mam.write)
	// evaluates against the actor GUC set transaction-locally.
	err := dbscope.RunUserScoped(r.Context(), h.pool, adminUserID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `
			INSERT INTO mdm_policies (
				name, description, priority, scope_type, scope_id, enabled,
				passcode_min_length, passcode_complexity, passcode_max_age_days,
				passcode_history_count, max_failed_attempts, inactivity_lock_mins,
				block_screenshots, block_copy_paste, require_device_encryption,
				min_os_version_ios, min_os_version_android,
				jailbreak_action, heartbeat_interval_secs, grace_period_mins
			) VALUES (
				$1, $2, $3, $4, $5, $6,
				$7, $8, $9, $10, $11, $12,
				$13, $14, $15, $16, $17, $18, $19, $20
			) RETURNING id
		`,
			name, desc, priority, scopeType, scopeID, enabled,
			passcodeMinLength, passcodeComplexity, passcodeMaxAgeDays,
			passcodeHistoryCount, maxFailedAttempts, inactivityLockMins,
			blockScreenshots, blockCopyPaste, requireEncryption,
			minOSVersionIOS, minOSVersionAndroid,
			jailbreakAction, heartbeatInterval, gracePeriodMins,
		).Scan(&id)
	})
	if err != nil {
		h.logger.Error("mdm: create policy failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to create policy")
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, map[string]interface{}{
		"id":      id,
		"message": "policy created",
	})
}

// UpdatePolicy handles PUT /admin/mdm/policies/{id}.
func (h *MDMHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	// authz already enforced+audited by route middleware.
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid policy id")
		return
	}

	var req policyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if err := req.validate(); err != nil {
		if verr, ok := err.(*mdm.ValidationError); ok {
			httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": verr.Message, "field": verr.Field})
			return
		}
	}

	if h.pool == nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database not configured")
		return
	}

	// Build dynamic UPDATE.
	//
	// V254 FORCE-RLS pairing (L2-C2 r2.3 (e)): Posture C write arm (mam.write)
	// evaluates against the actor GUC set transaction-locally.
	var adminUserID int64
	if claims := auth.UserFromContext(r.Context()); claims != nil {
		adminUserID = claims.UserID
	}
	var result pgconn.CommandTag
	err = dbscope.RunUserScoped(r.Context(), h.pool, adminUserID, func(tx pgx.Tx) error {
		var tErr error
		result, tErr = tx.Exec(r.Context(), `
		UPDATE mdm_policies SET
			name = COALESCE($2, name),
			description = COALESCE($3, description),
			priority = COALESCE($4, priority),
			scope_type = COALESCE($5, scope_type),
			scope_id = $6,
			enabled = COALESCE($7, enabled),
			passcode_min_length = COALESCE($8, passcode_min_length),
			passcode_complexity = COALESCE($9, passcode_complexity),
			passcode_max_age_days = COALESCE($10, passcode_max_age_days),
			passcode_history_count = COALESCE($11, passcode_history_count),
			max_failed_attempts = COALESCE($12, max_failed_attempts),
			inactivity_lock_mins = COALESCE($13, inactivity_lock_mins),
			block_screenshots = COALESCE($14, block_screenshots),
			block_copy_paste = COALESCE($15, block_copy_paste),
			require_device_encryption = COALESCE($16, require_device_encryption),
			min_os_version_ios = COALESCE($17, min_os_version_ios),
			min_os_version_android = COALESCE($18, min_os_version_android),
			jailbreak_action = COALESCE($19, jailbreak_action),
			heartbeat_interval_secs = COALESCE($20, heartbeat_interval_secs),
			grace_period_mins = COALESCE($21, grace_period_mins),
			updated_at = now()
		WHERE id = $1
	`, id,
			req.Name,
			req.Description,
			req.Priority,
			req.ScopeType,
			req.ScopeID,
			req.Enabled,
			req.PasscodeMinLength,
			req.PasscodeComplexity,
			req.PasscodeMaxAgeDays,
			req.PasscodeHistoryCount,
			req.MaxFailedAttempts,
			req.InactivityLockMins,
			req.BlockScreenshots,
			req.BlockCopyPaste,
			req.RequireDeviceEncryption,
			req.MinOSVersionIOS,
			req.MinOSVersionAndroid,
			req.JailbreakAction,
			req.HeartbeatIntervalSecs,
			req.GracePeriodMins,
		)
		return tErr
	})
	if err != nil {
		h.logger.Error("mdm: update policy failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to update policy")
		return
	}
	if result.RowsAffected() == 0 {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "policy not found")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"message": "policy updated"})
}

// DeletePolicy handles DELETE /admin/mdm/policies/{id}.
// Fails if it's the last global policy (409 conflict).
func (h *MDMHandler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	// authz already enforced+audited by route middleware.
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid policy id")
		return
	}

	if h.pool == nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database not configured")
		return
	}

	// Check if this is the last global policy, then delete.
	//
	// V254 FORCE-RLS pairing (L2-C2 r2.3 (e)): all three mdm_policies
	// statements run inside dbscope.RunUserScoped so the Posture C arms
	// evaluate against the actor GUC.
	var adminUserID int64
	if claims := auth.UserFromContext(r.Context()); claims != nil {
		adminUserID = claims.UserID
	}
	var (
		globalCount int
		policyScope string
		result      pgconn.CommandTag
	)
	err = dbscope.RunUserScoped(r.Context(), h.pool, adminUserID, func(tx pgx.Tx) error {
		// Best-effort probes preserved (errors ignored exactly as before the
		// wrap); the DELETE below is checked.
		_ = tx.QueryRow(r.Context(), `
			SELECT COUNT(*) FROM mdm_policies WHERE scope_type = 'global' AND enabled
		`).Scan(&globalCount)

		_ = tx.QueryRow(r.Context(), `SELECT scope_type FROM mdm_policies WHERE id = $1`, id).Scan(&policyScope)

		if policyScope == mdm.ScopeGlobal && globalCount <= 1 {
			return errLastGlobalPolicy
		}

		var tErr error
		result, tErr = tx.Exec(r.Context(), `DELETE FROM mdm_policies WHERE id = $1`, id)
		return tErr
	})
	if err != nil {
		if err == errLastGlobalPolicy {
			httputil.WriteJSON(w, http.StatusConflict, map[string]string{
				"error": "cannot delete the last global policy",
			})
			return
		}
		h.logger.Error("mdm: delete policy failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to delete policy")
		return
	}
	if result.RowsAffected() == 0 {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "policy not found")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"message": "policy deleted"})
}

// ReorderPolicies handles PUT /admin/mdm/policies/reorder.
// Body: {"ids": [3, 1, 2]} — sets priorities from high to low.
func (h *MDMHandler) ReorderPolicies(w http.ResponseWriter, r *http.Request) {
	// authz already enforced+audited by route middleware.
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if len(req.IDs) == 0 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "ids array is required")
		return
	}

	if h.pool == nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database not configured")
		return
	}

	// Set priorities: first ID gets highest priority, descending.
	//
	// V254 FORCE-RLS pairing (L2-C2 r2.3 (e)): the UPDATE batch runs inside
	// dbscope.RunUserScoped so the Posture C write arm evaluates against the
	// actor GUC; one transaction makes the reorder atomic.
	var adminUserID int64
	if claims := auth.UserFromContext(r.Context()); claims != nil {
		adminUserID = claims.UserID
	}
	if err := dbscope.RunUserScoped(r.Context(), h.pool, adminUserID, func(tx pgx.Tx) error {
		for i, id := range req.IDs {
			priority := len(req.IDs) - i
			if _, err := tx.Exec(r.Context(), `
				UPDATE mdm_policies SET priority = $1, updated_at = now() WHERE id = $2
			`, priority, id); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		h.logger.Error("mdm: reorder failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to reorder policies")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"message": "policies reordered"})
}
