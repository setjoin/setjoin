// Admin CRUD for offline-mail governance (policies + device approval queue).
// Mirrors admin_conditional_access.go / admin_mdm.go: parse → call reducer →
// JSON. RBAC is enforced+audited by the route middleware in main.go
// (mail.offline_policy for policy writes; mam.read/mam.write for devices).
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/reducererr"
)

// offlineCaller is the reducer-call seam for WipeDevice.
// ponytail: single-method interface so tests inject a fake without a live pool.
type offlineCaller interface {
	call(ctx context.Context, reducer string, args ...any) error
}

// poolOfflineCaller is the production offlineCaller backed by pgxpool.
type poolOfflineCaller struct{ pool *pgxpool.Pool }

func (c *poolOfflineCaller) call(ctx context.Context, reducer string, args ...any) error {
	switch reducer {
	case "offline_device_revoke":
		_, err := c.pool.Exec(ctx, `SELECT offline_device_revoke($1,$2)`, args...)
		return err
	default:
		return errors.New("offline_caller: unknown reducer " + reducer)
	}
}

// OfflineHandler serves /admin/offline/*.
type OfflineHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
	caller offlineCaller // seam for WipeDevice; nil when pool is nil
}

// NewOfflineHandler constructs the offline-governance admin handler.
func NewOfflineHandler(pool *pgxpool.Pool, logger *slog.Logger) *OfflineHandler {
	var c offlineCaller
	if pool != nil {
		c = &poolOfflineCaller{pool: pool}
	}
	return &OfflineHandler{pool: pool, logger: logger, caller: c}
}

type offlinePolicyReq struct {
	Name                          string `json:"name"`
	ScopeType                     string `json:"scope_type"`
	ScopeID                       *int64 `json:"scope_id,omitempty"`
	Enabled                       bool   `json:"enabled"`
	MaxOfflineDays                int    `json:"max_offline_days"`
	RequireApprove                bool   `json:"require_approval"`
	WipeOnLogout                  string `json:"wipe_on_logout"`
	Priority                      int    `json:"priority"`
	BackgroundSyncAllowed         *bool  `json:"background_sync_allowed,omitempty"`
	AutomaticNetworkMax           string `json:"automatic_network_max,omitempty"`
	AttachmentPrefetchMax         string `json:"attachment_prefetch_max,omitempty"`
	OpportunisticRequiresCharging *bool  `json:"opportunistic_requires_charging,omitempty"`
	ConnectivitySyncMode          string `json:"connectivity_sync_mode,omitempty"`
	ConnectivityFieldsProvided    bool   `json:"-"`
}

func decodeOfflinePolicyRequest(w http.ResponseWriter, r *http.Request) (offlinePolicyReq, error) {
	var req offlinePolicyReq
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return req, errors.New("request must contain one JSON object")
	}
	if req.WipeOnLogout == "" {
		req.WipeOnLogout = "admin_default"
	}
	hasAnyConnectivityField := req.BackgroundSyncAllowed != nil ||
		req.AutomaticNetworkMax != "" || req.AttachmentPrefetchMax != "" ||
		req.OpportunisticRequiresCharging != nil || req.ConnectivitySyncMode != ""
	hasAllConnectivityFields := req.BackgroundSyncAllowed != nil &&
		req.AutomaticNetworkMax != "" && req.AttachmentPrefetchMax != "" &&
		req.OpportunisticRequiresCharging != nil && req.ConnectivitySyncMode != ""
	if hasAnyConnectivityField && !hasAllConnectivityFields {
		return req, errors.New("connectivity policy fields must be supplied together")
	}
	req.ConnectivityFieldsProvided = hasAllConnectivityFields
	if req.AutomaticNetworkMax == "" {
		req.AutomaticNetworkMax = "unmetered"
	}
	if req.AttachmentPrefetchMax == "" {
		req.AttachmentPrefetchMax = "never"
	}
	if req.ConnectivitySyncMode == "" {
		req.ConnectivitySyncMode = "off"
	}
	if req.BackgroundSyncAllowed == nil {
		value := true
		req.BackgroundSyncAllowed = &value
	}
	if req.OpportunisticRequiresCharging == nil {
		value := true
		req.OpportunisticRequiresCharging = &value
	}
	return req, nil
}

func (h *OfflineHandler) actor(ctx context.Context) int64 {
	if c := auth.UserFromContext(ctx); c != nil {
		return c.UserID
	}
	return 0
}

// ListPolicies handles GET /admin/offline/policies.
func (h *OfflineHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database not configured")
		return
	}
	var out json.RawMessage
	if err := h.pool.QueryRow(r.Context(), `SELECT offline_policy_list()`).Scan(&out); err != nil {
		if h.logger != nil {
			h.logger.Error("offline list policies failed", "error", err)
		}
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

// GetPolicy handles GET /admin/offline/policies/{id}.
func (h *OfflineHandler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database not configured")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var out json.RawMessage
	if err := h.pool.QueryRow(r.Context(), `SELECT offline_policy_get($1)`, id).Scan(&out); err != nil {
		// Scan only errors on real DB failures (conn loss, timeout, pool exhaustion);
		// offline_policy_get() returns NULL for missing IDs, not pgx.ErrNoRows.
		if h.logger != nil {
			h.logger.Error("offline get policy failed", "error", err)
		}
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if out == nil {
		httputil.WriteError(w, http.StatusNotFound, "policy not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

func (h *OfflineHandler) upsert(w http.ResponseWriter, r *http.Request, id *int64) {
	req, err := decodeOfflinePolicyRequest(w, r)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if h.pool == nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database not configured")
		return
	}
	var newID int64
	if req.ConnectivityFieldsProvided {
		err = h.pool.QueryRow(r.Context(),
			`SELECT offline_policy_set_v2($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
			h.actor(r.Context()), id, req.Name, req.ScopeType, req.ScopeID,
			req.Enabled, req.MaxOfflineDays, req.RequireApprove, req.WipeOnLogout, req.Priority,
			*req.BackgroundSyncAllowed, req.AutomaticNetworkMax, req.AttachmentPrefetchMax,
			*req.OpportunisticRequiresCharging, req.ConnectivitySyncMode,
		).Scan(&newID)
	} else {
		err = h.pool.QueryRow(r.Context(),
			`SELECT offline_policy_set($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			h.actor(r.Context()), id, req.Name, req.ScopeType, req.ScopeID,
			req.Enabled, req.MaxOfflineDays, req.RequireApprove, req.WipeOnLogout, req.Priority,
		).Scan(&newID)
	}
	if err != nil {
		if reducererr.WriteClassified(w, r, err) {
			return
		}
		if h.logger != nil {
			h.logger.Error("offline policy set failed", "error", err)
		}
		httputil.WriteError(w, http.StatusBadRequest, "failed to save policy")
		return
	}
	status := http.StatusCreated
	if id != nil {
		status = http.StatusOK
	}
	httputil.WriteJSON(w, status, map[string]int64{"id": newID})
}

type offlinePreviewReq struct {
	TargetUserID string `json:"targetUserId"`
	DeviceID     string `json:"deviceId"`
}

// PreviewPolicy handles POST /admin/offline/policy-preview. The reducer repeats
// live permission+scope authorization before target lookup, so stale JWT claims
// cannot widen this diagnostic surface.
func (h *OfflineHandler) PreviewPolicy(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database not configured")
		return
	}
	var req offlinePreviewReq
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		httputil.WriteError(w, http.StatusBadRequest, "request must contain one JSON object")
		return
	}
	targetUserID, err := strconv.ParseInt(req.TargetUserID, 10, 64)
	if err != nil || targetUserID <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid targetUserId")
		return
	}
	deviceID, err := strconv.ParseInt(req.DeviceID, 10, 64)
	if err != nil || deviceID <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid deviceId")
		return
	}
	var out json.RawMessage
	if err := h.pool.QueryRow(r.Context(),
		`SELECT offline_sync_policy_preview($1,$2,$3)`,
		h.actor(r.Context()), targetUserID, deviceID).Scan(&out); err != nil {
		if reducererr.WriteClassified(w, r, err) {
			return
		}
		if h.logger != nil {
			h.logger.Error("offline policy preview failed", "error", err)
		}
		httputil.WriteError(w, http.StatusInternalServerError, "preview failed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

// CreatePolicy handles POST /admin/offline/policies.
func (h *OfflineHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	h.upsert(w, r, nil)
}

// UpdatePolicy handles PUT /admin/offline/policies/{id}.
func (h *OfflineHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	h.upsert(w, r, &id)
}

// DeletePolicy handles DELETE /admin/offline/policies/{id}.
// Calls offline_policy_delete (reducer) so state validation, audit log, and
// caps broadcast happen in-transaction — not a raw DELETE. BZ099/not_found →
// 404; BZ099/last_global → 409 (slug split owned by reducererr.Classify).
func (h *OfflineHandler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database not configured")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	_, err = h.pool.Exec(r.Context(),
		`SELECT offline_policy_delete($1,$2)`, id, h.actor(r.Context()))
	if err != nil {
		// BZ099 is slug-disambiguated inside reducererr.Classify: last_global →
		// 409 + reducer message; not_found → 404 "policy not found". No local
		// pre-check needed — the split lives entirely inside Classify.
		if reducererr.WriteClassified(w, r, err) {
			return
		}
		if h.logger != nil {
			h.logger.Error("offline policy delete failed", "error", err)
		}
		httputil.WriteError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// GetEnabled handles GET /admin/offline/enabled — returns the org master toggle.
func (h *OfflineHandler) GetEnabled(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database not configured")
		return
	}
	var enabled bool
	if err := h.pool.QueryRow(r.Context(), `
		SELECT COALESCE((
			SELECT enabled FROM feature_toggles WHERE key = 'feature.offline_mail'
		), FALSE)`).Scan(&enabled); err != nil {
		if h.logger != nil {
			h.logger.Error("offline toggle read failed", "error", err)
		}
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "toggle read failed")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]bool{"enabled": enabled})
}

// SetEnabled handles PUT /admin/offline/enabled — flips the org master toggle.
// Governance toggle: must audit + broadcast capsChanged (AND-of-4 gate).
func (h *OfflineHandler) SetEnabled(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database not configured")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	actor := h.actor(r.Context())
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "toggle failed")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if _, err := tx.Exec(r.Context(),
		`INSERT INTO feature_toggles (key, enabled) VALUES ('feature.offline_mail',$1)
		 ON CONFLICT (key) DO UPDATE SET enabled=$1`, req.Enabled); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "toggle failed")
		return
	}
	afterToggle, _ := json.Marshal(map[string]bool{"enabled": req.Enabled})
	if err := audit.Write(r.Context(), tx, audit.Entry{
		Actor: actor, Action: "offline_toggle", TargetType: "feature_toggle",
		After: afterToggle, Tier: "core",
	}); err != nil {
		if h.logger != nil {
			h.logger.Error("offline toggle audit failed", "error", err)
		}
		httputil.WriteError(w, http.StatusInternalServerError, "toggle failed")
		return
	}
	if _, err := tx.Exec(r.Context(),
		`SELECT app_notify('caps:offline','{"type":"capsChanged"}')`); err != nil {
		if h.logger != nil {
			h.logger.Warn("offline toggle notify failed", "error", err)
		}
		// best-effort: notify failure does not abort the toggle
	}
	if err := tx.Commit(r.Context()); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "toggle failed")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]bool{"enabled": req.Enabled})
}

// ListPendingDevices handles GET /admin/offline/devices/pending.
func (h *OfflineHandler) ListPendingDevices(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database not configured")
		return
	}
	var out json.RawMessage
	if err := h.pool.QueryRow(r.Context(), `SELECT offline_devices_pending()`).Scan(&out); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

// deviceAction executes an offline device state-machine transition.
// ponytail: switch over compile-time literals — fn is always a hardcoded caller
// constant, never user input; avoids gosec G202 on string concat.
func (h *OfflineHandler) deviceAction(w http.ResponseWriter, r *http.Request, fn string) {
	if h.pool == nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database not configured")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var q string
	switch fn {
	case "offline_device_approve":
		q = `SELECT offline_device_approve($1,$2)`
	case "offline_device_deny":
		q = `SELECT offline_device_deny($1,$2)`
	case "offline_device_revoke":
		q = `SELECT offline_device_revoke($1,$2)`
	default:
		httputil.WriteError(w, http.StatusInternalServerError, "unknown action")
		return
	}
	if _, err := h.pool.Exec(r.Context(), q, h.actor(r.Context()), id); err != nil {
		if h.logger != nil {
			h.logger.Warn("offline device action failed", "fn", fn, "error", err)
		}
		// BZ100 (illegal transition / stale race / device not found) classifies
		// to ClassConflict → 409 with the reducer message passed through.
		if reducererr.WriteClassified(w, r, err) {
			return
		}
		// Genuine infra/DB error (conn loss, pool exhaustion, RLS config error, etc.)
		httputil.WriteError(w, http.StatusInternalServerError, "device action failed")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ApproveDevice handles POST /admin/offline/devices/{id}/approve.
func (h *OfflineHandler) ApproveDevice(w http.ResponseWriter, r *http.Request) {
	h.deviceAction(w, r, "offline_device_approve")
}

// DenyDevice handles POST /admin/offline/devices/{id}/deny.
func (h *OfflineHandler) DenyDevice(w http.ResponseWriter, r *http.Request) {
	h.deviceAction(w, r, "offline_device_deny")
}

// RevokeDevice handles POST /admin/offline/devices/{id}/revoke.
func (h *OfflineHandler) RevokeDevice(w http.ResponseWriter, r *http.Request) {
	h.deviceAction(w, r, "offline_device_revoke")
}

// WipeDevice handles POST /admin/offline/devices/{id}/wipe.
// A remote-wipe of a native offline device reuses offline_device_revoke: revoke
// sets the wipe intent (wipe_requested=true, wipe_at=now()) + emits the
// offline.wipe push (the F1 WS pass-through delivers it), which the native
// client turns into window.setjoinNative.db.wipe('mail').
// Returns 202 Accepted — the wipe is async (fires when the device reconnects).
// authz (mam.write) is enforced+audited by route middleware.
// ponytail: inlined rather than reusing deviceAction to keep the 202 status
// without adding a status param to 3 existing callers; uses h.caller seam so
// unit tests verify reducer wiring without a live DB.
func (h *OfflineHandler) WipeDevice(w http.ResponseWriter, r *http.Request) {
	// ponytail: validate cheap inputs before the caller check — bad IDs never reach DB.
	deviceID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	if h.caller == nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database not configured")
		return
	}
	if err := h.caller.call(r.Context(), "offline_device_revoke", h.actor(r.Context()), deviceID); err != nil {
		if h.logger != nil {
			h.logger.Error("offline wipe device failed", "device_id", deviceID, "error", err)
		}
		// BZ100 → ClassConflict → 409 + reducer message (shared projection).
		if class := reducererr.Classify(err); class != reducererr.ClassUnknown {
			httputil.WriteError(w, class.HTTPStatus(), reducererr.Detail(err))
			return
		}
		httputil.WriteError(w, http.StatusInternalServerError, "wipe failed")
		return
	}
	httputil.WriteJSON(w, http.StatusAccepted, map[string]any{
		"status":    "wipe_requested",
		"device_id": deviceID,
	})
}
