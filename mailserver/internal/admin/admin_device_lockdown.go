// Admin enroll/approve/revoke/list for CA-2 device lockdown.
//
// Routes (registered in main.go; RBAC + audit are route-level middleware):
//
//	GET  /admin/devices/queue?state=&q=&limit=   — org-wide approval queue (mam.read)
//	GET  /admin/devices?user_id={id}             — per-user device list (mam.read)
//	POST /admin/devices/{id}/enroll|approve|revoke — lifecycle transitions (mam.write)
//
// Perm-gating: RequirePermAudited(mam.read/mam.write) at the route (main.go).
// The device_enroll_transition reducer also writes device_enroll_events audit rows.
//
// All SQL lives in shared/device — no cross-module import needed, no SQL duplication.
package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"

	shareddevice "setjoin.com/shared/device"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// DeviceLockdownHandler provides the CA-2 admin API for device lifecycle management.
// All endpoints assume an authenticated, authorized caller — RBAC is enforced once
// at route registration via RequirePermAudited(mam.read/mam.write).
type DeviceLockdownHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewDeviceLockdownHandler constructs a DeviceLockdownHandler.
func NewDeviceLockdownHandler(pool *pgxpool.Pool, logger *slog.Logger) *DeviceLockdownHandler {
	return &DeviceLockdownHandler{pool: pool, logger: logger}
}

// actionFromPath maps a URL action segment to its enroll-transition target.
// Returns ("", false) for any unrecognised action segment.
func actionFromPath(a string) (string, bool) {
	switch a {
	case "enroll":
		return "enrolled", true
	case "approve":
		return "approved", true
	case "revoke":
		return "revoked", true
	default:
		return "", false
	}
}

// Device-lifecycle reducer errors route through caErrorStatus → reducererr
// (c6): BZ095 (illegal transition / unknown device) classifies to
// ClassConflict → 409 so the UI can show "this device's state changed —
// refresh and retry" rather than a generic failure. The per-code entry the
// former dlErrorStatus held lives in reducererr.codeClass now.

// ── Queue ────────────────────────────────────────────────────────────────────

// Queue serves the org-wide approval queue (the CA-2 admin landing).
// ?state= defaults to 'enrolled' (waiting for approval); ?q= is a case-insensitive
// prefix over user email/display-name; ?limit= caps the page (default 100, max 500).
// Always returns a JSON array (empty array, never null — the UI's EMPTY state keys
// off length 0, not a 204).
// R1 carve-out (cross-user read): gated at the route by mam.read.
func (h *DeviceLockdownHandler) Queue(w http.ResponseWriter, r *http.Request) {
	// authz enforced+audited by route middleware.
	limit := 0
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = v
	}
	rows, err := shareddevice.ListApprovalQueue(r.Context(), h.pool, shareddevice.ApprovalQueueFilter{
		State: r.URL.Query().Get("state"),
		Query: r.URL.Query().Get("q"),
		Limit: limit,
	})
	if err != nil {
		h.logger.Error("device approval queue failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if rows == nil {
		rows = []shareddevice.ApprovalQueueRow{}
	}
	httputil.WriteJSON(w, http.StatusOK, rows)
}

// ── List ─────────────────────────────────────────────────────────────────────

// List returns all devices for a specific user (?user_id=<id> required).
// R1: user_id is taken from the query param (bound), not concatenated; the query
// filters strictly by that user_id so no cross-user data leaks.
func (h *DeviceLockdownHandler) List(w http.ResponseWriter, r *http.Request) {
	// authz enforced+audited by route middleware.
	uid, err := strconv.ParseInt(r.URL.Query().Get("user_id"), 10, 64)
	if err != nil || uid <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "user_id required")
		return
	}

	rows, err := shareddevice.ListDevicesForUser(r.Context(), h.pool, uid)
	if err != nil {
		h.logger.Error("device lockdown list failed", "error", err, "user_id", uid)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if rows == nil {
		rows = []shareddevice.DeviceListRow{}
	}
	httputil.WriteJSON(w, http.StatusOK, rows)
}

// ── Transition ───────────────────────────────────────────────────────────────

// Transition handles POST /admin/devices/{id}/{action}.
// {action} is one of enroll|approve|revoke.
// Body: {"reason": "…"} (optional).
//
// BZ095 (illegal transition / unknown device) → 409 with the reducer HINT detail
// so the UI can show "this device's state changed — refresh the queue" inline
// rather than a generic failure; any other DB error → 500.
//
// R3: the reducer device_enroll_transition holds the ownership check in the same
// WHERE clause as the state mutation — no TOCTOU.
func (h *DeviceLockdownHandler) Transition(w http.ResponseWriter, r *http.Request) {
	// authz enforced+audited by route middleware.
	toState, ok := actionFromPath(r.PathValue("action"))
	if !ok {
		httputil.WriteError(w, http.StatusBadRequest, "unknown action; want enroll|approve|revoke")
		return
	}
	deviceID, err := parsePathID(r, "id")
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid device id")
		return
	}

	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body)

	var terr error
	switch toState {
	case "enrolled":
		terr = shareddevice.EnrollDevice(r.Context(), h.pool, claims.UserID, deviceID, body.Reason)
	case "approved":
		terr = shareddevice.ApproveDevice(r.Context(), h.pool, claims.UserID, deviceID, body.Reason)
	case "revoked":
		terr = shareddevice.RevokeDevice(r.Context(), h.pool, claims.UserID, deviceID, body.Reason)
	}
	if terr != nil {
		h.logger.Error("device lockdown transition failed",
			"device_id", deviceID, "to", toState, "error", terr)
		httputil.WriteError(w, caErrorStatus(terr), caErrorDetail(terr))
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"device_id": deviceID, "state": toState})
}
