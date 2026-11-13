package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/httputil"
)

// UpdatesHandler provides client version management endpoints for the admin UI.
type UpdatesHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewUpdatesHandler creates an admin updates handler.
func NewUpdatesHandler(pool *pgxpool.Pool, logger *slog.Logger) *UpdatesHandler {
	return &UpdatesHandler{pool: pool, logger: logger}
}

// VersionSummary is returned by GET /admin/updates/summary.
type VersionSummary struct {
	TotalDevices int             `json:"total_devices"`
	UpToDate     int             `json:"up_to_date"`
	Outdated     int             `json:"outdated"`
	Critical     int             `json:"critical"`
	ByVersion    []VersionCount  `json:"by_version"`
	ByPlatform   []PlatformCount `json:"by_platform"`
}

type VersionCount struct {
	Version string `json:"version"`
	Count   int    `json:"count"`
}

type PlatformCount struct {
	Platform string `json:"platform"`
	Count    int    `json:"count"`
}

// DeviceInfo is returned by GET /admin/updates/devices.
type DeviceInfo struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Platform   string `json:"platform"`
	OSVersion  string `json:"os_version"`
	AppVersion string `json:"app_version"`
	LastSeen   string `json:"last_seen"`
	Status     string `json:"status"` // "up_to_date", "outdated", "critical"
}

// GetSummary returns counts by version, platform, and status.
func (h *UpdatesHandler) GetSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	summary := &VersionSummary{}

	// Total device count.
	h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM devices`).Scan(&summary.TotalDevices)

	// Count by version (top 10).
	rows, err := h.pool.Query(ctx,
		`SELECT COALESCE(app_version, 'unknown'), COUNT(*)
		 FROM devices
		 GROUP BY app_version
		 ORDER BY COUNT(*) DESC
		 LIMIT 10`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var vc VersionCount
			rows.Scan(&vc.Version, &vc.Count)
			summary.ByVersion = append(summary.ByVersion, vc)
		}
	}

	// Count by platform.
	rows2, err := h.pool.Query(ctx,
		`SELECT platform, COUNT(*) FROM devices GROUP BY platform ORDER BY COUNT(*) DESC`)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var pc PlatformCount
			rows2.Scan(&pc.Platform, &pc.Count)
			summary.ByPlatform = append(summary.ByPlatform, pc)
		}
	}

	// Up-to-date / outdated counts (placeholder — real logic compares against latest version).
	summary.UpToDate = summary.TotalDevices
	summary.Outdated = 0
	summary.Critical = 0

	httputil.WriteJSON(w, http.StatusOK, summary)
}

// GetDevices returns a paginated list of devices with version info.
func (h *UpdatesHandler) GetDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	limit, offset := httputil.ParseLimitOffset(r, 50, 100)

	rows, err := h.pool.Query(ctx,
		`SELECT d.id, d.device_name, d.platform, d.os_version, d.app_version, d.last_seen
		 FROM devices d
		 ORDER BY d.last_seen DESC NULLS LAST
		 LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		h.logger.Error("updates: device list query failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	var devices []DeviceInfo
	for rows.Next() {
		var d DeviceInfo
		rows.Scan(&d.ID, &d.Name, &d.Platform, &d.OSVersion, &d.AppVersion, &d.LastSeen)
		d.Status = "up_to_date" // placeholder — real comparison against latest
		devices = append(devices, d)
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"devices": devices,
		"offset":  offset,
		"limit":   limit,
	})
}

// PushUpdateRequest is the body for POST /admin/updates/push.
type PushUpdateRequest struct {
	DeviceIDs []int64 `json:"device_ids"`
	Version   string  `json:"version"`
	Message   string  `json:"message"`
}

// PushUpdate sends update notifications to selected devices.
// The actual push is handled by the existing NOTIFY system via pg_notify.
func (h *UpdatesHandler) PushUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req PushUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if len(req.DeviceIDs) == 0 {
		httputil.WriteError(w, http.StatusBadRequest, "device_ids is required")
		return
	}

	// Log the push event — the actual push dispatch is handled by the
	// NOTIFY dispatcher (notify.Dispatcher) which fans out pg_notify to
	// WebSocket-connected devices.
	for _, deviceID := range req.DeviceIDs {
		h.logger.Info("updates: push update notification",
			"device_id", deviceID,
			"version", req.Version,
		)
	}

	// Record in notification queue for async delivery.
	_, err := h.pool.Exec(ctx,
		`INSERT INTO notification_queue (event_type, payload, created_at)
		 VALUES ('update_available', $1, now())`,
		map[string]any{
			"device_ids": req.DeviceIDs,
			"version":    req.Version,
			"message":    req.Message,
		})
	if err != nil {
		h.logger.Warn("updates: push notification queue insert failed", "error", err)
		// Non-fatal — the push will still go through NOTIFY.
	}

	// Trigger pg_notify to fan out to connected devices.
	h.pool.Exec(ctx, `SELECT pg_notify('update_available', $1)`,
		strconv.Itoa(len(req.DeviceIDs)))

	w.WriteHeader(http.StatusNoContent)
}

// Ensure UpdatesHandler implements the needed interface for route registration.
var _ interface {
	GetSummary(http.ResponseWriter, *http.Request)
	GetDevices(http.ResponseWriter, *http.Request)
	PushUpdate(http.ResponseWriter, *http.Request)
} = (*UpdatesHandler)(nil)
