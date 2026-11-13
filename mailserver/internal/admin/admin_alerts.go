package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/httputil"
)

// AlertsHandler provides health alert status and configuration.
type AlertsHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewAlertsHandler creates an alerts handler.
func NewAlertsHandler(pool *pgxpool.Pool, logger *slog.Logger) *AlertsHandler {
	return &AlertsHandler{pool: pool, logger: logger}
}

// AlertStatus represents current alert state.
type AlertStatus struct {
	CheckName   string     `json:"checkName"`
	Consecutive int        `json:"consecutive"`
	LastError   string     `json:"lastError,omitempty"`
	LastChecked *time.Time `json:"lastChecked,omitempty"`
	AlertSentAt *time.Time `json:"alertSentAt,omitempty"`
	Suppressed  bool       `json:"suppressed"`
}

// List returns current health alert states.
func (h *AlertsHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Compute consecutive failures per check from health_history
	rows, err := h.pool.Query(ctx, `
		WITH ranked AS (
			SELECT check_name, status, checked_at,
				ROW_NUMBER() OVER (PARTITION BY check_name ORDER BY checked_at DESC) as rn
			FROM health_history
		),
		streaks AS (
			SELECT check_name, COUNT(*) as consecutive, MAX(checked_at) as last_checked
			FROM ranked
			WHERE status = 'error'
			  AND rn <= (
				  SELECT COUNT(*) FROM ranked r2
				  WHERE r2.check_name = ranked.check_name
				    AND r2.rn <= ranked.rn
				    AND r2.status = 'error'
			  )
			GROUP BY check_name
		)
		SELECT s.check_name, s.consecutive, s.last_checked,
		       h.details as last_error,
		       a.alert_sent_at,
		       COALESCE(a.suppressed, false) as suppressed
		FROM streaks s
		LEFT JOIN health_history h ON h.check_name = s.check_name AND h.checked_at = s.last_checked
		LEFT JOIN health_alerts a ON a.check_name = s.check_name
		WHERE s.consecutive >= 3
		ORDER BY s.last_checked DESC
	`)
	if err != nil {
		h.logger.Error("alerts list failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	out := make([]AlertStatus, 0)
	for rows.Next() {
		var a AlertStatus
		var lastChecked, alertSentAt *time.Time
		if err := rows.Scan(&a.CheckName, &a.Consecutive, &lastChecked, &a.LastError, &alertSentAt, &a.Suppressed); err != nil {
			continue
		}
		a.LastChecked = lastChecked
		a.AlertSentAt = alertSentAt
		out = append(out, a)
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

// Acknowledge suppresses an alert.
func (h *AlertsHandler) Acknowledge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		CheckName string `json:"checkName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.CheckName == "" {
		httputil.WriteError(w, http.StatusBadRequest, "checkName required")
		return
	}

	_, err := h.pool.Exec(ctx, `
		INSERT INTO health_alerts (check_name, suppressed, acknowledged_at)
		VALUES ($1, true, now())
		ON CONFLICT (check_name) DO UPDATE
		SET suppressed = true, acknowledged_at = now(), updated_at = now()
	`, req.CheckName)
	if err != nil {
		h.logger.Error("alert acknowledge failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Unsuppress re-enables alerting for a check.
func (h *AlertsHandler) Unsuppress(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		CheckName string `json:"checkName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.CheckName == "" {
		httputil.WriteError(w, http.StatusBadRequest, "checkName required")
		return
	}

	_, err := h.pool.Exec(ctx, `
		UPDATE health_alerts SET suppressed = false, updated_at = now()
		WHERE check_name = $1
	`, req.CheckName)
	if err != nil {
		h.logger.Error("alert unsuppress failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetConfig returns alert configuration (email addresses, min consecutive).
func (h *AlertsHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rows, err := h.pool.Query(ctx,
		`SELECT key, value FROM system_config WHERE key LIKE 'hc_%' OR key LIKE 'alert_%'`)
	if err != nil {
		h.logger.Error("alert config query failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	config := map[string]string{}
	for rows.Next() {
		var key string
		var value []byte
		if err := rows.Scan(&key, &value); err != nil {
			continue
		}
		config[key] = string(value)
	}

	httputil.WriteJSON(w, http.StatusOK, config)
}

// SetConfig updates alert configuration. Accepts a flat JSON object of key-value pairs.
func (h *AlertsHandler) SetConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Allowlist: alerts config owns ONLY the hc_ and alert_ key namespaces
	// (matching GetConfig's read filter). Without this gate a holder of
	// security.write could overwrite system_config keys (password_min_length,
	// identity_source, worm_mode, …) that are gated behind system.config via the
	// admin_config.go allowedConfigKeys allowlist.
	for key := range req {
		if !strings.HasPrefix(key, "hc_") && !strings.HasPrefix(key, "alert_") {
			httputil.WriteError(w, http.StatusBadRequest, "config key not writable via alerts API: "+key)
			return
		}
	}

	if err := batchUpsertSystemConfig(ctx, h.pool, "Health check configuration", req); err != nil {
		h.logger.Error("alert config update failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
