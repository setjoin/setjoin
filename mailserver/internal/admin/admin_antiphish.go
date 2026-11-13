package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/httputil"
)

// AntiPhishHandler provides read/write access to anti-phishing configuration.
type AntiPhishHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewAntiPhishHandler creates an anti-phishing config handler.
func NewAntiPhishHandler(pool *pgxpool.Pool, logger *slog.Logger) *AntiPhishHandler {
	return &AntiPhishHandler{pool: pool, logger: logger}
}

// antiPhishConfig is the wire format shared with the webmail admin UI.
type antiPhishConfig struct {
	DisplayNameEnabled  bool     `json:"display_name_enabled"`
	LookalikeEnabled    bool     `json:"lookalike_enabled"`
	ContactGraphEnabled bool     `json:"contact_graph_enabled"`
	StrictMode          bool     `json:"strict_mode"`
	ExclusionDomains    []string `json:"exclusion_domains"`
	ExclusionUsers      []string `json:"exclusion_users"`
}

// GetConfig returns current anti-phishing configuration.
func (h *AntiPhishHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rows, err := h.pool.Query(ctx,
		`SELECT key, value FROM system_config WHERE key LIKE 'antiphish_%' ORDER BY key`)
	if err != nil {
		h.logger.Error("antiphish config query failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	raw := map[string]string{}
	for rows.Next() {
		var k string
		var v []byte
		if err := rows.Scan(&k, &v); err != nil {
			continue
		}
		raw[k] = strings.Trim(string(v), `"`)
	}

	cfg := antiPhishConfig{
		DisplayNameEnabled:  rawBool(raw, "antiphish_display_name", true),
		LookalikeEnabled:    rawBool(raw, "antiphish_lookalike", true),
		ContactGraphEnabled: rawBool(raw, "antiphish_contact_graph", true),
		StrictMode:          rawBool(raw, "antiphish_strict_mode", false),
		ExclusionDomains:    rawStringSlice(raw, "antiphish_exclusion_domains"),
		ExclusionUsers:      rawStringSlice(raw, "antiphish_exclusion_users"),
	}

	httputil.WriteJSON(w, http.StatusOK, cfg)
}

// SetConfig updates anti-phishing configuration.
func (h *AntiPhishHandler) SetConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req antiPhishConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	kvs := map[string]interface{}{
		"antiphish_display_name":      req.DisplayNameEnabled,
		"antiphish_lookalike":         req.LookalikeEnabled,
		"antiphish_contact_graph":     req.ContactGraphEnabled,
		"antiphish_strict_mode":       req.StrictMode,
		"antiphish_exclusion_domains": req.ExclusionDomains,
		"antiphish_exclusion_users":   req.ExclusionUsers,
	}

	if err := batchUpsertSystemConfig(ctx, h.pool, "anti-phish config", kvs); err != nil {
		h.logger.Error("antiphish config update failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// rawBool reads a boolean from the raw config map, returning the default if absent.
func rawBool(raw map[string]string, key string, def bool) bool {
	v, ok := raw[key]
	if !ok {
		return def
	}
	// system_config stores booleans as JSON true/false or "true"/"false" quoted strings
	return v == "true" || v == "True"
}

// rawStringSlice reads a JSON array of strings from the raw config map.
func rawStringSlice(raw map[string]string, key string) []string {
	v, ok := raw[key]
	if !ok || v == "" {
		return []string{}
	}
	var out []string
	if err := json.Unmarshal([]byte(v), &out); err != nil {
		return []string{}
	}
	return out
}
