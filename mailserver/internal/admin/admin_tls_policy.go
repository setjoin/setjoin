package admin

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/httputil"
)

// TLSPolicyHandler manages outbound TLS policy configuration.
type TLSPolicyHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewTLSPolicyHandler creates a TLS policy admin handler.
func NewTLSPolicyHandler(pool *pgxpool.Pool, logger *slog.Logger) *TLSPolicyHandler {
	return &TLSPolicyHandler{pool: pool, logger: logger}
}

// tlsPolicyResponse is the JSON response for GET /admin/outbound-tls-policy.
type tlsPolicyResponse struct {
	EnforceDomains []string `json:"enforce_domains"`
	SkipDomains    []string `json:"skip_domains"`
	GlobalMode     string   `json:"global_mode"`
}

// tlsPolicyRequest is the JSON request body for PUT /admin/outbound-tls-policy.
type tlsPolicyRequest struct {
	EnforceDomains []string `json:"enforce_domains"`
	SkipDomains    []string `json:"skip_domains"`
	GlobalMode     string   `json:"global_mode"`
}

// validateTLSPolicyRequest checks that the request fields are valid.
func (h *TLSPolicyHandler) validateTLSPolicyRequest(req tlsPolicyRequest) error {
	if req.EnforceDomains == nil {
		return fmt.Errorf("enforce_domains must be an array")
	}
	if req.SkipDomains == nil {
		return fmt.Errorf("skip_domains must be an array")
	}
	if req.GlobalMode == "" {
		return fmt.Errorf("global_mode is required")
	}
	if req.GlobalMode != "enforce" && req.GlobalMode != "opportunistic" {
		return fmt.Errorf("global_mode must be 'enforce' or 'opportunistic', got %q", req.GlobalMode)
	}
	return nil
}

// GetTLSPolicy reads the current outbound TLS policy from system_config.
func (h *TLSPolicyHandler) GetTLSPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	keys := []string{"outbound_tls_enforce_domains", "outbound_tls_skip_domains", "outbound_tls_global_mode"}
	var resp tlsPolicyResponse

	for _, key := range keys {
		var raw json.RawMessage
		err := h.pool.QueryRow(ctx, `SELECT value FROM system_config WHERE key = $1`, key).Scan(&raw)
		if err != nil {
			// Key not found — use default (empty/opportunistic)
			continue
		}
		switch key {
		case "outbound_tls_enforce_domains":
			json.Unmarshal(raw, &resp.EnforceDomains)
		case "outbound_tls_skip_domains":
			json.Unmarshal(raw, &resp.SkipDomains)
		case "outbound_tls_global_mode":
			var mode string
			json.Unmarshal(raw, &mode)
			resp.GlobalMode = mode
		}
	}

	// Ensure arrays are never null in the JSON response.
	if resp.EnforceDomains == nil {
		resp.EnforceDomains = []string{}
	}
	if resp.SkipDomains == nil {
		resp.SkipDomains = []string{}
	}
	if resp.GlobalMode == "" {
		resp.GlobalMode = "opportunistic"
	}

	httputil.WriteJSON(w, http.StatusOK, resp)
}

// PutTLSPolicy updates the outbound TLS policy in system_config.
func (h *TLSPolicyHandler) PutTLSPolicy(w http.ResponseWriter, r *http.Request) {
	var req tlsPolicyRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if err := h.validateTLSPolicyRequest(req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx := r.Context()

	// Marshal and upsert each key.
	enforceJSON, err := json.Marshal(req.EnforceDomains)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to marshal enforce_domains")
		return
	}
	skipJSON, err := json.Marshal(req.SkipDomains)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to marshal skip_domains")
		return
	}
	modeJSON, err := json.Marshal(req.GlobalMode)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to marshal global_mode")
		return
	}

	upsert := `INSERT INTO system_config (key, value, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`

	for _, item := range []struct {
		key   string
		value []byte
	}{
		{"outbound_tls_enforce_domains", enforceJSON},
		{"outbound_tls_skip_domains", skipJSON},
		{"outbound_tls_global_mode", modeJSON},
	} {
		if _, err := h.pool.Exec(ctx, upsert, item.key, item.value); err != nil {
			h.logger.Error("admin tls policy upsert failed", "key", item.key, "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "database error")
			return
		}
	}

	// Notify via pg_notify so the SMTP outbound worker can reload its cached policy.
	if _, err := h.pool.Exec(ctx, `SELECT pg_notify('config_changed', $1)`,
		`{"key":"outbound_tls_policy","enabled":true}`); err != nil {
		h.logger.Warn("admin tls policy notify failed", "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}
