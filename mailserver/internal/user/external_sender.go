package user

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// ExternalSenderHandler provides GET/PUT /settings/external-sender —
// per-user toggle + domain-level config for external sender warning banners.
type ExternalSenderHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewExternalSenderHandler creates an ExternalSenderHandler.
func NewExternalSenderHandler(pool *pgxpool.Pool, logger *slog.Logger) *ExternalSenderHandler {
	return &ExternalSenderHandler{pool: pool, logger: logger}
}

// Get returns the current user's external-sender warning settings:
//   - userEnabled: per-user toggle (users.external_sender_warning)
//   - domainEnabled: per-domain override (external_sender_config.enabled), nil if absent
//   - domainWarnText: per-domain custom text, nil if absent
//   - domainWarnColor: per-domain custom color, nil if absent
//   - globalEnabled: master toggle (system_config external_sender.enabled)
func (h *ExternalSenderHandler) Get(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Fetch user's external_sender_warning toggle and email-derived domain for config lookup.
	var userEnabled bool
	var userEmail string
	err := h.pool.QueryRow(r.Context(),
		`SELECT COALESCE(external_sender_warning, TRUE), email
		 FROM users WHERE id = $1`,
		u.UserID,
	).Scan(&userEnabled, &userEmail)
	if err != nil {
		h.logger.Error("external sender get: user query failed", "error", err)
		// Fall back to defaults
		userEnabled = true
	}

	// Derive domain from email for domain-level config lookup.
	// Use a separate sub-query against the domains table (which may not exist in older schemas).
	var domainEnabled *bool
	var domainWarnText *string
	var domainWarnColor *string
	if userEmail != "" {
		parts := splitEmail(userEmail)
		if parts != "" {
			var dEnabled bool
			var dWarnText *string
			var dWarnColor string
			// Joins domains + external_sender_config by domain name.
			// Fails silently if any table/column is missing (pre-V051 schema).
			err := h.pool.QueryRow(r.Context(),
				`SELECT esc.enabled, esc.warn_text, esc.warn_color
				 FROM domains d
				 JOIN external_sender_config esc ON esc.domain_id = d.id
				 WHERE lower(d.name) = lower($1) AND d.is_local = TRUE`,
				parts,
			).Scan(&dEnabled, &dWarnText, &dWarnColor)
			if err == nil {
				domainEnabled = &dEnabled
				domainWarnText = dWarnText
				domainWarnColor = &dWarnColor
			}
		}
	}

	// Fetch global enabled toggle
	globalEnabled := true
	var raw string
	err = h.pool.QueryRow(r.Context(),
		`SELECT value FROM system_config WHERE key = 'external_sender.enabled'`,
	).Scan(&raw)
	if err == nil {
		if raw == "false" {
			globalEnabled = false
		}
	}

	resp := map[string]interface{}{
		"userEnabled":   userEnabled,
		"globalEnabled": globalEnabled,
	}
	if domainEnabled != nil {
		resp["domainEnabled"] = *domainEnabled
	}
	if domainWarnText != nil {
		resp["domainWarnText"] = *domainWarnText
	}
	if domainWarnColor != nil {
		resp["domainWarnColor"] = *domainWarnColor
	}

	httputil.WriteJSON(w, http.StatusOK, resp)
}

// Put updates the current user's external_sender_warning toggle.
func (h *ExternalSenderHandler) Put(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.Enabled == nil {
		httputil.WriteError(w, http.StatusBadRequest, "enabled is required")
		return
	}

	_, err := h.pool.Exec(r.Context(),
		`UPDATE users SET external_sender_warning = $2 WHERE id = $1`,
		u.UserID, *req.Enabled,
	)
	if err != nil {
		h.logger.Error("external sender put failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// splitEmail returns the domain portion of an email address, or "" if no '@' is found.
func splitEmail(email string) string {
	for i := len(email) - 1; i >= 0; i-- {
		if email[i] == '@' {
			return email[i+1:]
		}
	}
	return ""
}
