package admin

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/notify"
	"setjoin.com/shared/httputil"
)

// WelcomeEmailHandler serves the welcome-email config (system_config key
// "welcome_email"). Routes are RBAC-gated at registration (PermSystemConfig).
type WelcomeEmailHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewWelcomeEmailHandler constructs the welcome-email admin handler.
func NewWelcomeEmailHandler(pool *pgxpool.Pool, logger *slog.Logger) *WelcomeEmailHandler {
	return &WelcomeEmailHandler{pool: pool, logger: logger}
}

var welcomeLocales = map[string]bool{"en": true, "zh": true, "de": true}

// validateWelcomeConfig enforces the editable invariants: known default_locale,
// en present with non-empty subject + body_text, and no unknown locale keys.
func validateWelcomeConfig(cfg notify.WelcomeEmailConfig) error {
	if !welcomeLocales[cfg.DefaultLocale] {
		return fmt.Errorf("default_locale must be one of en, zh, de")
	}
	en, ok := cfg.Locales["en"]
	if !ok || en.Subject == "" || en.BodyText == "" {
		return fmt.Errorf("the en locale must have a non-empty subject and plain-text body")
	}
	for loc := range cfg.Locales {
		if !welcomeLocales[loc] {
			return fmt.Errorf("unknown locale %q (allowed: en, zh, de)", loc)
		}
	}
	return nil
}

// Get returns the current welcome-email config.
func (h *WelcomeEmailHandler) Get(w http.ResponseWriter, r *http.Request) {
	var raw json.RawMessage
	err := h.pool.QueryRow(r.Context(), `SELECT get_system_config('welcome_email')`).Scan(&raw)
	if err != nil {
		h.logger.Error("welcome-email get failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if len(raw) == 0 || string(raw) == "null" {
		// Not seeded (pre-V018) — return an empty disabled shell so the UI loads.
		httputil.WriteJSON(w, http.StatusOK, notify.WelcomeEmailConfig{
			Enabled: false, DefaultLocale: "en", Locales: map[string]notify.WelcomeLocale{},
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// Put validates and persists the config, recording updated_by for audit.
func (h *WelcomeEmailHandler) Put(w http.ResponseWriter, r *http.Request) {
	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var cfg notify.WelcomeEmailConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := validateWelcomeConfig(cfg); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	value, err := json.Marshal(cfg)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to encode config")
		return
	}
	if _, err := h.pool.Exec(r.Context(),
		`SELECT set_system_config('welcome_email', $1::jsonb, false, $2)`,
		value, claims.UserID,
	); err != nil {
		h.logger.Error("welcome-email put failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type welcomeTestSendRequest struct {
	Locale   string `json:"locale"`
	Subject  string `json:"subject"`
	BodyText string `json:"body_text"`
	BodyHTML string `json:"body_html"`
}

func (req welcomeTestSendRequest) template() notify.WelcomeLocale {
	return notify.WelcomeLocale{Subject: req.Subject, BodyText: req.BodyText, BodyHTML: req.BodyHTML}
}

// TestSend delivers the supplied (possibly unsaved) content to the calling
// admin's own mailbox, so they can preview personalization before saving.
func (h *WelcomeEmailHandler) TestSend(w http.ResponseWriter, r *http.Request) {
	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req welcomeTestSendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Subject == "" || req.BodyText == "" {
		httputil.WriteError(w, http.StatusBadRequest, "subject and plain-text body are required")
		return
	}
	if err := notify.SendWelcomeEmailWithConfig(r.Context(), h.pool, claims.UserID, req.Locale, req.template(), h.logger); err != nil {
		h.logger.Error("welcome-email test send failed", "user_id", claims.UserID, "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "failed to send test email")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
