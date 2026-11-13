package user

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// ProfileHandler persists the authenticated user's editable profile (display name).
type ProfileHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewProfileHandler creates a ProfileHandler.
func NewProfileHandler(pool *pgxpool.Pool, logger *slog.Logger) *ProfileHandler {
	return &ProfileHandler{pool: pool, logger: logger}
}

// Update handles POST /user/profile { "display_name": "..." }. The settings page saved
// to this route before it was mounted, so the display name never persisted and the UI
// always fell back to the email local-part; /auth/me already returns display_name, so
// once it's stored the name shows everywhere.
func (h *ProfileHandler) Update(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	name := strings.TrimSpace(req.DisplayName)
	if name == "" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "display name is required")
		return
	}
	if len([]rune(name)) > 255 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "display name is too long")
		return
	}
	if _, err := h.pool.Exec(r.Context(),
		`UPDATE users SET display_name = $1, updated_at = now() WHERE id = $2`,
		name, user.UserID); err != nil {
		h.logger.Error("profile update failed", "error", err, "user_id", user.UserID)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to update profile")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"display_name": name})
}
