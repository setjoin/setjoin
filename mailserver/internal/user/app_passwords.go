package user

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/reducererr"
)

// AppPasswordsHandler provides user-facing CRUD for app passwords.
type AppPasswordsHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewAppPasswordsHandler creates a new AppPasswordsHandler.
func NewAppPasswordsHandler(pool *pgxpool.Pool, logger *slog.Logger) *AppPasswordsHandler {
	return &AppPasswordsHandler{pool: pool, logger: logger}
}

// List returns the user's active app passwords (never shows the raw token).
func (h *AppPasswordsHandler) List(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, name, created_at, last_used_at, expires_at
		 FROM app_passwords
		 WHERE user_id = $1 AND revoked_at IS NULL
		 ORDER BY created_at DESC`, user.UserID)
	if err != nil {
		h.logger.Error("app password list failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	type appPassword struct {
		ID         int64      `json:"id"`
		Name       string     `json:"name"`
		CreatedAt  time.Time  `json:"createdAt"`
		LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
		ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	}
	out := make([]appPassword, 0)
	for rows.Next() {
		var p appPassword
		if rows.Scan(&p.ID, &p.Name, &p.CreatedAt, &p.LastUsedAt, &p.ExpiresAt) == nil {
			out = append(out, p)
		}
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// Generate creates a new app password and returns the ONE-TIME raw token.
func (h *AppPasswordsHandler) Generate(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	var req struct {
		Name  string `json:"name"`
		Label string `json:"label,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "name is required")
		return
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		h.logger.Error("app password gen failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	rawToken := "mail-ap-" + hex.EncodeToString(raw)

	hash := sha256.Sum256([]byte(rawToken))
	hashHex := hex.EncodeToString(hash[:])

	_, err := h.pool.Exec(r.Context(),
		`INSERT INTO app_passwords (user_id, name, label, token_hash) VALUES ($1, $2, $3, $4)`,
		user.UserID, req.Name, req.Label, hashHex)
	if err != nil {
		// Semantic IsCode branch: BZ015 is dual-purpose (litigation-hold delete
		// guard / app-password cap) — the cap meaning here keeps its bespoke 409
		// body; the shared classification (ClassForbidden/403) belongs to the
		// litigation-hold meaning. See the contract matrix row for BZ015.
		if reducererr.IsCode(err, "BZ015") {
			httputil.WriteProblemStatus(w, http.StatusConflict, "maximum 10 app passwords reached")
			return
		}
		h.logger.Error("app password insert failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, map[string]string{
		"token": rawToken,
		"name":  req.Name,
	})
}

// Revoke revokes (soft-deletes) an app password by ID.
func (h *AppPasswordsHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid id")
		return
	}

	tag, err := h.pool.Exec(r.Context(),
		`UPDATE app_passwords SET revoked_at = now()
		 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`,
		id, user.UserID)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
