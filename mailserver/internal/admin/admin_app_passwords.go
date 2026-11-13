package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/httputil"
)

// AppPasswordsHandler provides admin oversight of user app passwords.
type AppPasswordsHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewAppPasswordsHandler creates a new AppPasswordsHandler.
func NewAppPasswordsHandler(pool *pgxpool.Pool, logger *slog.Logger) *AppPasswordsHandler {
	return &AppPasswordsHandler{pool: pool, logger: logger}
}

// ListForUser returns all app passwords for a user (including recently revoked).
func (h *AppPasswordsHandler) ListForUser(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.PathValue("id")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid user id")
		return
	}

	// Domain-scoped admins fold their domain into the SAME resolving SELECT (R1):
	// app_passwords has no domain_id, so the predicate routes through users
	// (user_id IN the scoped user). An out-of-scope user yields an empty set —
	// indistinguishable from a user with no app passwords. domainScope == 0
	// (global admin) → no extra predicate.
	domainScope := middleware.DomainScopeFromContext(r.Context())
	var rows pgx.Rows
	if domainScope > 0 {
		rows, err = h.pool.Query(r.Context(),
			`SELECT id, name, created_at, last_used_at, expires_at, revoked_at
			 FROM app_passwords
			 WHERE user_id = $1
			   AND user_id IN (SELECT id FROM users WHERE id = $1 AND domain_id = $2)
			 ORDER BY revoked_at NULLS FIRST, created_at DESC`, userID, domainScope)
	} else {
		rows, err = h.pool.Query(r.Context(),
			`SELECT id, name, created_at, last_used_at, expires_at, revoked_at
			 FROM app_passwords
			 WHERE user_id = $1
			 ORDER BY revoked_at NULLS FIRST, created_at DESC`, userID)
	}
	if err != nil {
		h.logger.Error("admin app password list failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	type adminAppPassword struct {
		ID         int64      `json:"id"`
		Name       string     `json:"name"`
		CreatedAt  time.Time  `json:"createdAt"`
		LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
		ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
		RevokedAt  *time.Time `json:"revokedAt,omitempty"`
	}
	out := make([]adminAppPassword, 0)
	for rows.Next() {
		var p adminAppPassword
		if rows.Scan(&p.ID, &p.Name, &p.CreatedAt, &p.LastUsedAt, &p.ExpiresAt, &p.RevokedAt) == nil {
			out = append(out, p)
		}
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// RevokeForUser revokes a specific app password belonging to a user.
func (h *AppPasswordsHandler) RevokeForUser(w http.ResponseWriter, r *http.Request) {
	adminUser := auth.UserFromContext(r.Context())
	userIDStr := r.PathValue("userId")
	apIDStr := r.PathValue("apId")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid user id")
		return
	}
	apID, err := strconv.ParseInt(apIDStr, 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid app password id")
		return
	}

	// Domain-scoped admins fold their domain into the SAME mutating UPDATE (R3 —
	// no TOCTOU): app_passwords carries no domain_id, so the predicate routes
	// through users (user_id IN the scoped user). An out-of-scope (or missing)
	// app password matches 0 rows → 404, indistinguishable from missing.
	// domainScope == 0 (global admin) → no extra predicate.
	domainScope := middleware.DomainScopeFromContext(r.Context())
	var tag pgconn.CommandTag
	if domainScope > 0 {
		tag, err = h.pool.Exec(r.Context(),
			`UPDATE app_passwords SET revoked_at = now()
			 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
			   AND user_id IN (SELECT id FROM users WHERE id = $2 AND domain_id = $3)`,
			apID, userID, domainScope)
	} else {
		tag, err = h.pool.Exec(r.Context(),
			`UPDATE app_passwords SET revoked_at = now()
			 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`,
			apID, userID)
	}
	if err != nil || tag.RowsAffected() == 0 {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}

	// Audit the admin revocation
	apRevokeJSON, _ := json.Marshal(map[string]any{"revoked_by": adminUser.Email, "user_id": userID})
	_ = audit.Write(r.Context(), h.pool, audit.Entry{
		Actor: adminUser.UserID, Action: "app_password_revoke", TargetType: "app_password", TargetID: &apID,
		Before: apRevokeJSON, IP: httputil.ClientIP(r), Tier: "core",
	})

	w.WriteHeader(http.StatusNoContent)
}
