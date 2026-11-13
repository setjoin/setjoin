package user

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// SecureAccountHandler handles "This wasn't me" self-secure requests.
type SecureAccountHandler struct{ pool *pgxpool.Pool }

// NewSecureAccountHandler creates a SecureAccountHandler.
func NewSecureAccountHandler(pool *pgxpool.Pool) *SecureAccountHandler {
	return &SecureAccountHandler{pool: pool}
}

// Secure handles POST /user/sign-ins/secure-account.
// Self-scoped (R1): revokes all the caller's oauth tokens + sessions, then calls
// secure_account(user_id, user_id, ip, 'user_self_report') — all in one tx.
// The body is ignored; target is always the authenticated caller.
//
// ponytail: oauth UPDATE + session DELETE + reducer call reuse the RevokeAll SQL
// verbatim (three lines, no abstraction); add a shared helper only if a 4th caller appears.
func (h *SecureAccountHandler) Secure(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}
	ip := httputil.ClientIP(r)

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck

	if _, err := tx.Exec(r.Context(),
		`UPDATE oauth_tokens SET revoked_at = now(), revoked_by = $1
		 WHERE user_id = $1 AND revoked_at IS NULL`, claims.UserID); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	if _, err := tx.Exec(r.Context(),
		`DELETE FROM sessions WHERE user_id = $1`, claims.UserID); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	if _, err := tx.Exec(r.Context(),
		`SELECT secure_account($1, $1, $2::inet, 'user_self_report')`, claims.UserID, ip); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "secured"})
}
