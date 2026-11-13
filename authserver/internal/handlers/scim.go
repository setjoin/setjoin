package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/httputil"
)

// SCIMDisableHandler handles session revocation for SCIM-deprovisioned users.
type SCIMDisableHandler struct {
	// Svc is the token lifecycle owner; the all-session revoke funnels through it
	// (Wave 3 TokenService seam). Pool is used for the scim_external_id → user_id
	// lookup. Tests constructing the handler with only a Pool fall back to the
	// same revoke primitive.
	Svc  *token.TokenService
	Pool *pgxpool.Pool
}

// ServeHTTP revokes all active tokens for a user, identified either by numeric
// user_id (preferred — always present) or by SCIM external_id (legacy path,
// resolved via a lookup; only present for SCIM-provisioned accounts).
// POST /auth/scim/disable
// Body: {"user_id": 123} or {"external_id": "..."}
// Auth: RequireAPIKey middleware (INTERNAL_API_KEY)
func (h *SCIMDisableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ExternalID string `json:"external_id"`
		UserID     int64  `json:"user_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.ExternalID == "" && req.UserID == 0) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "user_id or external_id is required"})
		return
	}

	userID := req.UserID
	if userID == 0 {
		// Legacy path: look up user by scim_external_id.
		if err := h.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE scim_external_id = $1`,
			req.ExternalID,
		).Scan(&userID); err != nil {
			slog.Warn("scim_session_revoke_user_not_found",
				"external_id", req.ExternalID,
				"error", err,
			)
			httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
				"revoked": false,
				"reason":  "user not found",
			})
			return
		}
	}

	// Revoke all sessions for this user (through the TokenService seam).
	revoke := func() error {
		if h.Svc != nil {
			return h.Svc.RevokeAllForUser(r.Context(), userID)
		}
		return token.RevokeAllTokens(r.Context(), h.Pool, userID)
	}
	if err := revoke(); err != nil {
		slog.Error("scim_session_revoke_failed",
			"external_id", req.ExternalID,
			"user_id", userID,
			"error", err,
		)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "session revocation failed"})
		return
	}

	slog.Info("scim_session_revoke",
		"external_id", req.ExternalID,
		"user_id", userID,
	)

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"revoked": true,
	})
}
