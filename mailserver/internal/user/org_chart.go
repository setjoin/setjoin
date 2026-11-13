package user

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/permissions"

	"setjoin.com/mailserver/internal/auth"
)

// OrgChartHandler serves the org chart REST endpoint.
type OrgChartHandler struct {
	pool *pgxpool.Pool
}

// NewOrgChartHandler creates an org chart handler.
func NewOrgChartHandler(pool *pgxpool.Pool) *OrgChartHandler {
	return &OrgChartHandler{pool: pool}
}

// GetOrgChart returns the reporting chain for a user.
// Query params: ?userId= (optional, defaults to authenticated user)
func (h *OrgChartHandler) GetOrgChart(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	userID := claims.UserID
	if uidParam := r.URL.Query().Get("userId"); uidParam != "" {
		// Requires users.read to view another user's org chart.
		// IsAdmin is no longer the gate — the permission model controls access.
		if !claims.HasPermission(permissions.PermUsersRead) {
			httputil.WriteError(w, http.StatusForbidden, "users.read permission required")
			return
		}
		var parsed int64
		if _, err := fmt.Sscanf(uidParam, "%d", &parsed); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid userId")
			return
		}
		userID = parsed
	}

	// Domain scoping: target user must be in the same domain as the requester.
	var sameDomain bool
	err := h.pool.QueryRow(r.Context(),
		`SELECT EXISTS(
			SELECT 1 FROM users u1
			JOIN users u2 ON u2.domain_id = u1.domain_id
			WHERE u1.id = $1 AND u2.id = $2
		)`,
		claims.UserID, userID,
	).Scan(&sameDomain)
	if err != nil || !sameDomain {
		httputil.WriteError(w, http.StatusForbidden, "cannot view org chart for users in other domains")
		return
	}

	var managers, reports json.RawMessage
	if err := h.pool.QueryRow(r.Context(),
		`SELECT org_chart_managers($1)`, userID,
	).Scan(&managers); err != nil {
		managers = json.RawMessage("[]")
	}
	if err := h.pool.QueryRow(r.Context(),
		`SELECT org_chart_reports($1, 3)`, userID,
	).Scan(&reports); err != nil {
		reports = json.RawMessage("[]")
	}

	var userInfo json.RawMessage
	h.pool.QueryRow(r.Context(),
		`SELECT jsonb_build_object(
			'id', users.id::TEXT,
			'email', users.email,
			'displayName', users.display_name,
			'firstName', users.first_name,
			'lastName', users.last_name,
			'jobTitle', users.job_title,
			'department', departments.name,
			'avatar', CASE WHEN users.avatar_sha256 IS NOT NULL
				THEN jsonb_build_object('blobId', users.avatar_sha256) END
		)
		FROM users LEFT JOIN departments ON departments.id = users.department_id
		WHERE users.id = $1`, userID,
	).Scan(&userInfo)

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"user":     userInfo,
		"managers": managers,
		"reports":  reports,
	})
}
