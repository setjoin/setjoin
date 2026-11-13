package user

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// LoginHistoryHandler provides user-facing login history endpoints.
type LoginHistoryHandler struct {
	pool *pgxpool.Pool
}

// NewLoginHistoryHandler creates a login history handler.
func NewLoginHistoryHandler(pool *pgxpool.Pool) *LoginHistoryHandler {
	return &LoginHistoryHandler{pool: pool}
}

// ListLoginHistory handles GET /user/login-history.
// Query params:
//   - outcome: "" (all) | "success" | "failed"
//   - from / to: ISO date (YYYY-MM-DD) range filter
//   - limit: default 50, max 200
//   - offset: default 0
//
// Response: { "items": [...], "total": N, "failed_distinct": {count, locations, since} }
// R1: WHERE user_id = auth-context user_id; session_id matched against JWT JTI for "current" flag.
func (h *LoginHistoryHandler) ListLoginHistory(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}

	limit, offset := httputil.ParseLimitOffset(r, 50, 200)

	// outcome filter: "" = all, "success" = success only, "failed" = failures only.
	// ponytail: SQL cast (success = ($5 = 'success')) collapses the two branches into one param.
	outcome := r.URL.Query().Get("outcome")

	// Positional args: $1=user_id, $2=limit, $3=offset, $4=session_id (for current flag), $5=outcome.
	const mainQ = `
		SELECT id,
		       occurred_at,
		       COALESCE(host(source_ip), '') AS source_ip,
		       COALESCE(location, '')        AS location,
		       COALESCE(device_name, '')     AS device_name,
		       COALESCE(platform, '')        AS platform,
		       COALESCE(client, '')          AS client,
		       COALESCE(protocol, '')        AS protocol,
		       COALESCE(auth_method, '')     AS auth_method,
		       success,
		       COALESCE(fail_reason, '')     AS fail_reason,
		       (session_id IS NOT NULL AND session_id = $4) AS current,
		       COUNT(*) OVER ()              AS total
		FROM login_events
		WHERE user_id = $1
		  AND ($5 = '' OR success = ($5 = 'success'))
		ORDER BY occurred_at DESC
		LIMIT $2 OFFSET $3`

	// failed_distinct: last-7-day failure summary (count, distinct locations, oldest ts).
	const summaryQ = `
		SELECT COUNT(*),
		       COUNT(DISTINCT location),
		       COALESCE(to_char(MIN(occurred_at), 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), '')
		FROM login_events
		WHERE user_id = $1
		  AND success = false
		  AND occurred_at > now() - interval '7 days'`

	type LoginEvent struct {
		ID         int64  `json:"id"`
		OccurredAt string `json:"occurred_at"`
		SourceIP   string `json:"source_ip"`
		Location   string `json:"location"`
		DeviceName string `json:"device_name"`
		Platform   string `json:"platform"`
		Client     string `json:"client"`
		Protocol   string `json:"protocol"`
		AuthMethod string `json:"auth_method"`
		Success    bool   `json:"success"`
		FailReason string `json:"fail_reason,omitempty"`
		Current    bool   `json:"current"`
	}

	type FailedDistinct struct {
		Count     int    `json:"count"`
		Locations int    `json:"locations"`
		Since     string `json:"since"`
	}

	var items []LoginEvent
	var total int
	var fd FailedDistinct

	if err := dbscope.RunUserScoped(r.Context(), h.pool, claims.UserID, func(tx pgx.Tx) error {
		// Main rows.
		rows, err := tx.Query(r.Context(), mainQ, claims.UserID, limit, offset, claims.JTI, outcome)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e LoginEvent
			var occurredAt time.Time
			if scanErr := rows.Scan(
				&e.ID, &occurredAt, &e.SourceIP, &e.Location, &e.DeviceName, &e.Platform,
				&e.Client, &e.Protocol, &e.AuthMethod,
				&e.Success, &e.FailReason, &e.Current, &total,
			); scanErr != nil {
				continue
			}
			e.OccurredAt = occurredAt.UTC().Format(time.RFC3339)
			items = append(items, e)
		}
		if err := rows.Err(); err != nil {
			return err
		}

		// Summary query.
		return tx.QueryRow(r.Context(), summaryQ, claims.UserID).Scan(&fd.Count, &fd.Locations, &fd.Since)
	}); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	if items == nil {
		items = []LoginEvent{}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"items":           items,
		"total":           total,
		"failed_distinct": fd,
	})
}

// ReportSuspiciousLogin handles POST /user/login-history/{id}/report.
// Logs a security event to admin_audit_log for administrator review.
func (h *LoginHistoryHandler) ReportSuspiciousLogin(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}

	eventID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid event id")
		return
	}

	// Verify this event belongs to the user. Runs inside dbscope.RunUserScoped
	// (same seam as ListLoginHistory above): login_events is FORCE RLS with the
	// V048 login_events_owner policy keyed on app.current_user_id, so the
	// ownership check needs the actor GUC on its tx to survive the flip.
	var exists bool
	err = dbscope.RunUserScoped(r.Context(), h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM login_events WHERE id = $1 AND user_id = $2)`,
			eventID, claims.UserID,
		).Scan(&exists)
	})
	if err != nil || !exists {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "event not found")
		return
	}

	// Log security event to admin audit log
	notes := fmt.Sprintf("login_event_id=%d, reported_by_user=true", eventID)
	if err = audit.Write(r.Context(), h.pool, audit.Entry{
		Actor: claims.UserID, Action: "login_reported_suspicious", TargetType: "login_event", TargetID: &eventID,
		Notes: notes, Tier: audit.TierForAction("login_reported_suspicious"),
	}); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "reported"})
}
