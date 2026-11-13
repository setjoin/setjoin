// Admin API: Why-blocked trace over ca_signin_log.
//
// Routes (registered in main.go):
//
//	GET /admin/conditional-access/why?user=<id|email>&since=<24h|7d|30d>[&correlation_id=<str>]
//
// Returns the per-sign-in evaluated[] trace for a user + window.
// User lookup distinguishes not-found (404 {found:false}) from found-but-empty (200 {found:true,rows:[]}).
// Read-only — no audit / no notify. Gated: requireCAPolicyRead at the route.
package admin

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/httputil"
)

// CAWhyHandler provides the why-blocked trace endpoint.
type CAWhyHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewCAWhyHandler creates a CAWhyHandler.
func NewCAWhyHandler(pool *pgxpool.Pool, logger *slog.Logger) *CAWhyHandler {
	return &CAWhyHandler{pool: pool, logger: logger}
}

// sinceInterval maps the ?since= window param to an interval string.
// ponytail: same 3-value vocabulary as ca_policy_impact; reject anything else with 400.
func sinceInterval(since string) (time.Duration, bool) {
	switch since {
	case "24h":
		return 24 * time.Hour, true
	case "7d":
		return 7 * 24 * time.Hour, true
	case "30d":
		return 30 * 24 * time.Hour, true
	default:
		// Default to 7d if empty (convenience for the UI initial load).
		if since == "" {
			return 7 * 24 * time.Hour, true
		}
		return 0, false
	}
}

// Why returns the ca_signin_log trace for a user + time window.
//
// Query params:
//   - user=<id|email>     — resolved by numeric id first, then email; unresolvable → 404 {found:false}
//   - since=<24h|7d|30d>  — time window (default: 7d)
//   - correlation_id=     — optional; when set, filters to a single sign-in event
//
// Response:
//   - 404 {found:false}                   — user not resolvable
//   - 200 {found:true, user_id, rows:[]}  — user found, zero rows (calm empty state)
//   - 200 {found:true, user_id, rows:[…]} — user found, sign-in rows
//
// Gated: requireCAPolicyRead at the route.
func (h *CAWhyHandler) Why(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	userParam := q.Get("user")
	corrID := q.Get("correlation_id")
	sinceParam := q.Get("since")

	// Must have at least one of user= or correlation_id=.
	if userParam == "" && corrID == "" {
		httputil.WriteError(w, http.StatusBadRequest, "user or correlation_id is required")
		return
	}

	dur, ok := sinceInterval(sinceParam)
	if !ok {
		httputil.WriteError(w, http.StatusBadRequest, "since must be one of: 24h, 7d, 30d")
		return
	}
	cutoff := time.Now().Add(-dur)

	// ── Resolve user_id ──
	// If correlation_id is provided without user=, skip user lookup (log rows carry user_id).
	var userID int64
	if userParam != "" {
		// Try numeric id first, then email.
		if id, err := strconv.ParseInt(userParam, 10, 64); err == nil {
			// Validate the id exists (R1: cross-tenant admin read, not per-user data).
			var found bool
			if scanErr := h.pool.QueryRow(ctx,
				`SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, id,
			).Scan(&found); scanErr != nil || !found {
				httputil.WriteJSON(w, http.StatusNotFound, map[string]any{"found": false})
				return
			}
			userID = id
		} else {
			// Treat as email address — must be a local user (email col).
			var scanErr error
			scanErr = h.pool.QueryRow(ctx,
				`SELECT id FROM users WHERE email = $1`, strings.ToLower(userParam),
			).Scan(&userID)
			if scanErr == pgx.ErrNoRows {
				httputil.WriteJSON(w, http.StatusNotFound, map[string]any{"found": false})
				return
			}
			if scanErr != nil {
				h.logger.Error("ca-why user lookup failed", "error", scanErr)
				httputil.WriteError(w, http.StatusInternalServerError, "database error")
				return
			}
		}
	}

	// ── Query ca_signin_log ──
	// ponytail: direct SELECT (no reducer) — read-only telemetry; same pattern as SignInLog.
	var (
		rows pgx.Rows
		err  error
	)
	if corrID != "" && userID == 0 {
		// correlation_id only — resolve single event (user_id unknown until log row is read).
		rows, err = h.pool.Query(ctx,
			caSignInLogSelect+` WHERE correlation_id = $1 AND occurred_at >= $2 ORDER BY occurred_at DESC`,
			corrID, cutoff)
	} else if corrID != "" {
		// Both user and correlation_id.
		rows, err = h.pool.Query(ctx,
			caSignInLogSelect+` WHERE user_id = $1 AND correlation_id = $2 AND occurred_at >= $3 ORDER BY occurred_at DESC`,
			userID, corrID, cutoff)
	} else {
		// User only.
		rows, err = h.pool.Query(ctx,
			caSignInLogSelect+` WHERE user_id = $1 AND occurred_at >= $2 ORDER BY occurred_at DESC LIMIT 200`,
			userID, cutoff)
	}
	if err != nil {
		h.logger.Error("ca-why query failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	out := []map[string]any{} // non-nil so JSON serialises as [] not null.
	for rows.Next() {
		row, scanErr := scanCASignInLogRow(rows)
		if scanErr != nil {
			h.logger.Warn("ca-why scan failed", "error", scanErr)
			continue
		}
		out = append(out, row)
	}
	if rows.Err() != nil {
		h.logger.Error("ca-why rows error", "error", rows.Err())
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"found":   true,
		"user_id": userID,
		"rows":    out,
	})
}
