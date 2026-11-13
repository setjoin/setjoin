package admin

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/httputil"
)

// AuthLogHandler serves the auth event log viewer.
type AuthLogHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

func NewAuthLogHandler(pool *pgxpool.Pool, logger *slog.Logger) *AuthLogHandler {
	return &AuthLogHandler{pool: pool, logger: logger}
}

// List returns auth event log entries with optional filters.
func (h *AuthLogHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	provider := q.Get("provider")
	event := q.Get("event")
	since := q.Get("since")
	email := q.Get("email")
	limit := q.Get("limit")
	if limit == "" {
		limit = "200"
	}

	sql := `SELECT id, user_id, email, event, provider,
			COALESCE(host(ip_address::inet), ''), occurred_at
			FROM auth_event_log WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if provider != "" && provider != "all" {
		sql += ` AND provider = $` + strconv.Itoa(argIdx)
		args = append(args, provider)
		argIdx++
	}
	if event != "" && event != "all" {
		sql += ` AND event = $` + strconv.Itoa(argIdx)
		args = append(args, event)
		argIdx++
	}
	if since != "" {
		sql += ` AND occurred_at > now() - $` + strconv.Itoa(argIdx) + `::interval`
		args = append(args, since)
		argIdx++
	}
	if email != "" {
		sql += ` AND email ILIKE '%' || $` + strconv.Itoa(argIdx) + ` || '%'`
		args = append(args, email)
		argIdx++
	}
	sql += ` ORDER BY occurred_at DESC LIMIT $` + strconv.Itoa(argIdx)
	args = append(args, limit)

	rows, err := h.pool.Query(r.Context(), sql, args...)
	if err != nil {
		h.logger.Error("auth log query failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	type authLogEntry struct {
		ID         int64     `json:"id"`
		UserID     *int64    `json:"userId,omitempty"`
		Email      string    `json:"email"`
		Event      string    `json:"event"`
		Provider   string    `json:"provider"`
		IPAddress  string    `json:"ipAddress"`
		OccurredAt time.Time `json:"occurredAt"`
	}
	out := make([]authLogEntry, 0)
	for rows.Next() {
		var e authLogEntry
		if rows.Scan(&e.ID, &e.UserID, &e.Email, &e.Event, &e.Provider, &e.IPAddress, &e.OccurredAt) == nil {
			out = append(out, e)
		}
	}
	if out == nil {
		out = make([]authLogEntry, 0)
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}
