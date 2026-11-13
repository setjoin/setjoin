package admin

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/httputil"
)

// LinkProtectAuditHandler provides admin access to link protection audit logs.
type LinkProtectAuditHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewLinkProtectAuditHandler creates a link protect audit handler.
func NewLinkProtectAuditHandler(pool *pgxpool.Pool, logger *slog.Logger) *LinkProtectAuditHandler {
	return &LinkProtectAuditHandler{pool: pool, logger: logger}
}

// List returns paginated link protect audit entries.
// Query params: since (RFC 3339 timestamp), limit (default 50, max 100), url_hash
func (h *LinkProtectAuditHandler) List(w http.ResponseWriter, r *http.Request) {
	sinceStr := r.URL.Query().Get("since")
	urlHash := r.URL.Query().Get("url_hash")

	limit, _ := httputil.ParseLimitOffset(r, 50, 100)

	var since time.Time
	if sinceStr != "" {
		var err error
		since, err = time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid since format, use RFC 3339"})
			return
		}
	}

	where := "1=1"
	args := []interface{}{}
	argN := 0

	if !since.IsZero() {
		argN++
		where += " AND created_at >= $" + strconv.Itoa(argN)
		args = append(args, since)
	}
	if urlHash != "" {
		argN++
		where += " AND url_hash = $" + strconv.Itoa(argN)
		args = append(args, urlHash)
	}

	argN++
	args = append(args, limit)
	query := `SELECT id, url_hash, verdict, scanner, message_id, mailbox_id, client_ip, created_at
		FROM link_protect_audit WHERE ` + where + ` ORDER BY created_at DESC LIMIT $` + strconv.Itoa(argN)

	rows, err := h.pool.Query(r.Context(), query, args...)
	if err != nil {
		h.logger.Error("link_protect_audit: query failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	type item struct {
		ID        int64  `json:"id"`
		URLHash   string `json:"url_hash"`
		Verdict   string `json:"verdict"`
		Scanner   string `json:"scanner"`
		MessageID int64  `json:"message_id"`
		MailboxID int64  `json:"mailbox_id"`
		ClientIP  string `json:"client_ip"`
		CreatedAt string `json:"created_at"`
	}

	var items []item
	for rows.Next() {
		var i item
		var ts time.Time
		if err := rows.Scan(&i.ID, &i.URLHash, &i.Verdict, &i.Scanner, &i.MessageID, &i.MailboxID, &i.ClientIP, &ts); err != nil {
			h.logger.Error("link_protect_audit: scan failed", "error", err)
			continue
		}
		i.CreatedAt = ts.Format(time.RFC3339)
		items = append(items, i)
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"items": items,
		"count": len(items),
	})
}
