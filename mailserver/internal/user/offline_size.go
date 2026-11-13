package user

import (
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
)

// offlineSizeBucket is one cumulative age-window estimate in the GET /offline/size-estimate response.
type offlineSizeBucket struct {
	Window       string `json:"window"`
	MessageCount int64  `json:"messageCount"`
	BodyBytes    int64  `json:"bodyBytes"`
}

// OfflineSizeHandler serves GET /offline/size-estimate — per-age-bucket body bytes EXCLUDING
// attachments. Each bucket is cumulative (messages with received_at >= now()-window).
// "all" is the no-filter total. Platform-independent "needed on disk" preview
// for the native Storage slider (native-offline pivot 2026-06-23).
type OfflineSizeHandler struct {
	workerPool *pgxpool.Pool
	logger     *slog.Logger
}

// NewOfflineSizeHandler takes workerPool (BYPASSRLS) because the query is
// cross-mailbox-for-one-user (mb.user_id across all the user's mailboxes).
// INERT until DB_WORKER_DSN is set (workerPool aliases pool until then).
func NewOfflineSizeHandler(workerPool pgxutil.WorkerPool, logger *slog.Logger) *OfflineSizeHandler {
	return &OfflineSizeHandler{workerPool: workerPool.Pool, logger: logger}
}

func (h *OfflineSizeHandler) Get(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// One pass over the user's messages: COUNT/SUM of body-only bytes per cumulative
	// window + an "all" total. body bytes = octet_length(body_text)+octet_length(body_html);
	// attachments (carried in size_bytes / blobs) are excluded.
	// R1: JOIN mailboxes ON mb.user_id = $1 scopes to the authenticated user.
	// ponytail: single aggregate scan avoids N round-trips; 6 buckets = 12 scalar columns.
	const q = `
		SELECT
			COUNT(*) FILTER (WHERE m.received_at >= now() - interval '7 days')   AS c7,
			COALESCE(SUM(b) FILTER (WHERE m.received_at >= now() - interval '7 days'), 0)   AS b7,
			COUNT(*) FILTER (WHERE m.received_at >= now() - interval '30 days')  AS c30,
			COALESCE(SUM(b) FILTER (WHERE m.received_at >= now() - interval '30 days'), 0)  AS b30,
			COUNT(*) FILTER (WHERE m.received_at >= now() - interval '90 days')  AS c90,
			COALESCE(SUM(b) FILTER (WHERE m.received_at >= now() - interval '90 days'), 0)  AS b90,
			COUNT(*) FILTER (WHERE m.received_at >= now() - interval '180 days') AS c180,
			COALESCE(SUM(b) FILTER (WHERE m.received_at >= now() - interval '180 days'), 0) AS b180,
			COUNT(*) FILTER (WHERE m.received_at >= now() - interval '365 days') AS c365,
			COALESCE(SUM(b) FILTER (WHERE m.received_at >= now() - interval '365 days'), 0) AS b365,
			COUNT(*)        AS call,
			COALESCE(SUM(b), 0) AS ball
		FROM (
			SELECT m.received_at,
			       octet_length(COALESCE(m.body_text, '')) + octet_length(COALESCE(m.body_html, '')) AS b
			FROM messages m
			JOIN mailboxes mb ON mb.id = m.mailbox_id
			WHERE mb.user_id = $1 AND NOT m.is_deleted
		) m`

	var c7, b7, c30, b30, c90, b90, c180, b180, c365, b365, call, ball int64
	err := h.workerPool.QueryRow(r.Context(), q, u.UserID).Scan(
		&c7, &b7, &c30, &b30, &c90, &b90, &c180, &b180, &c365, &b365, &call, &ball,
	)
	if err != nil {
		h.logger.Error("offline size estimate failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	buckets := []offlineSizeBucket{
		{"7d", c7, b7},
		{"30d", c30, b30},
		{"90d", c90, b90},
		{"180d", c180, b180},
		{"365d", c365, b365},
		{"all", call, ball},
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{"buckets": buckets})
}
