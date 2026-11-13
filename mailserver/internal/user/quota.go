package user

import (
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// QuotaHandler serves GET /user/quota — the authenticated user's own mailbox
// storage total (used/quota summed across all their mailboxes). Read-only, for
// the Settings storage bar.
type QuotaHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewQuotaHandler takes the regular app pool (NOT workerPool). Unlike
// OfflineSizeHandler this query reads ONLY `mailboxes`, which has no native RLS
// policy (only messages/message_tags are ENABLE+FORCE'd, V004), so the app pool
// can read it even after the DSN switch to setjoin_app. The `WHERE user_id = $1`
// predicate is the R1 app-layer ownership scope. Mirrors ProfileHandler.
func NewQuotaHandler(pool *pgxpool.Pool, logger *slog.Logger) *QuotaHandler {
	return &QuotaHandler{pool: pool, logger: logger}
}

func (h *QuotaHandler) Get(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// R1: sum THIS user's own mailboxes only — user_id comes from auth, never the request.
	var used, quota int64
	if err := h.pool.QueryRow(r.Context(),
		`SELECT COALESCE(SUM(used_bytes),0), COALESCE(SUM(quota_bytes),0)
		 FROM mailboxes WHERE user_id = $1`,
		u.UserID).Scan(&used, &quota); err != nil {
		h.logger.Error("mailbox quota read failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]int64{"usedBytes": used, "quotaBytes": quota})
}
