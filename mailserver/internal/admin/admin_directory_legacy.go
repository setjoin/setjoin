package admin

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/httputil"
)

// writeLegacyDirectorySyncLog projects the current identity-sync ledger into
// the stable response shape consumed by the legacy AD and LDAP consoles. The
// ledger is organization-wide and has no domain dimension, so domain-scoped
// administrators receive an empty result rather than cross-domain details.
func writeLegacyDirectorySyncLog(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool, source string, limit int) {
	if middleware.DomainScopeFromContext(r.Context()) != 0 {
		httputil.WriteJSON(w, http.StatusOK, []map[string]interface{}{})
		return
	}
	rows, err := pool.Query(r.Context(), `
		SELECT source, users_checked, users_created, users_updated, users_disabled,
		       fields_skipped, CASE WHEN error IS NULL THEN 0 ELSE 1 END,
		       COALESCE(duration_ms, 0), sync_at, COALESCE(details, '{}'::jsonb)
		FROM identity_sync_log
		WHERE source = $1
		ORDER BY sync_at DESC
		LIMIT $2`, source, limit)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	out := []map[string]interface{}{}
	for rows.Next() {
		var rowSource string
		var checked, created, updated, disabled, skipped, errorCount, durationMS int
		var syncedAt time.Time
		var details []byte
		if err := rows.Scan(&rowSource, &checked, &created, &updated, &disabled, &skipped, &errorCount, &durationMS, &syncedAt, &details); err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "database error")
			return
		}
		out = append(out, map[string]interface{}{
			"source": rowSource, "checked": checked, "created": created,
			"updated": updated, "disabled": disabled, "skipped": skipped,
			"errors": errorCount, "durationSeconds": durationMS / 1000,
			"syncedAt": syncedAt, "details": json.RawMessage(details),
		})
	}
	if rows.Err() != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}
