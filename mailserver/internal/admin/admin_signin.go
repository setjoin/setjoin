package admin

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// SignInHandler provides admin per-user sign-in history, sessions, and secure-account.
type SignInHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewSignInHandler creates a SignInHandler.
func NewSignInHandler(pool *pgxpool.Pool, logger *slog.Logger) *SignInHandler {
	return &SignInHandler{pool: pool, logger: logger}
}

// domainGate confirms the target user exists AND is within the admin's domain scope.
// Returns (userID, true) on pass; writes 404 and returns (0, false) on miss.
// domainScope == 0 means global admin (no domain restriction).
//
// ponytail: single EXISTS subquery folds domain check and existence check into one
// roundtrip; avoids a separate lookup + TOCTOU (R1/R3).
func (h *SignInHandler) domainGate(w http.ResponseWriter, r *http.Request, uid int64) bool {
	domainScope := middleware.DomainScopeFromContext(r.Context())
	var ok bool
	var err error
	if domainScope > 0 {
		err = h.pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND domain_id = $2)`,
			uid, domainScope).Scan(&ok)
	} else {
		err = h.pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`,
			uid).Scan(&ok)
	}
	if err != nil || !ok {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return false
	}
	return true
}

// ListForUser handles GET /admin/users/{id}/sign-ins.
// Returns that user's login_events (attributed rows only, newest first).
// Domain-scoped: a domain-A admin cannot see domain-B users (→ 404).
// login_events has RLS on app.current_user_id; we set the GUC via RunUserScoped.
func (h *SignInHandler) ListForUser(w http.ResponseWriter, r *http.Request) {
	uid, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "bad id")
		return
	}
	if !h.domainGate(w, r, uid) {
		return
	}

	type loginEventRow struct {
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
	}

	var items []loginEventRow

	// ponytail: RunUserScoped sets app.current_user_id GUC for the RLS policy on
	// login_events (V028 all-protocol partitioned). Ceiling: no pagination (200 row cap);
	// add cursor pagination when an admin needs >200 events per user.
	if err := dbscope.RunUserScoped(r.Context(), h.pool, uid, func(tx pgx.Tx) error {
		const q = `
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
			       COALESCE(fail_reason, '')     AS fail_reason
			FROM login_events
			WHERE user_id = $1
			ORDER BY occurred_at DESC
			LIMIT 200`
		rows, err := tx.Query(r.Context(), q, uid)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e loginEventRow
			var occurredAt time.Time
			if scanErr := rows.Scan(
				&e.ID, &occurredAt, &e.SourceIP, &e.Location, &e.DeviceName,
				&e.Platform, &e.Client, &e.Protocol, &e.AuthMethod,
				&e.Success, &e.FailReason,
			); scanErr != nil {
				continue
			}
			e.OccurredAt = occurredAt.UTC().Format(time.RFC3339)
			items = append(items, e)
		}
		return rows.Err()
	}); err != nil {
		h.logger.Error("admin sign-in list failed", "uid", uid, "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}

	if items == nil {
		items = []loginEventRow{}
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

// SessionsForUser handles GET /admin/users/{id}/sessions.
// Returns that user's active oauth refresh families + web sessions (same UNION as
// the self-service GET /user/sessions, but scoped to the target user_id).
// Domain-scoped: out-of-scope target → 404.
func (h *SignInHandler) SessionsForUser(w http.ResponseWriter, r *http.Request) {
	uid, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "bad id")
		return
	}
	if !h.domainGate(w, r, uid) {
		return
	}

	// Reuse the same UNION ALL query as user.SessionsHandler.List (sessions.go)
	// with user_id = $1 (the target) and no current-session flag (admin view).
	// ponytail: duplicated SQL — three callers would justify extracting; two is fine.
	const q = `
		SELECT id::text,
		       'oauth'                                 AS kind,
		       COALESCE(client_id,'')                 AS client_id,
		       ''                                      AS device,
		       ''                                      AS location,
		       COALESCE(last_used_at, issued_at)       AS last_used_at,
		       COALESCE(last_used_protocol,'')         AS auth_method
		FROM oauth_tokens
		WHERE user_id = $1
		  AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > now())
		  AND previous_token_hash IS NULL
		  AND token_type IN ('refresh','xoauth2','app_password')
		UNION ALL
		SELECT id,
		       'web'                                   AS kind,
		       ''                                      AS client_id,
		       COALESCE(user_agent,'')                 AS device,
		       COALESCE(host(ip),'')                   AS location,
		       last_seen_at                            AS last_used_at,
		       COALESCE(auth_method,'')                AS auth_method
		FROM sessions
		WHERE user_id = $1
		  AND expires_at > now()
		ORDER BY last_used_at DESC NULLS LAST`

	rows, err := h.pool.Query(r.Context(), q, uid)
	if err != nil {
		h.logger.Error("admin sessions list failed", "uid", uid, "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	type sessionRow struct {
		ID         string `json:"id"`
		Kind       string `json:"kind"`
		ClientID   string `json:"client_id"`
		Device     string `json:"device"`
		Location   string `json:"location"`
		LastUsedAt string `json:"last_used_at"`
		AuthMethod string `json:"auth_method"`
	}

	sessions := []sessionRow{}
	for rows.Next() {
		var s sessionRow
		var lastUsedAt time.Time
		if err := rows.Scan(
			&s.ID, &s.Kind, &s.ClientID, &s.Device, &s.Location,
			&lastUsedAt, &s.AuthMethod,
		); err != nil {
			continue
		}
		s.LastUsedAt = lastUsedAt.UTC().Format(time.RFC3339)
		sessions = append(sessions, s)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("admin sessions scan failed", "uid", uid, "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{"sessions": sessions})
}

// SecureForUser handles POST /admin/users/{id}/secure-account.
// In one transaction: revokes target's oauth tokens + web sessions, then calls
// secure_account(target_id, admin_id, ip, 'admin_secure') which atomically sets
// must_change_password=true and writes the admin_audit_log row attributing the admin.
// Domain-scoped: out-of-scope target → 404.
func (h *SignInHandler) SecureForUser(w http.ResponseWriter, r *http.Request) {
	uid, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "bad id")
		return
	}
	// domainGate confirms existence + scope before we open the tx (no TOCTOU:
	// the tx re-scopes the mutations to the same user_id).
	if !h.domainGate(w, r, uid) {
		return
	}

	adminClaims := auth.UserFromContext(r.Context())
	if adminClaims == nil {
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

	// Revoke target's oauth families (R3: user_id in WHERE).
	if _, err := tx.Exec(r.Context(),
		`UPDATE oauth_tokens SET revoked_at = now(), revoked_by = $2
		 WHERE user_id = $1 AND revoked_at IS NULL`, uid, adminClaims.UserID); err != nil {
		h.logger.Error("admin secure-account oauth revoke failed", "target", uid, "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	// Delete target's web sessions (R3).
	if _, err := tx.Exec(r.Context(),
		`DELETE FROM sessions WHERE user_id = $1`, uid); err != nil {
		h.logger.Error("admin secure-account session delete failed", "target", uid, "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	// secure_account reducer: sets must_change_password=true, writes audit row
	// (user_id=admin_id, target_id=uid), emits admin:alert pg_notify.
	// BZ084 → user not found (already guarded by domainGate; belt-and-suspenders).
	if _, err := tx.Exec(r.Context(),
		`SELECT secure_account($1, $2, $3::inet, 'admin_secure')`,
		uid, adminClaims.UserID, ip); err != nil {
		h.logger.Error("admin secure-account reducer failed", "target", uid, "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "secured"})
}
