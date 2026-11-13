package user

import (
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// SessionsHandler provides user-facing active-session endpoints.
type SessionsHandler struct{ pool *pgxpool.Pool }

// NewSessionsHandler creates a SessionsHandler.
func NewSessionsHandler(pool *pgxpool.Pool) *SessionsHandler { return &SessionsHandler{pool: pool} }

// sessionRow is the unified shape returned by GET /user/sessions.
type sessionRow struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`      // "web" | "oauth"
	ClientID   string `json:"client_id"` // empty for web sessions
	Device     string `json:"device"`
	Location   string `json:"location"`
	LastUsedAt string `json:"last_used_at"`
	AuthMethod string `json:"auth_method"`
	Current    bool   `json:"current"`
}

// List handles GET /user/sessions — live oauth refresh families + web sessions
// for the authenticated caller only (R1). The presenting session is flagged
// current = true via JTI match.
//
// ponytail: single UNION ALL query avoids N+1; no pagination — session counts
// are small (add pagination when a user has >100 sessions, which is unusual).
func (h *SessionsHandler) List(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// UNION ALL: active (non-revoked, non-expired) oauth refresh families +
	// active (non-expired) web sessions, both scoped to the caller's user_id (R1).
	// oauth: previous_token_hash IS NULL selects the current/root token of each
	// rotation chain (the most recent un-rotated token in the family). app_passwords
	// and authorization codes are excluded.
	// web: id compared to JTI for the current flag; oauth is never current.
	const q = `
		SELECT id::text,
		       'oauth'                                 AS kind,
		       COALESCE(client_id,'')                 AS client_id,
		       ''                                      AS device,
		       ''                                      AS location,
		       COALESCE(last_used_at, issued_at)       AS last_used_at,
		       COALESCE(last_used_protocol,'')         AS auth_method,
		       false                                   AS current
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
		       COALESCE(auth_method,'')                AS auth_method,
		       (id = $2)                               AS current
		FROM sessions
		WHERE user_id = $1
		  AND expires_at > now()
		ORDER BY last_used_at DESC NULLS LAST`

	rows, err := h.pool.Query(r.Context(), q, claims.UserID, claims.JTI)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	sessions := []sessionRow{} // never nil → always JSON array
	for rows.Next() {
		var s sessionRow
		var lastUsedAt time.Time
		if err := rows.Scan(
			&s.ID, &s.Kind, &s.ClientID, &s.Device, &s.Location,
			&lastUsedAt, &s.AuthMethod, &s.Current,
		); err != nil {
			continue
		}
		s.LastUsedAt = lastUsedAt.UTC().Format(time.RFC3339)
		sessions = append(sessions, s)
	}
	if err := rows.Err(); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}

	// ponytail: wraps as {"sessions":[...]} matching the login_history convention;
	// the brief says bare []Session but the consistent envelope is the deliberate choice.
	// T12 (sa-task-12) must destructure .sessions — see sa-task-9-report.md.
	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{"sessions": sessions})
}

// Revoke handles DELETE /user/sessions/{id} — revokes the web session or the
// oauth token whose id matches AND belongs to the caller (R3). Tries web
// session first, then oauth token; no match → 404.
//
// ER5 occ_cea9ecad3167712dff3b74ab (individual-revoke): every individual
// revocation propagates through the CA-3a session-revocation contract
// (revoke_user_sessions), not a bare row deletion. Before this, revoke-all
// wrote the denylist row but revoking ONE session only deleted/updated local
// rows — any access JWT already issued for that session (web jti) or token
// family (oauth family_id) stayed acceptable to the gateway until its own
// expiry. The reducer now owns each arm atomically: scope='jti' deletes the
// web session row AND inserts the denylist entry (plus audit + the single
// 'session_revoke' app_notify); scope='family' revokes the whole rotation
// family AND inserts the family denylist entry with the family's durable
// lifetime floor. Inert while feature.cae_runtime is OFF; enforcement once ON.
func (h *SessionsHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "session id required")
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck // no-op after a successful Commit

	// Arm 1 — web session: existence check + reducer in the SAME transaction
	// (R3: the ownership predicate scopes the read; the reducer's own
	// user-bound DELETE re-checks it, so a concurrent steal cannot widen the
	// mutation). scope='jti' = denylist row + session deletion + audit + notify.
	var isWeb bool
	if err := tx.QueryRow(r.Context(),
		`SELECT EXISTS(SELECT 1 FROM sessions WHERE id = $1 AND user_id = $2)`,
		id, claims.UserID,
	).Scan(&isWeb); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	if isWeb {
		if _, err := tx.Exec(r.Context(),
			`SELECT revoke_user_sessions($1, 'jti', 'user_revoke_one', $1, $2, NULL)`,
			claims.UserID, id); err != nil {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
			return
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
		return
	}

	// Arm 2 — oauth token: resolve the rotation family (V025) of the caller's
	// own token and revoke through the same contract. scope='family' both
	// revokes every family member (root + rotated children — the findings 2+3
	// fix, now via the reducer) and writes the family denylist row.
	var familyID *string
	err = tx.QueryRow(r.Context(),
		`SELECT family_id::text FROM oauth_tokens WHERE id::text = $1 AND user_id = $2 LIMIT 1`,
		id, claims.UserID,
	).Scan(&familyID)
	if errors.Is(err, pgx.ErrNoRows) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	if familyID != nil && *familyID != "" {
		if _, err := tx.Exec(r.Context(),
			`SELECT revoke_user_sessions($1, 'family', 'user_revoke_one', $1, NULL, $2)`,
			claims.UserID, *familyID); err != nil {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
			return
		}
	} else {
		// Legacy/seed token with no family: the family contract has no durable
		// anchor to bind a denylist entry to, so fall back to revoking exactly
		// the presented token (same predicate as before — ownership in WHERE).
		// ponytail: upgrade path is backfilling family_id for legacy rows.
		ct, err := tx.Exec(r.Context(),
			`UPDATE oauth_tokens SET revoked_at = now(), revoked_by = $3
			 WHERE user_id = $2 AND revoked_at IS NULL AND id::text = $1`,
			id, claims.UserID, claims.UserID)
		if err != nil {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
			return
		}
		if ct.RowsAffected() == 0 {
			httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// RevokeAll handles POST /user/sessions/revoke-all — revokes all oauth tokens
// and deletes all web sessions for the authenticated caller in one transaction.
func (h *SessionsHandler) RevokeAll(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck

	if _, err := tx.Exec(r.Context(),
		`UPDATE oauth_tokens SET revoked_at = now(), revoked_by = $1
		 WHERE user_id = $1 AND revoked_at IS NULL`, claims.UserID); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	if _, err := tx.Exec(r.Context(),
		`DELETE FROM sessions WHERE user_id = $1`, claims.UserID); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	// web-session-revoke Tier 1 (TODOS.md): also write the CA-3a denylist row so
	// a still-valid stateless web JWT is actually denied once feature.cae_runtime
	// is ON — before this, revoke-all only deleted local rows (oauth_tokens /
	// sessions) and left any already-issued JWT usable until its own expiry.
	// Same reducer + call shape admin_conditional_access.go's RevokeSessions
	// already uses (self-service actor = the caller, not an admin). Inert (no
	// user-visible effect) while cae_runtime is OFF, the default.
	if _, err := tx.Exec(r.Context(),
		`SELECT revoke_user_sessions($1, 'all', 'user_revoke_all', $1, NULL, NULL)`,
		claims.UserID); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "revoked-all"})
}
