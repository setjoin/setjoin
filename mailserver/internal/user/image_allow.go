package user

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/validate"
)

// ImageAllowHandler manages the per-sender remote-image trust list (V091
// user_image_allow, WAVE-5 #5): the senders a user chose "Always load images
// from this sender" for. EXACT-ADDRESS grain — domain grain would trust every
// local-part at big shared providers. The list only ungates the remote-image
// FETCH in the webmail; the HTML body always still passes DOMPurify sanitize.
//
// Routes (registerUserRoutes):
//
//	GET    /settings/trusted-senders          → {"senders":[{sender, createdAt}]}
//	POST   /settings/trusted-senders          {"sender": "..."} → upsert
//	DELETE /settings/trusted-senders/{sender} → remove (204)
//
// All statements run through dbscope.RunUserScoped on the regular app pool so
// the V091 FORCE RLS self policy (app.current_user_id) admits them once the
// runtime DSN flips to setjoin_app; every statement ALSO carries the explicit
// user_id = $1 predicate from auth context (R1/R2/R3 — the primary guard).
type ImageAllowHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewImageAllowHandler creates an ImageAllowHandler on the regular app pool.
func NewImageAllowHandler(pool *pgxpool.Pool, logger *slog.Logger) *ImageAllowHandler {
	return &ImageAllowHandler{pool: pool, logger: logger}
}

// runMutation executes fn scoped to userID via RunUserScoped and writes the
// standard 500 on failure (logging with label). Returns false on failure —
// the caller should return immediately without writing its own response.
// Add/Remove share this exact run-scoped/log/500 shape; only the SQL differs.
func (h *ImageAllowHandler) runMutation(w http.ResponseWriter, r *http.Request, userID int64, label string, fn func(pgx.Tx) error) bool {
	if err := dbscope.RunUserScoped(r.Context(), h.pool, userID, fn); err != nil {
		h.logger.Error(label, "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return false
	}
	return true
}

// trustedSender is one allowlist row as returned by List.
type trustedSender struct {
	Sender    string `json:"sender"`
	CreatedAt string `json:"createdAt"`
}

// normalizeSender canonicalizes + validates a sender address. Returns "" when
// the value is not a plausible email address.
func normalizeSender(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if err := validate.ValidateEmail(s, validate.WithSMTPUTF8(true)); err != nil {
		return ""
	}
	return s
}

// List handles GET /settings/trusted-senders.
func (h *ImageAllowHandler) List(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	senders := []trustedSender{}
	if err := dbscope.RunUserScoped(r.Context(), h.pool, u.UserID, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(),
			`SELECT sender, created_at FROM user_image_allow
			 WHERE user_id = $1 ORDER BY created_at DESC, sender`, u.UserID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s trustedSender
			var createdAt time.Time
			if err := rows.Scan(&s.Sender, &createdAt); err != nil {
				return err
			}
			s.CreatedAt = createdAt.UTC().Format(time.RFC3339)
			senders = append(senders, s)
		}
		return rows.Err()
	}); err != nil {
		h.logger.Error("trusted-senders list failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"senders": senders})
}

// Add handles POST /settings/trusted-senders.
func (h *ImageAllowHandler) Add(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		Sender string `json:"sender"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	sender := normalizeSender(req.Sender)
	if sender == "" {
		httputil.WriteError(w, http.StatusBadRequest, "invalid sender address")
		return
	}

	ok := h.runMutation(w, r, u.UserID, "trusted-senders add failed", func(tx pgx.Tx) error {
		// R2: user_id comes from auth context, never from the request body.
		_, err := tx.Exec(r.Context(),
			`INSERT INTO user_image_allow (user_id, sender) VALUES ($1, $2)
			 ON CONFLICT (user_id, sender) DO NOTHING`, u.UserID, sender)
		return err
	})
	if !ok {
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"sender": sender})
}

// Remove handles DELETE /settings/trusted-senders/{sender}.
func (h *ImageAllowHandler) Remove(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	sender := normalizeSender(r.PathValue("sender"))
	if sender == "" {
		httputil.WriteError(w, http.StatusBadRequest, "invalid sender address")
		return
	}

	ok := h.runMutation(w, r, u.UserID, "trusted-senders remove failed", func(tx pgx.Tx) error {
		// R3: ownership in the same WHERE as the delete — no TOCTOU.
		_, err := tx.Exec(r.Context(),
			`DELETE FROM user_image_allow WHERE user_id = $1 AND sender = $2`, u.UserID, sender)
		return err
	})
	if !ok {
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
