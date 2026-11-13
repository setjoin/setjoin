package user

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
)

// FocusHandler handles the Focused/Other inbox split: POST /messages/{id}/focus
// with body {"focused": bool}. focused=true moves the message to Focused (removes
// the Other tag); focused=false moves it to Other (adds the Other tag). Either way
// the reducer records a per-sender override so future mail lands the same way.
type FocusHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewFocusHandler creates a FocusHandler. The pool is the worker (BYPASSRLS) pool:
// the ownership read joins across all of the user's mailboxes and set_message_focus
// writes message_tags + focus_sender_overrides (both RLS-forced). Ownership is
// enforced structurally — the bound read binds mailbox_id to mb.user_id, and the
// reducer re-derives the sender + owner from that same mailbox (never from req).
func NewFocusHandler(workerPool pgxutil.WorkerPool, logger *slog.Logger) *FocusHandler {
	return &FocusHandler{pool: workerPool.Pool, logger: logger}
}

// SetFocus handles POST /messages/{id}/focus.
func (h *FocusHandler) SetFocus(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	msgID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || msgID <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid message id")
		return
	}

	var req struct {
		Focused bool `json:"focused"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Bound ownership read (R1/R4, same statement — no TOCTOU): resolve the
	// message the caller must own via the shared helper (mailbox→user join). This
	// is the ONLY source of mailbox_id/received_at — never req.*. h.pool is the
	// worker (BYPASSRLS) pool, matching ResolveOwnedMessage's contract.
	om, err := ResolveOwnedMessage(r.Context(), h.pool, msgID, u.UserID)
	if err != nil {
		httputil.WriteError(w, http.StatusNotFound, "message not found")
		return
	}

	_, err = h.pool.Exec(r.Context(),
		`SELECT set_message_focus($1, $2, $3, $4)`,
		msgID, om.ReceivedAt, req.Focused, om.MailboxID,
	)
	if err != nil {
		h.logger.Error("set_message_focus failed", "message_id", msgID, "error", err)
		httputil.WriteError(w, reducerErrorStatus(err), "focus update failed")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"focused": req.Focused})
}
