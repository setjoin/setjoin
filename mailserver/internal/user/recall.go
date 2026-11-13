package user

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
)

// RecallHandler handles message recall: POST /messages/{id}/recall
// Allows a sender to retract a message from all recipient mailboxes if
// the recipients are local and the recall is within the configured window.
type RecallHandler struct {
	pool         *pgxpool.Pool
	logger       *slog.Logger
	recallWindow time.Duration
}

// NewRecallHandler creates a RecallHandler.
func NewRecallHandler(workerPool pgxutil.WorkerPool, logger *slog.Logger, recallWindow time.Duration) *RecallHandler {
	if recallWindow <= 0 {
		recallWindow = 5 * time.Minute
	}
	return &RecallHandler{pool: workerPool.Pool, logger: logger, recallWindow: recallWindow}
}

// Recall attempts to retract a message from recipient mailboxes.
// POST /messages/{id}/recall
func (h *RecallHandler) Recall(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	idStr := r.PathValue("id")
	msgID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid message id")
		return
	}

	// 1. Look up the message to get sender and timestamp. Recall is
	// SENDER-scoped: the caller recalls their OWN copy of a message they sent.
	// Bind the metadata read to a mailbox the authenticated user owns so this
	// read cannot leak from_addr/received_at/Message-ID of an arbitrary message
	// id (R4 per-user isolation — same statement, no TOCTOU). The is-sender
	// check below further verifies the from_addr belongs to the caller.
	var fromAddr string
	var receivedAt time.Time
	var mailboxID int64
	var messageIDHeader string
	err = h.pool.QueryRow(r.Context(),
		`SELECT m.from_addr, m.received_at, m.mailbox_id, m.message_id
		 FROM messages m
		 JOIN mailboxes mb ON mb.id = m.mailbox_id
		 WHERE m.id = $1 AND mb.user_id = $2`,
		msgID, u.UserID,
	).Scan(&fromAddr, &receivedAt, &mailboxID, &messageIDHeader)
	if err != nil {
		httputil.WriteError(w, http.StatusNotFound, "message not found")
		return
	}

	// 2. Verify the current user is the sender.
	if !h.isSender(r.Context(), u.UserID, u.Email, fromAddr) {
		httputil.WriteError(w, http.StatusForbidden, "only the sender can recall this message")
		return
	}

	// 3. Check the recall window.
	if time.Since(receivedAt) > h.recallWindow {
		httputil.WriteError(w, http.StatusGone, "recall window has expired")
		return
	}

	// 4. Route the recall through the reducer (ARCH-002). The reducer is the
	// structural gate: it touches ONLY unread, local copies, soft-moves them to
	// Trash via transition_message_location, inserts a recoverable stub, and writes
	// the message_recalls audit row. Its own WHERE is pinned to "a sent copy exists
	// in p_recaller_mailbox_id" — so even on a privileged pool it cannot reach a
	// message the caller didn't send. The isSender + window checks above stay as
	// defense-in-depth pre-gates.
	//
	// The return is a CALLER-SAFE verdict only: {type, recalled}. The reducer
	// deliberately does NOT return the cross-mailbox copy/cannot counts or the
	// per-recipient list — under Message-ID forgery that would be a recipient-state
	// enumeration oracle. We forward neither over the wire nor to logs above debug.
	var verdict []byte
	err = h.pool.QueryRow(r.Context(),
		`SELECT recall_message($1, $2, $3, 'user')`,
		messageIDHeader, u.UserID, mailboxID,
	).Scan(&verdict)
	if err != nil {
		h.logger.Error("recall reducer failed", "error", err)
		// Classify the reducer's BZ business error so an over-quota / forbidden /
		// not-found failure surfaces as 507 / 403 / 404 instead of a blanket 500;
		// an unrecognized error keeps the 500 fallback (ClassUnknown → 500).
		httputil.WriteError(w, reducerErrorStatus(err), "database error")
		return
	}

	var res struct {
		Type     string `json:"type"`
		Recalled bool   `json:"recalled"`
	}
	if err := json.Unmarshal(verdict, &res); err != nil {
		h.logger.Error("recall verdict decode failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	// Map the reducer verdict to an HTTP status. Only caller-scoped facts cross the
	// wire: {status, recalled}. No cross-mailbox count, no recipient list.
	var status int
	switch res.Type {
	case "success":
		status = http.StatusOK
	case "notFound":
		// No sent copy in the caller's own Sent folder → nothing the caller can
		// recall. 404 is also what the bound metadata read returns, so the two
		// "you have no such message" paths stay indistinguishable.
		status = http.StatusNotFound
	case "alreadyRecalled":
		status = http.StatusConflict
	case "disabled":
		// feature.recall is off. 404 (not 403): a 403 would confirm the message
		// exists-and-is-recallable-but-for-the-toggle, leaking message state; 404
		// keeps the feature-off response uniform with "no such recallable message"
		// and reveals nothing about the target.
		status = http.StatusNotFound
	default:
		h.logger.Error("recall unknown verdict type", "type", res.Type)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	// Caller-scoped log only. The true cross-mailbox copy/cannot counts live in the
	// message_recalls audit row, NOT here (they are a recipient-state oracle).
	h.logger.Info("message recall processed",
		"messageID", msgID,
		"verdict", res.Type,
	)

	httputil.WriteJSON(w, status, map[string]any{
		"status":   res.Type,
		"recalled": res.Recalled,
	})
}

// isSender checks whether the authenticated user owns the given from_addr.
func (h *RecallHandler) isSender(ctx context.Context, userID int64, userEmail, fromAddr string) bool {
	// Direct email match.
	if fromAddr == userEmail {
		return true
	}

	// Check aliases.
	var exists bool
	err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM aliases a
			JOIN mailboxes mb ON mb.id = a.mailbox_id
			WHERE mb.user_id = $1 AND a.email = $2
		)`,
		userID, fromAddr,
	).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
}
