package user

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
)

// QuarantineHandler provides user self-service for quarantined messages.
//
// native-RLS (W7) — two distinct shapes:
//   - List/Count JOIN messages ACROSS all the user's mailboxes (R1 mb.user_id) —
//     genuinely cross-mailbox-for-one-user, so they run on the setjoin_worker
//     (BYPASSRLS) workerPool (the admin-case treatment for a read that does not
//     fit one app.current_mailbox_id GUC).
//   - Release/Reject act on ONE specific message: they first resolve that
//     message's mailbox_id from a USER-OWNED quarantine row (an owner-scoped read
//     on quarantined_messages/mailboxes — NOT FORCE'd tables), then do the
//     messages/message_tags work inside dbscope.RunScoped(mailboxID) — the
//     option-(a) treatment: minimal owner read first, then a properly-scoped tenant
//     tx (GUC = the resolved mailbox), so it survives the W6 FORCE flip WITHOUT
//     a blanket bypass. R3: the resolved id can only be the user's own message.
//
// Both pools alias the app pool until DB_WORKER_DSN is set (W1b), so INERT today.
type QuarantineHandler struct {
	pool       *pgxpool.Pool
	workerPool *pgxpool.Pool
	logger     *slog.Logger
}

// NewQuarantineHandler takes the tenant app pool (wrapped per-message work) and
// the BYPASSRLS worker pool (cross-mailbox List/Count). See the type doc.
func NewQuarantineHandler(pool *pgxpool.Pool, workerPool pgxutil.WorkerPool, logger *slog.Logger) *QuarantineHandler {
	return &QuarantineHandler{pool: pool, workerPool: workerPool.Pool, logger: logger}
}

// List returns the user's own quarantined messages.
func (h *QuarantineHandler) List(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	limit, _ := strconv.Atoi(limitStr)
	offset, _ := strconv.Atoi(offsetStr)
	if limit <= 0 || limit > 50 {
		limit = 50
	}

	// Cross-mailbox-for-one-user read on the BYPASSRLS worker pool (see type doc).
	rows, err := h.workerPool.Query(r.Context(),
		`SELECT qm.id, qm.message_id, m.subject, m.from_addr,
		 qm.reason, qm.virus_name, qm.preview_token, qm.quarantined_at,
		 qm.released_at, qm.rejected_at, m.size_bytes
		 FROM quarantined_messages qm
		 JOIN messages m ON m.id = qm.message_id
		 JOIN mailboxes mb ON mb.id = qm.mailbox_id
		 WHERE mb.user_id = $1
		 ORDER BY qm.quarantined_at DESC LIMIT $2 OFFSET $3`,
		user.UserID, limit, offset,
	)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	type item struct {
		ID            int64   `json:"id"`
		MessageID     int64   `json:"messageId"`
		Subject       string  `json:"subject"`
		FromAddr      string  `json:"fromAddr"`
		Reason        string  `json:"reason"`
		VirusName     *string `json:"virusName,omitempty"`
		PreviewToken  string  `json:"previewToken"`
		QuarantinedAt string  `json:"quarantinedAt"`
		ReleasedAt    *string `json:"releasedAt,omitempty"`
		RejectedAt    *string `json:"rejectedAt,omitempty"`
		SizeBytes     int64   `json:"sizeBytes"`
	}
	var items []item
	for rows.Next() {
		var i item
		var releasedAt, rejectedAt *string
		if err := rows.Scan(&i.ID, &i.MessageID, &i.Subject, &i.FromAddr,
			&i.Reason, &i.VirusName, &i.PreviewToken, &i.QuarantinedAt,
			&releasedAt, &rejectedAt, &i.SizeBytes); err != nil {
			continue
		}
		if releasedAt != nil {
			i.ReleasedAt = releasedAt
		}
		if rejectedAt != nil {
			i.RejectedAt = rejectedAt
		}
		items = append(items, i)
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

// Count returns the number of active quarantined messages for the user.
func (h *QuarantineHandler) Count(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		httputil.WriteJSON(w, http.StatusOK, map[string]int{"count": 0})
		return
	}
	var count int
	h.pool.QueryRow(r.Context(),
		`SELECT COUNT(*) FROM quarantined_messages qm
		 JOIN mailboxes mb ON mb.id = qm.mailbox_id
		 WHERE mb.user_id = $1 AND qm.released_at IS NULL AND qm.rejected_at IS NULL`,
		user.UserID,
	).Scan(&count)
	httputil.WriteJSON(w, http.StatusOK, map[string]int{"count": count})
}

// Release releases a quarantined message to the user's inbox.
func (h *QuarantineHandler) Release(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid id")
		return
	}
	// Release + resolve the message's mailbox in ONE ownership-gated statement
	// (R3 — no TOCTOU): the mutating UPDATE folds ownership into its own WHERE
	// (mailbox_id IN the user's mailboxes) and RETURNINGs the fields the tag
	// rewrite needs. A foreign or already-released row matches 0 rows → pgx.ErrNoRows
	// → 403, and nothing is mutated. (Mirrors the sibling Reject handler.)
	// quarantined_messages is not FORCE'd, so this read needs no GUC.
	var msgID, mailboxID int64
	var originalTag string
	err = h.pool.QueryRow(r.Context(),
		`UPDATE quarantined_messages SET released_at = now(), released_by = $1
		 WHERE id = $2 AND released_at IS NULL AND mailbox_id IN
		 (SELECT id FROM mailboxes WHERE user_id = $1)
		 RETURNING message_id, mailbox_id, original_tag`, user.UserID, id,
	).Scan(&msgID, &mailboxID, &originalTag)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusForbidden, "not found or already released")
		return
	}
	// The message_tags rewrite runs inside a tenant tx scoped to that mailbox
	// (GUC = mailboxID), so it survives the W6 FORCE flip (option-(a) treatment).
	// The Quarantined→original tag swap goes through the release_quarantine_tags
	// reducer (arch A8) so it is atomic AND pushes a pg_notify — the open-coded
	// version bumped no state, so the released message reappeared in the folder only
	// after a manual refresh. Runs in a tenant tx scoped to that mailbox (GUC =
	// mailboxID) so it survives the W6 FORCE flip.
	if err := dbscope.RunScoped(r.Context(), h.pool, mailboxID, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(),
			`SELECT release_quarantine_tags($1, $2, $3, TRUE)`,
			msgID, mailboxID, originalTag)
		return err
	}); err != nil {
		h.logger.Error("quarantine release tag rewrite failed", "error", err, "id", id)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "released"})
}

// Reject permanently deletes a quarantined message (user self-service).
func (h *QuarantineHandler) Reject(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid id")
		return
	}
	// Reject + resolve the message's mailbox in one ownership-gated statement
	// (mailbox_id IN the user's mailboxes); quarantined_messages is not FORCE'd.
	var msgID, mailboxID int64
	err = h.pool.QueryRow(r.Context(),
		`UPDATE quarantined_messages SET rejected_at = now(), rejected_by = $1
		 WHERE id = $2 AND released_at IS NULL AND mailbox_id IN
		 (SELECT id FROM mailboxes WHERE user_id = $1)
		 RETURNING message_id, mailbox_id`, user.UserID, id,
	).Scan(&msgID, &mailboxID)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusForbidden, "not found or already processed")
		return
	}
	// The messages soft-delete runs inside a tenant tx scoped to that mailbox
	// (GUC = mailboxID), so it survives the W6 FORCE flip (option-(a) treatment).
	if err := dbscope.RunScoped(r.Context(), h.pool, mailboxID, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `UPDATE messages SET is_deleted = TRUE WHERE id = $1`, msgID)
		return err
	}); err != nil {
		h.logger.Error("quarantine reject soft-delete failed", "error", err, "id", id)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "rejected"})
}
