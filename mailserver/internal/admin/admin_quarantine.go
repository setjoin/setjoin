package admin

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
)

// QuarantineStatus represents the lifecycle state of a quarantined message.
type QuarantineStatus string

const (
	QuarantineActive   QuarantineStatus = "active"
	QuarantineReleased QuarantineStatus = "released"
	QuarantineRejected QuarantineStatus = "rejected"
)

// QuarantineHandler provides admin access to quarantined messages.
type QuarantineHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

func NewQuarantineHandler(workerPool pgxutil.WorkerPool, logger *slog.Logger) *QuarantineHandler {
	return &QuarantineHandler{pool: workerPool.Pool, logger: logger}
}

type quarantineItem struct {
	ID            int64   `json:"id"`
	MessageID     int64   `json:"messageId"`
	MailboxID     int64   `json:"mailboxId"`
	Subject       string  `json:"subject"`
	FromAddr      string  `json:"fromAddr"`
	OriginalTag   string  `json:"originalTag"`
	Reason        string  `json:"reason"`
	ReasonType    string  `json:"reasonType"`
	VirusName     *string `json:"virusName,omitempty"`
	PreviewToken  string  `json:"previewToken"`
	QuarantinedAt string  `json:"quarantinedAt"`
	ReleasedAt    *string `json:"releasedAt,omitempty"`
	ReleasedBy    *int64  `json:"releasedBy,omitempty"`
	RejectedAt    *string `json:"rejectedAt,omitempty"`
	RejectedBy    *int64  `json:"rejectedBy,omitempty"`
	SizeBytes     int64   `json:"sizeBytes"`
	Recipient     string  `json:"recipient"`
}

// List returns paginated quarantined messages.
func (h *QuarantineHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	status := r.URL.Query().Get("status") // active, released, rejected, all
	limit, offset := httputil.ParseLimitOffset(r, 50, 100)

	where := "1=1"
	args := []interface{}{}
	argN := 0

	switch QuarantineStatus(status) {
	case QuarantineReleased:
		where = "qm.released_at IS NOT NULL"
	case QuarantineRejected:
		where = "qm.rejected_at IS NOT NULL"
	case QuarantineActive:
		where = "qm.released_at IS NULL AND qm.rejected_at IS NULL"
	}

	if q != "" {
		argN++
		where += " AND (m.from_addr ILIKE $" + strconv.Itoa(argN) + " OR m.subject ILIKE $" + strconv.Itoa(argN) + ")"
		args = append(args, "%"+q+"%")
	}

	query := `SELECT qm.id, qm.message_id, qm.mailbox_id, m.subject, m.from_addr,
		 qm.original_tag, qm.reason, qm.reason_type, qm.virus_name, qm.preview_token,
		 qm.quarantined_at, qm.released_at, qm.released_by, qm.rejected_at, qm.rejected_by,
		 m.size_bytes, mb.email as recipient
		 FROM quarantined_messages qm
		 JOIN messages m ON m.id = qm.message_id
		 JOIN mailboxes mb ON mb.id = qm.mailbox_id
		 WHERE ` + where + ` ORDER BY qm.quarantined_at DESC LIMIT $` + strconv.Itoa(argN+1) + ` OFFSET $` + strconv.Itoa(argN+2)
	args = append(args, limit, offset)

	rows, err := h.pool.Query(r.Context(), query, args...)
	if err != nil {
		h.logger.Error("admin quarantine list failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	var items []quarantineItem
	for rows.Next() {
		var item quarantineItem
		var releasedAt, rejectedAt *time.Time
		if err := rows.Scan(&item.ID, &item.MessageID, &item.MailboxID, &item.Subject, &item.FromAddr,
			&item.OriginalTag, &item.Reason, &item.ReasonType, &item.VirusName, &item.PreviewToken,
			&item.QuarantinedAt, &releasedAt, &item.ReleasedBy, &rejectedAt, &item.RejectedBy,
			&item.SizeBytes, &item.Recipient); err != nil {
			continue
		}
		if releasedAt != nil {
			s := releasedAt.Format(time.RFC3339)
			item.ReleasedAt = &s
		}
		if rejectedAt != nil {
			s := rejectedAt.Format(time.RFC3339)
			item.RejectedAt = &s
		}
		items = append(items, item)
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

// Preview returns the raw stored HTML of a quarantined message body.
// Quarantine stores raw bytes for forensic fidelity; the webmail client
// sanitizes (DOMPurify) at render and wraps the preview in a sandboxed,
// CSP-locked iframe. No server-side mutation of the stored content.
func (h *QuarantineHandler) Preview(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid id")
		return
	}
	var bodyHTML, subject, fromAddr *string
	var quarantinedAt time.Time
	err = h.pool.QueryRow(r.Context(),
		`SELECT m.body_html, m.subject, m.from_addr, qm.quarantined_at
		 FROM quarantined_messages qm JOIN messages m ON m.id = qm.message_id
		 WHERE qm.id = $1`, id,
	).Scan(&bodyHTML, &subject, &fromAddr, &quarantinedAt)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"html":          coalesce(bodyHTML, ""),
		"subject":       coalesce(subject, ""),
		"fromAddr":      coalesce(fromAddr, ""),
		"quarantinedAt": quarantinedAt.Format(time.RFC3339),
	})
}

// Release releases a quarantined message to its recipient's inbox.
//
// Admin quarantine is CROSS-TENANT (see the W7 note at NewQuarantineHandler): the
// ownership gate is the org-wide requireMailPerm on the route, NOT a per-user
// predicate — an admin acts on EVERY mailbox's quarantined messages, not just their
// own. The UPDATE folds the only remaining precondition (still active) into its WHERE
// and RETURNINGs the tag-rewrite fields; a wrong or already-processed id matches 0
// rows → pgx.ErrNoRows → 404, so a no-op can no longer masquerade as success.
func (h *QuarantineHandler) Release(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid id")
		return
	}
	user := auth.UserFromContext(r.Context())
	var msgID, mailboxID int64
	var originalTag string
	err = h.pool.QueryRow(r.Context(),
		`UPDATE quarantined_messages SET released_at = now(), released_by = $1
		 WHERE id = $2 AND released_at IS NULL
		 RETURNING message_id, mailbox_id, original_tag`, user.UserID, id,
	).Scan(&msgID, &mailboxID, &originalTag)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found or already processed")
		return
	}
	// The Quarantined→original tag swap goes through the release_quarantine_tags
	// reducer (arch A8): one atomic call that sources received_at from messages (so
	// the composite message_tags FK holds), runs remove+restore in one txn, and emits
	// pg_notify. h.pool is the BYPASSRLS worker pool, so no tenant GUC is needed.
	if _, err := h.pool.Exec(r.Context(),
		`SELECT release_quarantine_tags($1, $2, $3, TRUE)`,
		msgID, mailboxID, originalTag); err != nil {
		h.logger.Error("admin quarantine release tag rewrite failed", "error", err, "id", id)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "released"})
}

// Reject permanently deletes a quarantined message. Cross-tenant, same as Release:
// no per-user predicate (the org-wide requireMailPerm is the gate); a wrong or
// already-processed id matches 0 rows → 404.
func (h *QuarantineHandler) Reject(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid id")
		return
	}
	user := auth.UserFromContext(r.Context())
	var msgID int64
	err = h.pool.QueryRow(r.Context(),
		`UPDATE quarantined_messages SET rejected_at = now(), rejected_by = $1
		 WHERE id = $2 AND released_at IS NULL
		 RETURNING message_id`, user.UserID, id,
	).Scan(&msgID)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found or already processed")
		return
	}
	h.pool.Exec(r.Context(), `DELETE FROM messages WHERE id = $1`, msgID)
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "rejected"})
}

// Stats returns quarantine counts.
func (h *QuarantineHandler) Stats(w http.ResponseWriter, r *http.Request) {
	var active, released, rejected int
	h.pool.QueryRow(r.Context(),
		`SELECT COUNT(*) FROM quarantined_messages WHERE released_at IS NULL AND rejected_at IS NULL`,
	).Scan(&active)
	h.pool.QueryRow(r.Context(),
		`SELECT COUNT(*) FROM quarantined_messages WHERE released_at IS NOT NULL`,
	).Scan(&released)
	h.pool.QueryRow(r.Context(),
		`SELECT COUNT(*) FROM quarantined_messages WHERE rejected_at IS NOT NULL`,
	).Scan(&rejected)
	httputil.WriteJSON(w, http.StatusOK, map[string]int{"active": active, "released": released, "rejected": rejected})
}

func coalesce(s *string, fallback string) string {
	if s == nil {
		return fallback
	}
	return *s
}
