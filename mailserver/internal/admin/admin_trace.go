package admin

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/delivery"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
)

// TraceHandler provides admin message trace search.
type TraceHandler struct {
	pool *pgxpool.Pool
	// workerPool (setjoin_worker, BYPASSRLS) carries ONLY the cross-mailbox
	// delivery_attempts read in Timeline — delivery_attempts is FORCE'd RLS +
	// fail-closed on a missing app.current_mailbox_id GUC, so the admin pool would
	// return zero rows after the native-RLS DSN flip (W6). The message_trace /
	// outbound_queue reads stay on pool (those tables are not RLS'd). workerPool
	// aliases pool until DB_WORKER_DSN is set, so this is INERT today.
	workerPool *pgxpool.Pool
	logger     *slog.Logger
}

// NewTraceHandler creates a message trace handler. workerPool is used only for
// the cross-mailbox delivery_attempts read in Timeline (see the struct doc).
func NewTraceHandler(pool *pgxpool.Pool, workerPool pgxutil.WorkerPool, logger *slog.Logger) *TraceHandler {
	return &TraceHandler{pool: pool, workerPool: workerPool.Pool, logger: logger}
}

// TraceRecord represents a single message trace event.
type TraceRecord struct {
	ID         int64           `json:"id"`
	MessageID  string          `json:"messageId"`
	Event      string          `json:"event"`
	FromAddr   string          `json:"fromAddr"`
	RcptAddr   string          `json:"rcptAddr"`
	RemoteHost *string         `json:"remoteHost,omitempty"`
	Details    json.RawMessage `json:"details,omitempty"`
	OccurredAt time.Time       `json:"occurredAt"`
}

// TraceSearchResponse is the paginated result.
type TraceSearchResponse struct {
	Records []TraceRecord `json:"records"`
	Total   int           `json:"total"`
	Limit   int           `json:"limit"`
	Offset  int           `json:"offset"`
}

// List searches message_trace with filters.
func (h *TraceHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	q := r.URL.Query()
	fromAddr := q.Get("from")
	rcptAddr := q.Get("to")
	subject := q.Get("subject")
	event := q.Get("event")
	status := q.Get("status")
	dateFrom := q.Get("dateFrom")
	dateTo := q.Get("dateTo")

	limit, offset := httputil.ParseLimitOffset(r, 50, 200)

	// Build dynamic WHERE
	where := "WHERE 1=1"
	args := []any{}
	argIdx := 1

	if fromAddr != "" {
		where += " AND from_addr ILIKE $" + strconv.Itoa(argIdx)
		args = append(args, "%"+fromAddr+"%")
		argIdx++
	}
	if rcptAddr != "" {
		where += " AND rcpt_addr ILIKE $" + strconv.Itoa(argIdx)
		args = append(args, "%"+rcptAddr+"%")
		argIdx++
	}
	if event != "" {
		where += " AND event = $" + strconv.Itoa(argIdx)
		args = append(args, event)
		argIdx++
	}
	if status != "" {
		where += " AND details->>'status' = $" + strconv.Itoa(argIdx)
		args = append(args, status)
		argIdx++
	}
	if subject != "" {
		where += " AND details->>'subject' ILIKE $" + strconv.Itoa(argIdx)
		args = append(args, "%"+subject+"%")
		argIdx++
	}
	if dateFrom != "" {
		if t, err := time.Parse(time.RFC3339, dateFrom); err == nil {
			where += " AND occurred_at >= $" + strconv.Itoa(argIdx)
			args = append(args, t)
			argIdx++
		}
	}
	if dateTo != "" {
		if t, err := time.Parse(time.RFC3339, dateTo); err == nil {
			where += " AND occurred_at <= $" + strconv.Itoa(argIdx)
			args = append(args, t)
			argIdx++
		}
	}

	// Count total
	countSQL := "SELECT COUNT(*) FROM message_trace " + where
	var total int
	if err := h.pool.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		h.logger.Error("trace count failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	// Fetch records
	selectSQL := `
		SELECT id, message_id, event, from_addr, rcpt_addr, remote_host, details, occurred_at
		FROM message_trace ` + where + `
		ORDER BY occurred_at DESC
		LIMIT $` + strconv.Itoa(argIdx) + ` OFFSET $` + strconv.Itoa(argIdx+1)
	args = append(args, limit, offset)

	rows, err := h.pool.Query(ctx, selectSQL, args...)
	if err != nil {
		h.logger.Error("trace query failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	records := make([]TraceRecord, 0)
	for rows.Next() {
		var rec TraceRecord
		var details []byte
		var remoteHost *string
		if err := rows.Scan(&rec.ID, &rec.MessageID, &rec.Event, &rec.FromAddr, &rec.RcptAddr, &remoteHost, &details, &rec.OccurredAt); err != nil {
			h.logger.Warn("trace scan skipped", "error", err)
			continue
		}
		if remoteHost != nil {
			rec.RemoteHost = remoteHost
		}
		if len(details) > 0 {
			rec.Details = details
		}
		records = append(records, rec)
	}

	httputil.WriteJSON(w, http.StatusOK, TraceSearchResponse{
		Records: records,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
	})
}

// Export returns message trace results as CSV download.
func (h *TraceHandler) Export(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	q := r.URL.Query()
	fromAddr := q.Get("from")
	rcptAddr := q.Get("to")
	subject := q.Get("subject")
	event := q.Get("event")
	status := q.Get("status")
	dateFrom := q.Get("dateFrom")
	dateTo := q.Get("dateTo")

	// Build dynamic WHERE (same as List)
	where := "WHERE 1=1"
	args := []any{}
	argIdx := 1

	if fromAddr != "" {
		where += " AND from_addr ILIKE $" + strconv.Itoa(argIdx)
		args = append(args, "%"+fromAddr+"%")
		argIdx++
	}
	if rcptAddr != "" {
		where += " AND rcpt_addr ILIKE $" + strconv.Itoa(argIdx)
		args = append(args, "%"+rcptAddr+"%")
		argIdx++
	}
	if event != "" {
		where += " AND event = $" + strconv.Itoa(argIdx)
		args = append(args, event)
		argIdx++
	}
	if status != "" {
		where += " AND details->>'status' = $" + strconv.Itoa(argIdx)
		args = append(args, status)
		argIdx++
	}
	if subject != "" {
		where += " AND details->>'subject' ILIKE $" + strconv.Itoa(argIdx)
		args = append(args, "%"+subject+"%")
		argIdx++
	}
	if dateFrom != "" {
		if t, err := time.Parse(time.RFC3339, dateFrom); err == nil {
			where += " AND occurred_at >= $" + strconv.Itoa(argIdx)
			args = append(args, t)
			argIdx++
		}
	}
	if dateTo != "" {
		if t, err := time.Parse(time.RFC3339, dateTo); err == nil {
			where += " AND occurred_at <= $" + strconv.Itoa(argIdx)
			args = append(args, t)
			argIdx++
		}
	}

	// Cap export at 10,000 rows to prevent memory exhaustion.
	selectSQL := `
		SELECT message_id, event, from_addr, rcpt_addr, remote_host, details, occurred_at
		FROM message_trace ` + where + `
		ORDER BY occurred_at DESC
		LIMIT 10000`

	rows, err := h.pool.Query(ctx, selectSQL, args...)
	if err != nil {
		h.logger.Error("trace export query failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="message-trace.csv"`)
	cw := csv.NewWriter(w)
	cw.Write([]string{"message_id", "event", "from_addr", "rcpt_addr", "remote_host", "details", "occurred_at"})

	for rows.Next() {
		var rec TraceRecord
		var details []byte
		var remoteHost *string
		if err := rows.Scan(&rec.MessageID, &rec.Event, &rec.FromAddr, &rec.RcptAddr, &remoteHost, &details, &rec.OccurredAt); err != nil {
			continue
		}
		var detailsStr string
		if len(details) > 0 {
			detailsStr = string(details)
		}
		host := ""
		if remoteHost != nil {
			host = *remoteHost
		}
		// Formula-injection guard: every cell below is data-derived (SMTP wire
		// addresses, remote host, JSON details) — neutralize at the writer seam
		// (admin_csv.go, migration.EscapeCSVCell) before serialization.
		cw.Write(escapeCSVCells([]string{
			rec.MessageID, rec.Event, rec.FromAddr, rec.RcptAddr,
			host, detailsStr, rec.OccurredAt.Format(time.RFC3339),
		}))
	}
	cw.Flush()
}

// TimelineEvent is a single ordered event in the delivery timeline.
type TimelineEvent struct {
	Event      string          `json:"event"`
	RcptAddr   *string         `json:"rcptAddr"`
	FromAddr   *string         `json:"fromAddr"`
	RemoteHost *string         `json:"remoteHost"`
	Details    json.RawMessage `json:"details"`
	OccurredAt time.Time       `json:"occurredAt"`
}

// TimelineQueue is the outbound_queue row for the message, if present.
type TimelineQueue struct {
	Status        string     `json:"status"`
	AttemptCount  int        `json:"attemptCount"`
	NextAttemptAt *time.Time `json:"nextAttemptAt"`
	LastError     *string    `json:"lastError"`
	RcptAddrs     []string   `json:"rcptAddrs"`
	QueuedAt      time.Time  `json:"queuedAt"`
}

// TimelineResponse is the JSON body for GET /admin/trace/{messageId}.
type TimelineResponse struct {
	MessageID      string          `json:"messageId"`
	Events         []TimelineEvent `json:"events"`
	Queue          *TimelineQueue  `json:"queue"`
	MultiRecipient bool            `json:"multiRecipient"`
	// Recipients is the cross-mailbox per-recipient delivery view (Phase 2b),
	// read from delivery_attempts keyed on the resolved message_pk (no mailbox
	// filter — RBAC gates the route). Omitted (nil) for legacy queue rows with no
	// message_pk link. Empty []  + DetailExpired when attempts were pruned.
	Recipients []delivery.Recipient `json:"recipients,omitempty"`
	// OverallStatus is the SERVER-MAPPED queue verdict (delivery.MapOverallStatus,
	// e.g. pending→queued) — not the raw outbound_queue.status enum.
	OverallStatus string `json:"overallStatus,omitempty"`
	// DetailExpired is true on retention skew: a terminal queue row whose
	// per-recipient attempts were pruned (the frontend renders the "detail
	// expired" note rather than a broken panel).
	DetailExpired bool `json:"detailExpired,omitempty"`
}

// Timeline returns the ordered delivery timeline for a single message:
// all message_trace events (ASC) plus the outbound_queue row if present.
// RBAC is enforced by the middleware chain (requireAuth + RequirePermAudited);
// the handler itself is read-only and has no write path.
func (h *TraceHandler) Timeline(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	messageID := r.PathValue("messageId")

	// Query 1: ordered trace events.
	const eventsSQL = `
		SELECT event, rcpt_addr, from_addr, remote_host, details, occurred_at
		FROM message_trace
		WHERE message_id = $1
		ORDER BY occurred_at ASC`

	rows, err := h.pool.Query(ctx, eventsSQL, messageID)
	if err != nil {
		h.logger.Error("trace timeline events query failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	events := make([]TimelineEvent, 0)
	for rows.Next() {
		var ev TimelineEvent
		var details []byte
		if err := rows.Scan(&ev.Event, &ev.RcptAddr, &ev.FromAddr, &ev.RemoteHost, &details, &ev.OccurredAt); err != nil {
			h.logger.Warn("trace timeline event scan skipped", "error", err)
			continue
		}
		if len(details) > 0 {
			ev.Details = details
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("trace timeline rows error", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	// Query 2: outbound_queue row (may not exist). message_id is non-unique RFC
	// text — it collides across re-sends / mailboxes — so resolve the LATEST send
	// by queued_at. This makes the single-row read deterministic (latest wins) and
	// yields the surrogate message_pk that keys the cross-mailbox recipients read.
	// message_pk/mailbox_id are scanned into locals (display/audit + the recipients
	// read), NOT exposed on the wire.
	const queueSQL = `
		SELECT status, attempt_count, next_attempt_at, last_error, rcpt_addrs, queued_at, message_pk, mailbox_id
		FROM outbound_queue
		WHERE message_id = $1
		ORDER BY queued_at DESC
		LIMIT 1`

	var queue *TimelineQueue
	var q TimelineQueue
	var messagePK *int64
	var mailboxID *int64 // display/audit only — NOT used as a read filter (cross-mailbox).
	err = h.pool.QueryRow(ctx, queueSQL, messageID).Scan(
		&q.Status, &q.AttemptCount, &q.NextAttemptAt, &q.LastError, &q.RcptAddrs, &q.QueuedAt, &messagePK, &mailboxID,
	)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		h.logger.Error("trace timeline queue query failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if err == nil {
		queue = &q
	}

	multiRecipient := queue != nil && len(queue.RcptAddrs) > 1

	resp := TimelineResponse{
		MessageID:      messageID,
		Events:         events,
		Queue:          queue,
		MultiRecipient: multiRecipient,
	}

	// Phase 2b: per-recipient cross-mailbox delivery drill-down. Only when the
	// queue row carries a V017 message_pk link (legacy rows leave Recipients nil
	// → the frontend keeps the first-recipient caveat).
	if queue != nil && messagePK != nil {
		resp.OverallStatus = delivery.MapOverallStatus(q.Status)
		resp.Recipients = h.readRecipients(ctx, *messagePK, q.RcptAddrs, resp.OverallStatus, &resp.DetailExpired)
	}

	httputil.WriteJSON(w, http.StatusOK, resp)
}

// readRecipients builds the cross-mailbox per-recipient delivery view for a Sent
// message, keyed on the resolved message_pk ALONE (no mailbox filter — RBAC gates
// the route). It runs the BINDING DISTINCT-ON read contract on workerPool
// (BYPASSRLS) via internal/delivery, overlays the latest attempt per recipient
// onto queue.rcpt_addrs (recipients with no attempt yet render queued), and sorts
// problems-first. On retention skew (terminal queue row, attempts pruned) it
// returns an empty slice and sets *detailExpired so the frontend shows the note
// instead of a broken panel.
func (h *TraceHandler) readRecipients(ctx context.Context, messagePK int64, rcptAddrs []string, overallStatus string, detailExpired *bool) []delivery.Recipient {
	// Admin trace is an RBAC-gated cross-mailbox surface — the explicitly-named
	// Admin variants are required since nil mailboxID is refused by the shared
	// user-scoped reads (D-MAILSERVER-INTERNAL-DELIVERY-001).
	latest := delivery.ReadLatestPerRecipientAdmin(ctx, h.workerPool, h.logger, messagePK)
	history := delivery.ReadAttemptHistoryAdmin(ctx, h.workerPool, h.logger, messagePK)

	// Retention skew: a terminal queue row (delivered/bounced) whose per-recipient
	// attempts were pruned (the configured retention window) → empty recipients +
	// the detail-expired note. Do NOT fabricate rows. A non-terminal queue
	// (queued/sending/deferred) with no attempts is genuinely not-yet-attempted,
	// so its rcpt_addrs still render below as queued.
	if len(latest) == 0 && delivery.IsTerminalStatus(overallStatus) {
		*detailExpired = true
		return []delivery.Recipient{}
	}

	out := make([]delivery.Recipient, 0, len(rcptAddrs))
	for _, email := range rcptAddrs {
		rec := delivery.Recipient{Email: email, Attempts: history[email]}
		if rec.Attempts == nil {
			rec.Attempts = []delivery.Attempt{}
		}
		if lr, ok := latest[email]; ok {
			rec.Status = delivery.MapRecipientStatus(lr.Outcome)
			rec.MxHost = lr.MxHost
			rec.LastSmtpCode = lr.Code
			rec.LastSmtpText = lr.Text
			if rec.Status == "delivered" {
				rec.DeliveredAt = lr.At
			}
		} else {
			// In rcpt_addrs but no attempt yet → queued.
			rec.Status = "queued"
		}
		out = append(out, rec)
	}

	delivery.SortProblemsFirst(out)
	return out
}
