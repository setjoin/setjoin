package user

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/delivery"
	"setjoin.com/mailserver/internal/received"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
)

// TraceHandler serves the inbound delivery trace for a message the authenticated
// user owns. Hostile header content degrades to an empty hop list — never a 500.
type TraceHandler struct {
	workerPool *pgxpool.Pool
	jmapURL    string
	self       received.Identity
	logger     *slog.Logger
}

// NewTraceHandler creates a handler for GET /messages/{emailId}/trace.
// pool should be the workerPool (BYPASSRLS) — the ownership query is cross-mailbox
// for one user (mb.user_id across all user's mailboxes).
func NewTraceHandler(workerPool pgxutil.WorkerPool, jmapURL string, self received.Identity, logger *slog.Logger) *TraceHandler {
	return &TraceHandler{workerPool: workerPool.Pool, jmapURL: jmapURL, self: self, logger: logger}
}

// rawInfo mirrors the frontend Trace.raw shape ({ url, sizeBytes }).
type rawInfo struct {
	URL       string `json:"url"`
	SizeBytes int64  `json:"sizeBytes"`
}

// outboundTrace is the user-local response type for a Sent message. It marshals
// to the same direction-tagged JSON the frontend branches on. auth is present
// (zero value) so the Auth tab doesn't break; raw mirrors the inbound download
// link so the Raw tab works. The per-recipient shapes come from internal/delivery
// (the shared read contract); the JSON tags are identical, so the wire shape is
// unchanged.
type outboundTrace struct {
	Direction     string               `json:"direction"` // always "outbound"
	Auth          map[string]any       `json:"auth"`      // empty AuthResults — Sent mail has no inbound auth verdict
	Raw           *rawInfo             `json:"raw"`
	OverallStatus string               `json:"overallStatus"`
	Recipients    []delivery.Recipient `json:"recipients"`
}

// Trace returns the delivery Trace for a message the user owns. Inbound messages
// get the parsed Received-chain trace; Sent (outbound) messages get the
// per-recipient delivery view. A parse error or panic degrades to a 200 with an
// empty inbound hop list — never a 500 from hostile header content.
func (h *TraceHandler) Trace(w http.ResponseWriter, r *http.Request) {
	// wrote tracks whether a response has been committed so the deferred recover
	// never calls WriteJSON a second time (double-WriteHeader = corrupt body).
	var wrote bool
	// Recover from any panic in the parse path to ensure hostile header content
	// never causes a 500. The empty trace lets the client fall back gracefully.
	defer func() {
		if rec := recover(); rec != nil && !wrote {
			h.logger.Warn("trace parse panic recovered", "recover", rec)
			wrote = true
			httputil.WriteJSON(w, http.StatusOK, received.Trace{Direction: "inbound", Hops: []received.Hop{}})
		}
	}()

	user := auth.UserFromContext(r.Context())
	if user == nil {
		wrote = true
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	emailID, err := strconv.ParseInt(r.PathValue("emailId"), 10, 64)
	if err != nil {
		wrote = true
		httputil.WriteError(w, http.StatusBadRequest, "invalid email ID")
		return
	}

	// Enforce ownership via the mailbox→user join (R1: SELECT filters by user_id
	// from auth context). Returns ErrNoRows when the message does not exist or is
	// not owned by this user — the caller never learns which (IDOR-safe 404).
	om, err := ResolveOwnedMessage(r.Context(), h.workerPool, emailID, user.UserID)
	if err != nil {
		if err == pgx.ErrNoRows {
			wrote = true
			httputil.WriteError(w, http.StatusNotFound, "email not found")
			return
		}
		h.logger.Error("trace ownership query failed", "email_id", emailID, "error", err)
		wrote = true
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	// Direction detection: a Sent message carries the Sent system location tag.
	// This is the authoritative signal (NOT "a queue/attempts row exists") so
	// local-only sends, still-queued sends, and undo-send all read as outbound.
	if h.isSentMessage(r.Context(), om) {
		// Pass &wrote so it is set adjacent to the actual WriteJSON inside
		// writeOutbound: the outbound reads then run while wrote is still false,
		// so the deferred recover() can emit the degrade response if one panics.
		h.writeOutbound(r, w, om, &wrote)
		return
	}

	// Inbound path (unchanged): fetch bounded header bytes and parse the chain.
	raw, err := h.fetchHeaderBytes(r, om.MailboxID, om.RawRef, om.Subject)
	if err != nil {
		// Degrade: proxy unavailable or non-200. Return empty trace so the client
		// can still fall back to Headers/Raw off the download endpoint.
		h.logger.Warn("trace header fetch failed, degrading to empty trace",
			"emailId", emailID, "error", err)
		wrote = true
		httputil.WriteJSON(w, http.StatusOK, received.Trace{Direction: "inbound", Hops: []received.Hop{}})
		return
	}

	// Set wrote adjacent to the actual WriteJSON (mirrors writeOutbound): ParseTrace
	// runs while wrote is still false, so a theoretical parse panic is caught by the
	// deferred recover() and degraded to the empty inbound trace rather than a corrupt
	// (or absent) response. ParseTrace is panic-free by design, so this is unreachable
	// today — it keeps the inbound path symmetric with the outbound guard discipline.
	tr, _ := received.ParseTrace(raw, h.self)
	wrote = true
	httputil.WriteJSON(w, http.StatusOK, tr)
}

// isSentMessage reports whether the owned message carries the Sent system
// location tag (the direction classifier). Defaults to false (inbound) on any
// query error — outbound is the additive surface, never the fallback.
func (h *TraceHandler) isSentMessage(ctx context.Context, om OwnedMessage) bool {
	var sent bool
	err := h.workerPool.QueryRow(ctx,
		`SELECT EXISTS (
		   SELECT 1 FROM message_tags mt
		     JOIN tags t ON t.id = mt.tag_id
		    WHERE mt.message_id = $1 AND mt.received_at = $2
		      AND t.mailbox_id = $3
		      AND t.name = 'Sent' AND t.tag_type = 'system'
		      AND t.exclusive_group = 'location')`,
		om.MessagePK, om.ReceivedAt, om.MailboxID,
	).Scan(&sent)
	if err != nil {
		h.logger.Warn("trace direction detection failed, treating as inbound",
			"emailId", om.MessagePK, "error", err)
		return false
	}
	return sent
}

// writeOutbound builds and writes the per-recipient delivery view for a Sent
// message. All reads are scoped by the resolved mailbox_id (ownership-by-filter,
// not RLS — the worker pool runs GUC-less). On a query failure it degrades to a
// minimal outbound shell (empty recipients) rather than a 500.
func (h *TraceHandler) writeOutbound(r *http.Request, w http.ResponseWriter, om OwnedMessage, wrote *bool) {
	ctx := r.Context()

	overallStatus, nextAttemptAt, deliveredAt, rcptAddrs, queueFound := h.readOutboundQueue(ctx, om)
	recips := h.readRecipients(ctx, om, rcptAddrs, queueFound, overallStatus, nextAttemptAt, deliveredAt)

	// overallStatus is empty when there is no queue row (undo-send) — derive a
	// best-effort verdict from the per-recipient statuses so the digest still
	// renders something honest.
	if overallStatus == "" {
		overallStatus = deriveOverallStatus(recips)
	}

	resp := outboundTrace{
		Direction:     "outbound",
		Auth:          map[string]any{},
		Raw:           &rawInfo{URL: h.rawURL(om), SizeBytes: 0},
		OverallStatus: overallStatus,
		Recipients:    recips,
	}
	*wrote = true
	httputil.WriteJSON(w, http.StatusOK, resp)
}

// readOutboundQueue returns the queue row's status, next/delivered timestamps,
// and authoritative recipient set for this Sent message. queueFound is false
// when no queue row exists (undo-send / local-only). Ownership: WHERE mailbox_id.
func (h *TraceHandler) readOutboundQueue(ctx context.Context, om OwnedMessage) (status string, nextAttemptAt, deliveredAt *time.Time, rcptAddrs []string, found bool) {
	err := h.workerPool.QueryRow(ctx,
		`SELECT status, next_attempt_at, delivered_at, rcpt_addrs
		   FROM outbound_queue
		  WHERE message_pk = $1 AND mailbox_id = $2
		  ORDER BY queued_at DESC
		  LIMIT 1`,
		om.MessagePK, om.MailboxID,
	).Scan(&status, &nextAttemptAt, &deliveredAt, &rcptAddrs)
	if err != nil {
		if err != pgx.ErrNoRows {
			h.logger.Warn("trace outbound_queue read failed", "email_id", om.MessagePK, "error", err)
		}
		return "", nil, nil, nil, false
	}
	return delivery.MapOverallStatus(status), nextAttemptAt, deliveredAt, rcptAddrs, true
}

// readRecipients builds the per-recipient view. The authoritative recipient set
// is rcpt_addrs (queue) overlaid with the latest delivery_attempts row per
// recipient. On undo-send (no queue row) the set comes from delivery_attempts
// alone. On retention-skew (queue present, attempts pruned) recipients is empty.
func (h *TraceHandler) readRecipients(ctx context.Context, om OwnedMessage, rcptAddrs []string, queueFound bool, overallStatus string, nextAttemptAt, deliveredAt *time.Time) []delivery.Recipient {
	latest := h.readLatestPerRecipient(ctx, om)
	history := h.readAttemptHistory(ctx, om)

	// Retention skew: a TERMINAL queue row (delivered/bounced) whose per-recipient
	// attempts were pruned (30d window). Return EMPTY recipients (the frontend
	// renders a "detail expired" note); do NOT fabricate rows. A non-terminal queue
	// (queued/sending/deferred) with no attempts is genuinely not-yet-attempted, so
	// its rcpt_addrs still render below as queued.
	if queueFound && len(latest) == 0 && delivery.IsTerminalStatus(overallStatus) {
		return []delivery.Recipient{}
	}

	// The recipient set: rcpt_addrs when the queue row exists, else the union of
	// recipients seen in delivery_attempts (undo-send fallback).
	emails := rcptAddrs
	if !queueFound {
		seen := map[string]bool{}
		emails = nil
		for email := range latest {
			if !seen[email] {
				seen[email] = true
				emails = append(emails, email)
			}
		}
	}

	out := make([]delivery.Recipient, 0, len(emails))
	for _, email := range emails {
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
				// Prefer the queue's delivered_at if present, else the attempt time.
				if deliveredAt != nil {
					rec.DeliveredAt = deliveredAt
				} else {
					rec.DeliveredAt = lr.At
				}
			}
			if rec.Status == "deferred" {
				rec.NextAttemptAt = nextAttemptAt
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

// readLatestPerRecipient reduces delivery_attempts to ONE current row per
// recipient via the shared BINDING DISTINCT-ON read contract. Passing
// &om.MailboxID preserves the user path's ownership-by-filter EXACTLY (the
// admin path passes nil for the cross-mailbox read).
func (h *TraceHandler) readLatestPerRecipient(ctx context.Context, om OwnedMessage) map[string]delivery.LatestRow {
	return delivery.ReadLatestPerRecipient(ctx, h.workerPool, h.logger, om.MessagePK, &om.MailboxID)
}

// readAttemptHistory returns the full per-recipient attempt history via the
// shared read contract. Ownership preserved by passing &om.MailboxID.
func (h *TraceHandler) readAttemptHistory(ctx context.Context, om OwnedMessage) map[string][]delivery.Attempt {
	return delivery.ReadAttemptHistory(ctx, h.workerPool, h.logger, om.MessagePK, &om.MailboxID)
}

// rawURL builds the same internal JMAP download URL the inbound path exposes.
func (h *TraceHandler) rawURL(om OwnedMessage) string {
	filename := sanitizeFilename(om.Subject) + ".eml"
	return fmt.Sprintf("%s/%d/%s/%s", h.jmapURL, om.MailboxID, om.RawRef, filename)
}

// deriveOverallStatus computes a best-effort overall verdict from per-recipient
// statuses (used only when there is no queue row, e.g. undo-send). Worst-first.
func deriveOverallStatus(recips []delivery.Recipient) string {
	var anyBounced, anyDeferred, anySending, anyQueued, anyDelivered bool
	for _, r := range recips {
		switch r.Status {
		case "bounced":
			anyBounced = true
		case "deferred":
			anyDeferred = true
		case "sending":
			anySending = true
		case "queued":
			anyQueued = true
		case "delivered":
			anyDelivered = true
		}
	}
	switch {
	case anyBounced:
		return "bounced"
	case anyDeferred:
		return "deferred"
	case anySending:
		return "sending"
	case anyQueued:
		return "queued"
	case anyDelivered:
		return "delivered"
	default:
		return "queued"
	}
}

// fetchHeaderBytes proxies to the internal JMAP download endpoint and reads
// up to received.MaxHeaderBytes. Only the header block is needed for Received
// chain parsing.
func (h *TraceHandler) fetchHeaderBytes(r *http.Request, mailboxID int64, rawRef, subject string) ([]byte, error) {
	filename := sanitizeFilename(subject) + ".eml"
	url := fmt.Sprintf("%s/%d/%s/%s", h.jmapURL, mailboxID, rawRef, filename)
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// Forward the Authorization header so the internal JMAP handler can verify JWT.
	if a := r.Header.Get("Authorization"); a != "" {
		req.Header.Set("Authorization", a)
	}
	// Cookie sessions (SPA default) authenticate via HttpOnly cookie, not Bearer.
	// Ownership is already enforced by ResolveOwnedMessage above, so forwarding
	// the cookie to the loopback proxy is safe.
	if c := r.Header.Get("Cookie"); c != "" {
		req.Header.Set("Cookie", c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, received.MaxHeaderBytes))
}
