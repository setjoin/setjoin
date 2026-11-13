package user

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/ssrf"
)

// NewsletterHandler handles RFC 8058 one-click unsubscribe.
type NewsletterHandler struct {
	// pool is the tenant app pool. workerPool is the setjoin_worker (BYPASSRLS)
	// pool: the unsubscribe lookup keys on mb.user_id ACROSS all the user's
	// mailboxes (a newsletter may be in any of them), so it does NOT fit one
	// app.current_mailbox_id GUC — it runs on workerPool, the admin-case
	// treatment for a cross-mailbox-for-one-user read (R1-scoped by mb.user_id).
	// workerPool aliases pool until DB_WORKER_DSN is set (W1b), so this is INERT.
	pool       *pgxpool.Pool
	workerPool *pgxpool.Pool
	logger     *slog.Logger
}

// NewNewsletterHandler creates a newsletter handler.
func NewNewsletterHandler(pool *pgxpool.Pool, workerPool pgxutil.WorkerPool, logger *slog.Logger) *NewsletterHandler {
	return &NewsletterHandler{pool: pool, workerPool: workerPool.Pool, logger: logger}
}

// Unsubscribe proxies a one-click unsubscribe request (RFC 8058).
// POST /messages/{emailId}/unsubscribe
func (h *NewsletterHandler) Unsubscribe(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	emailID := r.PathValue("emailId")
	if emailID == "" {
		httputil.WriteError(w, http.StatusBadRequest, "emailId required")
		return
	}

	// Look up the List-Unsubscribe header AND the sender address stored on the
	// message. Ownership is the mailbox→user join (messages has NO user_id column;
	// it keys on mailbox_id). Runs on the BYPASSRLS worker pool: the message may
	// live in any of the user's mailboxes (R1-scoped by mb.user_id,
	// cross-mailbox-for-one-user).
	//
	// m.from_addr is the SAME value the inbound delivery consumer matches against:
	// internal/smtp.inConnState.applyPerUserSpam compares
	// `user_sender_list.sender = headers.fromAddr`, where headers.fromAddr is the
	// raw parsed From address that storeAndDeliver writes into messages.from_addr.
	// So the block we insert below must be keyed on from_addr to ever match a
	// FUTURE message from this sender.
	var listUnsubscribe, fromAddr string
	err := h.workerPool.QueryRow(r.Context(),
		`SELECT COALESCE(m.list_unsubscribe, ''), COALESCE(m.from_addr, '')
		 FROM messages m
		 JOIN mailboxes mb ON mb.id = m.mailbox_id
		 WHERE m.id = $1 AND mb.user_id = $2`,
		emailID, claims.UserID,
	).Scan(&listUnsubscribe, &fromAddr)
	if err != nil {
		h.logger.Error("newsletter unsubscribe lookup failed", "error", err, "email_id", emailID)
		httputil.WriteError(w, http.StatusNotFound, "message not found")
		return
	}

	if listUnsubscribe == "" {
		httputil.WriteError(w, http.StatusBadRequest, "no unsubscribe URL available for this message")
		return
	}

	// Parse the List-Unsubscribe header per RFC 8058.
	// Format: <https://...> or <mailto:...>, optionally with a second URL.
	unsubURL := extractUnsubscribeURL(listUnsubscribe)
	if unsubURL == "" {
		httputil.WriteError(w, http.StatusBadRequest, "invalid List-Unsubscribe header")
		return
	}

	// RFC 8058 one-click unsubscribe: POST to the URL.
	// For mailto: URLs, we record the intent (cannot POST to mailto).
	// For https: URLs, we POST per RFC 8058.
	if strings.HasPrefix(unsubURL, "mailto:") {
		recipient := strings.TrimPrefix(unsubURL, "mailto:")
		h.logger.Info("newsletter unsubscribe (mailto)", "user", claims.UserID, "message", emailID, "recipient", recipient)
	} else {
		// HTTP/HTTPS unsubscribe — POST to the URL. The URL comes from the
		// sender-controlled List-Unsubscribe header, so it is an SSRF vector:
		// reject schemes other than http/https and literal internal/private/
		// link-local (incl. cloud-metadata) IP hosts before dialing.
		if err := ssrf.ValidateURL(unsubURL); err != nil {
			h.logger.Warn("newsletter unsubscribe URL rejected (SSRF guard)", "error", err, "url", unsubURL)
			httputil.WriteError(w, http.StatusBadRequest, "unsubscribe URL is not allowed")
			return
		}
		// Dial-time SSRF guard: ssrf.SafeHTTPClient's Control hook rejects
		// internal/link-local targets AFTER DNS resolution, so a sender whose
		// List-Unsubscribe host resolves to (or rebinds to) an internal IP is
		// blocked at connect time — ValidateURL above only catches literal IPs.
		client := ssrf.SafeHTTPClient(15 * time.Second)
		resp, err := client.Post(unsubURL, "application/x-www-form-urlencoded", strings.NewReader("List-Unsubscribe=One-Click"))
		if err != nil {
			h.logger.Warn("newsletter unsubscribe POST failed", "error", err, "url", unsubURL)
			// Still record the intent — the POST may still have been received
		}
		if resp != nil {
			resp.Body.Close()
		}
	}

	// Record the unsubscribe action
	var emailIDInt *int64
	if n, parseErr := strconv.ParseInt(emailID, 10, 64); parseErr == nil {
		emailIDInt = &n
	}
	if err = audit.Write(r.Context(), h.pool, audit.Entry{
		Actor: claims.UserID, Action: "unsubscribe_newsletter", TargetType: "message",
		TargetID: emailIDInt, Notes: "List-Unsubscribe POST", Tier: audit.TierForAction("unsubscribe_newsletter"),
	}); err != nil {
		h.logger.Warn("newsletter unsubscribe audit log failed", "error", err)
	}

	// Block the sender so FUTURE messages from it are caught by per-user spam.
	// The key MUST be the sender's From address (NOT the per-message Message-ID):
	// the inbound consumer (smtp.applyPerUserSpam) matches
	// `user_sender_list.sender = headers.fromAddr`. A Message-ID is unique per
	// message and would never match a future delivery, so the old
	// "newsletter:"+messageID key silently blocked nothing.
	//
	// We DO NOT canonicalize here: the consumer compares against the raw
	// headers.fromAddr (it does not route through identity.CanonicalizeAddress),
	// and messages.from_addr holds the byte-identical value storeAndDeliver wrote
	// from that same headers.fromAddr — so a raw-vs-raw compare is the exact match.
	if fromAddr != "" {
		_, err = h.pool.Exec(r.Context(),
			`INSERT INTO user_sender_list (user_id, sender, list_type)
			 VALUES ($1, $2, 'blocked')
			 ON CONFLICT (user_id, sender, list_type) DO NOTHING`,
			claims.UserID, fromAddr,
		)
		if err != nil {
			h.logger.Warn("newsletter sender block failed", "error", err)
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "unsubscribed"})
}

// extractUnsubscribeURL parses the List-Unsubscribe header value and returns
// the first https/http/mailto URL suitable for one-click unsubscribe (RFC 8058).
func extractUnsubscribeURL(header string) string {
	// RFC 8058 format: <https://example.com/unsub>, <mailto:unsub@example.com>
	parts := strings.Split(header, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if len(part) > 2 && part[0] == '<' && part[len(part)-1] == '>' {
			uri := part[1 : len(part)-1]
			if strings.HasPrefix(uri, "https://") || strings.HasPrefix(uri, "http://") {
				return uri
			}
			// Prefer HTTP over mailto; mailto is fallback
		}
	}
	// If no HTTP URL found, try mailto
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if len(part) > 2 && part[0] == '<' && part[len(part)-1] == '>' {
			uri := part[1 : len(part)-1]
			if strings.HasPrefix(uri, "mailto:") {
				return uri
			}
		}
	}
	return ""
}
