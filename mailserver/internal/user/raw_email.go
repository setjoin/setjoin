package user

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
)

// RawEmailHandler serves raw .eml downloads of messages the authenticated user owns.
type RawEmailHandler struct {
	// workerPool is the setjoin_worker (BYPASSRLS) pool. The ownership lookup keys
	// on mb.user_id ACROSS all the user's mailboxes (the message may live in any
	// of them), so it does NOT fit one app.current_mailbox_id GUC — it runs on the
	// bypass pool, the admin-case treatment for a cross-mailbox-for-one-user read
	// (R1-scoped by mb.user_id). The proxied JMAP /download re-checks ownership.
	// workerPool aliases pool until DB_WORKER_DSN is set (W1b), so this is INERT.
	workerPool *pgxpool.Pool
	jmapURL    string
	logger     *slog.Logger
}

// NewRawEmailHandler creates a handler for GET /messages/{emailId}/download.
func NewRawEmailHandler(workerPool pgxutil.WorkerPool, jmapURL string, logger *slog.Logger) *RawEmailHandler {
	return &RawEmailHandler{workerPool: workerPool.Pool, jmapURL: jmapURL, logger: logger}
}

// Download serves the raw RFC 5322 bytes of a message as a downloadable .eml file.
// It verifies ownership (message belongs to a mailbox owned by the authenticated user),
// then proxies to the internal JMAP download endpoint with forced Content-Type and
// Content-Disposition headers suitable for file download.
func (h *RawEmailHandler) Download(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	emailIDStr := r.PathValue("emailId")
	emailID, err := strconv.ParseInt(emailIDStr, 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid email ID")
		return
	}

	// Look up the message's raw blob reference and mailbox, enforcing ownership
	// via the mailbox→user join (R1: SELECT filters by user_id from auth context).
	om, err := ResolveOwnedMessage(r.Context(), h.workerPool, emailID, user.UserID)
	if err != nil {
		if err == pgx.ErrNoRows {
			httputil.WriteError(w, http.StatusNotFound, "email not found")
			return
		}
		h.logger.Error("raw email download query failed", "email_id", emailID, "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	rawRef, mailboxID, subject := om.RawRef, om.MailboxID, om.Subject

	filename := sanitizeFilename(subject) + ".eml"
	downloadURL := fmt.Sprintf("%s/%d/%s/%s", h.jmapURL, mailboxID, rawRef, filename)

	// Proxy to the internal JMAP download endpoint. Forward the original
	// Authorization header so the internal handler can verify the JWT.
	proxyReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, downloadURL, nil)
	if err != nil {
		h.logger.Error("raw email proxy request creation failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if authHdr := r.Header.Get("Authorization"); authHdr != "" {
		proxyReq.Header.Set("Authorization", authHdr)
	}

	resp, err := http.DefaultClient.Do(proxyReq)
	if err != nil {
		h.logger.Error("raw email proxy request failed", "email_id", emailID, "error", err)
		httputil.WriteError(w, http.StatusBadGateway, "download failed")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		httputil.WriteError(w, http.StatusNotFound, "email not found")
		return
	}

	w.Header().Set("Content-Type", "message/rfc822")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.WriteHeader(http.StatusOK)

	if _, err := io.Copy(w, resp.Body); err != nil {
		h.logger.Warn("raw email download stream interrupted", "email_id", emailID, "error", err)
	}
}

// sanitizeFilename replaces characters that are unsafe in filenames with underscores
// and truncates to a reasonable length.
func sanitizeFilename(s string) string {
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, s)
	// Limit to 100 bytes to avoid excessively long filenames.
	if len(s) > 100 {
		s = s[:100]
	}
	if s == "" {
		s = "message"
	}
	return s
}
