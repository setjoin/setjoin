package jmap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"setjoin.com/shared/httputil"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/toggle"
)

// mailtips.go — the three non-JMAP HTTP endpoints on JMAPHandler wired
// directly in main.go (not dispatched as JMAP methods): HandleReadReceipt
// (POST /auth/me/read-receipt, RFC 3798 MDN), HandleMailTips
// (GET /auth/me/mailtips), and HandleDlpCheck (POST /auth/me/dlp-check, the
// DLP compose-tip dry-run). Exported names are unchanged.
// See mailserver/internal/AGENTS.md.

// HandleReadReceipt sends an MDN (RFC 3798) when a user opens a message requesting one.
// POST /auth/me/read-receipt  body: {"messageId": "123"}
func (h *JMAPHandler) HandleReadReceipt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteProblemStatus(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	claims := mustUser(w, r)
	if claims == nil {
		return
	}

	// consent: the recipient's explicit choice (Track A privacy). The reducer is the
	// hard gate — for policy 'never' the MDN is suppressed regardless of consent, and
	// for 'ask' an MDN sends only when consent is true. Absent → false (privacy-safe).
	var req struct {
		MessageID string `json:"messageId"`
		Consent   bool   `json:"consent"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid body")
		return
	}
	msgID, _ := strconv.ParseInt(req.MessageID, 10, 64)
	if msgID <= 0 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid messageId")
		return
	}

	// send_read_receipt is mailbox-keyed (ADR-003): the account-slot argument is the
	// caller's primary mailbox id (the parseAccountID currency), not their users.id.
	// The reducer resolves the sender identity behind that mailbox via account_scope.
	accountMailboxID, err := identity.ResolvePrimaryMailbox(r.Context(), h.pool, claims.UserID)
	if err != nil {
		h.logger.Error("readreceipt primary mailbox lookup failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}

	// native-RLS: send_read_receipt reads messages → run inside the per-request
	// GUC tx (CallScoped) so it survives the W6 FORCE flip. (This is the deferred
	// B7/MDN path, but it is a live route, so it must be scoped like any other.)
	result, err := h.caller.CallScoped(r.Context(), accountMailboxID,
		"send_read_receipt", msgID, claims.Email, req.Consent)
	if err != nil {
		h.logger.Error("readreceipt failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

// HandleMailTips returns context-sensitive warnings for compose recipients.
// GET /auth/me/mailtips?recipients=alice@co.com,bob@outsider.com&from=billing@co.com
func (h *JMAPHandler) HandleMailTips(w http.ResponseWriter, r *http.Request) {
	claims := mustUser(w, r)
	if claims == nil {
		return
	}

	recipientsStr := r.URL.Query().Get("recipients")
	fromAddr := r.URL.Query().Get("from")
	if recipientsStr == "" && fromAddr == "" {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"warnings": []any{}})
		return
	}

	recipients := strings.Split(recipientsStr, ",")
	var cleanRecipients []string
	for _, rcpt := range recipients {
		rcpt = strings.TrimSpace(rcpt)
		if rcpt != "" {
			cleanRecipients = append(cleanRecipients, rcpt)
		}
	}

	ctx := r.Context()
	warnings := []map[string]any{}

	// 1. Large audience warning
	if len(cleanRecipients) > 25 {
		warnings = append(warnings, map[string]any{
			"type":    "large_audience",
			"message": fmt.Sprintf("Your message will be sent to %d recipients", len(cleanRecipients)),
			"count":   len(cleanRecipients),
		})
	}

	// 2. External domain detection + vacation status — batched queries
	if len(cleanRecipients) > 0 {
		// The external label is advisory, so a missing toggle service fails closed.
		// OOO lookup remains independent and still receives every clean recipient.
		externalLabelsEnabled := h.externalLabelsEnabled(ctx, claims.UserID)
		domainSet := make(map[string]struct{})
		domainRecipients := make(map[string][]string) // domain → recipients
		emails := make([]string, 0, len(cleanRecipients))
		for _, rcpt := range cleanRecipients {
			if externalLabelsEnabled {
				parts := strings.SplitN(rcpt, "@", 2)
				if len(parts) == 2 {
					domain := strings.ToLower(parts[1])
					domainSet[domain] = struct{}{}
					domainRecipients[domain] = append(domainRecipients[domain], rcpt)
				}
			}
			emails = append(emails, rcpt)
		}

		// Batch domain lookup
		if len(domainSet) > 0 {
			domains := make([]string, 0, len(domainSet))
			for d := range domainSet {
				domains = append(domains, d)
			}
			localDomains := make(map[string]bool)
			rows, err := h.pool.Query(ctx, `SELECT name FROM domains WHERE name = ANY($1)`, domains)
			if err == nil {
				for rows.Next() {
					var name string
					if err := rows.Scan(&name); err == nil {
						localDomains[name] = true
					}
				}
				rows.Close()
			}
			for domain, rcpts := range domainRecipients {
				if !localDomains[domain] {
					for _, rcpt := range rcpts {
						warnings = append(warnings, map[string]any{
							"type":      "external_recipient",
							"recipient": rcpt,
							"domain":    domain,
						})
					}
				}
			}
		}

		// 3. Out-of-office advisory (QoL #7) — routed through the
		// recipients_ooo_status reducer (logic-where-the-data-is). The reducer
		// resolves each address to an internal mailbox (via resolve_identity) and
		// returns DATES ONLY for those with an active auto-reply window (verbatim
		// with the deliver-side vacation trigger, incl. indefinite/null-end). An
		// external or unknown address returns nothing — indistinguishable from an
		// internal-not-OOO address, so there is no directory-enumeration oracle,
		// and the auto-reply subject/body never crosses the boundary. Best-effort:
		// any failure simply omits the OOO tips.
		if mbID, mbErr := identity.ResolvePrimaryMailbox(ctx, h.pool, claims.UserID); mbErr == nil {
			emailsJSON, _ := json.Marshal(emails)
			raw, oooErr := h.caller.CallScoped(ctx, mbID, "recipients_ooo_status", string(emailsJSON))
			if oooErr == nil {
				var rows []struct {
					Email string  `json:"email"`
					Until *string `json:"until"` // "YYYY-MM-DD", or null for indefinite
				}
				if json.Unmarshal(raw, &rows) == nil {
					for _, row := range rows {
						warnings = append(warnings, map[string]any{
							"type":      "ooo",
							"recipient": row.Email,
							"until":     row.Until,
						})
					}
				}
			} else {
				h.logger.Warn("mailtips ooo lookup failed", "error", oooErr)
			}
		}
	}

	// 4. Missing send_as permission check. On h.workerPool (BYPASSRLS): a
	// delegate-side read — the row lives on ANOTHER user's mailbox, naming
	// the viewer (native-RLS V090); R1 by md.user_id = the authenticated user.
	if fromAddr != "" {
		var hasPermission bool
		h.workerPool.QueryRow(ctx,
			`SELECT EXISTS(
				SELECT 1 FROM mailbox_delegates md
				JOIN mailboxes mb ON mb.id = md.mailbox_id
				WHERE md.user_id = $1 AND mb.email = $2
				  AND md.permission IN ('send_as','full_access')
			)`, claims.UserID, fromAddr,
		).Scan(&hasPermission)
		if !hasPermission && fromAddr != claims.Email {
			warnings = append(warnings, map[string]any{
				"type":    "no_send_as",
				"message": fmt.Sprintf("You don't have permission to send as %s", fromAddr),
				"from":    fromAddr,
			})
		}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"warnings": warnings})
}

func (h *JMAPHandler) externalLabelsFeatureEnabled() bool {
	return h != nil && h.toggles != nil &&
		h.toggles.IsEnabled(toggle.FeatureExternalSenderWarn)
}

func (h *JMAPHandler) externalLabelsEnabled(ctx context.Context, userID int64) bool {
	if !h.externalLabelsFeatureEnabled() || h.pool == nil || userID <= 0 {
		return false
	}
	var userEnabled bool
	if err := h.pool.QueryRow(ctx,
		`SELECT COALESCE(external_sender_warning, TRUE)
		   FROM users
		  WHERE id = $1`,
		userID,
	).Scan(&userEnabled); err != nil {
		if h.logger != nil {
			h.logger.Warn("mailtips external-label preference lookup failed",
				"user_id", userID, "error", err)
		}
		return false
	}
	return userEnabled
}

// HandleDlpCheck evaluates the current draft against DLP policies (dry-run of
// send.sql step 5a via the dlp_evaluate_draft reducer — same seam, so the tip
// can never disagree with enforcement). POST because the body travels;
// debounce is client-side (composeStore), not here.
// POST /auth/me/dlp-check  {"recipients":[...],"subject":"...","bodyText":"...","bodyHtml":"..."}
func (h *JMAPHandler) HandleDlpCheck(w http.ResponseWriter, r *http.Request) {
	claims := mustUser(w, r)
	if claims == nil {
		return
	}
	// Feature parity with enforcement: submission.go maps !feature.dlp →
	// app.skip_dlp, i.e. send skips 5a entirely. Same short-circuit here — no
	// DB call at all when the feature is off.
	if h.toggles == nil || !h.toggles.IsEnabled(toggle.FeatureDLP) {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"violated": false})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20) // > compose body cap; dlp_check has its own 5s timeout
	var req struct {
		Recipients []string `json:"recipients"`
		Subject    string   `json:"subject"`
		BodyText   string   `json:"bodyText"`
		BodyHTML   string   `json:"bodyHtml"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid body")
		return
	}
	mbID, err := identity.ResolvePrimaryMailbox(r.Context(), h.pool, claims.UserID)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	rcptJSON, _ := json.Marshal(req.Recipients)
	result, err := h.caller.CallScoped(r.Context(), mbID, "dlp_evaluate_draft",
		string(rcptJSON), req.Subject, req.BodyText, req.BodyHTML)
	if err != nil {
		// Advisory surface: fail OPEN to "no tip" (send-time enforcement is the
		// hard gate), but log — a broken dry-run must not block composing.
		h.logger.Warn("dlp draft check failed", "error", err)
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"violated": false})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}
