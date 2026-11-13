// Package approval — email-page handler (DD2).
//
// GET  /approvals/email/{token} — verify HMAC, render a confirmation page
//
//	showing the request subject + Approve/Deny
//	buttons that POST. NEVER decides (prefetch-safe).
//
// POST /approvals/email/{token} — verify HMAC, call the consumer wrapper as the
//
//	approver_user_id embedded in the token, render
//	a result page.
//
// # Token security model
//
// A token is base64url(json).base64url(HMAC-SHA256) using the server's JWTSecret
// (the same key used by linkprotect — no new key store). The payload binds:
//
//	(request_id, approver_user_id, decision, exp)
//
// HMAC verification on every use:
//   - A forged request_id, approver, or decision won't match the signature.
//
// Single-use is FREE from decide-idempotency:
//   - The reducer's atomic WHERE status='pending' raises BZ108 on replay.
//   - A reused token → "approval is no longer active".
//
// Expiry is FREE from the request's expires_at:
//   - An expired request is status='expired' or past expires_at → BZ108.
//   - The token also embeds exp for defense-in-depth (VerifyApprovalToken checks it).
//
// Prefetch-safety:
//   - GET NEVER calls decide. It only SELECTs and renders HTML.
//   - Only POST decides.
//
// Actor identity:
//   - The approver acts as the user_id bound in the VERIFIED TOKEN.
//   - There is no session; the email path is unauthenticated at the HTTP layer.
package approval

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/reducererr"
)

// ── Token ─────────────────────────────────────────────────────────────────────

// ApprovalEmailClaims is the payload of a signed approval-email token.
// The token binds (request_id, approver_user_id, decision) so a tampered field
// causes HMAC verification to fail.
type ApprovalEmailClaims struct {
	RequestID      int64  `json:"r"`
	ApproverUserID int64  `json:"a"`
	Decision       string `json:"d"` // "approve" or "deny"
	ExpiresAt      int64  `json:"e"` // Unix timestamp (defense-in-depth; request.expires_at is primary)
}

// SignApprovalToken creates an HMAC-SHA256 signed token.
// Format: base64url(payload).base64url(sig) — identical to linkprotect.SignToken.
func SignApprovalToken(claims ApprovalEmailClaims, secret []byte) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("approval_email: marshal claims: %w", err)
	}
	payloadB64 := base64.URLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payloadB64))
	sig := mac.Sum(nil)
	return payloadB64 + "." + base64.URLEncoding.EncodeToString(sig), nil
}

// VerifyApprovalToken validates a token and returns its claims.
// Returns an error on tamper, expiry, or malformed input.
func VerifyApprovalToken(tokenStr string, secret []byte) (*ApprovalEmailClaims, error) {
	parts := strings.SplitN(tokenStr, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("approval_email: invalid token format")
	}
	payloadB64, sigB64 := parts[0], parts[1]

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payloadB64))
	expectedSig := mac.Sum(nil)

	sig, err := base64.URLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("approval_email: invalid signature encoding")
	}
	if !hmac.Equal(sig, expectedSig) {
		return nil, fmt.Errorf("approval_email: signature mismatch")
	}

	payload, err := base64.URLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("approval_email: invalid payload encoding")
	}
	var claims ApprovalEmailClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("approval_email: invalid claims: %w", err)
	}
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, fmt.Errorf("approval_email: token expired")
	}
	return &claims, nil
}

// ── Handler ───────────────────────────────────────────────────────────────────

// EmailPageHandler serves GET/POST /approvals/email/{token}.
// Routes are UNAUTHENTICATED — security rests entirely on the HMAC token.
type EmailPageHandler struct {
	pool       *pgxpool.Pool
	workerPool rowQuerier // BYPASSRLS — mail consumers' cross-tenant decide replay ONLY (handler.go package doc)
	secret     []byte
	logger     *slog.Logger
}

// NewEmailPageHandler creates an EmailPageHandler.
// secret is the HMAC key — pass []byte(cfg.JWTSecret) (same as linkprotect).
// workerPool is the setjoin_worker (BYPASSRLS) pool the mail consumers' decide
// replay routes onto (see the package doc in handler.go); it aliases the app
// pool until DB_WORKER_DSN is set.
func NewEmailPageHandler(pool *pgxpool.Pool, workerPool pgxutil.WorkerPool, secret []byte, logger *slog.Logger) *EmailPageHandler {
	return &EmailPageHandler{pool: pool, workerPool: workerPool, secret: secret, logger: logger}
}

// approvalPageRequest holds the DB row fetched to render the confirm/info page.
type approvalPageRequest struct {
	ID              int64
	Subject         string
	Status          string
	ExpiresAt       time.Time
	DecidedByUserID *int64
}

// fetchApprovalRequest reads the approval_requests row by ID using the
// RLS-scoped transaction set by RunUserScoped(approverUserID). Under FORCE RLS
// (W6 flip) the approver can see the row via the approver_ref = current_user_id
// policy branch; visibility is additionally bounded by token HMAC.
func (h *EmailPageHandler) fetchApprovalRequest(ctx context.Context, tx pgx.Tx, id int64) (approvalPageRequest, error) {
	var r approvalPageRequest
	r.ID = id
	err := tx.QueryRow(ctx,
		`SELECT subject, status, expires_at, decided_by_user_id
		   FROM approval_requests WHERE id = $1`, id,
	).Scan(&r.Subject, &r.Status, &r.ExpiresAt, &r.DecidedByUserID)
	return r, err
}

// ServeGET handles GET /approvals/email/{token}.
// PREFETCH-SAFE: reads DB, renders HTML, never decides.
func (h *EmailPageHandler) ServeGET(w http.ResponseWriter, r *http.Request) {
	tok := r.PathValue("token")
	claims, err := VerifyApprovalToken(tok, h.secret)
	if err != nil {
		h.renderBadToken(w)
		return
	}

	ctx := r.Context()
	var req approvalPageRequest
	// RunUserScoped scopes the SELECT to the token's verified approver so the
	// query works correctly under FORCE RLS once DB_DSN becomes setjoin_app (W6).
	if err = dbscope.RunUserScoped(ctx, h.pool, claims.ApproverUserID, func(tx pgx.Tx) error {
		var fetchErr error
		req, fetchErr = h.fetchApprovalRequest(ctx, tx, claims.RequestID)
		return fetchErr
	}); err != nil {
		h.logger.Warn("email approval GET: fetch request", "id", claims.RequestID, "error", err)
		h.renderBadToken(w)
		return
	}

	if req.Status != "pending" {
		h.renderNoLongerActive(w, req.Status)
		return
	}

	// Render the confirmation page with Approve / Deny buttons (both POST).
	// The token is already in the URL path — the form action uses it.
	h.renderConfirm(w, req.Subject, tok, claims.Decision)
}

// ServePOST handles POST /approvals/email/{token}.
// Verifies HMAC → routes to consumer wrapper as the token's approver → renders result.
func (h *EmailPageHandler) ServePOST(w http.ResponseWriter, r *http.Request) {
	tok := r.PathValue("token")
	claims, err := VerifyApprovalToken(tok, h.secret)
	if err != nil {
		h.renderBadToken(w)
		return
	}

	ctx := r.Context()

	// RunUserScoped scopes the approval_requests visibility lookup (and the rbac
	// decide) to the token's verified approver under FORCE RLS. The MAIL
	// consumers' decide then runs on the WORKER (BYPASSRLS) pool — the reducer
	// replays a cross-tenant send()/deliver() leg a tenant GUC would fail closed
	// (see the package doc in handler.go; pinned by routing_test.go).
	var resultStatus string
	var workerFn string // set → decide runs on the worker pool after the scoped tx
	err = dbscope.RunUserScoped(ctx, h.pool, claims.ApproverUserID, func(tx pgx.Tx) error {
		// Fetch consumer_type to route to the right wrapper.
		var consumerType string
		if qErr := tx.QueryRow(ctx,
			`SELECT consumer_type FROM approval_requests WHERE id = $1`, claims.RequestID,
		).Scan(&consumerType); qErr != nil {
			h.logger.Warn("email approval POST: fetch consumer_type", "id", claims.RequestID, "error", qErr)
			return errNotFound
		}

		// Call the consumer wrapper. The actor is the approver_user_id from the
		// VERIFIED TOKEN (the HMAC binds it) — not a session, not a query param.
		switch consumerType {
		case "rbac.jit_activation":
			return tx.QueryRow(ctx,
				`SELECT rbac_approval_decide($1, $2, $3, $4)`,
				claims.RequestID, claims.ApproverUserID, claims.Decision, (*string)(nil),
			).Scan(&resultStatus)
		case "drive.export":
			// Tenant tx — same posture as rbac.jit_activation above (handler.go
			// package doc); the V116 wrapper is SECURITY DEFINER/self-contained.
			return tx.QueryRow(ctx,
				`SELECT drive_export_approval_decide($1, $2, $3, $4)`,
				claims.RequestID, claims.ApproverUserID, claims.Decision, (*string)(nil),
			).Scan(&resultStatus)
		case "drive.share":
			return tx.QueryRow(ctx,
				`SELECT drive_share_approval_decide($1, $2, $3, $4)`,
				claims.RequestID, claims.ApproverUserID, claims.Decision, (*string)(nil),
			).Scan(&resultStatus)
		case "mail.external_send":
			workerFn = "mail_external_approval_decide"
			return nil
		case "mail.group_moderation":
			workerFn = "group_moderation_approval_decide"
			return nil
		default:
			h.logger.Warn("email approval POST: unknown consumer_type", "type", consumerType)
			return errConsumerNotWired
		}
	})
	if err == nil && workerFn != "" {
		// Cross-tenant replay leg on the worker pool — reducer self-authorizes
		// p_actor and re-checks status='pending' atomically (TOCTOU-free split).
		// workerFn is one of two literals from the switch — never request input.
		err = h.workerPool.QueryRow(ctx,
			`SELECT `+workerFn+`($1, $2, $3, $4)`,
			claims.RequestID, claims.ApproverUserID, claims.Decision, (*string)(nil),
		).Scan(&resultStatus)
	}

	if err != nil {
		if errors.Is(err, errNotFound) {
			h.renderNoLongerActive(w, "not found")
			return
		}
		if errors.Is(err, errConsumerNotWired) {
			h.renderNoLongerActive(w, "unknown consumer")
			return
		}
		// Semantic render branches (HTML pages, not a wire projection) — IsCode.
		if reducererr.IsCode(err, "BZ108") { // not found / not pending — already decided or expired
			h.renderNoLongerActive(w, "decided")
			return
		}
		if reducererr.IsCode(err, "BZ107") { // not the designated approver — token is valid but wrong user
			h.renderBadToken(w)
			return
		}
		h.logger.Error("email approval POST: decide failed",
			"id", claims.RequestID, "approver", claims.ApproverUserID, "error", err)
		http.Error(w, "An error occurred. Please try again.", http.StatusInternalServerError)
		return
	}

	h.renderResult(w, resultStatus, claims.Decision)
}

// ── Notification email ────────────────────────────────────────────────────────

// resolveApproverEmails returns the email address(es) that should receive the
// approve-by-email notification for a request's (approver_kind, approver_ref).
//
//   - "user": the single designated approver's primary-mailbox email.
//   - "role_group": every ACTIVE member of the role group — active meaning the
//     same predicate approval_decide's BZ107 gate enforces (non-expired AND
//     admin_assignment_active), so the notification fan-out can never issue a
//     signed capability to a dormant-eligible member who could not use it.
//
// Each returned entry is (user_id, email); the caller signs one token PER
// user_id so whichever member clicks their own link, the token's embedded
// ApproverUserID is a real member the reducer's authorization check accepts.
func resolveApproverEmails(ctx context.Context, pool *pgxpool.Pool, approverKind string, approverRef int64) ([]int64, []string, error) {
	var userIDs []int64
	switch approverKind {
	case "user":
		userIDs = []int64{approverRef}
	case "role_group":
		// Same authorization predicate as approval_decide's BZ107 check (and the
		// V070/V073 RLS role_group branch): non-expired AND JIT-active. Calling
		// the admin_assignment_active reducer directly (rather than re-deriving
		// its toggle logic) keeps issuance and use on one authority — a dormant
		// eligible member is never emailed an approve/deny token it is not
		// authorized to use (D-MAILSERVER-INTERNAL-APPROVAL-003).
		rows, err := pool.Query(ctx,
			`SELECT user_id FROM admin_role_assignments
			   WHERE role_group_id = $1
			     AND (expires_at IS NULL OR expires_at > now())
			     AND admin_assignment_active(eligible, activated_until)`,
			approverRef,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve role_group members: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var uid int64
			if err := rows.Scan(&uid); err != nil {
				return nil, nil, err
			}
			userIDs = append(userIDs, uid)
		}
		if err := rows.Err(); err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("resolveApproverEmails: unknown approver_kind %q", approverKind)
	}

	emails := make([]string, 0, len(userIDs))
	resolved := make([]int64, 0, len(userIDs))
	for _, uid := range userIDs {
		mailboxID, err := identity.ResolvePrimaryMailbox(ctx, pool, uid)
		if err != nil {
			continue // best-effort: one member with no mailbox must not block the rest
		}
		var email string
		if err := pool.QueryRow(ctx,
			`SELECT COALESCE(mb.email, u.email) FROM mailboxes mb JOIN users u ON u.id = mb.user_id WHERE mb.id = $1`,
			mailboxID,
		).Scan(&email); err != nil {
			continue
		}
		resolved = append(resolved, uid)
		emails = append(emails, email)
	}
	return resolved, emails, nil
}

// SendApprovalNotification delivers an email to every eligible approver
// (the single designated user, or every active role_group member) containing
// Approve and Deny links for the given approval request. Fire-and-forget —
// call in a goroutine; failures are logged, never returned.
//
// baseURL is the gateway base (e.g. "https://mail.corp.com").
// secret is the HMAC key (same as NewEmailPageHandler — pass cfg.JWTSecret).
//
// pool MUST be the BYPASSRLS worker pool (main.go passes workerPool.Pool). This
// is a SYSTEM op — a notification about a request, with no acting user — so it
// runs outside any RunUserScoped GUC; under FORCE RLS (post-DSN-switch) both the
// approval_requests read below AND the deliver() fan-out fail-closed on the app
// pool (0 rows / 42501). Classified BYPASS in rls-coverage-allowlist.txt.
func SendApprovalNotification(
	ctx context.Context,
	pool *pgxpool.Pool,
	reqID int64,
	secret []byte,
	baseURL string,
	logger *slog.Logger,
) {
	var approverKind string
	var approverRef int64
	var subject string
	var expiresAt time.Time

	err := pool.QueryRow(ctx,
		`SELECT approver_kind, approver_ref, subject, expires_at
		   FROM approval_requests WHERE id = $1`, reqID,
	).Scan(&approverKind, &approverRef, &subject, &expiresAt)
	if err != nil {
		logger.Warn("approval notify: fetch request", "req_id", reqID, "error", err)
		return
	}

	userIDs, emails, err := resolveApproverEmails(ctx, pool, approverKind, approverRef)
	if err != nil {
		logger.Warn("approval notify: resolve approver emails", "req_id", reqID, "error", err)
		return
	}
	if len(userIDs) == 0 {
		logger.Warn("approval notify: no reachable approver email", "req_id", reqID, "approver_kind", approverKind, "approver_ref", approverRef)
		return
	}

	for i, approverUserID := range userIDs {
		sendOneApprovalEmail(ctx, pool, reqID, approverUserID, emails[i], subject, expiresAt, secret, baseURL, logger)
	}
}

// sendOneApprovalEmail signs the approve/deny tokens for one approver and
// delivers the notification to their mailbox. Split out of
// SendApprovalNotification so a role_group fan-out is a simple loop.
func sendOneApprovalEmail(
	ctx context.Context,
	pool *pgxpool.Pool,
	reqID int64,
	approverUserID int64,
	approverEmail string,
	subject string,
	expiresAt time.Time,
	secret []byte,
	baseURL string,
	logger *slog.Logger,
) {
	exp := expiresAt.Unix()
	approveTok, err := SignApprovalToken(ApprovalEmailClaims{
		RequestID: reqID, ApproverUserID: approverUserID, Decision: "approve", ExpiresAt: exp,
	}, secret)
	if err != nil {
		logger.Warn("approval notify: sign approve token", "error", err)
		return
	}
	denyTok, err := SignApprovalToken(ApprovalEmailClaims{
		RequestID: reqID, ApproverUserID: approverUserID, Decision: "deny", ExpiresAt: exp,
	}, secret)
	if err != nil {
		logger.Warn("approval notify: sign deny token", "error", err)
		return
	}

	approveURL := baseURL + "/approvals/email/" + approveTok
	denyURL := baseURL + "/approvals/email/" + denyTok

	bodyText := fmt.Sprintf(
		"You have an approval request pending action.\n\nRequest: %s\n\nApprove: %s\n\nDeny: %s\n\nThis link expires at %s.",
		subject, approveURL, denyURL, expiresAt.Format(time.RFC1123),
	)
	bodyHTML := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Approval Request</title></head>
<body style="font-family:sans-serif;max-width:600px;margin:auto;padding:24px">
<h2>Approval Request</h2>
<p><strong>%s</strong></p>
<p>
  <a href="%s" style="display:inline-block;padding:12px 24px;background:#2563eb;color:#fff;border-radius:6px;text-decoration:none;margin-right:12px">Approve</a>
  <a href="%s" style="display:inline-block;padding:12px 24px;background:#dc2626;color:#fff;border-radius:6px;text-decoration:none">Deny</a>
</p>
<p style="color:#6b7280;font-size:14px">This approval request expires %s.</p>
</body></html>`,
		template.HTMLEscapeString(subject), approveURL, denyURL,
		expiresAt.Format(time.RFC1123),
	)

	domain := approverEmail
	if at := strings.LastIndex(approverEmail, "@"); at >= 0 && at < len(approverEmail)-1 {
		domain = approverEmail[at+1:]
	}
	messageID := fmt.Sprintf("approval-%d-%d-%d@setjoin", reqID, approverUserID, time.Now().UnixNano())
	rawRef := fmt.Sprintf("system:approval-notify:%d:%d", reqID, approverUserID)
	size := int64(len(bodyText) + len(bodyHTML))

	_, err = pool.Exec(ctx,
		`SELECT deliver(
		   $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
		   FALSE, $15, $16, $17, $18, $19, $20)`,
		rawRef,
		messageID,
		"noreply@"+domain,
		"SetJoin Approvals",
		approverEmail,
		fmt.Sprintf(`[{"email":%q,"name":""}]`, approverEmail),
		"[]",
		"[]",
		"Approval required: "+subject,
		"",
		"",
		bodyText,
		bodyHTML,
		size,
		// p_has_attachments = FALSE (above)
		time.Now(),
		"none",
		"none",
		"none",
		0.0,
		"{}",
	)
	if err != nil {
		logger.Warn("approval notify: deliver failed", "req_id", reqID, "approver", approverUserID, "error", err)
		return
	}
	logger.Info("approval notification sent", "req_id", reqID, "approver", approverUserID)
}

// HandleApprovalCreatedNotify handles the "approval_created" pg_notify payload
// (fired by approval_request_create for EVERY consumer). It fans out the
// approve-by-email notification to the mail consumers (mail.external_send,
// mail.group_moderation); rbac.jit_activation is console-only (spec D7) and is
// skipped here. Centralizes what used to be a group-moderation-only direct
// call at the SMTP inbound seam — the external-send hold has no Go call site
// with the request id (send() PERFORMs approval_request_create and RETURNs
// NULL), so this NOTIFY-driven fan-out is the one path that reaches both.
// Safe to call with a malformed payload — logs and returns, never panics.
func HandleApprovalCreatedNotify(ctx context.Context, pool *pgxpool.Pool, payload []byte, secret []byte, baseURL string, logger *slog.Logger) {
	if baseURL == "" || len(secret) == 0 {
		return // approve-by-email not configured (no JWT secret / hostname)
	}
	var n struct {
		RequestID    int64  `json:"request_id"`
		ConsumerType string `json:"consumer_type"`
	}
	if err := json.Unmarshal(payload, &n); err != nil {
		logger.Warn("approval_created: malformed notify payload", "error", err, "payload", string(payload))
		return
	}
	if n.ConsumerType == "rbac.jit_activation" {
		return // D7: RBAC approval is console-only, no email
	}
	SendApprovalNotification(ctx, pool, n.RequestID, secret, baseURL, logger)
}

// ── HTML rendering ────────────────────────────────────────────────────────────

// renderConfirm renders the confirmation page.
// Each token carries a single decision ("approve" or "deny"); the page shows
// the request subject and ONE confirmation button that POSTs to the same URL.
// The email contains two separate pre-signed links (one per decision).
// Mobile-first, WCAG AA, 44 px touch targets.
func (h *EmailPageHandler) renderConfirm(w http.ResponseWriter, subject, token, decision string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	// ponytail: token-only inline CSS (no external deps, mobile-first, 44px, AA contrast).
	esc := template.HTMLEscapeString
	btnClass := "btn-approve"
	label := "Approve"
	if decision == "deny" {
		btnClass = "btn-deny"
		label = "Deny"
	}
	fmt.Fprintf(w, confirmPageHTML, esc(subject), "/approvals/email/"+token, btnClass, label) //nolint:gosec // subject is HTML-escaped by esc(); template is a static const
}

func (h *EmailPageHandler) renderResult(w http.ResponseWriter, status, decision string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	var verb string
	switch decision {
	case "approve":
		verb = "approved"
	case "deny":
		verb = "denied"
	default:
		verb = status
	}
	fmt.Fprintf(w, resultPageHTML, verb)
}

func (h *EmailPageHandler) renderNoLongerActive(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_ = reason
	_, _ = fmt.Fprint(w, inactivePageHTML)
}

func (h *EmailPageHandler) renderBadToken(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = fmt.Fprint(w, badTokenPageHTML)
}

// ── Page templates ────────────────────────────────────────────────────────────

// confirmPageHTML is the confirm page. Args: subject, action-url, btn-class, btn-label.
// The decision is baked into the token in the action URL — the page shows a
// single confirmation button. The email sends two separate pre-signed links
// (one for "approve", one for "deny"), each pointing to its own confirm page.
//
// ponytail: one small inline stylesheet, no external deps, mobile-first, AA contrast
// (white on #2563eb = 4.8:1; white on #dc2626 = 4.6:1 — both pass AA for large text).
const confirmPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Approval Request</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
     background:#f9fafb;color:#111827;min-height:100vh;
     display:flex;align-items:center;justify-content:center;padding:16px}
.card{background:#fff;border-radius:12px;box-shadow:0 1px 4px rgba(0,0,0,.1);
      max-width:480px;width:100%%;padding:32px 28px}
h1{font-size:1.25rem;font-weight:600;margin-bottom:8px}
.sub{color:#6b7280;font-size:.9rem;margin-bottom:24px}
.subject{font-size:1rem;font-weight:500;margin-bottom:24px;
         padding:12px;background:#f3f4f6;border-radius:8px;word-break:break-word}
.btn{display:inline-flex;align-items:center;justify-content:center;
     min-height:44px;padding:10px 24px;border:none;border-radius:8px;
     font-size:1rem;font-weight:500;cursor:pointer;color:#fff;width:100%%}
.btn-approve{background:#2563eb}.btn-approve:hover{background:#1d4ed8}
.btn-deny{background:#dc2626}.btn-deny:hover{background:#b91c1c}
@media(min-width:360px){.btn{width:auto}}
</style>
</head>
<body>
<div class="card" role="main">
  <h1>Approval Request</h1>
  <p class="sub">Your decision is required for the following request:</p>
  <div class="subject" aria-label="Request subject">%s</div>
  <form method="POST" action="%s">
    <button type="submit" class="btn %s" aria-label="%[4]s this request">%[4]s</button>
  </form>
</div>
</body></html>
`

const resultPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Decision recorded</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
     background:#f9fafb;color:#111827;min-height:100vh;
     display:flex;align-items:center;justify-content:center;padding:16px}
.card{background:#fff;border-radius:12px;box-shadow:0 1px 4px rgba(0,0,0,.1);
      max-width:480px;width:100%%;padding:32px 28px;text-align:center}
.icon{font-size:2.5rem;margin-bottom:16px}
h1{font-size:1.25rem;font-weight:600;margin-bottom:8px}
p{color:#6b7280;font-size:.9rem}
</style>
</head>
<body>
<div class="card" role="main">
  <div class="icon" aria-hidden="true">✓</div>
  <h1>Decision recorded</h1>
  <p>You have <strong>%s</strong> this request. The requester will be notified.</p>
</div>
</body></html>
`

const inactivePageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Approval no longer active</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
     background:#f9fafb;color:#111827;min-height:100vh;
     display:flex;align-items:center;justify-content:center;padding:16px}
.card{background:#fff;border-radius:12px;box-shadow:0 1px 4px rgba(0,0,0,.1);
      max-width:480px;width:100%;padding:32px 28px;text-align:center}
.icon{font-size:2.5rem;margin-bottom:16px}
h1{font-size:1.25rem;font-weight:600;margin-bottom:8px}
p{color:#6b7280;font-size:.9rem}
</style>
</head>
<body>
<div class="card" role="main">
  <div class="icon" aria-hidden="true">ℹ</div>
  <h1>This approval is no longer active</h1>
  <p>This request has already been decided or has expired. No action is needed.</p>
</div>
</body></html>
`

const badTokenPageHTML = `<!DOCTYPE html>` + //nolint:gosec // false positive: no credentials in this HTML template
	`
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Invalid link</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
     background:#f9fafb;color:#111827;min-height:100vh;
     display:flex;align-items:center;justify-content:center;padding:16px}
.card{background:#fff;border-radius:12px;box-shadow:0 1px 4px rgba(0,0,0,.1);
      max-width:480px;width:100%;padding:32px 28px;text-align:center}
.icon{font-size:2.5rem;margin-bottom:16px}
h1{font-size:1.25rem;font-weight:600;margin-bottom:8px}
p{color:#6b7280;font-size:.9rem}
</style>
</head>
<body>
<div class="card" role="main">
  <div class="icon" aria-hidden="true">✗</div>
  <h1>Invalid or expired link</h1>
  <p>This approval link is invalid or has expired. Please request a new notification email.</p>
</div>
</body></html>
`
