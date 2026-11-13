package notify

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/identity"
)

// splitLocalDomain splits an email-shaped address on the last '@' into its
// local-part and domain. If there is no '@', it returns ("", addr) — the
// whole string as domain, empty local-part.
func splitLocalDomain(addr string) (local, domain string) {
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return "", addr
	}
	return addr[:at], addr[at+1:]
}

// welcomeRecipient resolves the new user's primary mailbox address and the
// personalization values for the placeholder whitelist. It uses the canonical
// identity.ResolvePrimaryMailbox seam (ARCH-003) for the mailbox id, then one
// query for the personalization fields. OrgName and WebmailURL derive from the
// recipient's domain (no brand/webmail config key exists yet — spec §5 lists
// per-brand values as a future enhancement). DisplayName falls back to the
// email local-part.
func welcomeRecipient(ctx context.Context, pool *pgxpool.Pool, userID int64) (map[string]string, string, error) {
	mailboxID, err := identity.ResolvePrimaryMailbox(ctx, pool, userID)
	if err != nil {
		return nil, "", fmt.Errorf("welcome: resolve primary mailbox for user %d: %w", userID, err)
	}
	var displayName, username, email string
	err = pool.QueryRow(ctx,
		`SELECT u.display_name, u.username, COALESCE(mb.email, u.email)
		   FROM mailboxes mb JOIN users u ON u.id = mb.user_id
		  WHERE mb.id = $1`, mailboxID,
	).Scan(&displayName, &username, &email)
	if err != nil {
		return nil, "", fmt.Errorf("welcome: resolve recipient fields for mailbox %d: %w", mailboxID, err)
	}

	local, domain := splitLocalDomain(email)
	if displayName == "" {
		if local != "" {
			displayName = local
		} else {
			displayName = email
		}
	}

	vals := map[string]string{
		"DisplayName": displayName,
		"Email":       email,
		"Username":    username,
		"OrgName":     domain,
		"WebmailURL":  "https://" + domain,
	}
	return vals, email, nil
}

// SendWelcomeEmail delivers the configured welcome email into the new user's
// inbox. Fire-and-forget: it is called in a goroutine from interactive
// provisioning paths and never returns an error (failures are logged). It is
// idempotent — it will not deliver a second welcome to a mailbox that already
// has one (the system:welcome:<userID> sentinel), which makes it safe to call
// from SCIM's upsert-semantics POST. When the welcome_email config key is
// absent (should not happen post-V018) it logs and no-ops.
func SendWelcomeEmail(ctx context.Context, pool *pgxpool.Pool, userID int64, locale string, logger *slog.Logger) {
	already, err := welcomeAlreadySent(ctx, pool, userID)
	if err != nil {
		logger.Warn("welcome email: idempotency check failed", "user_id", userID, "error", err)
		return
	}
	if already {
		return
	}

	tmpl, ok := loadWelcomeTemplate(ctx, pool, userID, locale, logger)
	if !ok {
		return // disabled, absent config, or no usable template — nothing to send
	}

	vals, recipient, err := welcomeRecipient(ctx, pool, userID)
	if err != nil {
		logger.Warn("welcome email: resolve recipient failed", "user_id", userID, "error", err)
		return
	}
	if err := deliverWelcome(ctx, pool, userID, recipient, tmpl, vals); err != nil {
		logger.Warn("welcome email: delivery failed", "user_id", userID, "error", err)
		return
	}
	logger.Info("welcome email sent", "user_id", userID, "locale", locale)
}

// SendWelcomeEmailWithConfig delivers explicit, possibly-unsaved content (the
// admin "Send test to me" path). No idempotency guard — testing must be
// repeatable. Returns an error so the endpoint can report failure.
func SendWelcomeEmailWithConfig(ctx context.Context, pool *pgxpool.Pool, userID int64, locale string, tmpl WelcomeLocale, logger *slog.Logger) error {
	vals, recipient, err := welcomeRecipient(ctx, pool, userID)
	if err != nil {
		return err
	}
	return deliverWelcome(ctx, pool, userID, recipient, tmpl, vals)
}

// loadWelcomeTemplate loads the welcome_email config and resolves the template
// for locale. ok=false means do not send (disabled, no usable locale, or — on a
// pre-V018 database that somehow booted — the config key absent: log + no-op,
// the V018 seed is the single source of truth).
func loadWelcomeTemplate(ctx context.Context, pool *pgxpool.Pool, userID int64, locale string, logger *slog.Logger) (WelcomeLocale, bool) {
	cfg, found, err := LoadWelcomeConfig(ctx, pool)
	if err != nil {
		logger.Warn("welcome email: load config failed", "user_id", userID, "error", err)
		return WelcomeLocale{}, false
	}
	if !found {
		logger.Warn("welcome email: config key absent (V018 not applied?)", "user_id", userID)
		return WelcomeLocale{}, false
	}
	return resolveWelcomeTemplate(cfg, locale)
}

// welcomeAlreadySent reports whether a welcome message already exists for the
// user's mailbox (the system:welcome:<userID> raw_ref sentinel).
func welcomeAlreadySent(ctx context.Context, pool *pgxpool.Pool, userID int64) (bool, error) {
	var exists bool
	err := pool.QueryRow(ctx,
		`SELECT EXISTS (
		   SELECT 1 FROM messages m
		   JOIN mailboxes mb ON mb.id = m.mailbox_id
		   WHERE mb.user_id = $1 AND m.raw_ref = $2)`,
		userID, fmt.Sprintf("system:welcome:%d", userID),
	).Scan(&exists)
	return exists, err
}

// deliverWelcome substitutes the placeholder whitelist into subject/body and
// delivers a system message into the recipient's inbox via deliver(). body_text
// and body_html are passed as distinct columns (clients render from them); the
// raw_ref is a display sentinel, not a content-addressed blob.
func deliverWelcome(ctx context.Context, pool *pgxpool.Pool, userID int64, recipient string, tmpl WelcomeLocale, vals map[string]string) error {
	subject := substituteWelcomePlaceholders(tmpl.Subject, vals)
	bodyText := substituteWelcomePlaceholders(tmpl.BodyText, vals)
	bodyHTML := substituteWelcomePlaceholders(tmpl.BodyHTML, vals)

	_, domain := splitLocalDomain(recipient)
	messageID := fmt.Sprintf("welcome-%d-%d@setjoin", userID, time.Now().UnixNano())
	rawRef := fmt.Sprintf("system:welcome:%d", userID)

	_, err := pool.Exec(ctx,
		`SELECT deliver(
		   $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
		   FALSE, $15, $16, $17, $18, $19, $20)`,
		rawRef,            // p_raw_ref
		messageID,         // p_message_id
		"noreply@"+domain, // p_from_addr
		"SetJoin Team",    // p_from_name
		recipient,         // p_rcpt_addr
		fmt.Sprintf(`[{"email":%q,"name":""}]`, recipient), // p_to_addrs
		"[]",                               // p_cc_addrs
		"[]",                               // p_bcc_addrs
		subject,                            // p_subject
		"",                                 // p_in_reply_to
		"",                                 // p_references_hdr
		bodyText,                           // p_body_text
		bodyHTML,                           // p_body_html
		int64(len(bodyText)+len(bodyHTML)), // p_size_bytes
		// p_has_attachments FALSE (literal above)
		time.Now(), // p_sent_at
		"none",     // p_spf_result
		"none",     // p_dkim_result
		"none",     // p_dmarc_result
		0.0,        // p_spam_score
		"{}",       // p_spam_headers
	)
	return err
}
