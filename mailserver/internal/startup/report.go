package startup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SendRecoveryReport sends an email to the first admin user if startup_recovery
// detected and fixed any inconsistent state.
func SendRecoveryReport(ctx context.Context, pool *pgxpool.Pool, result json.RawMessage, logger *slog.Logger) {
	var summary struct {
		ResetOutboundQueue   int    `json:"reset_outbound_queue"`
		CleanedSessions      int    `json:"cleaned_sessions"`
		RepairedFolderCounts int    `json:"repaired_folder_counts"`
		RecoveredAt          string `json:"recovered_at"`
	}
	if err := json.Unmarshal(result, &summary); err != nil {
		logger.Warn("startup recovery report: failed to parse result", "error", err)
		return
	}

	if summary.ResetOutboundQueue == 0 && summary.RepairedFolderCounts == 0 {
		return // nothing to report
	}

	// Find first admin user with a primary mailbox
	var adminUserID int64
	var adminMailboxID int64
	var adminEmail string
	err := pool.QueryRow(ctx, `
		SELECT u.id, mb.id, u.email
		FROM users u
		JOIN mailboxes mb ON mb.user_id = u.id AND mb.is_primary = TRUE
		WHERE u.is_local_admin = TRUE AND u.enabled = TRUE
		ORDER BY u.id
		LIMIT 1
	`).Scan(&adminUserID, &adminMailboxID, &adminEmail)
	if err != nil {
		logger.Warn("startup recovery report: no admin user found", "error", err)
		return
	}

	subject := "Mailserver Startup Recovery Report"
	bodyText := fmt.Sprintf(
		"Startup recovery detected inconsistent state and performed repairs:\n\n"+
			"- Reset outbound queue items: %d\n"+
			"- Repaired folder counters: %d\n"+
			"- Recovered at: %s\n\n"+
			"This usually indicates an unclean shutdown or crash. "+
			"Please review crash_events for details.\n",
		summary.ResetOutboundQueue,
		summary.RepairedFolderCounts,
		summary.RecoveredAt,
	)
	bodyHTML := fmt.Sprintf(
		"<p>Startup recovery detected inconsistent state and performed repairs:</p>"+
			"<ul>"+
			"<li>Reset outbound queue items: %d</li>"+
			"<li>Repaired folder counters: %d</li>"+
			"<li>Recovered at: %s</li>"+
			"</ul>"+
			"<p>This usually indicates an unclean shutdown or crash. "+
			"Please review crash_events for details.</p>",
		summary.ResetOutboundQueue,
		summary.RepairedFolderCounts,
		summary.RecoveredAt,
	)

	messageID := fmt.Sprintf("<%s@mailserver>", randomID())

	_, err = pool.Exec(ctx,
		`SELECT send($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		adminUserID, adminMailboxID, "internal://startup-report", messageID, adminEmail,
		func() []byte { b, _ := json.Marshal([]map[string]string{{"email": adminEmail}}); return b }(), []byte("[]"), []byte("[]"),
		subject, "", "",
		bodyText, bodyHTML,
		int64(len(bodyText)), false, nil,
	)
	if err != nil {
		logger.Error("startup recovery report: failed to send email", "error", err)
		return
	}

	logger.Info("startup recovery report sent", "to", adminEmail)
}

func randomID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", b)
	}
	return hex.EncodeToString(b)
}
