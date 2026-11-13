package delivery

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

// queryLatestRows runs the binding DISTINCT-ON latest-row query (sql bound to
// args) and reduces it to ONE LatestRow per recipient — the read contract
// documented on ReadLatestPerRecipient. Shared by the mailbox-scoped and the
// explicitly-named admin variant, whose SQL differs only in the mailbox_id
// predicate; the scan, the Warn-and-degrade failure semantics, and the log
// wording are byte-identical to the pre-helper behavior.
func queryLatestRows(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger, messagePK int64, sql string, args ...any) map[string]LatestRow {
	out := map[string]LatestRow{}
	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		log.Warn("delivery_attempts latest read failed", "messagePK", messagePK, "error", err)
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var email string
		var lr LatestRow
		if err := rows.Scan(&email, &lr.MxHost, &lr.Code, &lr.Text, &lr.At, &lr.Outcome); err != nil {
			log.Warn("delivery_attempts latest scan failed", "messagePK", messagePK, "error", err)
			return out
		}
		out[email] = lr
	}
	return out
}

// queryAttemptHistory runs the full per-recipient append-only history query
// (sql bound to args), ordered chronologically by attempt_number ASC. Shared by
// the mailbox-scoped and admin variants of ReadAttemptHistory with identical
// scan and Warn-and-degrade semantics.
func queryAttemptHistory(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger, messagePK int64, sql string, args ...any) map[string][]Attempt {
	out := map[string][]Attempt{}
	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		log.Warn("delivery_attempts history read failed", "messagePK", messagePK, "error", err)
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var email string
		var a Attempt
		if err := rows.Scan(&email, &a.N, &a.At, &a.MxHost, &a.SmtpCode, &a.SmtpText, &a.Outcome, &a.TLS); err != nil {
			log.Warn("delivery_attempts history scan failed", "messagePK", messagePK, "error", err)
			return out
		}
		out[email] = append(out[email], a)
	}
	return out
}

// ReadLatestPerRecipient reduces delivery_attempts to ONE current row per
// recipient — the BINDING DISTINCT-ON read contract. NEVER COUNT/SUM the raw
// append-only rows (that inherits the per-attempt over-count); the DISTINCT-ON
// reduces to the latest attempt per recipient before any status/count derivation.
//
// mailboxID is REQUIRED: nil refuses with an empty result and a Warn — the old
// nil-means-cross-mailbox convention silently widened a user read to global
// scope on a future refactor (D-MAILSERVER-INTERNAL-DELIVERY-001). Sanctioned
// cross-mailbox reads go through the explicitly-named ReadLatestPerRecipientAdmin.
//
// Warn-and-degrade: a query/scan error returns the partial/empty map, never a
// panic.
func ReadLatestPerRecipient(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger, messagePK int64, mailboxID *int64) map[string]LatestRow {
	if mailboxID == nil {
		log.Warn("delivery read refused: nil mailboxID would widen to cross-mailbox scope — use ReadLatestPerRecipientAdmin for sanctioned admin reads")
		return map[string]LatestRow{}
	}
	sql := `SELECT DISTINCT ON (recipient_email)
	               recipient_email, mx_host, smtp_code, smtp_text, attempted_at, outcome
	          FROM delivery_attempts
	         WHERE message_pk = $1 AND mailbox_id = $2`
	sql += ` ORDER BY recipient_email, attempt_number DESC`

	return queryLatestRows(ctx, pool, log, messagePK, sql, messagePK, *mailboxID)
}

// ReadLatestPerRecipientAdmin is the EXPLICITLY-named cross-mailbox variant for
// RBAC-gated admin surfaces (D-MAILSERVER-INTERNAL-DELIVERY-001): every use is
// Warn-logged so audits can distinguish sanctioned global reads from scoped
// user reads. The SQL is otherwise identical to ReadLatestPerRecipient.
func ReadLatestPerRecipientAdmin(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger, messagePK int64) map[string]LatestRow {
	log.Warn("delivery read: cross-mailbox admin scope used",
		"messagePK", messagePK, "scope", "cross-mailbox/admin")
	sql := `SELECT DISTINCT ON (recipient_email)
	               recipient_email, mx_host, smtp_code, smtp_text, attempted_at, outcome
	          FROM delivery_attempts
	         WHERE message_pk = $1
	         ORDER BY recipient_email, attempt_number DESC`

	return queryLatestRows(ctx, pool, log, messagePK, sql, messagePK)
}

// ReadAttemptHistory returns the full per-recipient attempt history (every
// append-only row), ordered chronologically by attempt_number ASC.
//
// mailboxID is REQUIRED: nil refuses with an empty result and a Warn (see
// ReadLatestPerRecipient for the R1 rationale). Sanctioned cross-mailbox reads
// go through ReadAttemptHistoryAdmin. Warn-and-degrade on error.
func ReadAttemptHistory(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger, messagePK int64, mailboxID *int64) map[string][]Attempt {
	if mailboxID == nil {
		log.Warn("delivery history read refused: nil mailboxID would widen to cross-mailbox scope — use ReadAttemptHistoryAdmin for sanctioned admin reads")
		return map[string][]Attempt{}
	}
	sql := `SELECT recipient_email, attempt_number, attempted_at, mx_host, smtp_code, smtp_text, outcome, tls
	          FROM delivery_attempts
	         WHERE message_pk = $1 AND mailbox_id = $2
	         ORDER BY recipient_email, attempt_number ASC`

	return queryAttemptHistory(ctx, pool, log, messagePK, sql, messagePK, *mailboxID)
}

// ReadAttemptHistoryAdmin is the EXPLICITLY-named cross-mailbox variant for
// RBAC-gated admin surfaces; every use is Warn-logged (see
// ReadLatestPerRecipientAdmin).
func ReadAttemptHistoryAdmin(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger, messagePK int64) map[string][]Attempt {
	log.Warn("delivery history read: cross-mailbox admin scope used",
		"messagePK", messagePK, "scope", "cross-mailbox/admin")
	sql := `SELECT recipient_email, attempt_number, attempted_at, mx_host, smtp_code, smtp_text, outcome, tls
	          FROM delivery_attempts
	         WHERE message_pk = $1
	         ORDER BY recipient_email, attempt_number ASC`

	return queryAttemptHistory(ctx, pool, log, messagePK, sql, messagePK)
}
