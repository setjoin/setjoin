package user

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// OwnedMessage carries the identity + blob ref of a message proven to belong to
// the authenticated user. The surrogate (MessagePK, ReceivedAt) is the real key;
// MessageID is the non-unique RFC header value, for display/correlation only.
type OwnedMessage struct {
	RawRef     string
	MailboxID  int64
	MessagePK  int64
	ReceivedAt time.Time
	MessageID  string
	Subject    string
}

// ResolveOwnedMessage enforces ownership via the mailbox->user join (R1) on the
// worker pool and returns the message's identity. Returns pgx.ErrNoRows when the
// message does not exist or is not owned by userID.
//
// This is THE shared ownership-resolve for a message-by-id: prefer it over an
// inline `FROM messages m JOIN mailboxes mb … WHERE m.id=$1 AND mb.user_id=$2`
// whenever the columns you need are a subset of OwnedMessage (mailbox_id,
// received_at, message_id, subject, raw_ref). Sites that read OTHER columns in
// the same ownership-scoped statement (recall's from_addr, newsletter's
// list_unsubscribe) keep their own read INLINE on purpose — the RLS-coverage +
// gateway-ownership guards machine-verify each `messages`-touching literal
// against its construction pool, so folding those reads behind a shared SQL
// fragment would blind both guards. Different predicate entirely (mailbox-keyed,
// cross-mailbox list, attachment/quarantine join) → also stays inline.
func ResolveOwnedMessage(ctx context.Context, pool *pgxpool.Pool, emailID, userID int64) (OwnedMessage, error) {
	var om OwnedMessage
	err := pool.QueryRow(ctx,
		`SELECT m.raw_ref, m.mailbox_id, m.id, m.received_at,
		        COALESCE(m.message_id, ''), COALESCE(m.subject, 'message')
		   FROM messages m
		   JOIN mailboxes mb ON mb.id = m.mailbox_id
		  WHERE m.id = $1 AND mb.user_id = $2`,
		emailID, userID,
	).Scan(&om.RawRef, &om.MailboxID, &om.MessagePK, &om.ReceivedAt, &om.MessageID, &om.Subject)
	return om, err
}
