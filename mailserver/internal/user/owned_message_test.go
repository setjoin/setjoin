package user

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestResolveOwnedMessage_NotOwnedIsErrNoRows(t *testing.T) {
	pool := testPool(t) // existing helper; skips if no test DB
	_, err := ResolveOwnedMessage(context.Background(), pool, 999999, 1)
	if err != pgx.ErrNoRows {
		t.Fatalf("want ErrNoRows for non-owned, got %v", err)
	}
}

// TestResolveOwnedMessage_OtherUsersMessageIsErrNoRows is the focused ownership
// guard for the shared helper that focus/trace/raw-download route through. A real
// message owned by user A must be invisible to user B: the mailbox->user join
// (mb.user_id = $2) yields ErrNoRows, NOT the row. This distinguishes ownership
// from mere existence (the sibling test above uses a nonexistent id, which
// ErrNoRows regardless) — drop the `AND mb.user_id = $2` scope and B resolves A's
// message, failing here. Also asserts the legitimate owner still resolves it.
func TestResolveOwnedMessage_OtherUsersMessageIsErrNoRows(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	ctx := context.Background()

	ownerID := createTestUser(t, pool)
	ownerMailbox := ensureTestMailbox(t, pool, ownerID)
	msgID := insertTestMessage(t, pool, ownerMailbox,
		"owned-"+randomSuffix(t)+"@setjoin.test", "s@setjoin.test", time.Now())
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM messages WHERE id = $1`, msgID) })

	otherID := createTestUser(t, pool)

	// The non-owner must NOT be able to resolve the owner's message.
	if _, err := ResolveOwnedMessage(ctx, pool, msgID, otherID); err != pgx.ErrNoRows {
		t.Fatalf("non-owner resolved another user's message: want ErrNoRows, got %v", err)
	}

	// The owner still resolves it, with the correct mailbox (regression floor).
	om, err := ResolveOwnedMessage(ctx, pool, msgID, ownerID)
	if err != nil {
		t.Fatalf("owner failed to resolve own message: %v", err)
	}
	if om.MailboxID != ownerMailbox || om.MessagePK != msgID {
		t.Fatalf("owner resolve mismatch: got mailbox=%d pk=%d, want mailbox=%d pk=%d",
			om.MailboxID, om.MessagePK, ownerMailbox, msgID)
	}
}
