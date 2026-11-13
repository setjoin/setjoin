package jmap

import (
	"context"
	"testing"
)

// TestSessionStateReflectsNonEmailChanges pins arch A4: sessionState (RFC 8620
// §2) must change when ANY account state changes, not just email. It was derived
// from jmap_email_state alone, so a folder rename / contact / calendar / task
// edit left sessionState unchanged and a session-caching client never re-fetched.
func TestSessionStateReflectsNonEmailChanges(t *testing.T) {
	pool := testPoolDB(t)
	_, userID, mailboxID := insertTestUserWithMailbox(t, pool, false)
	h := &JMAPHandler{pool: pool, logger: testLoggerDB(t)}
	ctx := context.Background()

	before := h.GetSessionState(ctx, userID)
	if before == "0" {
		t.Fatalf("GetSessionState returned the error sentinel %q", before)
	}

	// Bump a NON-email counter — a folder create/rename bumps jmap_mailbox_state,
	// never jmap_email_state.
	if _, err := pool.Exec(ctx,
		`UPDATE mailboxes SET jmap_mailbox_state = jmap_mailbox_state + 1 WHERE id = $1`,
		mailboxID,
	); err != nil {
		t.Fatalf("bump mailbox state: %v", err)
	}

	after := h.GetSessionState(ctx, userID)
	if before == after {
		t.Errorf("sessionState unchanged after a non-email (mailbox) state bump: %q — must change on ANY account state change", before)
	}
}
