package user

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/pgxutil"
)

// insertTestQuarantine inserts a quarantined_messages row backed by a real
// message in the given mailbox and returns the quarantine row id. Cleans up
// after the test.
func insertTestQuarantine(t *testing.T, pool *pgxpool.Pool, mailboxID int64) (quarantineID, msgID int64) {
	t.Helper()
	ctx := context.Background()

	messageID := "quar-msg-" + randomSuffix(t) + "@setjoin.test"
	msgID = insertTestMessage(t, pool, mailboxID, messageID, "sender@setjoin.test", time.Now())
	// Mirror delivery: the quarantined copy carries the Quarantined tag.
	tagMessageLocation(t, pool, msgID, mailboxID, "Quarantined")

	err := pool.QueryRow(ctx,
		`INSERT INTO quarantined_messages (message_id, mailbox_id, original_tag, reason, reason_type)
		 VALUES ($1, $2, 'Inbox', 'test quarantine', 'admin')
		 RETURNING id`,
		msgID, mailboxID,
	).Scan(&quarantineID)
	if err != nil {
		t.Fatalf("insertTestQuarantine: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM quarantined_messages WHERE id = $1`, quarantineID)
	})
	return quarantineID, msgID
}

// TestQuarantineReleaseOwn asserts a user can release their own quarantined
// message: the UPDATE affects the row, released_at/released_by are stamped, and
// the response is the released status.
func TestQuarantineReleaseOwn(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := NewQuarantineHandler(pool, pgxutil.WorkerPool{Pool: pool}, testLogger())

	ctx := context.Background()
	userID := createTestUser(t, pool)
	mailboxID := ensureTestMailbox(t, pool, userID)
	quarantineID, _ := insertTestQuarantine(t, pool, mailboxID)

	claims := &auth.Claims{UserID: userID, Email: "owner@setjoin.test", Type: auth.TypeAccess}
	idStr := strconv.FormatInt(quarantineID, 10)
	req := httptest.NewRequest(http.MethodPost, "/quarantine/"+idStr+"/release", nil)
	req.SetPathValue("id", idStr)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.Release(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Release returned %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["status"] != "released" {
		t.Errorf("status = %q, want \"released\"", resp["status"])
	}

	// The mutating UPDATE must have stamped released_at + released_by.
	var releasedBy *int64
	var releasedAt *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT released_at, released_by FROM quarantined_messages WHERE id = $1`, quarantineID,
	).Scan(&releasedAt, &releasedBy); err != nil {
		t.Fatalf("query released row: %v", err)
	}
	if releasedAt == nil {
		t.Error("released_at was not stamped")
	}
	if releasedBy == nil || *releasedBy != userID {
		t.Errorf("released_by = %v, want %d", releasedBy, userID)
	}
}

// TestQuarantineReleaseForeign asserts a user CANNOT release another user's
// quarantine row. The ownership predicate folded into the mutating UPDATE makes
// it affect 0 rows → the handler returns 403/404 and the victim's row is left
// untouched (no released_at / released_by written). Before the R3 fix the
// UPDATE's WHERE omitted ownership, so a forged id could release a foreign row.
func TestQuarantineReleaseForeign(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := NewQuarantineHandler(pool, pgxutil.WorkerPool{Pool: pool}, testLogger())

	ctx := context.Background()

	// Victim owns the quarantine row.
	victimID := createTestUser(t, pool)
	victimMailbox := ensureTestMailbox(t, pool, victimID)
	quarantineID, _ := insertTestQuarantine(t, pool, victimMailbox)

	// Attacker is a different authenticated user.
	attackerID := createTestUser(t, pool)
	ensureTestMailbox(t, pool, attackerID)

	claims := &auth.Claims{UserID: attackerID, Email: "attacker@setjoin.test", Type: auth.TypeAccess}
	idStr := strconv.FormatInt(quarantineID, 10)
	req := httptest.NewRequest(http.MethodPost, "/quarantine/"+idStr+"/release", nil)
	req.SetPathValue("id", idStr)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.Release(rec, req)

	if rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
		t.Fatalf("foreign release returned %d, want 403 or 404: %s", rec.Code, rec.Body.String())
	}

	// The victim's row must be untouched — no released_at, no released_by.
	var releasedAt *time.Time
	var releasedBy *int64
	if err := pool.QueryRow(ctx,
		`SELECT released_at, released_by FROM quarantined_messages WHERE id = $1`, quarantineID,
	).Scan(&releasedAt, &releasedBy); err != nil {
		t.Fatalf("query victim row: %v", err)
	}
	if releasedAt != nil {
		t.Error("victim's row was released by a foreign user (released_at stamped)")
	}
	if releasedBy != nil {
		t.Errorf("victim's row released_by was set to %v by a foreign user", releasedBy)
	}
}
