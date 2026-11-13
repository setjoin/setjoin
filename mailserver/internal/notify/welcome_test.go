package notify

import (
	"context"
	"io"
	"log/slog"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/testsupport"
)

// testPool connects to the test database, skipping when DB_DSN is unset.
// Mirrors the repo's per-area convention (admin's mailboxTestPool delegates to
// the same testsupport.OpenTestPool helper).
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return testsupport.OpenTestPool(t)
}

func TestWelcomeRecipient(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	// Provision a throwaway user via the canonical reducer.
	var userID int64
	err := pool.QueryRow(ctx,
		`SELECT (provision_account('wr@welcome.test', 'Wendy Recipient')->>'user_id')::bigint`).Scan(&userID)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID) })

	vals, rcpt, err := welcomeRecipient(ctx, pool, userID)
	if err != nil {
		t.Fatalf("welcomeRecipient: %v", err)
	}
	if rcpt != "wr@welcome.test" {
		t.Errorf("recipient = %q, want wr@welcome.test", rcpt)
	}
	if vals["DisplayName"] != "Wendy Recipient" {
		t.Errorf("DisplayName = %q", vals["DisplayName"])
	}
	if vals["Email"] != "wr@welcome.test" || vals["Username"] != "wr" {
		t.Errorf("Email/Username wrong: %+v", vals)
	}
	if vals["OrgName"] != "welcome.test" || vals["WebmailURL"] != "https://welcome.test" {
		t.Errorf("OrgName/WebmailURL wrong: %+v", vals)
	}
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func getWelcomeRaw(t *testing.T, pool *pgxpool.Pool) []byte {
	t.Helper()
	var raw []byte
	if err := pool.QueryRow(context.Background(), `SELECT get_system_config('welcome_email')`).Scan(&raw); err != nil {
		t.Fatalf("getWelcomeRaw: %v", err)
	}
	return raw
}

// countWelcomes returns how many welcome messages exist for the user's mailbox.
func countWelcomes(t *testing.T, pool *pgxpool.Pool, userID int64) int {
	t.Helper()
	var n int
	err := pool.QueryRow(context.Background(),
		`SELECT count(*)::int FROM messages m
		   JOIN mailboxes mb ON mb.id = m.mailbox_id
		  WHERE mb.user_id = $1 AND m.raw_ref = $2`,
		userID, "system:welcome:"+itoa(userID)).Scan(&n)
	if err != nil {
		t.Fatalf("countWelcomes: %v", err)
	}
	return n
}

func provisionUser(t *testing.T, pool *pgxpool.Pool, email, name string) int64 {
	t.Helper()
	var id int64
	if err := pool.QueryRow(context.Background(),
		`SELECT (provision_account($1, $2)->>'user_id')::bigint`, email, name).Scan(&id); err != nil {
		t.Fatalf("provision: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, id) })
	return id
}

func TestSendWelcomeEmail_DeliversOnceWhenEnabled(t *testing.T) {
	pool := testPool(t)
	id := provisionUser(t, pool, "send1@welcome.test", "Send One")

	SendWelcomeEmail(context.Background(), pool, id, "en", discardLogger())
	if got := countWelcomes(t, pool, id); got != 1 {
		t.Fatalf("after first send, welcome count = %d, want 1", got)
	}
	// Idempotency: a second auto-send must not duplicate.
	SendWelcomeEmail(context.Background(), pool, id, "en", discardLogger())
	if got := countWelcomes(t, pool, id); got != 1 {
		t.Fatalf("after second send, welcome count = %d, want 1 (idempotent)", got)
	}
}

func TestSendWelcomeEmail_NoOpWhenDisabled(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	// Disable the feature (rolled back by cleanup).
	prev := getWelcomeRaw(t, pool)
	_, _ = pool.Exec(ctx, `SELECT set_system_config('welcome_email', jsonb_set($1::jsonb,'{enabled}','false'), false, NULL)`, prev)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `SELECT set_system_config('welcome_email', $1::jsonb, false, NULL)`, prev)
	})

	id := provisionUser(t, pool, "send2@welcome.test", "Send Two")
	SendWelcomeEmail(ctx, pool, id, "en", discardLogger())
	if got := countWelcomes(t, pool, id); got != 0 {
		t.Fatalf("disabled config should send nothing, count = %d", got)
	}
}

func TestSendWelcomeEmailWithConfig_DeliversExplicitContent(t *testing.T) {
	pool := testPool(t)
	id := provisionUser(t, pool, "test3@welcome.test", "Test Three")
	tmpl := WelcomeLocale{Subject: "Preview for {{DisplayName}}", BodyText: "Hi {{Email}}", BodyHTML: ""}
	if err := SendWelcomeEmailWithConfig(context.Background(), pool, id, "en", tmpl, discardLogger()); err != nil {
		t.Fatalf("WithConfig: %v", err)
	}
	var subject string
	_ = pool.QueryRow(context.Background(),
		`SELECT subject FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id
		  WHERE mb.user_id=$1 ORDER BY m.id DESC LIMIT 1`, id).Scan(&subject)
	if subject != "Preview for Test Three" {
		t.Errorf("subject = %q, want substituted", subject)
	}
}
