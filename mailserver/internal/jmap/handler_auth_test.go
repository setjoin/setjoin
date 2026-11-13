package jmap

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// testPoolDB returns a pool connected to the DB_DSN database.
// Skips the test if DB_DSN is not set.
func testPoolDB(t *testing.T) *pgxpool.Pool {
	return testsupport.OpenTestPool(t)
}

func testLoggerDB(_ *testing.T) *slog.Logger {
	return testsupport.TestLogger()
}

func randomSuffixDB(_ *testing.T) string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic("rand.Read failed: " + err.Error())
	}
	return fmt.Sprintf("%x", b)
}

// insertTestUserWithMailbox creates a user and a primary mailbox.
// If divergeID is true, dummy mailboxes are inserted first so user.id != mailbox.id.
// Returns (domainID, userID, mailboxID).
func insertTestUserWithMailbox(t *testing.T, pool *pgxpool.Pool, divergeID bool) (domainID, userID, mailboxID int64) {
	t.Helper()
	ctx := context.Background()

	suffix := randomSuffixDB(t)
	domainName := "test-jmap-" + suffix + ".example.com"
	err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ($1) RETURNING id`,
		domainName,
	).Scan(&domainID)
	if err != nil {
		t.Fatalf("insertTestUserWithMailbox: insert domain: %v", err)
	}

	// Advance mailboxes sequence to create intentional ID divergence.
	if divergeID {
		for i := 0; i < 3; i++ {
			dummyEmail := fmt.Sprintf("dummy-%s-%d@%s", suffix, i, domainName)
			_, err := pool.Exec(ctx,
				`INSERT INTO mailboxes (user_id, domain_id, email, type, display_name, is_primary)
				 VALUES (NULL, $1, $2, 'personal', 'Dummy', FALSE)`,
				domainID, dummyEmail,
			)
			if err != nil {
				t.Fatalf("insertTestUserWithMailbox: insert dummy mailbox %d: %v", i, err)
			}
		}
	}

	// Create user.
	username := "testuser-" + suffix
	userEmail := username + "@" + domainName
	err = pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		username, domainID, userEmail, "Test User", "$2a$10$placeholder",
	).Scan(&userID)
	if err != nil {
		t.Fatalf("insertTestUserWithMailbox: insert user: %v", err)
	}

	// Create primary mailbox.
	err = pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, type, display_name, is_primary)
		 VALUES ($1, $2, $3, 'personal', $4, TRUE) RETURNING id`,
		userID, domainID, userEmail, "Test User",
	).Scan(&mailboxID)
	if err != nil {
		t.Fatalf("insertTestUserWithMailbox: insert primary mailbox: %v", err)
	}

	// Clean up at end of test.
	t.Cleanup(func() {
		// Delete in order respecting foreign keys.
		pool.Exec(context.Background(), `DELETE FROM mailboxes WHERE id = $1`, mailboxID)
		pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
		pool.Exec(context.Background(), `DELETE FROM domains WHERE id = $1`, domainID)
	})

	return domainID, userID, mailboxID
}

// ── Unit tests (nil pool, backward-compat fallback) ──

func TestParseAccountID_EmptyAccountId(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	// parseAccountID is a method now, call via h.
	accountID, errResp := h.parseAccountID(context.Background(), "", 1)
	if errResp == nil {
		t.Fatal("expected error for empty accountId, got nil")
	}
	if accountID != 0 {
		t.Errorf("expected 0 accountID, got %d", accountID)
	}
	var e Error
	if err := json.Unmarshal(errResp, &e); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if e.Type != "accountNotFound" {
		t.Errorf("expected accountNotFound, got %s", e.Type)
	}
}

func TestParseAccountID_InvalidAccountId(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	accountID, errResp := h.parseAccountID(context.Background(), "not-a-number", 1)
	if errResp == nil {
		t.Fatal("expected error for invalid accountId, got nil")
	}
	if accountID != 0 {
		t.Errorf("expected 0 accountID, got %d", accountID)
	}
	var e Error
	if err := json.Unmarshal(errResp, &e); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if e.Type != "accountNotFound" {
		t.Errorf("expected accountNotFound, got %s", e.Type)
	}
}

func TestParseAccountID_NegativeAccountId(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	accountID, errResp := h.parseAccountID(context.Background(), "-1", 1)
	if errResp == nil {
		t.Fatal("expected error for negative accountId, got nil")
	}
	if accountID != 0 {
		t.Errorf("expected 0 accountID, got %d", accountID)
	}
}

func TestParseAccountID_NilPool_FallbackMatch(t *testing.T) {
	// When pool is nil, fall back to comparing accountID against userID.
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	accountID, errResp := h.parseAccountID(context.Background(), "42", 42)
	if errResp != nil {
		t.Fatalf("expected success for matching ids (fallback path), got: %s", string(errResp))
	}
	if accountID != 42 {
		t.Errorf("expected 42, got %d", accountID)
	}
}

func TestParseAccountID_NilPool_FallbackMismatch(t *testing.T) {
	// When pool is nil, fall back to comparing accountID against userID.
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	_, errResp := h.parseAccountID(context.Background(), "99", 42)
	if errResp == nil {
		t.Fatal("expected error for mismatched ids (fallback path)")
	}
}

// ── Integration tests (real pool, primary mailbox resolution) ──

func TestParseAccountID_MatchesPrimaryMailbox(t *testing.T) {
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))

	_, userID, mailboxID := insertTestUserWithMailbox(t, pool, false /* no divergence */)

	// Request the primary mailbox id — must succeed.
	reqID := strconv.FormatInt(mailboxID, 10)
	resolved, errResp := h.parseAccountID(context.Background(), reqID, userID)
	if errResp != nil {
		t.Fatalf("parseAccountID failed for primary mailbox %d, user %d: %s",
			mailboxID, userID, string(errResp))
	}
	if resolved != mailboxID {
		t.Errorf("expected resolved id %d, got %d", mailboxID, resolved)
	}
}

func TestParseAccountID_RejectsNonPrimaryMailbox(t *testing.T) {
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))

	// Create user A with primary mailbox.
	_, userIDA, mailboxIDA := insertTestUserWithMailbox(t, pool, false)
	// Create user B with primary mailbox.
	_, userIDB, _ := insertTestUserWithMailbox(t, pool, false)

	_ = userIDB // user B is separate

	// User A trying to access user B's primary mailbox — must fail.
	reqID := strconv.FormatInt(mailboxIDA+1, 10) // a nonexistent/non-primary mailbox for user A
	_, errResp := h.parseAccountID(context.Background(), reqID, userIDA)
	if errResp == nil {
		t.Fatal("expected error accessing non-primary mailbox, got nil")
	}
	var e Error
	if err := json.Unmarshal(errResp, &e); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if e.Type != "accountNotFound" {
		t.Errorf("expected accountNotFound, got %s", e.Type)
	}
}

func TestParseAccountID_RejectsUserIDWhenDiverged(t *testing.T) {
	// The critical bug fix: when user.id != primary mailbox.id (divergence),
	// requesting the user's own id as accountId must be REJECTED.
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))

	_, userID, mailboxID := insertTestUserWithMailbox(t, pool, true /* diverge: userID != mailboxID */)

	if userID == mailboxID {
		t.Skipf("sequences aligned (userID=%d, mailboxID=%d) — divergence not possible; test skipped",
			userID, mailboxID)
	}

	// Requesting userID as accountId should fail — it's not the primary mailbox.
	reqID := strconv.FormatInt(userID, 10)
	_, errResp := h.parseAccountID(context.Background(), reqID, userID)
	if errResp == nil {
		t.Errorf("BUG STILL PRESENT: requesting userID=%d as accountId succeeded, "+
			"but primary mailbox is %d — divergence not checked", userID, mailboxID)
	}

	// Requesting primary mailbox ID should still succeed.
	reqPrimary := strconv.FormatInt(mailboxID, 10)
	resolved, errResp := h.parseAccountID(context.Background(), reqPrimary, userID)
	if errResp != nil {
		t.Fatalf("parseAccountID with primary mailbox %d, user %d: %s",
			mailboxID, userID, string(errResp))
	}
	if resolved != mailboxID {
		t.Errorf("expected %d, got %d", mailboxID, resolved)
	}
}

func TestParseAccountID_NoPrimaryMailbox(t *testing.T) {
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))

	// Create a user without a primary mailbox.
	suffix := randomSuffixDB(t)
	domainName := "test-jmap-noprimary-" + suffix + ".example.com"
	ctx := context.Background()
	var domainID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ($1) RETURNING id`, domainName,
	).Scan(&domainID)
	if err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	username := "testuser-noprimary-" + suffix
	userEmail := username + "@" + domainName
	var userID int64
	err = pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		username, domainID, userEmail, "Test User", "$2a$10$placeholder",
	).Scan(&userID)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
		pool.Exec(context.Background(), `DELETE FROM domains WHERE id = $1`, domainID)
	})

	// Any accountId should fail because user has no primary mailbox.
	_, errResp := h.parseAccountID(context.Background(), "1", userID)
	if errResp == nil {
		t.Fatal("expected error when user has no primary mailbox, got nil")
	}
	var e Error
	if err := json.Unmarshal(errResp, &e); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if e.Type != "accountNotFound" {
		t.Errorf("expected accountNotFound, got %s", e.Type)
	}
}
