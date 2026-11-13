package ldaputil

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"

	"setjoin.com/shared/testsupport"
)

func randSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return fmt.Sprintf("%x", b)
}

// TestDisableUserClearsAccountAndSessions proves DisableUser attempts all three
// deprovisioning writes: flips users.enabled to FALSE and clears the user's
// sessions + ws_subscriptions. (Error propagation is proven by code review — the
// seam mirrors the already-tested AD/LDAP disable paths — this covers the write
// contract.)
func TestDisableUserClearsAccountAndSessions(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "ldaputil-dis-" + suffix + ".local"

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	email := "dis-" + suffix + "@" + domain
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash, enabled)
		 VALUES ($1, lower($2), 'Disable Test', $3, '$2a$10$placeholder', TRUE)
		 RETURNING id`,
		"dis-"+suffix, email, domainID,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM sessions WHERE user_id = $1`, userID)
		pool.Exec(c, `DELETE FROM ws_subscriptions WHERE user_id = $1`, userID)
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, userID)
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID)
	})

	if _, err := pool.Exec(ctx,
		`INSERT INTO sessions (user_id, expires_at) VALUES ($1, now() + interval '1 day')`, userID,
	); err != nil {
		t.Fatalf("insert session: %v", err)
	}

	if err := DisableUser(ctx, pool, userID); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}

	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM users WHERE id = $1`, userID).Scan(&enabled); err != nil {
		t.Fatalf("read enabled: %v", err)
	}
	if enabled {
		t.Error("DisableUser left users.enabled = TRUE")
	}

	var sessionCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id = $1`, userID).Scan(&sessionCount); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessionCount != 0 {
		t.Errorf("DisableUser left %d live session(s), want 0", sessionCount)
	}
}
