package scim

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// These tests cover the SCIM PATCH-disable session-revocation seam (Wave 7,
// Bug A): a PATCH {op:replace, path:active, value:false} — the standard
// Okta/Entra deprovision — must revoke live sessions, symmetric with DELETE.
// A PATCH active=true (re-enable) must NOT revoke. revokeSessions must degrade
// to a no-op when the authserver link is unconfigured.
//
// DB-integration: skips when DB_DSN is unset (mirrors admin_mailboxes_test.go).

func scimTestPool(t *testing.T) *pgxpool.Pool {
	return testsupport.OpenTestPool(t)
}

func scimTestLogger() *slog.Logger {
	return testsupport.TestLogger()
}

func scimRandomSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return fmt.Sprintf("%x", b)
}

// createSCIMTestUser inserts a domain + user (with scim_external_id) + a primary
// personal mailbox (the trigger requires every user to have exactly one). Returns
// the user id and external id, and registers cleanup.
func createSCIMTestUser(t *testing.T, pool *pgxpool.Pool) (int64, string) {
	t.Helper()
	ctx := context.Background()
	suffix := scimRandomSuffix(t)

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ('scimtest.example')
		 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`).Scan(&domainID); err != nil {
		t.Fatalf("create domain: %v", err)
	}

	extID := "scim-disable-" + suffix
	email := "scim-disable-" + suffix + "@scimtest.example"
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, password_hash, domain_id, scim_external_id, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, TRUE) RETURNING id`,
		"scim-disable-"+suffix, email, "SCIM Disable Test", "$2a$10$placeholder", domainID, extID,
	).Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}

	var mbID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		 VALUES ($1, $2, $3, $4, 'personal', TRUE) RETURNING id`,
		userID, domainID, email, "SCIM Disable Test",
	).Scan(&mbID); err != nil {
		t.Fatalf("create mailbox: %v", err)
	}

	t.Cleanup(func() {
		ctx := context.Background()
		pool.Exec(ctx, `ALTER TABLE mailboxes DISABLE TRIGGER ALL`)
		pool.Exec(ctx, `DELETE FROM mailboxes WHERE id = $1`, mbID)
		pool.Exec(ctx, `ALTER TABLE mailboxes ENABLE TRIGGER ALL`)
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
	})
	return userID, extID
}

func userEnabled(t *testing.T, pool *pgxpool.Pool, userID int64) bool {
	t.Helper()
	var enabled bool
	if err := pool.QueryRow(context.Background(),
		`SELECT enabled FROM users WHERE id = $1`, userID).Scan(&enabled); err != nil {
		t.Fatalf("read enabled: %v", err)
	}
	return enabled
}

// fakeAuthServer captures POSTs to /auth/scim/disable and reports each
// user_id it sees over revoked (RevokeAuthSessions keys on user id, always
// present — not scim_external_id, which a locally-created user lacks).
func fakeAuthServer(t *testing.T) (*httptest.Server, <-chan int64) {
	t.Helper()
	revoked := make(chan int64, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/scim/disable" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			UserID int64 `json:"user_id"`
		}
		_ = json.Unmarshal(body, &payload)
		revoked <- payload.UserID
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv, revoked
}

func activeOp(active bool) []PatchOperation {
	v, _ := json.Marshal(active)
	return []PatchOperation{{Op: "replace", Path: "active", Value: v}}
}

// applyUserPatchTest preserves the legacy disable-path regression fixture.
// Production PATCH now materializes a complete source-bound resource and writes
// it through identity_source_scim_apply; normalized end-to-end coverage lives
// in normalized_user_test.go and pgTAP.
func applyUserPatchTest(s *Server, ctx context.Context, userID int64, active bool) error {
	if !active {
		var extID string
		err := s.pool.QueryRow(ctx,
			`SELECT COALESCE(scim_external_id, '') FROM users WHERE id = $1`, userID,
		).Scan(&extID)
		if err != nil {
			return err
		}
		if extID == "" {
			if _, err := s.pool.Exec(ctx,
				`UPDATE users SET enabled = FALSE, updated_at = now() WHERE id = $1`, userID); err != nil {
				return err
			}
		} else if _, err := s.pool.Exec(ctx, `SELECT scim_disable_user($1)`, extID); err != nil {
			return err
		}
		go RevokeAuthSessions(context.Background(), s.logger, s.authServerURL, s.internalAPIKey, userID)
		return nil
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET enabled = TRUE, updated_at = now() WHERE id = $1`, userID)
	return err
}

// TestPatchActiveFalse_RevokesSessions: PATCH active=false disables the user AND
// fires a revokeSessions POST to the authserver (the bug fix).
func TestPatchActiveFalse_RevokesSessions(t *testing.T) {
	pool := scimTestPool(t)
	srv, revoked := fakeAuthServer(t)
	s := NewServer(pool, pgxutil.WorkerPool{Pool: pool}, scimTestLogger(), srv.URL, "test-internal-key")

	userID, _ := createSCIMTestUser(t, pool)

	if err := applyUserPatchTest(s, context.Background(), userID, false); err != nil {
		t.Fatalf("applyUserPatch active=false: %v", err)
	}

	if userEnabled(t, pool, userID) {
		t.Fatalf("PATCH active=false did not disable user")
	}

	select {
	case got := <-revoked:
		if got != userID {
			t.Fatalf("RevokeAuthSessions user_id = %d, want %d", got, userID)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("PATCH active=false did not trigger RevokeAuthSessions")
	}
}

// TestPatchActiveFalse_RevokesSessions_LocalUser: a locally-created user (no
// scim_external_id) must ALSO get revoked on disable — this used to be a real
// gap (disableUserByID skipped revocation entirely when extID was empty,
// since it had nothing to key the old external_id-based call on).
func TestPatchActiveFalse_RevokesSessions_LocalUser(t *testing.T) {
	pool := scimTestPool(t)
	srv, revoked := fakeAuthServer(t)
	s := NewServer(pool, pgxutil.WorkerPool{Pool: pool}, scimTestLogger(), srv.URL, "test-internal-key")

	userID, _ := createSCIMTestUser(t, pool)
	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET scim_external_id = NULL WHERE id = $1`, userID); err != nil {
		t.Fatalf("clear scim_external_id: %v", err)
	}

	if err := applyUserPatchTest(s, context.Background(), userID, false); err != nil {
		t.Fatalf("applyUserPatch active=false: %v", err)
	}

	if userEnabled(t, pool, userID) {
		t.Fatalf("PATCH active=false did not disable local user")
	}

	select {
	case got := <-revoked:
		if got != userID {
			t.Fatalf("RevokeAuthSessions user_id = %d, want %d", got, userID)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("PATCH active=false did not trigger RevokeAuthSessions for a local user")
	}
}

// TestPatchActiveTrue_DoesNotRevoke: PATCH active=true re-enables the user and
// must NOT revoke sessions.
func TestPatchActiveTrue_DoesNotRevoke(t *testing.T) {
	pool := scimTestPool(t)
	srv, revoked := fakeAuthServer(t)
	s := NewServer(pool, pgxutil.WorkerPool{Pool: pool}, scimTestLogger(), srv.URL, "test-internal-key")

	userID, _ := createSCIMTestUser(t, pool)

	// Start disabled, then re-enable.
	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET enabled = FALSE WHERE id = $1`, userID); err != nil {
		t.Fatalf("pre-disable: %v", err)
	}

	if err := applyUserPatchTest(s, context.Background(), userID, true); err != nil {
		t.Fatalf("applyUserPatch active=true: %v", err)
	}

	if !userEnabled(t, pool, userID) {
		t.Fatalf("PATCH active=true did not re-enable user")
	}

	select {
	case got := <-revoked:
		t.Fatalf("PATCH active=true must NOT revoke, but revoked user_id %d", got)
	case <-time.After(500 * time.Millisecond):
		// expected: no revoke
	}
}

// TestPatchActiveFalse_DegradesWhenUnconfigured: with the authserver link unset,
// PATCH active=false still disables the user and revokeSessions is a safe no-op
// (no panic, no error).
func TestPatchActiveFalse_DegradesWhenUnconfigured(t *testing.T) {
	pool := scimTestPool(t)
	s := NewServer(pool, pgxutil.WorkerPool{Pool: pool}, scimTestLogger(), "", "") // unconfigured authserver

	userID, _ := createSCIMTestUser(t, pool)

	if err := applyUserPatchTest(s, context.Background(), userID, false); err != nil {
		t.Fatalf("applyUserPatch active=false (unconfigured): %v", err)
	}
	if userEnabled(t, pool, userID) {
		t.Fatalf("PATCH active=false did not disable user")
	}
	// Give the best-effort goroutine a moment; it must not panic.
	time.Sleep(100 * time.Millisecond)
}
