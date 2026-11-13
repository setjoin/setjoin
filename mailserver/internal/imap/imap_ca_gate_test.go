package imap

// TestIMAPCAGate_HandleLogin proves that a user-scoped block policy causes
// handleLogin to deny the connection end-to-end.
//
// This is the handler-level CA gate test that complements the pure-helper test
// (TestPostAuthGateDenies). It drives the REAL handleLogin handler with a real
// database user (correct password) and a ThreatInterceptor whose PolicyEngine is
// backed by a fake in-memory store that blocks that specific user.
//
// Structure:
//  - One test user ("blocked") is inserted with a known bcrypt password.
//  - A second user ("allowed") is inserted with the same password.
//  - A ThreatInterceptor with policyEngine = block-user-scoped policy is wired
//    into the Server.
//  - handleLogin is called directly on a connState + bufConn.
//  - Blocked user: asserts c.authed == false AND response contains "NO" with
//    the conditional_access_blocked reason.
//  - Allowed user (control): asserts c.authed == true AND response contains "OK".
//
// DB gating: requires DB_DSN pointing at the loaded mailserver_test DB. Skips
// cleanly when DB_DSN is unset (DB-less CI stays green).

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
	"setjoin.com/mailserver/internal/webhook"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
)

// caGatePolicyStore is an in-package fake threat.PolicyStore that blocks one
// specific user ID. Implements the three PolicyStore interface methods.
type caGatePolicyStore struct {
	blockedUserID int64
}

func (f *caGatePolicyStore) LoadAllPolicies(_ context.Context) ([]threat.PolicyRow, error) {
	return []threat.PolicyRow{
		{
			ID:          1,
			Priority:    10,
			Name:        "block-test-user",
			Enabled:     true,
			ScopeType:   "user",
			ScopeTarget: fmt.Sprintf("%d", f.blockedUserID),
			Conditions:  map[string]interface{}{},
			Actions:     map[string]interface{}{"action": "block"},
		},
	}, nil
}

func (f *caGatePolicyStore) LoadPolicies(_ context.Context, _ threat.PolicyEvalContext) ([]threat.PolicyRow, error) {
	return f.LoadAllPolicies(context.Background())
}

func (f *caGatePolicyStore) ResolveGeoTier(_ context.Context, _ string) (string, error) {
	return "low", nil
}

func (f *caGatePolicyStore) LoadBreakGlass(_ context.Context) ([]int64, error) {
	return nil, nil
}

func (f *caGatePolicyStore) LoadNamedLocations(_ context.Context) ([]threat.NamedLocation, error) {
	return nil, nil
}

func (f *caGatePolicyStore) LoadAuthStrengths(_ context.Context) ([]threat.AuthStrength, error) {
	return nil, nil
}

// discardLogger is a slog.Logger that discards all output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// openCAGatePool opens a pgxpool for the test DB or skips the test.
func openCAGatePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set — skipping IMAP CA gate integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("cannot open DB pool (%s): %v", dsn, err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("DB ping failed: %v", err)
	}
	return pool
}

// insertCAGateUser provisions a complete test account (person + primary mailbox)
// with a known bcrypt password. Returns the user ID and registers cleanup.
func insertCAGateUser(t *testing.T, pool *pgxpool.Pool, label, email, password string) int64 {
	t.Helper()
	ctx := context.Background()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost) // MinCost for test speed
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword(%s): %v", label, err)
	}

	// Ensure the test domain exists.
	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ('cagate.test', TRUE)
		 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`,
	).Scan(&domainID); err != nil {
		t.Fatalf("upsert domain: %v", err)
	}

	// Clean up any leftover rows from a prior run (the unique index is on lower(email),
	// so ON CONFLICT (email) does not match the partial expression index). Login
	// binds mailbox_lifecycle rows to the user and address claims to the mailbox,
	// the primary-mailbox trigger blocks plain mailbox deletes, and deleting the
	// user first SET NULLs mailboxes.user_id into the mailboxes_shared_not_primary
	// check — so tear down in dependency order (repo pattern: admin_users_test).
	// Best-effort: rows may not exist.
	pool.Exec(ctx, `DELETE FROM mailbox_address_claims WHERE normalized_address = lower($1)`, email)
	pool.Exec(ctx, `DELETE FROM mailbox_lifecycle WHERE bound_user_id IN
		(SELECT id FROM users WHERE lower(email) = lower($1))`, email)
	pool.Exec(ctx, `ALTER TABLE mailboxes DISABLE TRIGGER ALL`)
	pool.Exec(ctx, `DELETE FROM mailboxes WHERE lower(email) = lower($1)`, email)
	pool.Exec(ctx, `ALTER TABLE mailboxes ENABLE TRIGGER ALL`)
	pool.Exec(ctx, `DELETE FROM users WHERE lower(email) = lower($1)`, email)

	var userID int64
	if err := pool.QueryRow(ctx,
		`SELECT (provision_account(
		   p_email => $1,
		   p_display_name => $2,
		   p_username => $3,
		   p_password_hash => $4,
		   p_enabled => TRUE,
		   p_create_only => TRUE
		 )->>'user_id')::bigint`,
		email, label, label, string(hash),
	).Scan(&userID); err != nil {
		t.Fatalf("provision account %s: %v", label, err)
	}

	t.Cleanup(func() {
		// Same teardown order as the pre-clean: address claims → lifecycle rows
		// → (trigger disabled) mailbox → user. The test's real logins create all
		// of these, and each one blocks the next delete. Best-effort.
		c := context.Background()
		pool.Exec(c, `DELETE FROM auth_event_log WHERE email = $1`, email)
		pool.Exec(c, `DELETE FROM mailbox_address_claims WHERE mailbox_id IN
			(SELECT id FROM mailboxes WHERE user_id = $1)`, userID)
		pool.Exec(c, `DELETE FROM mailbox_lifecycle WHERE bound_user_id = $1`, userID)
		pool.Exec(c, `ALTER TABLE mailboxes DISABLE TRIGGER ALL`)
		pool.Exec(c, `DELETE FROM mailboxes WHERE user_id = $1`, userID)
		pool.Exec(c, `ALTER TABLE mailboxes ENABLE TRIGGER ALL`)
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, userID)
	})

	return userID
}

// buildCAGateThreatInterceptor creates a ThreatInterceptor whose PolicyEngine
// blocks exactly blockedUserID. pool is the real test-DB pool used by
// RecordResult (auth_attempts INSERT). The pre-auth pipeline steps are all
// disabled via the static toggles, so Intercept() takes the fast path and
// never touches any threat-feed/lockout/spray/rate-limit tables.
// Only EvaluatePostAuth fires the CA policy check.
func buildCAGateThreatInterceptor(blockedUserID int64, pool *pgxpool.Pool) *threat.ThreatInterceptor {
	store := &caGatePolicyStore{blockedUserID: blockedUserID}
	// Disable all pre-auth pipeline features; enable only conditional access.
	tg := toggle.NewStatic(map[string]bool{
		toggle.FeatureThreatFeed:        false,
		toggle.FeatureGeoBlock:          false,
		toggle.FeatureSprayDetect:       false,
		toggle.FeatureCaptcha:           false,
		toggle.FeatureTarpit:            false,
		toggle.FeatureRateLimit:         false,
		toggle.FeatureConditionalAccess: true,
	})
	pe := threat.NewPolicyEngine(store, tg, nil, nil, discardLogger(), false)
	// threat.New wires logger, toggles, pool, and policyEngine so EvaluatePostAuth
	// has a non-nil logger and RecordResult can use the real pool.
	return threat.New(pool, nil, tg, nil, threat.ThreatConfig{}, discardLogger(), pe)
}

func TestIMAPCAGate_HandleLogin(t *testing.T) {
	pool := openCAGatePool(t)
	// Close via t.Cleanup registered BEFORE the fixture cleanups: t.Cleanup runs
	// LIFO, so fixtures delete their rows while the pool is still open (a defer
	// here would close the pool first and silently strand every cleanup delete).
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	const (
		blockedEmail = "cagate-blocked@cagate.test"
		allowedEmail = "cagate-allowed@cagate.test"
		testPassword = "T3stP@ss-cagate"
	)

	blockedUserID := insertCAGateUser(t, pool, "cagate-blocked", blockedEmail, testPassword)
	insertCAGateUser(t, pool, "cagate-allowed", allowedEmail, testPassword)

	ti := buildCAGateThreatInterceptor(blockedUserID, pool)
	wdispatcher := webhook.NewDispatcher(pool, discardLogger())

	srv := &Server{
		pool:              pool,
		logger:            discardLogger(),
		webhookDispatcher: wdispatcher,
		threatInterceptor: ti,
	}

	// ── Blocked user: handleLogin must deny. ──────────────────────────────────
	t.Run("blocked user is denied", func(t *testing.T) {
		bc := &bufConn{}
		c := &connState{
			srv:    srv,
			conn:   bc,
			authed: false,
			userID: 0,
		}
		c.handleLogin(ctx, "A1", fmt.Sprintf(`"%s" "%s"`, blockedEmail, testPassword))

		out := bc.String()
		if c.authed {
			t.Errorf("blocked user: c.authed = true; want false\nresponse: %s", out)
		}
		if c.userID != 0 {
			t.Errorf("blocked user: c.userID = %d; want 0\nresponse: %s", c.userID, out)
		}
		if !strings.Contains(out, "NO") {
			t.Errorf("blocked user: response does not contain NO\nresponse: %s", out)
		}
		if !strings.Contains(out, "conditional_access_blocked") {
			t.Errorf("blocked user: response does not contain conditional_access_blocked reason\nresponse: %s", out)
		}
	})

	// ── Non-blocked user (control): handleLogin must succeed. ─────────────────
	t.Run("non-blocked user authenticates successfully", func(t *testing.T) {
		bc := &bufConn{}
		c := &connState{
			srv:    srv,
			conn:   bc,
			authed: false,
			userID: 0,
		}
		c.handleLogin(ctx, "A2", fmt.Sprintf(`"%s" "%s"`, allowedEmail, testPassword))

		out := bc.String()
		if !c.authed {
			t.Errorf("allowed user: c.authed = false; want true\nresponse: %s", out)
		}
		if !strings.Contains(out, "OK") {
			t.Errorf("allowed user: response does not contain OK\nresponse: %s", out)
		}
		if strings.Contains(out, "conditional_access_blocked") {
			t.Errorf("allowed user: response contains unexpected deny reason\nresponse: %s", out)
		}
		if c.release != nil {
			c.release()
		}
	})
}
