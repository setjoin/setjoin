package smtp

// TestSMTPCAGate_CheckPassword proves that a user-scoped block policy causes
// checkPassword to deny the connection end-to-end via the SMTP submission path.
//
// This is the handler-level CA gate test for the SMTP protocol. It drives the
// REAL checkPassword handler method with a real database user (correct password)
// and a ThreatInterceptor whose PolicyEngine is backed by a fake in-memory
// store that blocks that specific user.
//
// Structure:
//  - One test user ("smtp-ca-blocked") is inserted with a known bcrypt password.
//  - A second user ("smtp-ca-allowed") is inserted with the same password.
//  - A ThreatInterceptor with policyEngine = block-user-scoped policy is wired
//    into the SubmissionServer.
//  - checkPassword is called directly on a subConnState (same package, unexported
//    but accessible within the smtp package tests).
//  - Blocked user: asserts c.authed == false AND response contains "535"
//    with the conditional_access_blocked reason.
//  - Allowed user (control): asserts c.authed == true AND response contains "235".
//
// DB gating: requires DB_DSN pointing at the loaded mailserver_test DB. Skips
// cleanly when DB_DSN is unset (DB-less CI stays green).

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
	wh "setjoin.com/mailserver/internal/webhook"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
)

// smtpCAGatePolicyStore is a fake threat.PolicyStore that blocks one specific
// user ID. Implements the three PolicyStore interface methods.
type smtpCAGatePolicyStore struct {
	blockedUserID int64
}

func (f *smtpCAGatePolicyStore) LoadAllPolicies(_ context.Context) ([]threat.PolicyRow, error) {
	return []threat.PolicyRow{
		{
			ID:          1,
			Priority:    10,
			Name:        "smtp-block-test-user",
			Enabled:     true,
			ScopeType:   "user",
			ScopeTarget: fmt.Sprintf("%d", f.blockedUserID),
			Conditions:  map[string]interface{}{},
			Actions:     map[string]interface{}{"action": "block"},
		},
	}, nil
}

func (f *smtpCAGatePolicyStore) LoadPolicies(_ context.Context, _ threat.PolicyEvalContext) ([]threat.PolicyRow, error) {
	return f.LoadAllPolicies(context.Background())
}

func (f *smtpCAGatePolicyStore) ResolveGeoTier(_ context.Context, _ string) (string, error) {
	return "low", nil
}

func (f *smtpCAGatePolicyStore) LoadBreakGlass(_ context.Context) ([]int64, error) {
	return nil, nil
}

func (f *smtpCAGatePolicyStore) LoadNamedLocations(_ context.Context) ([]threat.NamedLocation, error) {
	return nil, nil
}

func (f *smtpCAGatePolicyStore) LoadAuthStrengths(_ context.Context) ([]threat.AuthStrength, error) {
	return nil, nil
}

func smtpCADiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// smtpBufConn is a net.Conn that writes to a buffer and blocks forever on Read.
// RemoteAddr returns a real *net.TCPAddr so checkPassword's IP extraction works.
type smtpBufConn struct {
	bytes.Buffer
}

func (c *smtpBufConn) Read(p []byte) (int, error) { select {} }
func (c *smtpBufConn) Close() error               { return nil }
func (c *smtpBufConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 587}
}
func (c *smtpBufConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 55000}
}
func (c *smtpBufConn) SetDeadline(time.Time) error      { return nil }
func (c *smtpBufConn) SetReadDeadline(time.Time) error  { return nil }
func (c *smtpBufConn) SetWriteDeadline(time.Time) error { return nil }

// openSMTPCAGatePool opens a pgxpool for the test DB or skips the test.
func openSMTPCAGatePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set — skipping SMTP CA gate integration test")
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

// insertSMTPCAGateUser inserts a test user into the test DB with a known bcrypt
// password. Returns the user ID. Registers cleanup to delete the user.
func insertSMTPCAGateUser(t *testing.T, pool *pgxpool.Pool, label, email, password string) int64 {
	t.Helper()
	ctx := context.Background()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword(%s): %v", label, err)
	}

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ('smtpca.test', TRUE)
		 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`,
	).Scan(&domainID); err != nil {
		t.Fatalf("upsert smtpca.test domain: %v", err)
	}

	// Clean up any leftover row from a prior run. Best-effort.
	pool.Exec(ctx, `DELETE FROM users WHERE lower(email) = lower($1)`, email)

	// The auth-attempt throttle counts in the SHARED test DB
	// (rate_limit_counters) across runs; a polluted window turns every AUTH
	// into 421 before the conditional-access gate is even reached. Reset this
	// fixture's per-account key and the loopback IP key.
	pool.Exec(ctx, `DELETE FROM rate_limit_counters WHERE key = 'acct:' || lower($1) OR key = 'ip:127.0.0.1'`, email) //nolint:errcheck

	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash, enabled)
		 VALUES ($1, $2, $3, $4, $5, TRUE)
		 RETURNING id`,
		label, domainID, email, label, string(hash),
	).Scan(&userID); err != nil {
		t.Fatalf("insert smtp ca user %s: %v", label, err)
	}

	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM auth_event_log WHERE email = $1`, email)
		pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
	})

	return userID
}

// buildSMTPCAGateThreatInterceptor creates a ThreatInterceptor whose PolicyEngine
// blocks exactly blockedUserID. All pre-auth pipeline features are disabled so
// Intercept() fast-paths to ActionProceed without touching any threat tables.
func buildSMTPCAGateThreatInterceptor(blockedUserID int64, pool *pgxpool.Pool) *threat.ThreatInterceptor {
	store := &smtpCAGatePolicyStore{blockedUserID: blockedUserID}
	tg := toggle.NewStatic(map[string]bool{
		toggle.FeatureThreatFeed:        false,
		toggle.FeatureGeoBlock:          false,
		toggle.FeatureSprayDetect:       false,
		toggle.FeatureCaptcha:           false,
		toggle.FeatureTarpit:            false,
		toggle.FeatureRateLimit:         false,
		toggle.FeatureConditionalAccess: true,
	})
	pe := threat.NewPolicyEngine(store, tg, nil, nil, smtpCADiscardLogger(), false)
	return threat.New(pool, nil, tg, nil, threat.ThreatConfig{}, smtpCADiscardLogger(), pe)
}

func TestSMTPCAGate_CheckPassword(t *testing.T) {
	pool := openSMTPCAGatePool(t)
	defer pool.Close()
	ctx := context.Background()

	const (
		blockedEmail = "smtp-ca-blocked@smtpca.test"
		allowedEmail = "smtp-ca-allowed@smtpca.test"
		testPassword = "T3stP@ss-smtpca"
	)

	blockedUserID := insertSMTPCAGateUser(t, pool, "smtp-ca-blocked", blockedEmail, testPassword)
	insertSMTPCAGateUser(t, pool, "smtp-ca-allowed", allowedEmail, testPassword)

	ti := buildSMTPCAGateThreatInterceptor(blockedUserID, pool)
	dispatcher := wh.NewDispatcher(pool, smtpCADiscardLogger())
	tg := toggle.NewStatic(map[string]bool{})

	srv := &SubmissionServer{
		pool:              pool,
		logger:            smtpCADiscardLogger(),
		dispatcher:        dispatcher,
		threatInterceptor: ti,
		toggles:           tg,
	}

	// ── Blocked user: checkPassword must deny with 535. ───────────────────────
	t.Run("blocked user is denied with 535", func(t *testing.T) {
		conn := &smtpBufConn{}
		c := &subConnState{
			srv:    srv,
			conn:   conn,
			tp:     textproto.NewConn(conn),
			authed: false,
			userID: 0,
		}
		c.checkPassword(ctx, blockedEmail, testPassword)

		out := conn.String()
		if c.authed {
			t.Errorf("blocked user: c.authed = true; want false\nresponse: %s", out)
		}
		if c.userID != 0 {
			t.Errorf("blocked user: c.userID = %d; want 0\nresponse: %s", c.userID, out)
		}
		if !strings.Contains(out, "535") {
			t.Errorf("blocked user: response does not contain 535\nresponse: %s", out)
		}
		if !strings.Contains(out, "conditional_access_blocked") {
			t.Errorf("blocked user: response does not contain conditional_access_blocked reason\nresponse: %s", out)
		}
	})

	// ── Non-blocked user (control): checkPassword must succeed with 235. ──────
	t.Run("non-blocked user authenticates successfully with 235", func(t *testing.T) {
		conn := &smtpBufConn{}
		c := &subConnState{
			srv:    srv,
			conn:   conn,
			tp:     textproto.NewConn(conn),
			authed: false,
			userID: 0,
		}
		c.checkPassword(ctx, allowedEmail, testPassword)

		out := conn.String()
		if !c.authed {
			t.Errorf("allowed user: c.authed = false; want true\nresponse: %s", out)
		}
		if !strings.Contains(out, "235") {
			t.Errorf("allowed user: response does not contain 235\nresponse: %s", out)
		}
		if strings.Contains(out, "conditional_access_blocked") {
			t.Errorf("allowed user: response contains unexpected deny reason\nresponse: %s", out)
		}
		if c.release != nil {
			c.release()
		}
	})
}
