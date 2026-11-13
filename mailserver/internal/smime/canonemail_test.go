package smime

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/identity"
)

// newTestPool dials mailserver_test_smime via TEST_DB_DSN; skips when unset so
// the pure-Go suite stays runnable without a database. Mirrors the smtp pkg's
// DB-test connection pattern (smime_trust_pool_db_test.go).
func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping database-dependent test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// newTestTx opens a transaction on a fresh pool and ALWAYS rolls it back at test
// end — perfect isolation with zero residue, so the DB-backed tests are re-run
// safe even though some seeded rows (a user's only primary mailbox) are
// un-deletable in place (the mailbox triggers correctly forbid it). The returned
// pgx.Tx satisfies the smime.Querier seam, so it drops straight into
// CanonRecipientEmail / ResolveRecipientCert.
func newTestTx(t *testing.T) (context.Context, pgx.Tx) {
	t.Helper()
	pool := newTestPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	return ctx, tx
}

// TestCanonRecipientEmail_PureCanonicalization covers the DB-free cases: the
// helper must agree with identity.CanonicalizeAddress for trim/fold/display-name
// strip. These run without a database (q == nil is the no-resolve path).
func TestCanonRecipientEmail_PureCanonicalization(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"uppercase + spaces", "  USER@Example.COM  ", "user@example.com"},
		{"display name strip", `"Name" <User@Example.com>`, "user@example.com"},
		{"already canonical", "bob@example.com", "bob@example.com"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// With a nil Querier the helper must still produce the
			// identity-canonical form (never panic, never the raw input).
			got := CanonRecipientEmail(ctx, nil, tc.raw)
			if got != tc.want {
				t.Errorf("CanonRecipientEmail(%q)=%q, want %q", tc.raw, got, tc.want)
			}
			// Parity: identity-canonical is the floor.
			if want := identity.CanonicalizeAddress(tc.raw).String(); got != want {
				t.Errorf("CanonRecipientEmail(%q)=%q != identity.CanonicalizeAddress=%q", tc.raw, got, want)
			}
		})
	}
}

// TestCanonRecipientEmail_AliasResolution covers the DB path: an alias address
// resolves to its mailbox's primary address; a no-match passes through the
// identity-canonical form.
func TestCanonRecipientEmail_AliasResolution(t *testing.T) {
	ctx, tx := newTestTx(t)

	// Seed inside the rolled-back tx: domain → user → primary mailbox →
	// (primary alias + secondary alias).
	var domID int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ('canon.test', TRUE) RETURNING id`).Scan(&domID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	const primary = "canon-primary@example.com"
	const alias = "canon-alias@example.com"

	var mbID, userID int64
	// A primary mailbox requires a user_id (mailboxes_shared_not_primary check).
	if err := tx.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash)
		 VALUES ('canon-primary-user', $1, $2, 'Canon Primary', 'x') RETURNING id`,
		domID, primary).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if err := tx.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, is_primary)
		 VALUES ($1, $2, $3, 'Canon Primary', true) RETURNING id`,
		userID, domID, primary).Scan(&mbID); err != nil {
		t.Fatalf("insert mailbox: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO aliases (mailbox_id, email, domain_id, is_primary) VALUES ($1, $2, $3, true)`,
		mbID, primary, domID); err != nil {
		t.Fatalf("insert primary alias: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO aliases (mailbox_id, email, domain_id, is_primary) VALUES ($1, $2, $3, false)`,
		mbID, alias, domID); err != nil {
		t.Fatalf("insert secondary alias: %v", err)
	}

	// (c) alias → primary (also exercises uppercase canonicalization first).
	if got := CanonRecipientEmail(ctx, tx, "  Canon-Alias@Example.com "); got != primary {
		t.Errorf("alias resolution: got %q, want %q", got, primary)
	}
	// Primary address resolves to itself (its own is_primary row).
	if got := CanonRecipientEmail(ctx, tx, primary); got != primary {
		t.Errorf("primary self-resolution: got %q, want %q", got, primary)
	}
	// (d) no alias match → identity-canonical passthrough, never raw.
	if got := CanonRecipientEmail(ctx, tx, "Nobody@Example.com"); got != "nobody@example.com" {
		t.Errorf("no-match passthrough: got %q, want %q", got, "nobody@example.com")
	}
}

// errQuerier always returns an error row, to assert fail-soft to identity-canonical.
type errQuerier struct{ err error }

func (e errQuerier) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row { return errRow{e.err} }

type errRow struct{ err error }

func (r errRow) Scan(_ ...any) error { return r.err }

// TestCanonRecipientEmail_DBErrorFailsSoft asserts a query error returns the
// identity-canonical form (not the raw input) and never panics.
func TestCanonRecipientEmail_DBErrorFailsSoft(t *testing.T) {
	ctx := context.Background()
	q := errQuerier{err: context.DeadlineExceeded}
	got := CanonRecipientEmail(ctx, q, "  Boom@Example.com  ")
	if got != "boom@example.com" {
		t.Errorf("DB-error fail-soft: got %q, want %q", got, "boom@example.com")
	}
}
