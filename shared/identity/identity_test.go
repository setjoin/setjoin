package identity

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
)

// These tests require a loaded mailserver_test database. They are skipped when
// DB_DSN is unset so the package still builds/tests in a DB-less environment.
//
//	DB_DSN=postgres://mail@127.0.0.1:5432/mailserver_test?sslmode=disable go test ./identity/...
//
// ARCH-003: the account-slot currency is a mailbox id, and users.id !=
// mailboxes.id in production. Every fixture here uses DIVERGENT ids (the
// mailbox id is forced far away from the user id) so a lookup that confused the
// two columns would fail the test.

func testPool(t *testing.T) *pgxpool.Pool {
	return testsupport.OpenTestPool(t)
}

// fixture inserts a domain, two users, and (optionally) divergent-id mailboxes.
// It returns the two user ids and the first user's primary mailbox id, and
// registers cleanup that tears every inserted row down.
type fixture struct {
	domainID    int64
	userA       int64 // has a primary mailbox at primaryA
	userB       int64 // has a primary mailbox at primaryB (a DIFFERENT user)
	userNone    int64 // has NO primary mailbox
	primaryA    int64 // userA's primary mailbox id (divergent from userA)
	nonPrimaryA int64 // a second, NON-primary mailbox owned by userA
	primaryB    int64 // userB's primary mailbox id
}

func setupFixture(t *testing.T, pool *pgxpool.Pool) fixture {
	t.Helper()
	ctx := context.Background()

	// Unique domain per fixture so a crashed run (cleanup not yet registered)
	// can never block the next run on the UNIQUE(name) constraint.
	dom := fmt.Sprintf("identity-seam-test-%d.example", time.Now().UnixNano())

	var f fixture
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`,
		dom,
	).Scan(&f.domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	mkUser := func(name string) int64 {
		var uid int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO users (username, domain_id, email, display_name)
			 VALUES ($1, $2, $1 || '@' || $3, $1) RETURNING id`,
			name, f.domainID, dom,
		).Scan(&uid); err != nil {
			t.Fatalf("insert user %s: %v", name, err)
		}
		return uid
	}
	f.userA = mkUser("seam-a")
	f.userB = mkUser("seam-b")
	f.userNone = mkUser("seam-none")

	// Force divergent ids: insert several throwaway SHARED mailbox rows
	// (user_id IS NULL — the schema's shared/resource case) to advance the
	// mailboxes BIGSERIAL well past the users sequence, so mailbox.id != user.id
	// (ARCH-003). Shared mailboxes have no primary-mailbox requirement, so this
	// does not trip the BZ014 "user must have a primary" trigger.
	for i := 0; i < 5; i++ {
		if _, err := pool.Exec(ctx,
			`INSERT INTO mailboxes (user_id, domain_id, email, display_name, is_primary)
			 VALUES (NULL, $1, 'pad-' || $2 || '@' || $3, 'pad', FALSE)`,
			f.domainID, strconv.Itoa(i), dom,
		); err != nil {
			t.Fatalf("insert padding mailbox: %v", err)
		}
	}

	mkPrimary := func(uid int64, label string) int64 {
		var mbID int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO mailboxes (user_id, domain_id, email, display_name, is_primary)
			 VALUES ($1, $2, $3 || '@' || $4, $3, TRUE) RETURNING id`,
			uid, f.domainID, label, dom,
		).Scan(&mbID); err != nil {
			t.Fatalf("insert primary mailbox %s: %v", label, err)
		}
		return mbID
	}
	f.primaryA = mkPrimary(f.userA, "seam-a-primary")
	f.primaryB = mkPrimary(f.userB, "seam-b-primary")

	// A second, non-primary mailbox for userA.
	if err := pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, is_primary)
		 VALUES ($1, $2, 'seam-a-secondary@' || $3, 'seam-a-secondary', FALSE) RETURNING id`,
		f.userA, f.domainID, dom,
	).Scan(&f.nonPrimaryA); err != nil {
		t.Fatalf("insert secondary mailbox: %v", err)
	}

	// Sanity: the fixture must actually be divergent, else the test proves nothing.
	if f.primaryA == f.userA || f.primaryB == f.userB {
		t.Fatalf("fixture not divergent: primaryA=%d userA=%d primaryB=%d userB=%d (ARCH-003 requires user_id != mailbox_id)",
			f.primaryA, f.userA, f.primaryB, f.userB)
	}

	t.Cleanup(func() {
		// Children first (mailboxes reference users + domains).
		_, _ = pool.Exec(ctx, `DELETE FROM mailboxes WHERE domain_id = $1`, f.domainID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE domain_id = $1`, f.domainID)
		_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, f.domainID)
	})
	return f
}

func TestResolvePrimaryMailbox(t *testing.T) {
	pool := testPool(t)
	f := setupFixture(t, pool)
	ctx := context.Background()

	got, err := ResolvePrimaryMailbox(ctx, pool, f.userA)
	if err != nil {
		t.Fatalf("ResolvePrimaryMailbox(userA): unexpected error: %v", err)
	}
	if got != f.primaryA {
		t.Fatalf("ResolvePrimaryMailbox(userA) = %d, want divergent primary %d", got, f.primaryA)
	}
	// Explicitly assert divergence held end-to-end (it must NOT have returned userA).
	if got == f.userA {
		t.Fatalf("ResolvePrimaryMailbox returned the user id %d, not the mailbox id — ARCH-003 violation", got)
	}
}

func TestResolvePrimaryMailbox_NoPrimary(t *testing.T) {
	pool := testPool(t)
	f := setupFixture(t, pool)
	ctx := context.Background()

	_, err := ResolvePrimaryMailbox(ctx, pool, f.userNone)
	if !errors.Is(err, ErrNoPrimaryMailbox) {
		t.Fatalf("ResolvePrimaryMailbox(userNone) error = %v, want ErrNoPrimaryMailbox", err)
	}
	// The sentinel wraps pgx.ErrNoRows so existing callers keep working.
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("ErrNoPrimaryMailbox should wrap pgx.ErrNoRows, got %v", err)
	}
}

func TestValidateAccountID(t *testing.T) {
	pool := testPool(t)
	f := setupFixture(t, pool)
	ctx := context.Background()

	// True: the caller's own primary mailbox.
	own, grants, err := ValidateAccountID(ctx, pool, f.primaryA, f.userA, nil)
	if err != nil {
		t.Fatalf("ValidateAccountID(primaryA, userA): unexpected error: %v", err)
	}
	if !own {
		t.Fatalf("ValidateAccountID(primaryA=%d, userA=%d) own = false, want true", f.primaryA, f.userA)
	}
	if len(grants) != 0 {
		t.Fatalf("ValidateAccountID(primaryA) grants = %v, want none (own mailbox)", grants)
	}

	// False: a non-primary mailbox the caller happens to own.
	own, grants, err = ValidateAccountID(ctx, pool, f.nonPrimaryA, f.userA, nil)
	if err != nil {
		t.Fatalf("ValidateAccountID(nonPrimaryA, userA): unexpected error: %v", err)
	}
	if own || len(grants) != 0 {
		t.Fatalf("ValidateAccountID(nonPrimaryA=%d, userA=%d) = (%v,%v), want invalid (not the primary)", f.nonPrimaryA, f.userA, own, grants)
	}

	// False: another user's primary mailbox (the auth-bypass case ARCH-003 closes).
	own, grants, err = ValidateAccountID(ctx, pool, f.primaryB, f.userA, nil)
	if err != nil {
		t.Fatalf("ValidateAccountID(primaryB, userA): unexpected error: %v", err)
	}
	if own || len(grants) != 0 {
		t.Fatalf("ValidateAccountID(primaryB=%d, userA=%d) = (%v,%v), want invalid (cross-user, no delegates arm)", f.primaryB, f.userA, own, grants)
	}

	// False (no error): a user with no primary mailbox cannot match anything.
	own, grants, err = ValidateAccountID(ctx, pool, f.primaryA, f.userNone, nil)
	if err != nil {
		t.Fatalf("ValidateAccountID(_, userNone): unexpected error: %v", err)
	}
	if own || len(grants) != 0 {
		t.Fatalf("ValidateAccountID(_, userNone) = (%v,%v), want invalid (no primary mailbox)", own, grants)
	}
}

// dbDelegates is a real DelegateGrants implementation over the superuser test
// pool (RLS is bypassed here; the RunUserScoped RLS shape is pinned by the
// jmap package's tests + rls_mailbox_delegates.pg / rls_shared_mailbox_use.pg).
func dbDelegates(pool *pgxpool.Pool) DelegateGrants {
	return func(ctx context.Context, mailboxID, userID int64) ([]string, error) {
		rows, err := pool.Query(ctx,
			`SELECT permission FROM mailbox_delegates WHERE mailbox_id = $1 AND user_id = $2`,
			mailboxID, userID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var grants []string
		for rows.Next() {
			var g string
			if err := rows.Scan(&g); err != nil {
				return nil, err
			}
			grants = append(grants, g)
		}
		return grants, rows.Err()
	}
}

// TestValidateAccountID_DelegateArm covers the #13 shared-mailbox widening:
// an accountId that is NOT the caller's primary is valid iff the caller holds
// a mailbox_delegates grant on it — present / absent / revoked (the lookup is
// per-request, so a revocation is effective on the very next call).
func TestValidateAccountID_DelegateArm(t *testing.T) {
	pool := testPool(t)
	f := setupFixture(t, pool)
	ctx := context.Background()

	// Grant userA 'read' + 'send_on_behalf' on userB's primary mailbox.
	for _, perm := range []string{"read", "send_on_behalf"} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by)
			 VALUES ($1, $2, $3, $4)`,
			f.primaryB, f.userA, perm, f.userB); err != nil {
			t.Fatalf("insert delegate grant %s: %v", perm, err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM mailbox_delegates WHERE mailbox_id = $1 AND user_id = $2`, f.primaryB, f.userA)
	})

	// Grant present: valid via the delegate arm, both levels reported.
	own, grants, err := ValidateAccountID(ctx, pool, f.primaryB, f.userA, dbDelegates(pool))
	if err != nil {
		t.Fatalf("ValidateAccountID(delegated): unexpected error: %v", err)
	}
	if own {
		t.Fatalf("ValidateAccountID(delegated) own = true, want false (not the primary)")
	}
	if len(grants) != 2 {
		t.Fatalf("ValidateAccountID(delegated) grants = %v, want [read send_on_behalf]", grants)
	}

	// Grant absent: userB holds nothing on userA's primary.
	own, grants, err = ValidateAccountID(ctx, pool, f.primaryA, f.userB, dbDelegates(pool))
	if err != nil {
		t.Fatalf("ValidateAccountID(no grant): unexpected error: %v", err)
	}
	if own || len(grants) != 0 {
		t.Fatalf("ValidateAccountID(no grant) = (%v,%v), want invalid", own, grants)
	}

	// Revoked: delete the grants — the NEXT call must see them gone (uncached).
	if _, err := pool.Exec(ctx, `DELETE FROM mailbox_delegates WHERE mailbox_id = $1 AND user_id = $2`, f.primaryB, f.userA); err != nil {
		t.Fatalf("revoke grants: %v", err)
	}
	own, grants, err = ValidateAccountID(ctx, pool, f.primaryB, f.userA, dbDelegates(pool))
	if err != nil {
		t.Fatalf("ValidateAccountID(revoked): unexpected error: %v", err)
	}
	if own || len(grants) != 0 {
		t.Fatalf("ValidateAccountID(revoked) = (%v,%v), want invalid immediately after revocation", own, grants)
	}
}

// TestValidateAccountID_DelegateArmNotConsultedForPrimary pins the hot path:
// when the accountId IS the caller's primary, the delegate lookup must not run
// (no extra transaction on every JMAP call).
func TestValidateAccountID_DelegateArmNotConsultedForPrimary(t *testing.T) {
	pool := testPool(t)
	f := setupFixture(t, pool)
	ctx := context.Background()

	called := false
	spy := func(context.Context, int64, int64) ([]string, error) {
		called = true
		return nil, nil
	}
	own, _, err := ValidateAccountID(ctx, pool, f.primaryA, f.userA, spy)
	if err != nil || !own {
		t.Fatalf("ValidateAccountID(primaryA) = (%v, err=%v), want own", own, err)
	}
	if called {
		t.Fatal("delegate lookup ran for the caller's own primary mailbox — hot path must skip it")
	}
}

// TestValidateAccountID_DelegateLookupError pins error propagation: a failing
// delegate lookup is a hard error (fail-closed), never a silent no-grants.
func TestValidateAccountID_DelegateLookupError(t *testing.T) {
	pool := testPool(t)
	f := setupFixture(t, pool)
	ctx := context.Background()

	boom := errors.New("delegate lookup down")
	failing := func(context.Context, int64, int64) ([]string, error) { return nil, boom }
	_, _, err := ValidateAccountID(ctx, pool, f.primaryB, f.userA, failing)
	if !errors.Is(err, boom) {
		t.Fatalf("ValidateAccountID(failing delegates) err = %v, want the lookup error", err)
	}
}
