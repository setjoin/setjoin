// guest_belt_db_test.go — permanent DB-gated regression coverage for the G0
// Task 5 unconditional guest satellite belt (chain.go's applyGuestBelt) and
// the auth.CheckPassword guest refusal (bcrypt.go). guest_belt_test.go only
// proves the pool-nil seam (claim-only enforcement, no DB); every invariant
// that actually touches guest_accounts/guest_account_status was previously
// proven only by a throwaway smoke test that got deleted — this file is the
// permanent replacement. Mirrors the repo's established DB-gated idiom
// (chat/tracer_integration_test.go's chatDSN/chatTestPool: os.Getenv("DB_DSN")
// + t.Skip when unset, since 'mail' is a superuser in the test DB — see
// scripts/load-test-schema.sh — no role dance is needed here because
// guest_account_status/is_guest_account are SECURITY DEFINER and bypass RLS
// internally regardless of the calling role).
package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/jwtutil"
)

func guestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set — skipping DB-gated guest belt test")
	}
	return dsn
}

func guestTestPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// guestSeq gives every seeded row a unique email/username within a test
// run (users_email_lower_idx is UNIQUE) without a dedicated fixture sequence.
var guestSeq int64

func nextGuestLabel(t *testing.T, prefix string) string {
	t.Helper()
	n := atomic.AddInt64(&guestSeq, 1)
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), n)
}

// seedGuestBeltUser creates a bare users row (no mailbox — guests are
// mailbox-less by the G0 floor, V143) and, when guestStatus != "", a
// guest_accounts row with that status/expiry. Returns the user id + email.
// Cleanup deletes the users row; guest_accounts cascades (ON DELETE CASCADE).
func seedGuestBeltUser(t *testing.T, pool *pgxpool.Pool, label, passwordHash, guestStatus string, expiresAt *time.Time) (int64, string) {
	t.Helper()
	ctx := context.Background()

	var domainID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM domains WHERE name = 'guest.invalid'`).Scan(&domainID); err != nil {
		t.Fatalf("resolve guest.invalid domain (expect V143 loaded): %v", err)
	}

	name := nextGuestLabel(t, label)
	email := name + "@guestbelt.test"
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		name, domainID, email, label, passwordHash,
	).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID); err != nil {
			t.Errorf("cleanup user %d: %v", userID, err)
		}
	})

	if guestStatus != "" {
		if _, err := pool.Exec(ctx,
			`INSERT INTO guest_accounts (user_id, invited_email, invited_by_email, host_domain_id, status, expires_at)
			 VALUES ($1, $2, $2, $3, $4, $5)`,
			userID, email, domainID, guestStatus, expiresAt,
		); err != nil {
			t.Fatalf("seed guest_accounts: %v", err)
		}
	}
	return userID, email
}

// 1. Satellite HIT overrides claim: a member-claiming token for a userID
// with an ACTIVE guest_accounts row must be forced to guest, no error.
func TestGuestBelt_DB_SatelliteHitOverridesClaim(t *testing.T) {
	dsn := guestDSN(t)
	pool := guestTestPool(t, dsn)
	userID, _ := seedGuestBeltUser(t, pool, "hit-override", "x", "active", nil)

	c := &Chain{}
	c.SetGuestPool(pool)
	claims := &Claims{UserID: userID, AccountType: ""} // member claim
	if err := c.applyGuestBelt(t.Context(), claims); err != nil {
		t.Fatalf("applyGuestBelt: %v", err)
	}
	if claims.AccountType != jwtutil.AccountTypeGuest {
		t.Fatalf("AccountType = %q, want guest — a satellite hit must override the member claim", claims.AccountType)
	}
}

// 2. No-row + guest claim => deny. A token claiming guest for a userID with
// NO guest_accounts row is an inconsistency the belt must fail closed on.
func TestGuestBelt_DB_NoRowGuestClaimDenied(t *testing.T) {
	dsn := guestDSN(t)
	pool := guestTestPool(t, dsn)
	userID, _ := seedGuestBeltUser(t, pool, "no-row-member", "x", "", nil) // no guest_accounts row

	c := &Chain{}
	c.SetGuestPool(pool)
	claims := &Claims{UserID: userID, AccountType: jwtutil.AccountTypeGuest}
	err := c.applyGuestBelt(t.Context(), claims)
	if err == nil {
		t.Fatal("applyGuestBelt returned nil — a guest-claiming token with no satellite row must be denied")
	}
	if !errors.Is(err, ErrGuestInactive) {
		t.Fatalf("err = %v, want ErrGuestInactive", err)
	}
}

// 3. Lookup error => ErrGuestLookupUnavailable, never nil, never a silent
// resolve to member. Forced via an already-canceled context — the guest
// pool's QueryRow fails before it can even reach pgx.ErrNoRows, so this
// exercises the belt's real "default" (non-ErrNoRows) error branch without
// touching any production code to make it testable.
func TestGuestBelt_DB_LookupErrorDenies(t *testing.T) {
	dsn := guestDSN(t)
	pool := guestTestPool(t, dsn)
	userID, _ := seedGuestBeltUser(t, pool, "lookup-err", "x", "active", nil)

	c := &Chain{}
	c.SetGuestPool(pool)
	claims := &Claims{UserID: userID, AccountType: jwtutil.AccountTypeGuest}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already-canceled: QueryRow must fail, not silently succeed

	err := c.applyGuestBelt(ctx, claims)
	if err == nil {
		t.Fatal("applyGuestBelt returned nil on a lookup failure — must deny")
	}
	if !errors.Is(err, ErrGuestLookupUnavailable) {
		t.Fatalf("err = %v, want ErrGuestLookupUnavailable", err)
	}
	if claims.AccountType != jwtutil.AccountTypeGuest {
		t.Fatalf("AccountType mutated to %q on a lookup error — a query failure must never resolve the claim (member or otherwise)", claims.AccountType)
	}
}

// 4. BZ219: a guest row that is disabled, or active-but-expired, must deny
// with ErrGuestInactive — while STILL forcing AccountType=guest (the belt
// forces the claim before it evaluates status, so a denied guest is never
// mistaken for a plain member either).
func TestGuestBelt_DB_BZ219InactiveOrExpired(t *testing.T) {
	dsn := guestDSN(t)
	pool := guestTestPool(t, dsn)
	past := time.Now().Add(-1 * time.Hour)

	cases := []struct {
		name    string
		status  string
		expires *time.Time
	}{
		{"disabled", "disabled", nil},
		{"expired-status", "expired", nil},
		{"active-but-past-expiry", "active", &past},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			userID, _ := seedGuestBeltUser(t, pool, "bz219-"+tc.name, "x", tc.status, tc.expires)

			c := &Chain{}
			c.SetGuestPool(pool)
			claims := &Claims{UserID: userID}
			err := c.applyGuestBelt(t.Context(), claims)
			if err == nil {
				t.Fatalf("applyGuestBelt returned nil for status=%s expires=%v — BZ219 must deny", tc.status, tc.expires)
			}
			if !errors.Is(err, ErrGuestInactive) {
				t.Fatalf("err = %v, want ErrGuestInactive", err)
			}
			if claims.AccountType != jwtutil.AccountTypeGuest {
				t.Fatalf("AccountType = %q, want guest even when denied", claims.AccountType)
			}
		})
	}
}

// 5. auth.CheckPassword refuses a guest identity outright (fail closed, same
// sentinel as a bad password — no oracle distinguishing "guest" from "wrong
// password"). A control case proves the same seeding shape succeeds for a
// non-guest member, so the refusal is specifically guest-caused, not an
// artifact of the fixture.
func TestCheckPassword_DB_GuestRefusal(t *testing.T) {
	dsn := guestDSN(t)
	pool := guestTestPool(t, dsn)
	const pw = "correct-horse-battery-staple-9"
	hash, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	t.Run("guest_denied", func(t *testing.T) {
		_, email := seedGuestBeltUser(t, pool, "checkpw-guest", hash, "active", nil)
		u, err := CheckPassword(t.Context(), pool, email, pw)
		if err == nil {
			t.Fatal("CheckPassword succeeded for a guest identity — must refuse")
		}
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("err = %v, want ErrInvalidCredentials (same sentinel as a bad password — no oracle)", err)
		}
		if u != nil {
			t.Fatal("CheckPassword returned a non-nil user alongside an error")
		}
	})

	t.Run("member_control_succeeds", func(t *testing.T) {
		_, email := seedGuestBeltUser(t, pool, "checkpw-member", hash, "", nil) // no guest row
		u, err := CheckPassword(t.Context(), pool, email, pw)
		if err != nil {
			t.Fatalf("CheckPassword denied a plain member with the correct password: %v (proves the guest case above is refused BECAUSE it's a guest, not fixture drift)", err)
		}
		if u == nil {
			t.Fatal("CheckPassword returned nil user with nil error")
		}
	})
}
