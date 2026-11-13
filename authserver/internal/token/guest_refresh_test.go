// guest_refresh_test.go — Guest G0 Task 11 (the authserver-side refresh
// companion to the mailserver tracer's 10 legs — the P13 refresh
// containment): (a) a guest's ROTATED access token still carries acct=guest
// (the ~1h refresh is where a login-only claim would silently vanish); (b)
// guest_set_status('disable') kills the refresh chain — the next
// RefreshTokens call fails and the family is revoked.
//
// The DB fixture is self-contained on a canonical mailserver_test: it creates
// one exact, stable test-only host domain, uses unique principals per run, and
// removes every user/role/assignment/token row it owns before closing its pool.
// The stable domain itself is deliberately retained so concurrent packages can
// never race a shared-domain delete.
package token

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const guestRefreshHostDomain = "guest-refresh-fixture.example"

type guestRefreshFixture struct {
	guestID      int64
	adminID      int64
	roleID       int64
	hostDomain   string
	hostDomainID int64
	guestEmail   string
}

func newGuestRefreshFixture(t *testing.T, pool *pgxpool.Pool, label string, withAdmin bool) guestRefreshFixture {
	t.Helper()
	ctx := t.Context()
	suffix := uuid.NewString()
	f := guestRefreshFixture{
		hostDomain: guestRefreshHostDomain,
		guestEmail: label + "-" + suffix + "@guest.invalid",
	}

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		steps := []struct {
			name string
			sql  string
			args []any
		}{
			{"oauth tokens", `DELETE FROM oauth_tokens WHERE user_id=$1`, []any{f.guestID}},
			{"role assignments", `DELETE FROM admin_role_assignments WHERE role_group_id=$1 OR user_id=$2`, []any{f.roleID, f.adminID}},
			{"role group", `DELETE FROM admin_role_groups WHERE id=$1`, []any{f.roleID}},
			{"guest account", `DELETE FROM guest_accounts WHERE user_id=$1`, []any{f.guestID}},
			{"fixture users", `DELETE FROM users WHERE id IN ($1,$2)`, []any{f.guestID, f.adminID}},
		}
		for _, step := range steps {
			if _, err := pool.Exec(cleanupCtx, step.sql, step.args...); err != nil {
				t.Errorf("cleanup %s: %v", step.name, err)
			}
		}
	})

	if err := pool.QueryRow(ctx, `
		INSERT INTO domains(name,is_local)
		VALUES ($1,TRUE)
		ON CONFLICT (name) DO UPDATE SET is_local=EXCLUDED.is_local
		RETURNING id`, f.hostDomain).Scan(&f.hostDomainID); err != nil {
		t.Fatalf("seed stable host domain: %v", err)
	}
	var guestDomainID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM domains WHERE name='guest.invalid'`).Scan(&guestDomainID); err != nil {
		t.Fatalf("resolve canonical guest.invalid domain: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO users(username,domain_id,email,display_name,enabled)
		VALUES ($1,$2,$3,$4,TRUE)
		RETURNING id`, label+"-"+suffix, guestDomainID, f.guestEmail, "Guest Refresh "+label).Scan(&f.guestID); err != nil {
		t.Fatalf("seed guest user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status)
		VALUES ($1,$2,$2,$3,'active')`, f.guestID, f.guestEmail, f.hostDomainID); err != nil {
		t.Fatalf("seed guest account: %v", err)
	}

	if !withAdmin {
		return f
	}
	adminUsername := label + "-admin-" + suffix
	adminEmail := adminUsername + "@" + f.hostDomain
	if err := pool.QueryRow(ctx, `
		INSERT INTO users(username,domain_id,email,display_name,enabled)
		VALUES ($1,$2,$3,$4,TRUE)
		RETURNING id`, adminUsername, f.hostDomainID, adminEmail, "Guest Refresh Admin "+label).Scan(&f.adminID); err != nil {
		t.Fatalf("seed admin user: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO admin_role_groups(name,permissions,domain_scope)
		VALUES ($1,ARRAY['guests.manage'],$2)
		RETURNING id`, label+"-managers-"+suffix, f.hostDomainID).Scan(&f.roleID); err != nil {
		t.Fatalf("seed guests.manage role: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,eligible)
		VALUES ($1,$2,$1,FALSE)`, f.adminID, f.roleID); err != nil {
		t.Fatalf("seed guests.manage assignment: %v", err)
	}
	return f
}

// TestGuestRefresh_RotatedAccessCarriesGuestClaim: RefreshTokens re-derives
// is_guest_account fresh from the DB at rotation time (refresh.go's
// accountTypeFor(isGuest)) rather than trusting whatever the presented
// refresh JWT claims — so a guest's rotated access token carries acct=guest
// even though the refresh token itself was minted with no AccountType set.
func TestGuestRefresh_RotatedAccessCarriesGuestClaim(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping guest refresh integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	f := newGuestRefreshFixture(t, pool, "rotated-claim", false)

	p := newTestProvider(t)
	family := uuid.New().String()
	// Deliberately the plain IssueRefreshWithFamily (no AccountType claim on
	// the refresh token itself) — the point of this leg is that RefreshTokens
	// does NOT need it to carry the claim forward.
	refreshTok, err := p.IssueRefreshWithFamily(f.guestID, f.guestEmail, family)
	if err != nil {
		t.Fatalf("IssueRefreshWithFamily: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO oauth_tokens (user_id, token_hash, token_type, expires_at, family_id)
		 VALUES ($1, $2, 'refresh', now() + interval '30 days', $3::uuid)
		 ON CONFLICT DO NOTHING`,
		f.guestID, tokenHash(refreshTok), family,
	); err != nil {
		t.Fatalf("seed oauth_tokens: %v", err)
	}

	result, err := RefreshTokens(ctx, pool, p, nil, refreshTok)
	if err != nil {
		t.Fatalf("RefreshTokens (active guest): %v", err)
	}
	claims, err := p.Validate(result.AccessToken)
	if err != nil {
		t.Fatalf("Validate rotated access token: %v", err)
	}
	if !claims.IsGuest() {
		t.Fatalf("rotated access token AccountType = %q, want guest", claims.AccountType)
	}
}

// TestGuestRefresh_DisableKillsFamily: guest_set_status(disable) revokes the
// refresh family in the SAME transaction (guest_account.sql's C-7 atomicity)
// — the next RefreshTokens call on the (already-rotated) successor token
// fails with the same error shape as any invalid/expired token, and zero
// live oauth_tokens rows remain for the guest.
//
// The 1.1s sleep between minting firstTok and priming the rotation is
// deliberate: refresh JWTs (IssueRefreshWithFamilyAndCnf) carry no jti and
// truncate iat/exp to whole seconds, so two mints for the same
// user+email+family+cnf within the same wall-clock second produce a
// byte-identical token — colliding oauth_tokens.token_hash (no unique
// constraint on that column) across two rows and non-deterministically
// steering RefreshTokens' un-ordered `WHERE token_hash = $1 FOR UPDATE`
// lookup into its grace-window/reuse-detection branch instead of the plain
// revoked-token branch this test means to exercise. That is a real, narrow
// latent gap in refresh.go (rapid-fire same-second rotation can collide) —
// tracked as a finding in the Task 11 report, not fixed here (out of Guest
// G0's scope) — this sleep sidesteps it deterministically for the leg under
// test.
func TestGuestRefresh_DisableKillsFamily(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping guest refresh integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	f := newGuestRefreshFixture(t, pool, "disable-family", true)
	var rolePermissions []string
	var roleScope int64
	if err := pool.QueryRow(ctx, `SELECT permissions, domain_scope FROM admin_role_groups WHERE id=$1`, f.roleID).Scan(&rolePermissions, &roleScope); err != nil {
		t.Fatalf("read guests.manage role: %v", err)
	}
	if len(rolePermissions) != 1 || rolePermissions[0] != "guests.manage" || roleScope != f.hostDomainID {
		t.Fatalf("fixture role permissions=%v scope=%d, want [guests.manage] scope=%d", rolePermissions, roleScope, f.hostDomainID)
	}

	p := newTestProvider(t)
	family := uuid.New().String()
	firstTok, err := p.IssueRefreshWithFamily(f.guestID, f.guestEmail, family)
	if err != nil {
		t.Fatalf("IssueRefreshWithFamily: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO oauth_tokens (user_id, token_hash, token_type, expires_at, family_id)
		 VALUES ($1, $2, 'refresh', now() + interval '30 days', $3::uuid)
		 ON CONFLICT DO NOTHING`,
		f.guestID, tokenHash(firstTok), family,
	); err != nil {
		t.Fatalf("seed oauth_tokens: %v", err)
	}

	time.Sleep(1100 * time.Millisecond) // see the doc comment above: dodge the same-second token collision

	// Rotate once while active, producing the successor token under test.
	result, err := RefreshTokens(ctx, pool, p, nil, firstTok)
	if err != nil {
		t.Fatalf("RefreshTokens (priming rotation): %v", err)
	}

	if _, err := pool.Exec(ctx, `SELECT guest_set_status($1, $2, 'disable')`, f.adminID, f.guestID); err != nil {
		t.Fatalf("guest_set_status(disable): %v", err)
	}

	_, err = RefreshTokens(ctx, pool, p, nil, result.RefreshToken)
	if err == nil {
		t.Fatal("RefreshTokens with the successor token for a disabled guest must fail")
	}
	if !strings.Contains(err.Error(), "revoked or expired") {
		t.Fatalf("disabled-guest refresh error = %q, want the same shape as an invalid/expired token", err.Error())
	}

	var live int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM oauth_tokens WHERE user_id = $1 AND revoked_at IS NULL`, f.guestID,
	).Scan(&live); err != nil {
		t.Fatalf("count live rows: %v", err)
	}
	if live != 0 {
		t.Fatalf("%d oauth_tokens row(s) still live for the disabled guest, want 0 (disable must revoke the family)", live)
	}
}
