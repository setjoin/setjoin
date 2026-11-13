// guest_sso_test.go — Guest Accounts G0 Task 14, P17: an SSO assertion
// resolving to a guest satellite row must fail CLOSED — no identity link, no
// token issuance, no email refresh — regardless of which ResolveExisting leg
// (stable-id OIDC/SAML, or the resolve_identity address union) produced the
// hit. Mirrors identity_resolver_test.go's fakeResolver seam: a scripted
// ResolveExisting result drives lookupOrJITUser's post-resolution branches
// without wiring a real OIDC/SAML round-trip. DB-gated (DB_DSN via
// openHandlerPool, same idiom as every other DB-backed test in this package).
package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// seedGuestUser creates a mailbox-less guest (users row + guest_accounts
// satellite, active) in the system guest domain, mirroring
// admin_guest_target_test.go's seed shape. Registers cleanup.
func seedGuestUser(t *testing.T, pool *pgxpool.Pool) (userID int64, email string) {
	t.Helper()
	ctx := context.Background()

	var guestDomainID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM domains WHERE name = 'guest.invalid'`).Scan(&guestDomainID); err != nil {
		t.Skipf("no guest.invalid domain in test DB (expect V143 loaded): %v", err)
	}
	var hostDomainID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM domains WHERE name != 'guest.invalid' LIMIT 1`).Scan(&hostDomainID); err != nil {
		t.Skipf("no host domain in test DB: %v", err)
	}

	suffix := randSuffix()
	email = "ssoguest-" + suffix + "@guest.invalid"
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, enabled)
		 VALUES ($1, $2, $1, $1, TRUE) RETURNING id`,
		email, guestDomainID,
	).Scan(&userID); err != nil {
		t.Fatalf("seed guest user: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM oauth_tokens WHERE user_id = $1`, userID)
		pool.Exec(c, `DELETE FROM guest_accounts WHERE user_id = $1`, userID)
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, userID)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO guest_accounts (user_id, invited_email, invited_by_email, host_domain_id, status)
		 VALUES ($1, $2, $2, $3, 'active')`,
		userID, email, hostDomainID,
	); err != nil {
		t.Fatalf("seed guest_accounts satellite: %v", err)
	}
	return userID, email
}

// TestLookupOrJITUser_GuestResolveAddress_FailsClosed: a resolveAddress hit
// (the resolve_identity address-union seam) on a guest row must NOT link an
// OIDC/SAML identity, must NOT issue tokens, and must return 401 instead of
// the normal address-hit 200.
func TestLookupOrJITUser_GuestResolveAddress_FailsClosed(t *testing.T) {
	pool := openHandlerPool(t)
	guestID, guestEmail := seedGuestUser(t, pool)

	fake := &fakeResolver{
		user: &userRow{ID: guestID, Email: guestEmail},
		src:  resolveAddress,
	}
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
	h.deps.identityResolver = fake

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/saml/idp/acs", nil)
	h.lookupOrJITUser(rr, req,
		guestEmail, "guest-oidc-sub", "guest-oidc-iss", "guest-saml-nameid", "guest-saml-idp",
		nil, true, newNoMappings("oidc"))

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("guest resolveAddress hit: want 401, got %d: %s", rr.Code, rr.Body.String())
	}
	if fake.calls != 1 {
		t.Fatalf("resolver called %d times, want exactly 1", fake.calls)
	}

	var oidcSub, samlNameID *string
	if err := pool.QueryRow(context.Background(),
		`SELECT oidc_subject, saml_name_id FROM users WHERE id = $1`, guestID,
	).Scan(&oidcSub, &samlNameID); err != nil {
		t.Fatalf("re-read guest identity columns: %v", err)
	}
	if oidcSub != nil || samlNameID != nil {
		t.Fatalf("guest resolveAddress hit linked an identity: oidc_subject=%v saml_name_id=%v, want both nil", oidcSub, samlNameID)
	}

	var tokenCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM oauth_tokens WHERE user_id = $1`, guestID).Scan(&tokenCount); err != nil {
		t.Fatalf("count oauth_tokens: %v", err)
	}
	if tokenCount != 0 {
		t.Fatalf("guest resolveAddress hit issued %d oauth_tokens row(s), want 0", tokenCount)
	}
}

// TestLookupOrJITUser_GuestResolveStableID_FailsClosed: a resolveOIDC stable-id
// hit on a guest row must NOT refresh the SSO email and must return 401 instead
// of the normal stable-id-hit 200 (settleSSOMappingsThenIssue never runs).
func TestLookupOrJITUser_GuestResolveStableID_FailsClosed(t *testing.T) {
	pool := openHandlerPool(t)
	guestID, guestEmail := seedGuestUser(t, pool)

	fake := &fakeResolver{
		user: &userRow{ID: guestID, Email: guestEmail},
		src:  resolveOIDC,
	}
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
	h.deps.identityResolver = fake

	newEmail := "changed-" + guestEmail
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/oidc/idp/callback", nil)
	h.lookupOrJITUser(rr, req,
		newEmail, "guest-oidc-sub-2", "guest-oidc-iss-2", "", "",
		nil, true, newNoMappings("oidc"))

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("guest resolveOIDC hit: want 401, got %d: %s", rr.Code, rr.Body.String())
	}

	var gotEmail string
	if err := pool.QueryRow(context.Background(),
		`SELECT email FROM users WHERE id = $1`, guestID).Scan(&gotEmail); err != nil {
		t.Fatalf("re-read guest email: %v", err)
	}
	if gotEmail != guestEmail {
		t.Fatalf("guest email refreshed to %q despite fail-closed, want unchanged %q", gotEmail, guestEmail)
	}

	var tokenCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM oauth_tokens WHERE user_id = $1`, guestID).Scan(&tokenCount); err != nil {
		t.Fatalf("count oauth_tokens: %v", err)
	}
	if tokenCount != 0 {
		t.Fatalf("guest resolveOIDC hit issued %d oauth_tokens row(s), want 0", tokenCount)
	}
}
