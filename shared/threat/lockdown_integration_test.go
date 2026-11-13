package threat

import (
	"context"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/device"
	"setjoin.com/shared/toggle"
)

// (a) user-scoped lockdown over IMAP/SMTP: a scoped user is blocked at the
// post-auth pass (client_type:"legacy" block), a non-scoped user proceeds.
//
// Exercises the full real flow: real DB-backed PolicyStore → PolicyEngine →
// EvaluatePostAuth → matchAll(client_type:legacy umbrella) → dispatchAction(block).
// Scope: group, so the non-member (GroupIDs=[]) is not in scope → proceed.
func TestLockdown_IMAPUserScoped(t *testing.T) {
	if os.Getenv("TEST_DB_DSN") == "" {
		t.Skip("TEST_DB_DSN not set")
	}
	pool, err := pgxpool.New(context.Background(), os.Getenv("TEST_DB_DSN"))
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	// Close via t.Cleanup FIRST (registered before the fixture cleanup below)
	// so LIFO runs clean() against an OPEN pool and only then closes it.
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	// ponytail: synthetic group id — user_group_members.group_id has no FK.
	const groupID int64 = 99042

	clean := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM conditional_access_policies WHERE name='lkd-imap-scoped-test'`)
		_, _ = pool.Exec(ctx, `DELETE FROM user_group_members WHERE group_id=$1`, groupID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE email='lkd-a@lkd-imap.example'`)
		_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE name='lkd-imap.example'`)
	}
	clean()
	t.Cleanup(clean)

	// Provision an isolated domain + user (matches device_credential_test.go seeding pattern).
	var domainID, uid int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ('lkd-imap.example') RETURNING id`).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name)
		 VALUES ('lkd-a', $1, 'lkd-a@lkd-imap.example', 'LKD IMAP A') RETURNING id`,
		domainID).Scan(&uid); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	// Member of synthetic group groupID.
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_group_members (user_id, group_id) VALUES ($1, $2)`, uid, groupID); err != nil {
		t.Fatalf("insert group member: %v", err)
	}

	// Seed a group-scoped policy: block legacy auth (imap/smtp → "legacy" via umbrella)
	// for members of groupID. Pass scope_target as a string (pgx cannot cast int64 → text).
	_, err = pool.Exec(ctx,
		`INSERT INTO conditional_access_policies
		     (priority, name, scope_type, scope_target, state, enabled,
		      conditions, actions, exclude_users, exclude_groups)
		 VALUES (
		     199, 'lkd-imap-scoped-test', 'group', $1, 'on', true,
		     '{"client_type":"legacy"}'::jsonb,
		     '{"operator":"all","grants":[{"action":"block"}],"reason":"lockdown imap scoped test"}'::jsonb,
		     '[]'::jsonb, '[]'::jsonb
		 )`, strconv.FormatInt(groupID, 10))
	if err != nil {
		t.Fatalf("insert policy: %v", err)
	}

	tg := toggle.NewStatic(map[string]bool{toggle.FeatureConditionalAccess: true})
	store := NewPolicyStore(pool, testLogger())
	pe := NewPolicyEngine(store, tg, nil, nil, testLogger(), false)
	ti := &ThreatInterceptor{logger: testLogger(), policyEngine: pe, toggles: tg}

	// Scoped member over IMAP → blocked (imap → umbrella → "legacy" → block matches).
	member := &ConnectionMeta{Protocol: ProtocolIMAP, UserID: uid, GroupIDs: []int64{groupID}}
	res, reason := ti.EvaluatePostAuth(ctx, member)
	if res != ActionReject {
		t.Fatalf("member over IMAP: want ActionReject, got %v (reason=%q)", res, reason)
	}

	// Non-member over IMAP → proceed (scope doesn't match: GroupIDs=[]).
	nonMember := &ConnectionMeta{Protocol: ProtocolIMAP, UserID: uid + 99999, GroupIDs: []int64{}}
	if res2, _ := ti.EvaluatePostAuth(ctx, nonMember); res2 != ActionProceed {
		t.Fatalf("non-member over IMAP: want ActionProceed, got %v", res2)
	}
}

// (b) stolen token, no device proof, blocked: a request with no X-Device-*
// headers is not bound under lockdown. The DeviceCredentialResolver resolves
// (false,0,"") — the strict gate then blocks the request.
//
// Equivalent to an attacker who stole a JWT session token but cannot produce
// the X-Device-HMAC proof (the shared HMAC secret never leaves the native shell).
func TestLockdown_StolenTokenNoProof(t *testing.T) {
	if os.Getenv("TEST_DB_DSN") == "" {
		t.Skip("TEST_DB_DSN not set")
	}
	pool, err := pgxpool.New(context.Background(), os.Getenv("TEST_DB_DSN"))
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	res := NewDeviceCredentialResolver(pool, testLogger(), device.NewSecretCodec([]byte("device-test-master-secret-key"), cryptokey.ProfileStandard))
	// No X-Device-ID / X-Device-HMAC headers → the resolver short-circuits on
	// the missing device-id header and returns (false,0,"").
	// Under lockdown the strict gate blocks on a non-bound result.
	if b, _, _ := res.Resolve(context.Background(), httptest.NewRequest("POST", "/jmap", nil), 1); b {
		t.Fatal("no proof must not be bound (stolen-token case)")
	}
	// Keep imports live in the skeleton (also used by test c).
	_ = toggle.NewStatic
	_ = strconv.Itoa
	_ = time.Now
}

// (c) revoke → next proof-bearing request blocked: approve+bind → 200; revoke;
// next proof request → not bound. Asserts the resolver reads revoked_at live
// per request (the honest revocation contract — no TTL cache between approval
// and revoke on the resolver side).
func TestLockdown_RevokeNextRequestBlocked(t *testing.T) {
	if os.Getenv("TEST_DB_DSN") == "" {
		t.Skip("TEST_DB_DSN not set")
	}
	pool, err := pgxpool.New(context.Background(), os.Getenv("TEST_DB_DSN"))
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	// Close via t.Cleanup FIRST (registered before any fixture cleanup below)
	// so LIFO runs cleanups against an OPEN pool and only then closes it.
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	secret := "aabbccddeeff00112233445566778899"

	// Pre-clean (matches device_credential_test.go cleanup pattern).
	clean := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM devices WHERE fingerprint LIKE 'lkd-rv-test%'`)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE email='lkd-rv@lkd-revoke.example'`)
		_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE name='lkd-revoke.example'`)
	}
	clean()
	t.Cleanup(clean)

	var domainID, uid, did int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ('lkd-revoke.example') RETURNING id`).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name)
		 VALUES ('lkd-rv', $1, 'lkd-rv@lkd-revoke.example', 'LKD Revoke') RETURNING id`,
		domainID).Scan(&uid); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	// Reuse seeding from TestDeviceCredentialResolver: approved device.
	if err := pool.QueryRow(ctx,
		`INSERT INTO devices (user_id, fingerprint, hmac_secret, enroll_state)
		 VALUES ($1, 'lkd-rv-test-fp-pad-to-32chars-xxx', $2, 'approved') RETURNING id`,
		uid, secret).Scan(&did); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	resolver := NewDeviceCredentialResolver(pool, testLogger(), device.NewSecretCodec([]byte("device-test-master-secret-key"), cryptokey.ProfileStandard))

	// Fresh proof → bound (pre-revoke baseline).
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	if b, _, _ := resolver.Resolve(ctx, signedDeviceRequest("/jmap", secret, did, ts, "lkd-nonce-pre"), uid); !b {
		t.Fatal("pre-revoke: approved device with valid proof must be bound")
	}

	// Revoke: set revoked_at + flip enroll_state.
	if _, err := pool.Exec(ctx,
		`UPDATE devices SET revoked_at = now(), enroll_state = 'revoked' WHERE id = $1`, did); err != nil {
		t.Fatalf("revoke device: %v", err)
	}

	// Same HMAC secret, fresh timestamp, but the device is revoked → not bound.
	// The resolver reads the revoked posture live per request — no TTL cache
	// means revocation takes effect immediately on the next request (spec §8
	// contract), and GetDeviceSecret filters revoked devices outright.
	ts2 := strconv.FormatInt(time.Now().Unix(), 10)
	if b, _, _ := resolver.Resolve(ctx, signedDeviceRequest("/jmap", secret, did, ts2, "lkd-nonce-post"), uid); b {
		t.Fatal("post-revoke: next proof-bearing request must not be bound (revoked device)")
	}
}
