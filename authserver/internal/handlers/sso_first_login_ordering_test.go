package handlers

// SSO first-login token-staleness fix.
//
// The known limitation: on SSO login the three resolution paths in
// lookupOrJITUser minted the access token BEFORE applyGroupMappings wrote this
// login's governed admin_role_assignments. Because is_admin is DERIVED from those
// rows (isAdminExprSQL), a FIRST-login admin grant did not exist yet at mint time,
// so the token claimed IsAdmin=false — correct only after the next refresh. The fix
// routes SSO issuance through settleSSOMappingsThenIssue, which settles the mapping,
// re-derives is_admin from the just-written rows, THEN mints.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"setjoin.com/authserver/internal/federation"
	"setjoin.com/shared/testsupport"
)

func TestNormalizedSSOEmailReconcileCompletesBeforeMintFence(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	userID := seedSSOTestActorDB(t, pool, ctx, "sso-normalized-fence")
	defer cleanSSOActor(t, pool, context.Background(), userID)

	sourceKey := fmt.Sprintf("oidc:sso-fence-%d", time.Now().UnixNano())
	var sourceID, sourceGeneration int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO identity_sources(
			source_key,display_name,kind,capabilities,state
		) VALUES(
			$1,'SSO fence regression','oidc',
			'{"authenticate":true,"stable_immutable_subject":true}'::jsonb,
			'active'
		) RETURNING id,generation`,
		sourceKey,
	).Scan(&sourceID, &sourceGeneration); err != nil {
		t.Fatalf("seed normalized source: %v", err)
	}
	var linkID, linkGeneration int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO user_identity_links(
			user_id,source_id,external_subject,purposes,state,link_method
		) VALUES($1,$2,$3,ARRAY['authenticate'],'active','jit')
		RETURNING id,generation`,
		userID, sourceID, "subject-"+sourceKey,
	).Scan(&linkID, &linkGeneration); err != nil {
		t.Fatalf("seed normalized link: %v", err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM user_identity_links WHERE id=$1`, linkID)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM identity_sources WHERE id=$1`, sourceID)
	}()

	var oldEmail string
	if err := pool.QueryRow(ctx,
		`SELECT email FROM users WHERE id=$1`, userID,
	).Scan(&oldEmail); err != nil {
		t.Fatalf("read seed email: %v", err)
	}
	newEmail := fmt.Sprintf("sso-fence-%d@sso-test.internal", userID)
	j := newTestJWT()
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: j, Logger: discardLogger(),
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/callback", nil).
		WithContext(ctx)
	rec := httptest.NewRecorder()
	h.settleSSOMappingsThenIssue(rec, req, &userRow{
		ID:                       userID,
		Email:                    oldEmail,
		IdentitySourceID:         sourceID,
		IdentitySourceGeneration: sourceGeneration,
		IdentityLinkID:           linkID,
		IdentityLinkGeneration:   linkGeneration,
	}, newEmail, []string{}, newNoMappings("oidc"), "oidc")

	if rec.Code != http.StatusOK {
		t.Fatalf("normalized settlement status=%d body=%s", rec.Code, rec.Body.String())
	}
	var storedEmail string
	if err := pool.QueryRow(ctx,
		`SELECT email FROM users WHERE id=$1`, userID,
	).Scan(&storedEmail); err != nil {
		t.Fatalf("read reconciled email: %v", err)
	}
	if storedEmail != newEmail {
		t.Fatalf("reconciled email=%q want %q", storedEmail, newEmail)
	}
	var anchors int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM oauth_tokens WHERE user_id=$1`, userID,
	).Scan(&anchors); err != nil {
		t.Fatalf("count committed family anchors: %v", err)
	}
	if anchors != 1 {
		t.Fatalf("committed family anchors=%d want 1", anchors)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	access, _ := body["access_token"].(string)
	claims, err := j.Validate(access)
	if err != nil {
		t.Fatalf("validate normalized access token: %v", err)
	}
	if claims.Email != newEmail {
		t.Fatalf("normalized access-token email=%q want %q", claims.Email, newEmail)
	}
}

// TestSSOFirstLogin_TokenReflectsJustMappedAdmin is the behavioral regression:
// a user with NO prior assignment logs in via SSO with a group mapped to
// user_admin. The minted first-login access token must already carry IsAdmin=true
// (the just-written grant), not the stale pre-mapping value.
func TestSSOFirstLogin_TokenReflectsJustMappedAdmin(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID := seedSSOTestActorDB(t, pool, ctx, "sso-firstlogin")
	defer cleanSSOActor(t, pool, ctx, userID)

	// IdP group → user_admin (group 2). On first login no assignment exists yet,
	// so applyGroupMappings WRITES it; the mint that follows must read it.
	mapper := &staticMapper{mappings: []federation.GroupMapping{
		{IDPGroup: "idp-ua", AdminRole: strPtr("user_admin")},
	}}
	j := newTestJWT()
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: j, Logger: discardLogger()})

	// user.IsAdmin is the STALE lookup-phase value: false, because the lookup ran
	// before applyGroupMappings created the assignment row.
	user := &userRow{ID: userID, Email: "sso-firstlogin@sso-test.internal", IsAdmin: false}

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rr := httptest.NewRecorder()
	h.settleSSOMappingsThenIssue(rr, req, user, user.Email, []string{"idp-ua"}, mapper, "saml")

	if rr.Code != http.StatusOK {
		t.Fatalf("settleSSOMappingsThenIssue: status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	accessTok, ok := body["access_token"].(string)
	if !ok || accessTok == "" {
		t.Fatalf("response missing access_token: %v", body)
	}
	claims, err := j.Validate(accessTok)
	if err != nil {
		t.Fatalf("validate access token: %v", err)
	}
	if !claims.IsAdmin {
		t.Error("SSO first-login token must reflect the just-mapped admin grant (IsAdmin=true); got false — token minted before applyGroupMappings settled the assignment")
	}
	// The in-place re-derive must also refresh the struct field used by the mint.
	if !user.IsAdmin {
		t.Error("settleSSOMappingsThenIssue must re-derive user.IsAdmin from the just-written assignment")
	}
}

// TestSSOLogin_RevokeReflectedInTokenSameLogin is the symmetric case: a user with
// a prior SSO super_admin grant logs in WITHOUT that mapping. applyGroupMappings
// revokes the stale grant; the same-login token must already reflect the demotion
// (IsAdmin=false), not carry the now-revoked authority until the next refresh.
func TestSSOLogin_RevokeReflectedInTokenSameLogin(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	// A keeper Super Admin ensures trg_protect_last_super_admin does not block
	// the revoke delete.  The documented design: "to demote a sole SSO Super Admin,
	// provision another Super Admin first" — the keeper satisfies that precondition.
	keeperID := seedSSOTestActorWithRole(t, ctx, "sso-revoke-keeper", 1)
	defer cleanSSOActorSweep(t, ctx, keeperID)

	userID := seedSSOTestActorDB(t, pool, ctx, "sso-revoke-token")
	defer cleanSSOActor(t, pool, ctx, userID)

	// Prior SSO-granted super_admin (group 1, NULL granted_by).
	seedSSOAdminAssignmentForProvider(t, pool, ctx, userID, 1, "test:default")

	// Login with only a non-admin distribution mapping → the revoke sweep removes
	// the stale admin grant.
	mapper := &staticMapper{mappings: []federation.GroupMapping{
		{IDPGroup: "idp-users", AdminRole: nil},
	}}
	j := newTestJWT()
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: j, Logger: discardLogger()})

	// user.IsAdmin is the STALE lookup-phase value: true, because the lookup ran
	// before the revoke sweep removed the grant.
	user := &userRow{ID: userID, Email: "sso-revoke-token@sso-test.internal", IsAdmin: true}

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rr := httptest.NewRecorder()
	h.settleSSOMappingsThenIssue(rr, req, user, user.Email, []string{"idp-users"}, mapper, "saml")

	if rr.Code != http.StatusOK {
		t.Fatalf("settleSSOMappingsThenIssue: status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	accessTok, _ := body["access_token"].(string)
	if accessTok == "" {
		t.Fatalf("response missing access_token: %v", body)
	}
	claims, err := j.Validate(accessTok)
	if err != nil {
		t.Fatalf("validate access token: %v", err)
	}
	if claims.IsAdmin {
		t.Error("SSO login that revokes the admin grant must mint IsAdmin=false in the SAME login; got true — token minted before applyGroupMappings swept the stale grant")
	}
}

func TestSSOLogin_MappingFailureRollsBackAndDoesNotMint(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	userID := seedSSOTestActorDB(t, pool, ctx, "sso-atomic-failure")
	defer cleanSSOActor(t, pool, ctx, userID)

	original := adminRoleToGroupID
	adminRoleToGroupID = map[string]int64{
		"invalid_test_role": 999999,
		"user_admin":        2,
	}
	defer func() { adminRoleToGroupID = original }()

	mapper := &staticMapper{mappings: []federation.GroupMapping{
		{IDPGroup: "bad", AdminRole: strPtr("invalid_test_role")},
		{IDPGroup: "good", AdminRole: strPtr("user_admin")},
	}}
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/callback", nil)
	h.settleSSOMappingsThenIssue(
		rec, req,
		&userRow{ID: userID, Email: "sso-atomic-failure@sso-test.internal"},
		"sso-atomic-failure@sso-test.internal",
		[]string{"bad", "good"}, mapper, "oidc",
	)
	if rec.Code != http.StatusConflict {
		t.Fatalf("mapping failure status=%d want 409: %s",
			rec.Code, rec.Body.String())
	}
	var grants, tokens int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments
		  WHERE user_id=$1 AND role_group_id=2 AND granted_by IS NULL`,
		userID,
	).Scan(&grants); err != nil {
		t.Fatalf("count rolled-back grants: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM oauth_tokens WHERE user_id=$1`,
		userID,
	).Scan(&tokens); err != nil {
		t.Fatalf("count tokens after failed mapping: %v", err)
	}
	if grants != 0 || tokens != 0 {
		t.Fatalf("partial SSO state survived failed mapping: grants=%d tokens=%d",
			grants, tokens)
	}
}

// TestLookupOrJITUser_SettlesMappingsBeforeMint_StaticGuard pins the ordering at
// the source level (runs without a DB): every SSO path must issue via
// settleSSOMappingsThenIssue (never h.issueTokens directly), and the helper must
// run applyGroupMappings → re-derive (lookupUser) → issueTokens in that order.
func TestLookupOrJITUser_SettlesMappingsBeforeMint_StaticGuard(t *testing.T) {
	luj := funcSrc(t, "auth.go", "lookupOrJITUser")
	if !strings.Contains(luj, "settleSSOMappingsThenIssue") {
		t.Error("lookupOrJITUser must issue SSO tokens via settleSSOMappingsThenIssue (mappings settled before mint)")
	}
	// Guard against regressing to the buggy direct ordering: no SSO path may mint
	// directly, and applyGroupMappings must not be called as a fire-and-forget step
	// after issuance.
	if strings.Contains(luj, "h.issueTokens(") {
		t.Error("lookupOrJITUser must not call h.issueTokens directly — route through settleSSOMappingsThenIssue so applyGroupMappings runs first")
	}
	if strings.Contains(luj, "h.applyGroupMappings(") {
		t.Error("lookupOrJITUser must not call h.applyGroupMappings directly — it is now sequenced (before mint) inside settleSSOMappingsThenIssue")
	}

	helper := funcSrc(t, "auth.go", "settleSSOMappingsThenIssue")
	requireOrder(t, helper, "settleSSOMappingsThenIssue ordering",
		"applyGroupMappings",          // 1. settle this login's governed assignments (+ revoke)
		"mappingTx.Commit",            // 2. publish profile/mappings before the mint fence
		"lookupUser",                  // 3. re-derive is_admin from the committed rows
		"identity_auth_mint_fence",    // 4. final source/link/user authority recheck
		"issueTokens",                 // 5. mint into a deferred HTTP response
		"commitDeferredTokenResponse", // 6. publish only after anchor commit
	)
}
