package handlers

// web-session-revoke Tier 1 (TODOS.md, Queue B #1): before this, no web login
// path ever wrote a `sessions` row — GET /user/sessions (mailserver) only ever
// showed OAuth/IMAP families, never "you're logged into the web app". These
// tests are the red-first proof for issueTokensWithFactors' new INSERT.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/testsupport"
)

// TestIssueTokensWithFactors_InsertsSessionsRow: a password login inserts a
// sessions row keyed by the access token's own jti, hashing the actual issued
// token and carrying the request's User-Agent + the resolved auth_method.
func TestIssueTokensWithFactors_InsertsSessionsRow(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID := seedSSOTestActorDB(t, pool, ctx, "session-row")
	defer cleanSSOActor(t, pool, ctx, userID)

	j := newTestJWT()
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: j, Logger: discardLogger()})
	user := &userRow{ID: userID, Email: "does-not-matter@sso-test.internal"}

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.Header.Set("User-Agent", "test-agent/1.0")
	rr := httptest.NewRecorder()
	h.issueTokensWithFactors(rr, req, user, CompletionRequest{Factors: []string{token.AMRPassword}})

	if rr.Code != http.StatusOK {
		t.Fatalf("issueTokensWithFactors: status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	claims, err := j.Validate(body.AccessToken)
	if err != nil {
		t.Fatalf("validate access token: %v", err)
	}
	wantHash := sha256.Sum256([]byte(body.AccessToken))

	var (
		gotUserID    int64
		gotAuthMeth  string
		gotHash      []byte
		gotUserAgent string
	)
	if err := pool.QueryRow(ctx,
		`SELECT user_id, auth_method, token_hash, user_agent FROM sessions WHERE id = $1`,
		claims.JTI,
	).Scan(&gotUserID, &gotAuthMeth, &gotHash, &gotUserAgent); err != nil {
		t.Fatalf("expected a sessions row for jti %q: %v", claims.JTI, err)
	}
	if gotUserID != userID {
		t.Errorf("sessions.user_id = %d, want %d", gotUserID, userID)
	}
	if gotAuthMeth != "password" {
		t.Errorf("sessions.auth_method = %q, want %q", gotAuthMeth, "password")
	}
	if string(gotHash) != string(wantHash[:]) {
		t.Error("sessions.token_hash must be sha256(access_token)")
	}
	if gotUserAgent != "test-agent/1.0" {
		t.Errorf("sessions.user_agent = %q, want %q", gotUserAgent, "test-agent/1.0")
	}
}

func TestLogoutFailsClosedWhenRevocationStoreIsUnavailable(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: createClosedPool(t), JWT: newTestJWT(), Logger: discardLogger(),
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req = req.WithContext(ContextWithUser(
		req.Context(), &token.Claims{UserID: 42, Email: "logout@example.com"},
	))
	rec := httptest.NewRecorder()
	h.Logout(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("logout status=%d, want 503; body=%s",
			rec.Code, rec.Body.String())
	}
}

// TestIssueTokensWithFactors_PushAuthMethodSatisfiesSessionsCheck is the
// regression for sessions_auth_method_check (V094): authMethodFromFactors can
// return "push" (native push-MFA approve, device.go MFAApprove) — a value
// V066 never added to the CHECK constraint (only 'certificate' was). Since the
// sessions INSERT is best-effort, a violation wouldn't fail the login, but the
// row would silently never appear — this proves it now does.
func TestIssueTokensWithFactors_PushAuthMethodSatisfiesSessionsCheck(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID := seedSSOTestActorDB(t, pool, ctx, "session-row-push")
	defer cleanSSOActor(t, pool, ctx, userID)

	j := newTestJWT()
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: j, Logger: discardLogger()})
	user := &userRow{ID: userID, Email: "does-not-matter@sso-test.internal"}

	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/approve", nil)
	rr := httptest.NewRecorder()
	h.issueTokensWithFactors(rr, req, user, CompletionRequest{
		Factors: []string{token.AMRSoftwareKey, token.AMRUserPresence},
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("issueTokensWithFactors: status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	claims, err := j.Validate(body.AccessToken)
	if err != nil {
		t.Fatalf("validate access token: %v", err)
	}
	var gotAuthMeth string
	if err := pool.QueryRow(ctx,
		`SELECT auth_method FROM sessions WHERE id = $1`, claims.JTI,
	).Scan(&gotAuthMeth); err != nil {
		t.Fatalf("expected a sessions row for jti %q (push auth_method must satisfy the CHECK): %v", claims.JTI, err)
	}
	if gotAuthMeth != "push" {
		t.Errorf("sessions.auth_method = %q, want %q", gotAuthMeth, "push")
	}
}

// Identity I5: issueTokensWithFactors is the single mint funnel, so it must
// fail closed while a committed transition still has a mandatory session/SFU
// effect pending. Optional subscriber delivery is intentionally not authority.
func TestIssueTokensWithFactors_RefusesUnfinishedIdentityTransitionFence(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID := seedSSOTestActorDB(t, pool, ctx, "identity-admission-fence")
	defer cleanSSOActor(t, pool, ctx, userID)

	var (
		sourceID         int64
		sourceGeneration int64
		linkID           int64
		transitionID     string
	)
	if err := pool.QueryRow(ctx,
		`SELECT id,generation FROM identity_sources
		  WHERE source_key='legacy:scim'`,
	).Scan(&sourceID, &sourceGeneration); err != nil {
		t.Fatalf("load identity source fixture: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO user_identity_links(
		     user_id,source_id,external_subject,purposes,state,link_method
		 ) VALUES($1,$2,$3,ARRAY['authenticate']::text[],'candidate','operator')
		 RETURNING id`,
		userID, sourceID, "auth-fence:"+t.Name()+":"+randSuffix(),
	).Scan(&linkID); err != nil {
		t.Fatalf("create identity link fixture: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO identity_transitions(
		     user_id,kind,state,source_id,link_id,source_generation,
		     link_generation,lifecycle_generation,preview_digest,
		     preview_snapshot,preview_expires_at,actor_user_id,reason,
		     idempotency_key,request_digest,committed_at
		 ) VALUES(
		     $1,'directory_to_local','effects_pending',$2,$3,$4,
		     1,1,digest('auth-fence-preview','sha256'),
		     '{}'::jsonb,statement_timestamp()+interval '15 minutes',
		     $1,'auth mint admission fence fixture',gen_random_uuid(),
		     digest('auth-fence-request','sha256'),statement_timestamp()
		 ) RETURNING id::text`,
		userID, sourceID, linkID, sourceGeneration,
	).Scan(&transitionID); err != nil {
		t.Fatalf("create identity transition fixture: %v", err)
	}
	defer func() {
		_, _ = pool.Exec(ctx, `DELETE FROM identity_transition_effects WHERE transition_id=$1`, transitionID)
		_, _ = pool.Exec(ctx, `DELETE FROM identity_transitions WHERE id=$1`, transitionID)
		_, _ = pool.Exec(ctx, `DELETE FROM user_identity_links WHERE id=$1`, linkID)
	}()
	if _, err := pool.Exec(ctx,
		`INSERT INTO identity_transition_effects(
		     transition_id,effect_kind,state,attempt_count,completed_at
		 ) VALUES
		     ($1::uuid,'auth_sessions','completed',1,statement_timestamp()),
		     ($1::uuid,'livekit_sessions','pending',0,NULL),
		     ($1::uuid,'subscriber_notice','pending',0,NULL)`,
		transitionID,
	); err != nil {
		t.Fatalf("create identity effect fixtures: %v", err)
	}
	defer func() {
		_, _ = pool.Exec(ctx,
			`DELETE FROM identity_transition_effects WHERE transition_id=$1::uuid;
			 DELETE FROM identity_transitions WHERE id=$1::uuid;
			 DELETE FROM user_identity_links WHERE id=$2`,
			transitionID, linkID,
		)
	}()

	var before int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM oauth_tokens WHERE user_id=$1`, userID,
	).Scan(&before); err != nil {
		t.Fatalf("count tokens before fenced mint: %v", err)
	}

	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	h.issueTokensWithFactors(
		rr, req,
		&userRow{ID: userID, Email: "identity-admission-fence@sso-test.internal"},
		CompletionRequest{Factors: []string{token.AMRPassword}},
	)

	if rr.Code != http.StatusConflict {
		t.Fatalf("fenced token mint status = %d, want 409; body=%s",
			rr.Code, rr.Body.String())
	}
	var after int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM oauth_tokens WHERE user_id=$1`, userID,
	).Scan(&after); err != nil {
		t.Fatalf("count tokens after fenced mint: %v", err)
	}
	if after != before {
		t.Fatalf("fenced token mint wrote oauth token rows: before=%d after=%d",
			before, after)
	}
}
