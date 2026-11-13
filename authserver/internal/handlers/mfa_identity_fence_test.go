package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/testsupport"
)

func TestMFAPendingCompletionRechecksNormalizedIdentityFence(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	userID := seedSSOTestActorDB(t, pool, ctx, "mfa-identity-fence")
	defer cleanSSOActor(t, pool, ctx, userID)

	sourceKey := fmt.Sprintf("oidc:mfa-fence-%d", time.Now().UnixNano())
	var sourceID, sourceGeneration int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO identity_sources(
			source_key,display_name,kind,capabilities,state
		) VALUES(
			$1,'MFA identity fence','oidc',
			'{"authenticate":true,"stable_immutable_subject":true}'::jsonb,
			'active'
		) RETURNING id,generation`,
		sourceKey,
	).Scan(&sourceID, &sourceGeneration); err != nil {
		t.Fatalf("seed identity source: %v", err)
	}
	var linkID, linkGeneration int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO user_identity_links(
			user_id,source_id,external_subject,purposes,state,link_method
		) VALUES($1,$2,$3,ARRAY['authenticate'],'active','jit')
		RETURNING id,generation`,
		userID, sourceID, "subject-"+sourceKey,
	).Scan(&linkID, &linkGeneration); err != nil {
		t.Fatalf("seed identity link: %v", err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM user_identity_links WHERE id=$1`, linkID)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM identity_sources WHERE id=$1`, sourceID)
	}()

	var email string
	if err := pool.QueryRow(ctx, `SELECT email FROM users WHERE id=$1`, userID).
		Scan(&email); err != nil {
		t.Fatalf("read actor email: %v", err)
	}
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
	})
	claims := &token.Claims{
		UserID: userID,
		Email:  email,
		Type:   token.TypeMFAPending,
		AMR:    []string{token.AMRPassword},
		IdentityFence: &jwtutil.IdentityFenceClaim{
			SourceID:         sourceID,
			SourceGeneration: sourceGeneration,
			LinkID:           linkID,
			LinkGeneration:   linkGeneration,
		},
	}
	user := &userRow{ID: userID, Email: email}

	okResponse := httptest.NewRecorder()
	okRequest := httptest.NewRequest(http.MethodPost, "/auth/totp/verify", nil)
	h.issueTokensFromMFAPending(
		okResponse, okRequest, user, claims, CompletionMetadata{}, token.AMROTP,
	)
	if okResponse.Code != http.StatusOK ||
		!strings.Contains(okResponse.Body.String(), "access_token") {
		t.Fatalf("unchanged normalized fence status=%d body=%s",
			okResponse.Code, okResponse.Body.String())
	}

	if _, err := pool.Exec(ctx,
		`UPDATE identity_sources SET state='paused' WHERE id=$1`, sourceID,
	); err != nil {
		t.Fatalf("pause source between factors: %v", err)
	}
	var before int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM oauth_tokens WHERE user_id=$1`, userID,
	).Scan(&before); err != nil {
		t.Fatalf("count anchors before rejected completion: %v", err)
	}

	rejected := httptest.NewRecorder()
	rejectedRequest := httptest.NewRequest(
		http.MethodPost, "/auth/totp/verify", nil,
	)
	h.issueTokensFromMFAPending(
		rejected, rejectedRequest, user, claims, CompletionMetadata{}, token.AMROTP,
	)
	if rejected.Code == http.StatusOK ||
		strings.Contains(rejected.Body.String(), "access_token") ||
		rejected.Header().Get("Set-Cookie") != "" {
		t.Fatalf("paused source leaked completed session: status=%d headers=%v body=%s",
			rejected.Code, rejected.Header(), rejected.Body.String())
	}
	var after int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM oauth_tokens WHERE user_id=$1`, userID,
	).Scan(&after); err != nil {
		t.Fatalf("count anchors after rejected completion: %v", err)
	}
	if after != before {
		t.Fatalf("paused source completion wrote anchor: before=%d after=%d",
			before, after)
	}
}
