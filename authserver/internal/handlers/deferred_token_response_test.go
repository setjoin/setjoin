package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/testsupport"
)

type commitFailureTx struct{ pgx.Tx }

func (commitFailureTx) Commit(context.Context) error {
	return errors.New("injected caller-owned transaction commit failure")
}

func TestCommitDeferredTokenResponseDoesNotLeakOnCommitFailure(t *testing.T) {
	pending := newDeferredTokenResponse()
	pending.Header().Add("Set-Cookie", "access_token=secret")
	pending.Header().Set("Content-Type", "application/json")
	pending.WriteHeader(http.StatusOK)
	_, _ = pending.Write([]byte(`{"access_token":"secret","refresh_token":"secret"}`))

	dst := httptest.NewRecorder()
	committed, err := commitDeferredTokenResponse(
		context.Background(),
		dst,
		pending,
		func(context.Context) error { return errors.New("injected commit failure") },
	)
	if err == nil || committed {
		t.Fatalf("commit result = (%v, %v), want (false, error)", committed, err)
	}
	if dst.Code != http.StatusOK || dst.Body.Len() != 0 || len(dst.Header()) != 0 {
		t.Fatalf("commit failure leaked response: status=%d headers=%v body=%q",
			dst.Code, dst.Header(), dst.Body.String())
	}
}

func TestCommitDeferredTokenResponseDoesNotLeakAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pending := newDeferredTokenResponse()
	http.SetCookie(pending, &http.Cookie{Name: "access_token", Value: "secret"})
	_, _ = pending.Write([]byte(`{"access_token":"secret"}`))

	dst := httptest.NewRecorder()
	committed, err := commitDeferredTokenResponse(
		ctx,
		dst,
		pending,
		func(ctx context.Context) error { return ctx.Err() },
	)
	if !errors.Is(err, context.Canceled) || committed {
		t.Fatalf("commit result = (%v, %v), want (false, context canceled)", committed, err)
	}
	if dst.Body.Len() != 0 || len(dst.Header()) != 0 {
		t.Fatalf("cancellation leaked response: headers=%v body=%q",
			dst.Header(), dst.Body.String())
	}
}

func TestCommitDeferredTokenResponsePublishesOnlyAfterCommit(t *testing.T) {
	pending := newDeferredTokenResponse()
	pending.Header().Add("Set-Cookie", "access_token=committed")
	_, _ = pending.Write([]byte(`{"access_token":"committed"}`))
	commitCalled := false

	dst := httptest.NewRecorder()
	committed, err := commitDeferredTokenResponse(
		context.Background(),
		dst,
		pending,
		func(context.Context) error {
			if dst.Body.Len() != 0 || len(dst.Header()) != 0 {
				t.Fatal("response became visible before commit")
			}
			commitCalled = true
			return nil
		},
	)
	if err != nil || !committed || !commitCalled {
		t.Fatalf("commit result = (%v, %v), called=%v", committed, err, commitCalled)
	}
	if !strings.Contains(dst.Body.String(), "committed") ||
		dst.Header().Get("Set-Cookie") == "" {
		t.Fatalf("committed response missing: headers=%v body=%q",
			dst.Header(), dst.Body.String())
	}
}

func TestCommitDeferredTokenResponseFlushesFailureWithoutCommit(t *testing.T) {
	pending := newDeferredTokenResponse()
	pending.Header().Set("Content-Type", "application/problem+json")
	pending.WriteHeader(http.StatusConflict)
	_, _ = pending.Write([]byte(`{"detail":"identity changed"}`))
	commitCalled := false

	dst := httptest.NewRecorder()
	committed, err := commitDeferredTokenResponse(
		context.Background(),
		dst,
		pending,
		func(context.Context) error {
			commitCalled = true
			return nil
		},
	)
	if err != nil || committed || commitCalled {
		t.Fatalf("failure result=(%v,%v), commitCalled=%v",
			committed, err, commitCalled)
	}
	if dst.Code != http.StatusConflict ||
		!strings.Contains(dst.Body.String(), "identity changed") {
		t.Fatalf("failure response not flushed: status=%d body=%q",
			dst.Code, dst.Body.String())
	}
}

func TestCallerOwnedCompletionCommitFailureDoesNotPublishOrPersistAnchor(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	userID := seedSSOTestActorDB(t, pool, ctx, "completion-commit-failure")
	defer cleanSSOActor(t, pool, ctx, userID)
	var email string
	if err := pool.QueryRow(ctx, `SELECT email FROM users WHERE id=$1`, userID).
		Scan(&email); err != nil {
		t.Fatalf("read completion actor: %v", err)
	}
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
	})

	for _, tt := range []struct {
		name    string
		factors []string
	}{
		{"normalized-sso", []string{token.AMRPassword}},
		{"fenced-totp-enrollment", []string{token.AMRPassword, token.AMROTP}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin caller-owned transaction: %v", err)
			}
			defer tx.Rollback(ctx) //nolint:errcheck
			failing := commitFailureTx{Tx: tx}
			pending := newDeferredTokenResponse()
			h.issueTokensWithFactors(
				pending,
				httptest.NewRequest(http.MethodPost, "/auth/"+tt.name, nil),
				&userRow{ID: userID, Email: email},
				CompletionRequest{
					Factors: tt.factors,
					Metadata: CompletionMetadata{
						ConditionalAccess: CompletionConditionalAccess{Evaluated: true},
						MintTx:            failing,
					},
				},
			)
			if !pending.successful() {
				t.Fatalf("issuance did not reach tentative success: status=%d body=%s",
					pending.status, pending.body.String())
			}
			var body struct {
				AccessToken string `json:"access_token"`
			}
			if err := json.Unmarshal(pending.body.Bytes(), &body); err != nil {
				t.Fatalf("decode tentative response: %v", err)
			}
			claims, err := h.jwt.Validate(body.AccessToken)
			if err != nil {
				t.Fatalf("validate tentative access token: %v", err)
			}
			var inside, outside int
			if err := tx.QueryRow(ctx,
				`SELECT count(*) FROM oauth_tokens WHERE user_id=$1 AND family_id=$2::uuid`,
				userID, claims.FamilyID,
			).Scan(&inside); err != nil {
				t.Fatalf("count tentative anchor: %v", err)
			}
			if err := pool.QueryRow(ctx,
				`SELECT count(*) FROM oauth_tokens WHERE user_id=$1 AND family_id=$2::uuid`,
				userID, claims.FamilyID,
			).Scan(&outside); err != nil {
				t.Fatalf("count externally visible anchor: %v", err)
			}
			if inside != 1 || outside != 0 {
				t.Fatalf("anchor visibility inside/outside=%d/%d want 1/0", inside, outside)
			}

			dst := httptest.NewRecorder()
			committed, err := commitDeferredTokenResponse(ctx, dst, pending, failing.Commit)
			if err == nil || committed {
				t.Fatalf("commit result=(%v,%v), want false,error", committed, err)
			}
			if dst.Body.Len() != 0 || len(dst.Header()) != 0 {
				t.Fatalf("commit failure leaked response headers=%v body=%q",
					dst.Header(), dst.Body.String())
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatalf("rollback tentative anchor: %v", err)
			}
			if err := pool.QueryRow(ctx,
				`SELECT count(*) FROM oauth_tokens WHERE user_id=$1 AND family_id=$2::uuid`,
				userID, claims.FamilyID,
			).Scan(&outside); err != nil {
				t.Fatalf("count anchor after rollback: %v", err)
			}
			if outside != 0 {
				t.Fatalf("commit failure persisted %d refresh-family anchors", outside)
			}
		})
	}
}
