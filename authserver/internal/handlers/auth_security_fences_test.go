package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

type mfaStatusFakeRow struct {
	raw []byte
	err error
}

func (r mfaStatusFakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	target, ok := dest[0].(*json.RawMessage)
	if !ok {
		return errors.New("unexpected scan target")
	}
	*target = append((*target)[:0], r.raw...)
	return nil
}

type mfaStatusFakeQuerier struct {
	row pgx.Row
}

func (q mfaStatusFakeQuerier) QueryRow(context.Context, string, ...any) pgx.Row {
	return q.row
}

func TestReadMFAStatusFailsClosedOnUnavailableOrMalformedPolicy(t *testing.T) {
	tests := []struct {
		name string
		row  pgx.Row
	}{
		{"query error", mfaStatusFakeRow{err: errors.New("database unavailable")}},
		{"malformed json", mfaStatusFakeRow{raw: []byte(`{`)}},
		{"unknown status", mfaStatusFakeRow{raw: []byte(`{"status":"allow"}`)}},
		{"missing status", mfaStatusFakeRow{raw: []byte(`{"error":"user not found"}`)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := readMFAStatus(
				context.Background(), mfaStatusFakeQuerier{row: tt.row}, 42,
			); err == nil {
				t.Fatal("unprovable MFA policy must fail closed")
			}
		})
	}

	valid, err := readMFAStatus(
		context.Background(),
		mfaStatusFakeQuerier{row: mfaStatusFakeRow{
			raw: []byte(`{"status":"enrollment_required","message":"enroll"}`),
		}},
		42,
	)
	if err != nil || valid.Status != "enrollment_required" || valid.Message != "enroll" {
		t.Fatalf("valid MFA result rejected: %+v, %v", valid, err)
	}
}

func TestCredentialFenceRejectsPasswordHashChangedAfterProof(t *testing.T) {
	pool := openHandlerPool(t)
	ctx := context.Background()
	var domainID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM domains LIMIT 1`).Scan(&domainID); err != nil {
		t.Skipf("no test domain: %v", err)
	}

	oldHash, err := bcrypt.GenerateFromPassword([]byte("Fence-Old-Password!1"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte("Fence-New-Password!2"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users(username,email,display_name,domain_id,password_hash,enabled)
		 VALUES ('credential-fence-test','credential-fence-test@example.com',
		         'Credential Fence Test',$1,$2,TRUE)
		 RETURNING id`,
		domainID, string(oldHash),
	).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, userID) }) //nolint:errcheck

	proof := credentialFenceForPasswordHash(string(oldHash))
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT identity_auth_local_mint_fence($1)`, userID); err != nil {
		t.Fatalf("acquire mint fence: %v", err)
	}
	if err := verifyCredentialFence(ctx, tx, userID, proof); err != nil {
		t.Fatalf("current credential proof rejected: %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(ctx, `UPDATE users SET password_hash=$1 WHERE id=$2`, string(newHash), userID); err != nil {
		t.Fatalf("change credential: %v", err)
	}
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT identity_auth_local_mint_fence($1)`, userID); err != nil {
		t.Fatalf("acquire mint fence after change: %v", err)
	}
	if err := verifyCredentialFence(ctx, tx, userID, proof); err == nil {
		t.Fatal("stale password proof remained valid after credential change")
	}
}

func TestIdentityAndCredentialFenceInputValidation(t *testing.T) {
	ctx := context.Background()
	if err := applyIdentityFenceClaim(ctx, nil, 42, nil); err != nil {
		t.Fatalf("nil identity fence = %v, want no-op", err)
	}
	for _, fence := range []*jwtutil.IdentityFenceClaim{
		{},
		{SourceID: 1, SourceGeneration: 1, LinkID: 1},
	} {
		if err := applyIdentityFenceClaim(ctx, nil, 42, fence); err == nil {
			t.Fatalf("invalid identity fence %+v unexpectedly accepted", fence)
		}
	}
	if err := verifyCredentialFence(ctx, nil, 42, ""); err != nil {
		t.Fatalf("empty credential fence = %v, want no-op", err)
	}
}

func TestCredentialFenceFailsClosedWhenIdentityDisappears(t *testing.T) {
	pool := openHandlerPool(t)
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background()) //nolint:errcheck
	if err := verifyCredentialFence(
		context.Background(), tx, 9_223_372_036_854_000_000, "stale-proof",
	); err == nil {
		t.Fatal("missing identity unexpectedly satisfied credential fence")
	}
}

func TestDefaultIdentityElevationBeginFailsClosedOnStoreError(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: createClosedPool(t), JWT: newTestJWT(), Logger: discardLogger(),
	})
	err := h.identityLinkElevationBegin(
		context.Background(),
		identityLinkFlow{
			UserID: 42, FlowID: "00000000-0000-0000-0000-000000000001",
			SessionJTI: "session", Kind: "oidc", ProviderKey: "provider",
			ExpiresAt: time.Now().Add(time.Minute).Unix(),
		},
		[]byte("session-hash"),
	)
	if err == nil {
		t.Fatal("closed identity elevation store unexpectedly succeeded")
	}
}

func TestIssuanceRejectsInvalidIdentityAndStaleCredentialFences(t *testing.T) {
	pool := openHandlerPool(t)
	ctx := context.Background()
	userID := seedSSOTestActorDB(t, pool, ctx, "issuance-fence-errors")
	defer cleanSSOActor(t, pool, ctx, userID)
	user := &userRow{
		ID: userID, Email: "issuance-fence-errors@sso-test.internal",
	}
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
	})

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	rec := httptest.NewRecorder()
	h.issueTokensWithFactors(rec, req, user, CompletionRequest{
		Factors:  []string{token.AMRPassword},
		Metadata: CompletionMetadata{IdentityFence: &jwtutil.IdentityFenceClaim{}},
	})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("invalid identity fence status=%d, want 500: %s",
			rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/auth/totp/verify", nil)
	rec = httptest.NewRecorder()
	h.issueTokensFromMFAPending(
		rec, req, user,
		&token.Claims{
			AMR:             []string{token.AMRPassword},
			CredentialFence: "stale-password-proof",
		},
		CompletionMetadata{},
		token.AMROTP,
	)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("stale credential fence status=%d, want 401: %s",
			rec.Code, rec.Body.String())
	}
}

func TestIssuanceFailsClosedWhenMintTransactionCannotBegin(t *testing.T) {
	cfg, err := pgxpool.ParseConfig(liveDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 1
	var acquisitions atomic.Int32
	cfg.BeforeAcquire = func(context.Context, *pgx.Conn) bool {
		return acquisitions.Add(1) <= 2
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.issueTokensWithFactors(
		rec, req, &userRow{ID: 42, Email: "cancelled-mint@example.com"},
		CompletionRequest{Factors: []string{token.AMRPassword}},
	)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("cancelled mint transaction status=%d, want 503: %s",
			rec.Code, rec.Body.String())
	}
}

func TestSSOSettlementFailsClosedOnProfileAndAuthorizationReload(t *testing.T) {
	pool := openHandlerPool(t)
	ctx := context.Background()
	userID := seedSSOTestActorDB(t, pool, ctx, "sso-settlement-errors")
	defer cleanSSOActor(t, pool, ctx, userID)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
	})

	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/callback", nil)
	rec := httptest.NewRecorder()
	h.settleSSOMappingsThenIssue(
		rec, req,
		&userRow{
			ID: userID, Email: "sso-settlement-errors@sso-test.internal",
		},
		"attacker@example.com\nX-Injected: yes",
		nil, nil, "oidc",
	)
	if rec.Code != http.StatusConflict {
		t.Fatalf("invalid SSO profile status=%d, want 409: %s",
			rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/auth/oidc/callback", nil)
	rec = httptest.NewRecorder()
	h.settleSSOMappingsThenIssue(
		rec, req,
		&userRow{
			ID: 9_223_372_036_854_000_000, Email: "missing@example.com",
		},
		"", nil, nil, "oidc",
	)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing authorization reload status=%d, want 503: %s",
			rec.Code, rec.Body.String())
	}

	hWithNormalizedEntitlements := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
		Toggles: toggle.NewTestFlags(map[string]bool{
			toggle.FeatureIdentityModelV2: true,
		}),
	})
	req = httptest.NewRequest(http.MethodPost, "/auth/oidc/callback", nil)
	rec = httptest.NewRecorder()
	hWithNormalizedEntitlements.settleSSOMappingsThenIssue(
		rec, req,
		&userRow{
			ID: userID, Email: "sso-settlement-errors@sso-test.internal",
		},
		"", nil, newNoMappings("oidc"), "oidc",
	)
	if rec.Code != http.StatusConflict {
		t.Fatalf("unbound normalized entitlement status=%d, want 409: %s",
			rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/auth/oidc/callback", nil)
	rec = httptest.NewRecorder()
	h.settleSSOMappingsThenIssue(
		rec, req,
		&userRow{
			ID: userID, Email: "sso-settlement-errors@sso-test.internal",
			IdentitySourceID:         9_223_372_036_854_000_000,
			IdentitySourceGeneration: 1,
			IdentityLinkID:           9_223_372_036_854_000_000,
			IdentityLinkGeneration:   1,
		},
		"", nil, nil, "oidc",
	)
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale normalized fence status=%d, want 409: %s",
			rec.Code, rec.Body.String())
	}

	workerCfg, err := pgxpool.ParseConfig(liveDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	workerCfg.MaxConns = 1
	var workerAcquisitions atomic.Int32
	workerCfg.BeforeAcquire = func(context.Context, *pgx.Conn) bool {
		return workerAcquisitions.Add(1) == 1
	}
	boundedWorker, err := pgxpool.NewWithConfig(context.Background(), workerCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(boundedWorker.Close)
	hWithClosedWorker := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, DatabaseWorker: pgxutil.WorkerPool{Pool: boundedWorker},
		JWT: newTestJWT(), Logger: discardLogger(),
	})
	workerCtx, cancelWorker := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancelWorker()
	req = httptest.NewRequest(
		http.MethodPost, "/auth/oidc/callback", nil,
	).WithContext(workerCtx)
	rec = httptest.NewRecorder()
	hWithClosedWorker.settleSSOMappingsThenIssue(
		rec, req,
		&userRow{
			ID: userID, Email: "sso-settlement-errors@sso-test.internal",
			IdentitySourceID:         1,
			IdentitySourceGeneration: 1,
			IdentityLinkID:           1,
			IdentityLinkGeneration:   1,
		},
		"", nil, nil, "oidc",
	)
	if rec.Code != http.StatusServiceUnavailable ||
		!strings.Contains(rec.Body.String(), "identity mint fence unavailable") {
		t.Fatalf("unavailable worker fence response status=%d, want 503 mint-fence error: %s",
			rec.Code, rec.Body.String())
	}
}

func TestChangePasswordRejectsDisabledIdentityAtMintFence(t *testing.T) {
	pool := openHandlerPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	email := "change-password-fence-" + randSuffix() + "@example.com"
	userID := seedLocalUser(t, pool, email)
	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET enabled=FALSE WHERE id=$1`, userID,
	); err != nil {
		t.Fatal(err)
	}
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
	})
	body := strings.NewReader(
		`{"old_password":"Old-Passw0rd!","new_password":"New-Fenced-Passw0rd!"}`,
	)
	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", body)
	req = req.WithContext(ContextWithUser(
		req.Context(), &token.Claims{UserID: userID, Email: email},
	))
	rec := httptest.NewRecorder()
	h.ChangePassword(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled change-password status=%d, want 503: %s",
			rec.Code, rec.Body.String())
	}
}

func TestMFAPendingCarriesCredentialFence(t *testing.T) {
	provider := newTestJWT()
	const want = "opaque-password-version-digest"
	raw, err := provider.IssueMFAPendingWithFences(
		42, "fence@example.com", nil, want, token.AMRPassword,
	)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := provider.Validate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if claims.CredentialFence != want {
		t.Fatalf("credential fence=%q, want %q", claims.CredentialFence, want)
	}
}
