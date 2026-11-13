package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/authserver/internal/token"
)

// ── Login status-code regression suite ──────────────────────────────────────
//
// Pins two Login (auth.go) branches by their HTTP status code:
//   - an MFA-enrolled user's valid password submits into a step-up challenge:
//     202 Accepted + mfa_token (never a plain 200 — that would skip the second
//     factor entirely).
//   - a force-password-change gate (must_change_password = TRUE): 403
//     Forbidden + force_token (never 200/202 — that would grant access before
//     the required change).

func TestLogin_MFAEnabledUser_Returns202WithMFAToken(t *testing.T) {
	pool := openHandlerPool(t)
	ctx := context.Background()
	ensureEnrollmentLocalDomain(t, pool)

	jwt := newTestJWT()
	h := NewAuthHandler(AuthHandlerConfig{
		Pool:   pool,
		JWT:    jwt,
		Logger: discardLogger(),
	})

	const (
		email = "login-mfa-regression@example.com"
		pw    = "Login-MFA-Regr3ss10n!"
	)
	hash, err := bcryptHashForTest(pw)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	var userID int64
	err = pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, sync_source, enabled,
		                    password_hash, totp_enabled)
		 SELECT $1, $1, 'MFA Regression User', id, 'local', TRUE, $2, TRUE
		 FROM domains WHERE is_local = TRUE
		 ORDER BY id LIMIT 1
		 RETURNING id`,
		email, hash,
	).Scan(&userID)
	if err != nil {
		t.Skipf("could not seed test user (schema/domains not loaded?): %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID) })

	body, _ := json.Marshal(map[string]string{"email": email, "password": pw})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	// Bug: a plain 200 here would mean the user was granted full tokens
	// WITHOUT the enrolled second factor ever being challenged.
	if rr.Code != http.StatusAccepted {
		t.Fatalf("MFA-enabled user login: want 202, got %d — %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		MFARequired bool   `json:"mfa_required"`
		MFAToken    string `json:"mfa_token"`
		Status      string `json:"status"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rr.Body.String())
	}
	if !resp.MFARequired {
		t.Error(`response must carry "mfa_required": true`)
	}
	if resp.MFAToken == "" {
		t.Error(`response must carry a non-empty "mfa_token"`)
	} else {
		claims, err := jwt.Validate(resp.MFAToken)
		if err != nil {
			t.Fatalf("validate mfa_token: %v", err)
		}
		if claims.CredentialFence == "" {
			t.Fatal("password-first MFA token omitted its credential-version fence")
		}
	}
	if resp.Status != "mfa_required" {
		t.Errorf(`status = %q, want "mfa_required"`, resp.Status)
	}

	// The 202 body must NOT contain full access/refresh tokens — that would be
	// the pre-MFA-gate bug (full access granted on password alone).
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err == nil {
		if _, ok := raw["access_token"]; ok {
			t.Error("202 mfa_required response must not include access_token")
		}
		if _, ok := raw["refresh_token"]; ok {
			t.Error("202 mfa_required response must not include refresh_token")
		}
	}
}

func TestLogin_MFARequiredUserReturnsEnrollmentChallenge(t *testing.T) {
	pool := openHandlerPool(t)
	ctx := context.Background()
	ensureEnrollmentLocalDomain(t, pool)
	jwt := newTestJWT()
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: jwt, Logger: discardLogger(),
	})
	const (
		email = "login-mfa-enrollment-required@example.com"
		pw    = "Login-MFA-Enr0llment!"
	)
	hash, err := bcryptHashForTest(pw)
	if err != nil {
		t.Fatal(err)
	}
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users(
		     username,email,display_name,domain_id,sync_source,enabled,
		     password_hash,totp_enabled,push_mfa_enabled,mfa_exempt
		 )
		 SELECT $1,$1,'MFA Enrollment Required',id,'local',TRUE,
		        $2,FALSE,FALSE,FALSE
		   FROM domains WHERE is_local=TRUE ORDER BY id LIMIT 1
		 RETURNING id`,
		email, hash,
	).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM users WHERE id=$1`, userID)
	})

	body, _ := json.Marshal(map[string]string{"email": email, "password": pw})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("enrollment-required login status=%d, want 403: %s",
			rec.Code, rec.Body.String())
	}
	var response struct {
		Status      string `json:"status"`
		MFARequired bool   `json:"mfa_required"`
		MFAToken    string `json:"mfa_token"`
		Reason      string `json:"reason"`
		Message     string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "mfa_enrollment_required" ||
		!response.MFARequired || response.MFAToken == "" ||
		response.Reason != "enrollment_required" || response.Message == "" {
		t.Fatalf("enrollment response=%+v", response)
	}
	claims, err := jwt.Validate(response.MFAToken)
	if err != nil || claims.Type != token.TypeMFAPending ||
		claims.CredentialFence == "" {
		t.Fatalf("enrollment token claims=%+v err=%v", claims, err)
	}
}

func TestLoginFailsClosedWhenMFAPolicyCannotBeRead(t *testing.T) {
	seedPool := openHandlerPool(t)
	ctx := context.Background()
	ensureEnrollmentLocalDomain(t, seedPool)
	const (
		email = "login-mfa-policy-unavailable@example.com"
		pw    = "Login-MFA-Policy-Unavailable!"
	)
	hash, err := bcryptHashForTest(pw)
	if err != nil {
		t.Fatal(err)
	}
	var userID int64
	if err := seedPool.QueryRow(ctx,
		`INSERT INTO users(
		     username,email,display_name,domain_id,sync_source,enabled,
		     password_hash,totp_enabled,push_mfa_enabled,mfa_exempt
		 )
		 SELECT $1,$1,'MFA Policy Unavailable',id,'local',TRUE,
		        $2,FALSE,FALSE,TRUE
		   FROM domains WHERE is_local=TRUE ORDER BY id LIMIT 1
		 RETURNING id`,
		email, hash,
	).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = seedPool.Exec(context.Background(),
			`DELETE FROM users WHERE id=$1`, userID)
	})

	cfg, err := pgxpool.ParseConfig(liveDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 1
	var acquisitions atomic.Int32
	cfg.BeforeAcquire = func(context.Context, *pgx.Conn) bool {
		return acquisitions.Add(1) == 1
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
	})
	body, _ := json.Marshal(map[string]string{"email": email, "password": pw})
	requestCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(
		http.MethodPost, "/auth/login", bytes.NewReader(body),
	).WithContext(requestCtx)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("MFA policy outage status=%d, want 503: %s",
			rec.Code, rec.Body.String())
	}
}

func TestLogin_ForcePasswordChange_Returns403(t *testing.T) {
	pool := openHandlerPool(t)
	ctx := context.Background()
	ensureEnrollmentLocalDomain(t, pool)

	h := NewAuthHandler(AuthHandlerConfig{
		Pool:   pool,
		JWT:    newTestJWT(),
		Logger: discardLogger(),
	})

	const (
		email = "login-forcechange-regression@example.com"
		pw    = "Login-ForceChange-Regr3ss10n!"
	)
	hash, err := bcryptHashForTest(pw)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	var userID int64
	err = pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, sync_source, enabled,
		                    password_hash, must_change_password)
		 SELECT $1, $1, 'Force Change Regression User', id, 'local', TRUE, $2, TRUE
		 FROM domains WHERE is_local = TRUE
		 ORDER BY id LIMIT 1
		 RETURNING id`,
		email, hash,
	).Scan(&userID)
	if err != nil {
		t.Skipf("could not seed test user (schema/domains not loaded?): %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID) })

	body, _ := json.Marshal(map[string]string{"email": email, "password": pw})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	// Bug: a 200/202 here would grant (or half-grant) access before the
	// mandatory password change, bypassing the admin-forced gate entirely.
	if rr.Code != http.StatusForbidden {
		t.Fatalf("force-password-change user login: want 403, got %d — %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Status              string `json:"status"`
		ForcePasswordChange bool   `json:"force_password_change"`
		ForceToken          string `json:"force_token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rr.Body.String())
	}
	if resp.Status != "force_password_change" {
		t.Errorf(`status = %q, want "force_password_change"`, resp.Status)
	}
	if !resp.ForcePasswordChange {
		t.Error(`response must carry "force_password_change": true`)
	}
	if resp.ForceToken == "" {
		t.Error(`response must carry a non-empty "force_token"`)
	}
}
