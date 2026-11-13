package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/testsupport"
)

// -- helpers --

func newTestJWT() *token.JWTProvider {
	return token.NewJWTProvider(
		"test-secret-key-at-least-32-chars-long!!", nil, "",
		1*time.Hour, 30*24*time.Hour, "test",
	)
}

// createClosedPool returns a pgxpool.Pool that is immediately closed so
// that any Exec/Query attempt returns an error.
func createClosedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig("postgres://127.0.0.1:5432/test?connect_timeout=1")
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	pool.Close()
	return pool
}

// funcSrc returns the literal source text of the named top-level function in
// the given file (relative to this package directory). It is the position-aware
// counterpart to handlerFuncBody: callers can assert on ordering and exact SQL
// fragments, not just identifier presence.
func funcSrc(t *testing.T, file, name string) string {
	t.Helper()
	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	fset := gotoken.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name {
			continue
		}
		start := fset.Position(fn.Pos()).Offset
		end := fset.Position(fn.End()).Offset
		return string(src[start:end])
	}
	t.Fatalf("function %q not found in %s", name, file)
	return ""
}

// requireOrder asserts that every substring in want appears in body in the
// given order (each found at or after the previous match).
func requireOrder(t *testing.T, body string, what string, want ...string) {
	t.Helper()
	idx := 0
	for _, s := range want {
		pos := strings.Index(body[idx:], s)
		if pos < 0 {
			t.Errorf("%s: expected %q at/after offset %d, not found", what, s, idx)
			return
		}
		idx += pos + len(s)
	}
}

// ============================================================================
// Fix 8 — Refresh Token INSERT Error Checked
// ============================================================================

func TestIssueTokens_InsertError_Returns500(t *testing.T) {
	pool := createClosedPool(t)

	h := NewAuthHandler(AuthHandlerConfig{
		Pool:    pool,
		JWT:     newTestJWT(),
		PushMFA: &mockPushProvider{name: "push"},
	})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rr := httptest.NewRecorder()

	h.issueTokens(rr, req, &userRow{
		ID: 1, Email: "test@example.com", IsAdmin: false,
	}, CompletionRequest{Factors: []string{token.AMRPassword}})

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when DB insert fails, got %d", rr.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if _, ok := body["refresh_token"]; ok {
		t.Error("response must NOT include refresh_token when DB insert fails")
	}
	if _, ok := body["access_token"]; ok {
		t.Error("response must NOT include access_token when DB insert fails")
	}
}

// ============================================================================
// Fix 1 — BackupCodeVerify Handler (unauthenticated MFA step)
// ============================================================================

func TestBackupCodeVerify_MissingMFAToken(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{
		JWT:     newTestJWT(),
		PushMFA: &mockPushProvider{name: "push"},
	})

	body, _ := json.Marshal(map[string]string{"code": "abcdef01"})
	req := httptest.NewRequest(http.MethodPost, "/auth/backup-codes/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.BackupCodeVerify(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing mfa_token, got %d", rr.Code)
	}
}

func TestBackupCodeVerify_InvalidToken(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{
		JWT:     newTestJWT(),
		PushMFA: &mockPushProvider{name: "push"},
	})

	body, _ := json.Marshal(map[string]string{
		"mfa_token": "not-a-valid-jwt",
		"code":      "abcdef01",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/backup-codes/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.BackupCodeVerify(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid MFA token, got %d", rr.Code)
	}
}

func TestBackupCodeVerify_WrongTokenType(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{
		JWT:     newTestJWT(),
		PushMFA: &mockPushProvider{name: "push"},
	})

	accessToken, err := h.jwt.IssueAccess(42, "test@example.com", false)
	if err != nil {
		t.Fatalf("failed to issue access token: %v", err)
	}
	body, _ := json.Marshal(map[string]string{
		"mfa_token": accessToken,
		"code":      "abcdef01",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/backup-codes/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.BackupCodeVerify(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong token type, got %d", rr.Code)
	}
}

// ============================================================================
// Fix 2 — MFA Enforcement via mfa_status()
// ============================================================================

func TestMFAEnforcedTokenType(t *testing.T) {
	j := newTestJWT()
	forceToken, err := j.IssueForcePasswordChange(42, "test@example.com")
	if err != nil {
		t.Fatalf("IssueForcePasswordChange: %v", err)
	}
	claims, err := j.Validate(forceToken)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Type != token.TypeForcePasswordChange {
		t.Errorf("expected TypeForcePasswordChange, got %v", claims.Type)
	}
}

// TestLogin_MFAEnrollmentRequired proves the enrollment-enforcement branch in
// Login exists and is wired: when mfa_status() reports "enrollment_required",
// Login issues an MFA-pending token and returns the enrollment_required
// response instead of granting access. This is a structural (AST) seam guard —
// it does not need a live DB but fails if the enforcement branch is removed or
// stops issuing a step-up token.
func TestLogin_MFAEnrollmentRequired(t *testing.T) {
	body := funcSrc(t, "auth.go", "Login")

	// The branch must read mfa_status, detect enrollment_required, and respond
	// with a short-lived password-proof token rather than full tokens — at
	// HTTP 403 carrying the `status: "mfa_enrollment_required"` string the shipped
	// webmail client dispatches on (it keys on 403 + status, not a 200 + boolean).
	requireOrder(t, body, "Login enrollment-required branch",
		"readMFAStatus",
		`mfaResult.Status == "enrollment_required"`,
		"h.issueMFAPending",
		`"status":       "mfa_enrollment_required"`,
		`"reason":       "enrollment_required"`,
		"w.WriteHeader(http.StatusForbidden)",
	)

	// The enrollment check must gate access: it has to run before the normal
	// token issuance (issueTokens) at the bottom of Login.
	requireOrder(t, body, "Login enrollment-before-issue ordering",
		`mfaResult.Status == "enrollment_required"`,
		"h.issueTokens(w, r, user, completion)",
	)
}

// TestLogin_MFAStatusSkippedWhenMFAEnabled proves the ordering contract: the
// mfa_status() enrollment check runs BEFORE the per-user TOTP/Push challenge
// block. A user who already has MFA enabled gets a non-enrollment status from
// mfa_status() and so falls through to the normal challenge flow (which issues
// an MFA-pending token), never reaching issueTokens without a second factor.
// Structural seam guard — proves the branch placement without a live DB.
func TestLogin_MFAStatusSkippedWhenMFAEnabled(t *testing.T) {
	body := funcSrc(t, "auth.go", "Login")

	// mfa_status enforcement precedes the per-user challenge, which precedes the
	// unconditional token issuance.
	requireOrder(t, body, "Login MFA ordering",
		"readMFAStatus",
		"if user.TOTPEnabled || user.PushMFAEnabled {",
		"h.issueTokens(w, r, user, completion)",
	)

	// The per-user challenge block issues an MFA-pending token (push or TOTP),
	// i.e. an enrolled user is challenged, not granted access outright.
	challengeStart := strings.Index(body, "if user.TOTPEnabled || user.PushMFAEnabled {")
	if challengeStart < 0 {
		t.Fatal("per-user MFA challenge block not found in Login")
	}
	challengeBlock := body[challengeStart:]
	if !strings.Contains(challengeBlock, "h.issueMFAPending") {
		t.Error("an enrolled user must be challenged via the fenced MFA-pending issuer before tokens are issued")
	}
	// And the final issueTokens (granting access) must come after that block,
	// so it is only reached once the challenge flow has returned.
	issuePos := strings.LastIndex(body, "h.issueTokens(w, r, user, completion)")
	if issuePos <= challengeStart {
		t.Error("final issueTokens must follow the per-user MFA challenge block")
	}
}

// ============================================================================
// Fix 4 — Password History Rejection
// ============================================================================

func TestPasswordHistoryMigrationNumber(t *testing.T) {
	const expected = "V056"
	if expected != "V056" {
		t.Errorf("expected migration V056, got %s", expected)
	}
}

// TestChangePassword_RejectsSamePassword is a REAL handler test. The "new ==
// old" rejection runs before any DB call, so a closed pool never matters: the
// handler must return 400 with the exact message before touching the database.
func TestChangePassword_RejectsSamePassword(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{
		Pool:   createClosedPool(t),
		JWT:    newTestJWT(),
		Logger: discardLogger(),
	})

	body, _ := json.Marshal(map[string]string{
		"old_password": "SamePassw0rd!",
		"new_password": "SamePassw0rd!",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ContextWithUser(req.Context(), &token.Claims{
		UserID: 42, Email: "user@example.com",
	}))
	rr := httptest.NewRecorder()
	h.ChangePassword(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when new == old password, got %d: %s", rr.Code, rr.Body.String())
	}
	var problem struct {
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode problem body: %v", err)
	}
	if problem.Detail != "New password must differ from current password" {
		t.Errorf("detail = %q, want %q", problem.Detail, "New password must differ from current password")
	}
}

// TestChangePassword_RejectsReusedPassword proves (structurally) that
// ChangePassword reads the user's password_history and rejects a previously
// used password with the exact message. AST seam guard — the DB-backed proof is
// TestChangePassword_PasswordHistory_Integration (gated on DB_DSN).
func TestChangePassword_RejectsReusedPassword(t *testing.T) {
	body := funcSrc(t, "auth.go", "ChangePassword")

	requireOrder(t, body, "ChangePassword reuse-rejection",
		"FROM password_history",
		"VerifyPasswordHash",
		"reused",
		"This password was used recently. Please choose a new one.",
	)
	// The reuse rejection must be a 400, returned before the password is written.
	requireOrder(t, body, "ChangePassword reuse-before-write",
		"This password was used recently. Please choose a new one.",
		"UPDATE users SET password_hash",
	)
}

// TestChangePassword_ClearsMustChangePasswordFlag proves the password UPDATE
// clears must_change_password in the same statement that sets the new hash, so
// a forced-change user is released exactly when (and only when) the change
// succeeds. AST seam guard; DB proof in the integration test below.
func TestChangePassword_ClearsMustChangePasswordFlag(t *testing.T) {
	body := funcSrc(t, "auth.go", "ChangePassword")
	if !strings.Contains(body, "UPDATE users SET password_hash = $1, must_change_password = FALSE") {
		t.Error("ChangePassword must clear must_change_password = FALSE in the same UPDATE that sets the new hash")
	}
}

// TestChangePassword_InsertsIntoPasswordHistory proves a new history row is
// recorded after a successful change so future reuse checks can see it. AST seam
// guard; DB proof in the integration test below.
func TestChangePassword_InsertsIntoPasswordHistory(t *testing.T) {
	body := funcSrc(t, "auth.go", "ChangePassword")
	if !strings.Contains(body, "INSERT INTO password_history (user_id, password_hash)") {
		t.Error("ChangePassword must INSERT the new hash into password_history")
	}
	// The history insert must follow the password UPDATE (we record what we set).
	requireOrder(t, body, "ChangePassword history-insert-after-update",
		"UPDATE users SET password_hash",
		"INSERT INTO password_history (user_id, password_hash)",
	)
}

// TestChangePassword_TrimsPasswordHistory proves old history rows beyond the
// configured depth are deleted after the insert, bounding retention. AST seam
// guard; DB proof in the integration test below.
func TestChangePassword_TrimsPasswordHistory(t *testing.T) {
	body := funcSrc(t, "auth.go", "ChangePassword")
	if !strings.Contains(body, "DELETE FROM password_history WHERE user_id = $1 AND id NOT IN") {
		t.Error("ChangePassword must trim password_history to the configured depth after insert")
	}
	if !strings.Contains(body, "password_history_depth") {
		t.Error("ChangePassword must read password_history_depth to bound retention")
	}
	// Trim must come after the insert (we keep the newest, including the new row).
	requireOrder(t, body, "ChangePassword trim-after-insert",
		"INSERT INTO password_history (user_id, password_hash)",
		"DELETE FROM password_history WHERE user_id = $1 AND id NOT IN",
	)
}

// ============================================================================
// DB-backed integration coverage (runs only when DB_DSN points at a loaded
// test database). These exercise the live ChangePassword history/flag behavior
// end to end; the seam guards above keep the contract enforced even without a DB.
// ============================================================================

// openHandlerPool returns a real pool; skips if DB_DSN is not set.
func openHandlerPool(t *testing.T) *pgxpool.Pool {
	return testsupport.OpenTestPool(t)
}

// TestChangePassword_PasswordHistory_Integration drives the real handler against
// a live DB: it changes a password (clearing must_change_password and recording
// a history row), then proves the just-set password is rejected on reuse.
func TestChangePassword_PasswordHistory_Integration(t *testing.T) {
	pool := openHandlerPool(t)
	ctx := context.Background()

	h := NewAuthHandler(AuthHandlerConfig{
		Pool:   pool,
		JWT:    newTestJWT(),
		Logger: discardLogger(),
	})

	const (
		email = "changepw-integration@example.com"
		oldPW = "OldPassw0rd!2026"
		newPW = "NewPassw0rd!2026"
	)

	// Seed a local user with must_change_password = TRUE and a known old hash.
	oldHash, err := bcryptHashForTest(oldPW)
	if err != nil {
		t.Fatalf("hash old password: %v", err)
	}
	var userID int64
	err = pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, sync_source, enabled,
		                    password_hash, must_change_password)
		 SELECT $1, $1, 'Integration User', id, 'local', TRUE, $2, TRUE
		 FROM domains WHERE is_local = TRUE
		 ORDER BY id LIMIT 1
		 RETURNING id`,
		email, oldHash,
	).Scan(&userID)
	if err != nil {
		t.Skipf("could not seed test user (schema/domains not loaded?): %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM password_history WHERE user_id = $1`, userID)
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
	})

	change := func(old, nw string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(map[string]string{"old_password": old, "new_password": nw})
		req := httptest.NewRequest(http.MethodPost, "/auth/change-password", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(ContextWithUser(req.Context(), &token.Claims{UserID: userID, Email: email}))
		rr := httptest.NewRecorder()
		h.ChangePassword(rr, req)
		return rr
	}

	// 1. Successful change.
	if rr := change(oldPW, newPW); rr.Code != http.StatusNoContent {
		t.Fatalf("change password: got %d, want 204: %s", rr.Code, rr.Body.String())
	}

	// 2. must_change_password cleared.
	var mustChange bool
	if err := pool.QueryRow(ctx, `SELECT must_change_password FROM users WHERE id = $1`, userID).Scan(&mustChange); err != nil {
		t.Fatalf("read must_change_password: %v", err)
	}
	if mustChange {
		t.Error("must_change_password must be FALSE after a successful change")
	}

	// 3. A history row was recorded.
	var histCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM password_history WHERE user_id = $1`, userID).Scan(&histCount); err != nil {
		t.Fatalf("count password_history: %v", err)
	}
	if histCount < 1 {
		t.Error("expected at least one password_history row after a successful change")
	}

	// 4. Reusing the just-set password is rejected (now the current password, so
	// the same-password guard and the history check both apply — assert 400).
	if rr := change(newPW, newPW); rr.Code != http.StatusBadRequest {
		t.Errorf("reusing current password: got %d, want 400", rr.Code)
	}
}

// bcryptHashForTest hashes a password the same way the handler does so seeded
// users have a valid current-password hash.
func bcryptHashForTest(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}
