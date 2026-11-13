# Auth & MFA Security Fixes — Design Spec

Date: 2026-06-05
Status: Design

## Goal

Fix 13 auth/MFA security findings from the full-codebase quality audit. These are mechanical fixes across `authserver/internal/handlers/auth.go`, `totp.go`, `webauthn.go`, and the admin `CreateUser` path.

## Fixes

### 1. Backup Code MFA Path — Dead End

**Finding:** Login handler sets `fallback=["backup_codes"]` in MFA response (lines 194, 212). `TOTPVerify` only accepts TOTP codes. `PushMFAVerify` only accepts push answers. `VerifyBackupCode` handler at line 901 requires authentication — can't be called during MFA step. Backup codes are advertised but unusable.

**Fix:** Add `BackupCodeVerify` endpoint — unauthenticated, accepts `{"mfa_token":"...", "code":"..."}`, validates MFA-pending token + backup code, issues access+refresh tokens. Or extend `TOTPVerify` to also accept backup codes.

**File:** `authserver/internal/handlers/auth.go` ~line 901, new handler

### 2. MFA Enforcement Policy Never Called

**Finding:** `mfa_status()` PL/pgSQL function exists in `auth_policy.sql` but is never called by any Go handler. Admin sets `mfa_enforcement_mode='required'` in system_config — users without TOTP/push can still log in with password only.

**Fix:** In Login handler, after password verification but before issuing tokens, call `mfa_status()`. If status is `enrollment_required`, return a `ForcePasswordChange` token redirecting user to MFA setup.

**File:** `authserver/internal/handlers/auth.go` ~line 177

### 3. TOTP Re-Setup Without Verification

**Finding:** `TOTPSetup` overwrites `totp_secret_enc` without requiring current TOTP code or password re-auth. Attacker with stolen access token silently replaces TOTP secret, locking legitimate user out.

**Fix:** Require current TOTP code (or password re-auth) before overwriting TOTP secret. Log the event to `admin_audit_log`.

**File:** `authserver/internal/handlers/totp.go` line 19

### 4. Password History Not Checked

**Finding:** `ChangePassword` has no check against previously used passwords. No `password_history` table exists. Users can cycle back to old passwords.

**Fix:** Add `password_history(user_id, password_hash, created_at)` table. Before accepting new password, bcrypt-compare against last N entries (default 5). Insert new hash on success.

**File:** `authserver/internal/handlers/auth.go` line 322, new migration

### 5. must_change_password Flag Ignored

**Finding:** `verifyPassword` (line 793) queries `id/email/is_admin/password_hash/TOTP/Push` but ignores `must_change_password`. User with this flag set can still log in normally.

**Fix:** Query `must_change_password` in `verifyPassword`. In Login handler, after password verification, if flag is true, issue `TypeForcePasswordChange` token instead of normal access token.

**File:** `authserver/internal/handlers/auth.go` lines 793-808, ~177

### 6. New Password Same as Old Not Rejected

**Finding:** `ChangePassword` doesn't compare new_password against old_password. bcrypt hash differs but password is semantically unchanged.

**Fix:** After `bcrypt.CompareHashAndPassword` succeeds for old_password, compare `req.NewPassword != req.OldPassword` and reject with specific error.

**File:** `authserver/internal/handlers/auth.go` line 322

### 7. Common/Weak Password Check Missing

**Finding:** `validate_password()` PL/pgSQL only checks length + character classes. Passwords like 'Password1!' pass all checks.

**Fix:** Add `common_passwords` lookup table (top 10k leaked passwords, bcrypt-hashed). Before accepting new password, check its hash against the table. Also check password doesn't contain user's email or display_name.

**Files:** `authserver/internal/handlers/auth.go` line 322, `mailserver/sql/reducers/auth_policy.sql` line 7, new migration

### 8. Refresh Token INSERT Error Ignored

**Finding:** `issueTokens` (line 836) doesn't check error from `INSERT INTO oauth_tokens`. If INSERT fails, the refresh token in the JSON response is invalid — no matching hash in DB. User gets unrecoverable session.

**Fix:** Check `Exec` error. If non-nil, log error and return 500. Do not encode refresh token in response.

**File:** `authserver/internal/handlers/auth.go` line 836

### 9. User-Not-Found Unlogged in verifyPassword

**Finding:** When user query returns no rows (line 807), `verifyPassword` returns error without logging. Only bcrypt failures are logged. Brute-force attempts against non-existent accounts leave no audit trail.

**Fix:** In verifyPassword, when user not found, call `pwhash.LogAuthEvent` with `event='login_failed'`, `provider='bcrypt'`, `email=the_attempted_email`, before returning error.

**File:** `authserver/internal/handlers/auth.go` line 807

### 10. WebAuthn Leaks Raw Go Errors

**Finding:** `WebAuthnRegisterBegin` (line 27) returns `http.Error(w, "webauthn error: " + err.Error(), 500)`. Same at lines 65, 80, 132, 223, 245. Internal library errors and DB errors exposed to client.

**Fix:** Replace with `WriteProblem(w, r, &Problem{Type: TypeInternalError, ...})`. Log actual error server-side. This also applies the RFC 7807 standard from Spec B.

**File:** `authserver/internal/handlers/webauthn.go` lines 27, 65, 80, 132, 223, 245

### 11. JIT Creates Non-ASCII Username

**Finding:** `createJITUser` (line 735) uses `parts[0]` (email local part) directly as both `username` AND `display_name`. For Chinese SAML assertion `张三@company.com`, creates `username='张三'` with no ASCII fallback.

**Fix:** Apply Spec A email policy: if local part contains CJK, generate pinyin user_name. Store original display_name separately. Reject or auto-convert if domain policy requires ASCII local parts.

**File:** `authserver/internal/handlers/auth.go` line 735

### 12. TOTP Secret Changes Unlogged

**Finding:** No audit log entries for TOTP setup, confirmation, or disable events. Security-sensitive operation with no record.

**Fix:** Write to `admin_audit_log` on: `totp_setup_initiated`, `totp_confirmed`, `totp_disabled`, `totp_secret_changed`. Include user_id and timestamp.

**File:** `authserver/internal/handlers/totp.go`

### 13. Admin CreateUser Ignores Password Policy

**Finding:** Admin CreateUser handler checks `len(req.Password) >= 8` (hardcoded) but ignores the configurable password policy from `system_config` (min_length, uppercase, lowercase, digit, special). Auth server's `PasswordPolicy` endpoint reads these — admin handler does not.

**Fix:** Import `shared/validate/password.go` from Spec A. Call `validate.Password(req.Password, policy)` before creating user.

**File:** `mailserver/internal/admin/admin_users.go` line 146

## New Tables

### password_history

| Column | Type | Purpose |
|--------|------|---------|
| id | BIGSERIAL PK | |
| user_id | BIGINT NOT NULL REFERENCES users(id) | |
| password_hash | TEXT NOT NULL | bcrypt hash of old password |
| created_at | TIMESTAMPTZ DEFAULT now() | |
| INDEX on (user_id, created_at DESC) | | |

Keeps last N entries per user (default 5). Older entries cleaned by retention job.

### common_passwords

| Column | Type | Purpose |
|--------|------|---------|
| id | BIGSERIAL PK | |
| password_hash | TEXT NOT NULL UNIQUE | bcrypt hash of common password |

Seeded with top 10k common passwords. Checked during password validation: `SELECT EXISTS(SELECT 1 FROM common_passwords WHERE password_hash = crypt($1, password_hash))`.

## References

- `authserver/internal/handlers/auth.go` — Login, Refresh, ChangePassword, verifyPassword, issueTokens, createJITUser
- `authserver/internal/handlers/totp.go` — TOTP setup, confirm, verify
- `authserver/internal/handlers/webauthn.go` — WebAuthn registration, login
- `mailserver/sql/reducers/auth_policy.sql` — validate_password PL/pgSQL function
- `mailserver/internal/admin/admin_users.go` — CreateUser handler
- `shared/validate/password.go` — Spec A password validator
- `shared/httputil/problem.go` — Spec B RFC 7807 error responses
