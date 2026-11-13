# Forgot Password Flow — Design Spec

> **Phase:** 16.7.3.4 — Self-service password reset via MFA
> **Status:** Design approved, awaiting implementation
> **Scope:** Auth server endpoints + schema; no webmail UI changes

## Motivation

Currently, users who forget their password must contact an administrator, who resets it
via `POST /admin/users/{id}/reset-password` (admin_users.go). This is the only path.
Stalwart takes the same approach. Gmail and Office 365 offer self-service reset via
pre-registered second factors — we now have TOTP and push MFA, so we can do the same.

## Design

Three new endpoints on the auth server. All are `POST`. All pass through the existing
threat interceptor pipeline (spray detection, lockout escalation, CAPTCHA, tarpit, rate limit).

### Flow

```
POST /auth/forgot-password/begin   { email }
    │
    │  Constant-time response — no user enumeration.
    │  User not found or MFA not enabled → "If an account with that email exists
    │  and has multi-factor authentication enabled, a verification challenge has
    │  been sent."
    │  User found + TOTP enabled  → { method: "totp" }
    │  User found + push enabled  → { method: "push", challenge_nonce: "..." }
    │
POST /auth/forgot-password/verify  { email, code | push_nonce }
    │
    │  Threat interceptor counts failures per source IP + target username.
    │  Wrong code → "Invalid verification code." (constant time)
    │  Correct    → { reset_token: "<JWT>" }
    │
POST /auth/forgot-password/reset   { email, reset_token, new_password }
    │
    │  JWT validation: type=password_reset, sub=user_id, exp ≤ now+5min
    │  Single-use check: token_hash NOT IN used_password_reset_tokens
    │  validate_password(new_password, is_admin) — reuses existing PG function
    │  bcrypt.GenerateFromPassword(new_password, DefaultCost)
    │  RevokeAllTokens(user_id)
    │  INSERT INTO audit_log (event_type='password_reset')
    │  INSERT INTO used_password_reset_tokens (token_hash)
    │  → 200 { message: "Password has been reset." }
```

### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/auth/forgot-password/begin` | No | Check email, return available MFA method |
| `POST` | `/auth/forgot-password/verify` | No | Verify MFA code, issue reset token |
| `POST` | `/auth/forgot-password/reset` | No | Consume reset token, set new password |

### Reset Token (JWT)

Signed with the same HMAC-SHA256 key (`JWT_SECRET`). Claims:

| Claim | Value |
|-------|-------|
| `sub` | `user_id` (string) |
| `type` | `"password_reset"` |
| `iat` | Issued at |
| `exp` | `iat + 5 minutes` |
| `jti` | Random 32-byte hex — used for single-use tracking |

### Single-Use Enforcement

```sql
CREATE UNLOGGED TABLE used_password_reset_tokens (
    token_hash  TEXT PRIMARY KEY,  -- SHA-256 hex of the JWT string
    used_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- pg_cron: prune tokens older than 10 minutes every 5 minutes
```

Verification: `INSERT INTO used_password_reset_tokens (token_hash) VALUES ($1) ON CONFLICT DO NOTHING`.
If `rows affected = 0`, token was already used — reject.

### Password Policy Reuse

`/reset` calls the existing `validate_password(password, is_admin)` PG function,
which enforces the same rules as `ChangePassword`:

| Parameter | Config key | Default |
|-----------|-----------|---------|
| Minimum length | `password_min_length` | 8 |
| Require uppercase | `password_require_uppercase` | true |
| Require lowercase | `password_require_lowercase` | true |
| Require digit | `password_require_digit` | true |
| Require special | `password_require_special` | true |

### Feature Toggles

| Key | Default | Description |
|-----|---------|-------------|
| `feature.forgot_password` | true | Master switch — disable to revert to admin-only reset |
| `feature.forgot_password_push` | true | Enable push MFA as a verification method; disable to force TOTP-only |

Push MFA is opt-out. If `forgot_password_push` is false, `/begin` only offers TOTP
even if the user has push devices registered.

### Security Properties

- **No user enumeration**: `/begin` returns identical body and timing for missing users,
  users without MFA, and valid users. Same 200 status code in all cases.
- **No MFA bypass**: User must complete TOTP or push MFA to obtain a reset token.
- **Single-use tokens**: `used_password_reset_tokens` table with PK constraint prevents replay.
- **Short-lived tokens**: 5-minute JWT expiry. Table rows pruned after 10 minutes.
- **Session eviction**: All existing tokens revoked on reset — same `RevokeAllTokens()`
  called by `ChangePassword`. An attacker who triggered the reset loses any stolen sessions.
- **Existing threat pipeline**: Spray detection, lockout escalation, CAPTCHA, tarpit,
  and rate limiting all apply to `/begin` and `/verify` — same as login.
- **Constant-time comparisons**: `hmac.Equal()` for token hash lookup. No early return
  in user lookup path.
- **No recovery email needed**: Verification is via pre-registered MFA, not a link sent
  to an alternate inbox. No schema change to `users`.
- **Audit trail**: `audit_log` entries for begin, verify_failed, verify_success, reset.

### Files

| File | Lines | Purpose |
|------|-------|---------|
| `authserver/internal/handlers/forgot_password.go` | ~180 | Begin, Verify, Reset handlers |
| `authserver/sql/migrations/V025__forgot_password.sql` | ~30 | `used_password_reset_tokens` table + feature toggle seeds + pg_cron job |
| `authserver/cmd/authserver/main.go` | ~15 | Route registration (3 routes, threat-wrapped) |
| **Total** | **~225** | **3 files** |

### Non-goals

- Email recovery link (requires new `recovery_email` column — add later if needed)
- SMS verification (no SMS infrastructure)
- Admin UI toggle page (already exists at `/admin/features` — pick up new toggles automatically)
- Webmail self-service page (deferred — admin reset via existing admin panel covers the gap)

### References

- OWASP Forgot Password Cheat Sheet — token hashing, single-use, constant-time, MFA preservation
- NIST SP 800-63B §5.1.1 — memorized secret verifiers (bcrypt minimum)
- OWASP ASVS v4.0.3 §2.5 — Credential Recovery requirements
