> Superseded by retired-docs:superpowers/specs/2026-06-21-conditional-email-address-policy-design.md (shipped 2026-06).

# Validation Layer & Email Address Policy — Design Spec

Date: 2026-06-05
Status: Design

## Goal

Build a shared validation layer (JS → Go → DB) for every user-input field in the system, and implement an Exchange-style email address policy with CJK→ASCII prefix auto-generation (pinyin). Fix the 40+ critical/high validation-related findings from the full-codebase quality audit.

## Architecture

Three-layer validation: JS (UX), Go (authoritative security), DB CHECK constraints (defense-in-depth). All Go validators share the same interface:

```go
func ValidateXxx(input string, opts ...XxxOptions) error
// Returns nil if valid, non-nil *ValidationError if not.
// ValidationError includes: Field, Value (truncated/sanitized), Reason, Code
```

Every handler that rejects input logs the rejection to `admin_audit_log`.

## Validation Catalog

### Email

| Layer | Implementation | Behavior |
|-------|---------------|----------|
| JS | `isEmail()` in `validation.ts` | RFC 5321 regex, max 254 chars, reject consecutive dots, spaces |
| Go | `validate.Email()` | `net/mail.ParseAddress`, reject empty/overlong/invalid. Configurable: reject non-ASCII local-part (per-domain SMTPUTF8 flag). |
| DB | CHECK constraint | `email ~* '^[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}$'` |

Applied to: `users.email`, `aliases.email`, `mailboxes.email_field`, `contacts.email_jsonb`

### Domain

Go-only: `validate.Domain()` — RFC 1035 hostname. Reject spaces, empty segments, >253 chars, no dot, leading/trailing hyphens. No DB CHECK (domain names can be IDN).

### Display Name

- Go: `validate.DisplayName()` — reject empty-after-trim, only whitespace, control chars (\x00-\x1f), max 128 chars. CJK/emoji/Unicode OK.
- JS: `validateDisplayName()` — trim check, maxLength(128).

### User Name (别名 — SMTP Prefix)

- Go: `validate.UserName()` — ASCII only (a-z, A-Z, 0-9, dot, hyphen, underscore), min 1, max 64, reject consecutive dots, leading/trailing dots/hyphens, reserved words (postmaster, abuse, etc.)
- Auto-generated from display name via pinyin when CJK detected. Latin names use `given.surname`. Duplicate resolution: append 01, 02, etc.
- Unique per domain via: `UNIQUE(domain_id, lower(user_name))`

### Resource Names (departments, folders, groups, tags)

- Go: `validate.ResourceName()` — reject empty, '/', '\', null bytes, '.' or '..' as entire name, max 128 chars.
- DB: CHECK constraint preventing empty strings.

### Password

- Go: `validate.Password(password, policy)` — configurable min length, character classes, check against `common_passwords` table, reject if contains user's email/display_name.
- No JS layer (passwords validated server-side only).

## Email Address Policy

### Per-domain policy stored in `domains.email_policy` (JSONB)

```json
{
  "primary_template": "{user_name}@{domain}",
  "additional_templates": ["{given_name}.{surname}@{domain}"],
  "duplicate_resolution": "number_suffix",
  "auto_generate_user_name": true,
  "user_name_max_length": 64
}
```

### Template variables

| Variable | Source | Example (Chinese) | Example (English) |
|----------|--------|-------------------|-------------------|
| `{user_name}` | users.user_name (别名) | zhangsan | john.smith |
| `{given_name}` | users.given_name | san | john |
| `{surname}` | users.surname | zhang | smith |
| `{first_initial}` | First char of given_name | s | j |
| `{domain}` | domains.name | company.com | company.com |

### Pinyin auto-generation (via github.com/mozillazg/go-pinyin)

```
CJK display name "张三"
  → go-pinyin: zhang, san
  → given_name=san, surname=zhang, user_name=zhangsan

Latin display name "John Smith"  
  → split on space: given=John, surname=Smith
  → user_name=john.smith

Duplicate check: SELECT user_name FROM users WHERE domain_id=$1 AND user_name LIKE $2
  → zhangsan → exists? → zhangsan01 → exists? → zhangsan02 ✓
```

### Admin UI

Domain settings page gets an "Email Address Policy" section:
- Template editor with variable insertion
- Additional address toggles with add/remove
- Duplicate resolution dropdown (number suffix / random / reject)
- Live preview with test name
- "Apply to all existing users" action (regenerates additional addresses only, never primaries)

### User creation flow

1. Admin types display name
2. System auto-fills given_name + surname (pinyin or Latin split)
3. System auto-generates user_name (editable)
4. System previews all SMTP addresses from domain policy
5. Admin confirms or overrides user_name
6. System creates user with all addresses as aliases

## Database Changes

### New columns on `users`
- `given_name TEXT` — Latin/pinyin given name
- `surname TEXT` — Latin/pinyin surname
- `user_name TEXT` — ASCII alias, unique per domain

### New constraints
- CHECK on `users.email`, `aliases.email`, `mailboxes.email_field`
- CHECK on `users.user_name` (ASCII only)
- UNIQUE on `users.domain_id, lower(users.user_name)`
- CHECK on `departments.name` (non-empty)
- `common_passwords` lookup table (top 10k, bcrypt hashed)

### New JSONB column on `domains`
- `email_policy JSONB` — per-domain address policy

## New Package Structure

```
shared/validate/
  validate.go          — ValidationError type
  email.go             — ValidateEmail
  domain.go            — ValidateDomain
  displayname.go       — ValidateDisplayName
  username.go          — ValidateUserName + pinyin
  resourcename.go      — ValidateResourceName
  password.go          — ValidatePassword + common check
  i18n/pinyin.go       — CJK detection + go-pinyin wrapper
  i18n/latin.go        — Latin name parsing
  validate_test.go
```

## Audit Trail

Every validation rejection logs to `admin_audit_log`:
```json
{
  "event_type": "validation_failed",
  "field": "email",
  "value_sanitized": "not-an-email",
  "reason": "missing @ character",
  "handler": "CreateUser"
}
```

Sanitized values: email truncated to 100 chars, passwords never logged, display names truncated to 50 chars.

## Performance

- JS validation: <0.1ms (regex + length checks)
- Go validation: <50µs per call (net/mail.ParseAddress is the slowest)
- DB CHECK: inline during INSERT, microseconds (PostgreSQL regex on bounded-length strings)
- Pinyin generation: ~1ms (one-time during user creation, not per-request)
- Zero measurable impact on request latency

## References

- Exchange Online Email Address Policies: template variables %g, %s, %m, %1g
- RFC 5321 (SMTP), RFC 5322 (Internet Message Format), RFC 6531 (SMTPUTF8)
- `github.com/mozillazg/go-pinyin` — pure Go Chinese pinyin library
- `shared/validate/` — new shared package following `shared/cryptokey/` pattern
- `docs/standards/DATABASE_SECURITY.md` — constraint patterns
- Audit findings: 40+ critical/high validation gaps from `docs/plans/archive/quality-audit-2026-06-05.md`
