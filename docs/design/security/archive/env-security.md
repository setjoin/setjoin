# Environment Variable Security & First-Boot Secret Generation

## Context

Audit found 3 issues: `.gitignore` lacks `.env`, Go config has hardcoded DB credentials as defaults, `config.env.sample` uses real-looking dev credentials instead of placeholders. Additionally, the user wants first-time deployment to auto-generate all secrets so admins don't need to configure a dozen env vars before using the product.

## Design Principles

1. **Admin only picks their password** — all internal secrets are invisible, auto-generated, and just work.
2. **Idempotent generation** — safe to restart; secrets generated once, never overwritten.
3. **Config file is source of truth** — `/opt/mailserver/config.env`, `chmod 0600`, never in git.
4. **`crypto/rand`** — all generated values are cryptographically secure.

## Fixes (from audit)

### Fix 1: Add `.env` to `.gitignore`

```
.DS_Store
node_modules/
.env
.env.*
!.env.sample
```

### Fix 2: Remove hardcoded DB credentials from Go config defaults

**File:** `mailserver/gateway/internal/config/config.go`

```go
// Before:
DatabaseDSN:    envutil.Getenv("DB_DSN", "postgres://mail:mail@127.0.0.1:5433/mailserver"),
DatabaseDirect: envutil.Getenv("DB_DIRECT_DSN", "postgres://mail:mail@127.0.0.1:5432/mailserver"),

// After:
DatabaseDSN:    envutil.Getenv("DB_DSN", ""),
DatabaseDirect: envutil.Getenv("DB_DIRECT_DSN", ""),
```

Same for authserver `config.go`:
```go
// Before:
DatabaseDSN: envutil.Getenv("DB_DSN", "postgres://localhost:5432/mailserver"),

// After:
DatabaseDSN: envutil.Getenv("DB_DSN", ""),
```

The `validate()` function already checks required fields — adding `DB_DSN` to the required list catches missing config at startup with a clear error message instead of silently connecting to the wrong database.

### Fix 3: Replace default credentials in config.env.sample with placeholders

```
DB_DSN=postgres://user:password@127.0.0.1:5433/mailserver
DB_DIRECT_DSN=postgres://user:password@127.0.0.1:5432/mailserver
MINIO_ACCESS_KEY=change-me
MINIO_SECRET_KEY=change-me
```

## First-Boot Secret Generation

### Detection

Gateway startup checks `system_config` for a `secret_generation_version` key after migrations run. If absent — first boot.

### What gets generated

| Secret | Bits | Stored in | Admin visible? |
|--------|------|-----------|---------------|
| `JWT_SECRET` | 256 | config.env | No |
| `DB_ENCRYPTION_KEY` | 256 | config.env | No |
| `INTERNAL_API_KEY` | 256 | config.env | No |
| `VAPID_PRIVATE_KEY` | ECDSA P-256 | config.env | No |
| `S3_ACCESS_KEY` / `MINIO_ACCESS_KEY` | 160 | config.env + MinIO bootstrap | No |
| `S3_SECRET_KEY` / `MINIO_SECRET_KEY` | 256 | config.env + MinIO bootstrap | No |
| Default admin | — | Admin picks via web UI | Yes |

### How it works

1. Gateway starts → runs migrations → checks for `secret_generation_version` in `system_config`
2. If absent: generates all secrets → writes to `config.env` with `0600` → bootstraps MinIO with the generated access/secret keys → sets `secret_generation_version = 1` in `system_config`
3. If present: reads secrets from `config.env` as normal — skip generation
4. Web setup page (`/setup`) detects no admin user exists → shows "Create your admin account" form
5. Admin enters email + password → account created → redirected to login
6. All internal secrets were never displayed — they just work

### Web setup page changes

Current setup page only handles restore from backup. Add a "Fresh Install" path:

```
┌─────────────────────────────────┐
│  Welcome to Mailserver          │
│                                 │
│  Create your admin account:     │
│                                 │
│  Email:    [________________]   │
│  Password: [________________]   │
│                                 │
│  [Create Account]               │
│                                 │
│  ── or ──                       │
│                                 │
│  [Restore from Backup]          │
└─────────────────────────────────┘
```

After creation → redirect to `/login`. The admin account is created via the existing `ensure_default_admin` flow but with the user-supplied password instead of the `DEFAULT_ADMIN_PASSWORD` env var.

### config.env after generation

```
# Auto-generated on first boot: 2026-05-24T12:00:00Z
# Change these in the Admin Portal under Settings > System

JWT_SECRET=a8Fk2LpQxR9wY3mNvB5cD7eF1gH4iJ6k
DB_ENCRYPTION_KEY=mN8oL3pQxR5sT7uV9wX1yZ2aB4cD6eF
INTERNAL_API_KEY=gH0iJ2kL4mN6oP8qR0sT2uV4wX6yZ8
VAPID_PRIVATE_KEY=base64-encoded-ecdsa-key
MINIO_ACCESS_KEY=generated-20-char-access-key
MINIO_SECRET_KEY=generated-40-char-secret-key
```

## Verification

1. `.env` appears in `.gitignore` — `grep '\.env' .gitignore` returns the entry
2. Go config defaults to empty string — `grep 'postgres://' config.go` returns nothing
3. `config.env.sample` uses placeholders — `grep -E 'mail:mail|minioadmin' config.env.sample` returns nothing
4. First-boot: start gateway without config → `secret_generation_version` appears in `system_config`, all secrets in `config.env`, MinIO bootstrap received the keys
5. Second boot: restart → secrets unchanged, no re-generation
6. Web setup: `curl /setup` with no admin users → shows "Create admin account" form. `curl /setup` with admin exists → returns 404
7. `go test ./...` — all tests pass (ensure no test relies on hardcoded DB DSN default)
