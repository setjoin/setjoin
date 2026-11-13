# mailctl CLI — Design Spec

## Summary

A `kubectl`-style CLI for the mailserver REST API. Two auth modes (API key for automation/AI, JWT login for interactive humans). 25+ subcommands covering user, domain, mailbox, backup, migration, webhook, health, config, quota, DLP, and quarantine management.

---

## Part 1: Architecture

### Binary

Single Go binary: `cmd/mailctl/main.go`. Uses standard library `flag` + subcommand dispatch. No external CLI frameworks — follow the project's minimal-dependency philosophy.

```
mailctl
├── user        create, bulk-create, delete, list, get, password, quota
├── domain      add, list, delete
├── mailbox     create, list, get, delete, delegates
├── backup      run, list, download, delete
├── migration   start, list, status, cancel, pause, resume
├── health      check, version
├── webhook     create, list, delete, rotate-secret, deliveries
├── config      get, set
├── dlp         patterns, update
├── quarantine  list, release, reject
├── login       (interactive JWT login)
└── logout      (clear stored JWT)
```

### Credential Store

`~/.mailctl/config.yaml`:

```yaml
server: https://mail.example.com
auth:
  mode: apikey          # or "jwt"
  api_key: "mctl-abc123..."
  # or
  token: "eyJhbGci..."
  refresh_token: "eyJ..."
```

**Environment variable override (CI/CD):**

```bash
export MAILCTL_SERVER=https://mail.example.com
export MAILCTL_API_KEY=mctl-abc123
```

Precedence: CLI flags > env vars > config file.

`mailctl login https://mail.example.com` prompts for email + password + TOTP (if MFA), stores JWT.
`mailctl logout` clears the JWT.

### Output Formats

All commands support:
- `--json` — JSON output for scripting/AI consumption
- `--table` (default) — human-readable tabular output
- `--quiet` — suppress output, exit 0 on success

### Auth Header

API key mode: `Authorization: Bearer mctl-<hex>` (32-byte random, stored in admin auth)
JWT mode: `Authorization: Bearer <jwt>` (standard web portal JWT)

---

## Part 2: Command Reference

### User Management

```bash
mailctl user create --email alice@local.com --display "Alice" --password "temp123"
mailctl user list [--domain company.com] [--json]
mailctl user get alice@local.com
mailctl user delete alice@local.com
mailctl user password alice@local.com --new-password "newpass"
mailctl user quota alice@local.com --set-bytes 100G --set-count 500
```

### Domain Management

```bash
mailctl domain add company.com
mailctl domain list [--json]
mailctl domain delete company.com
```

### Mailbox Management

```bash
mailctl mailbox create --email sales@company.com --type shared --display "Sales Team"
mailctl mailbox list [--domain company.com] [--type shared] [--json]
mailctl mailbox get sales@company.com
mailctl mailbox delete sales@company.com
mailctl mailbox delegate add sales@company.com --user alice@local.com --permission full_access
mailctl mailbox delegate remove sales@company.com --user alice@local.com
mailctl mailbox delegate list sales@company.com
```

### Backup

```bash
mailctl backup run [--provider s3|oss] [--bucket my-backups]
mailctl backup list [--json]
mailctl backup download <backup-id> --output backup.tar.gz
mailctl backup delete <backup-id>
```

### Migration

```bash
mailctl migration start --type ews --config ews-config.json
mailctl migration start --type imap --config imap-config.json
mailctl migration list [--json]
mailctl migration status <job-id>
mailctl migration cancel <job-id>
mailctl migration pause <job-id>
mailctl migration resume <job-id>
```

### Health

```bash
mailctl health check [--json]
mailctl version
```

### Webhooks

```bash
mailctl webhook create --url https://hooks.example.com --events user.created,auth.login_failed
mailctl webhook list [--json]
mailctl webhook delete <id>
mailctl webhook rotate-secret <id>
mailctl webhook deliveries <id> [--json]
mailctl webhook events
```

### Config

```bash
mailctl config get <key>
mailctl config set <key> <value>
mailctl config list [--prefix feature.] [--json]
```

### DLP

```bash
mailctl dlp patterns [--json]
mailctl dlp update < pattern-updates.json
```

### Quarantine

```bash
mailctl quarantine list [--status held|released] [--json]
mailctl quarantine release <id>
mailctl quarantine reject <id>
```

---

## Part 3: API Key Management

### Admin UI

Admin settings page or a new "API Keys" section. Create/revoke API keys per admin user. Each key gets a `mctl-` prefix and a descriptive label (e.g., "Ansible automation", "CI pipeline").

### Schema

**No new table needed.** Reuse `app_passwords` (already built). API keys are app passwords with a `label`:

```sql
ALTER TABLE app_passwords ADD COLUMN IF NOT EXISTS label TEXT;
```

`app_passwords` already has `user_id`, `token_hash`, `created_at`, `last_used_at`, `revoked_at`. API key format: `mctl-` + 32-byte hex (same as `mail-ap-` pattern). A key with label "CI pipeline" is distinguishable from one named "Thunderbird".

### Authentication Flow

API key auth reuses the existing `CheckAppPassword` path — already wired into SMTP, IMAP, and HTTP. The `adminLimit` middleware protects the REST API. No new auth code needed.

### Handler

No new handler needed. The existing `GET/POST/DELETE /auth/me/app-passwords` already supports create/list/revoke. API keys appear in the settings "App Passwords" section. Admin oversight via the existing `admin_app_passwords.go` handler (already built).

### Schema Redundancy Eliminated

| Before | After |
|--------|-------|
| `admin_api_keys` table (new V022) | Reuse `app_passwords` + `label` column |
| `api_keys.go` handler (new) | Reuse existing `app_passwords.go` handler |
| 2 new files, 1 migration | 0 new files, 0 new migrations |

---

## Part 4: AI-Friendly Design

- `--json` on every command for machine consumption
- Consistent exit codes: 0=success, 1=error, 2=usage
- `mailctl health check --json` returns the exact REST API health response
- `mailctl config list --json` dumps all config keys with descriptions
- No interactive prompts when `--json` is used (all required flags must be provided)
- Stderr for error messages, stdout for structured output — AI agents can parse reliably

---

---

## Part 5: Industry Validation & Refinements

### Comparison

| Pattern | Exchange Online | GAM (Google) | Stalwart | Our Design |
|---------|----------------|-------------|----------|------------|
| Auth | Azure AD + cert | OAuth + SA | Basic or API key | API key + JWT |
| Naming | Verb-Noun (PowerShell) | `gam entity action` | CRUD: get/query/create/update/delete | Subcommand: `mailctl entity action` |
| Bulk ops | CSV via `Import-Csv` | CSV with `~column` vars | JSON apply plan | Add `bulk-create --csv` |
| Infra-as-code | DSC | None built-in | `apply` + `snapshot` | v2: `system apply` + `system snapshot` |
| Env vars | Tenants via modules | None | `STALWART_URL` etc. | Add `MAILCTL_SERVER`, `MAILCTL_API_KEY` |
| Output | Objects (pipeline) | CSV/text redirect | JSON (default) | `--json` / `--table` / `--quiet` |
| Schema discovery | `Get-Command` | None | `describe` (auto-downloads schema) | v2: auto-discover from OpenAPI |

### Added from Research

**Bulk CSV import (GAM pattern):**

```bash
mailctl user bulk-create users.csv
```

CSV format:
```csv
email,display_name,password,quota_bytes
alice@local.com,Alice,temp123,107374182400
bob@local.com,Bob,temp456,53687091200
```

**Environment variable support (CI/CD):**

```bash
export MAILCTL_SERVER=https://mail.example.com
export MAILCTL_API_KEY=mctl-abc123
mailctl user list --json
mailctl health check
```

Same precedence as `kubectl`: flags > env vars > config file.

**v2 deferred: Infrastructure-as-Code**

```
mailctl system snapshot > backup.json   # export all state
mailctl system apply plan.json          # idempotent bulk apply
```

Stalwart's `apply`/`snapshot` pattern. Useful for disaster recovery and GitOps.

---

## Part 6: Security

| # | Measure | Detail |
|---|---------|--------|
| 1 | File permissions | `~/.mailctl/config.yaml` created with `0600`. `mailctl` warns if not owner-only readable. Same as `kubectl`/`.ssh/config`. |
| 2 | Rate limiting | Already covered — admin REST API has `adminLimit` middleware. API key calls hit same routes as web portal. |
| 3 | Env var exposure | `MAILCTL_API_KEY` visible in `/proc/*/environ`. Standard for CLI tools. Documented as acceptable risk. Prefer config file for interactive use. |
| 4 | Token expiry | Deferred to v2 — add optional expiry to app passwords. Same mechanism for IMAP app passwords and CLI API keys. |
| 5 | Server-side audit | Already covered — REST API mutations write `admin_audit_log`. CLI actions are audited identically to web portal actions. |
| 6 | Config file overwrite | On `mailctl login`, if config exists, prompt before overwriting. `--force` flag to skip. |

---

## File Structure

**Simplified: 5 files instead of 18.** API keys reuse existing `app_passwords` infrastructure. Subcommands in a single file until individual commands grow complex.

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `mailserver/cmd/mailctl/main.go` | Entry point + flag parsing + dispatch |
| Create | `mailserver/cmd/mailctl/commands.go` | All subcommands (~30 lines each, ~350 lines total) |
| Create | `mailserver/cmd/mailctl/auth.go` | JWT login + config.yaml read/write + env vars |
| Create | `mailserver/cmd/mailctl/client.go` | HTTP client wrapper (auth header, JSON, error handling) |
| Modify | `mailserver/sql/schema/019_app_passwords.sql` (or migration) | Add `label` column to `app_passwords` |
| — | (no new handler) | Reuses existing `app_passwords.go` + `admin_app_passwords.go` |
| — | (no new routes) | Reuses existing `/auth/me/app-passwords` + `/admin/users/{id}/app-passwords` |
| Modify | `mailserver/webmail/src/routes/settings/+page.svelte` | Add `label` field to app password create form |
