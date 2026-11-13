# Input Validation Design

## Context

Form audit across 30+ forms found ~40 fields with zero validation. The compose modal — the most-used form — has no `required`, `maxlength`, or format checks on any field. Password rules exist in `system_config` with a PL/pgSQL enforcer, but the frontend has no way to read them and hardcodes `minlength="8"`. Upload size limits are hardcoded at 50MB in the JMAP session handler rather than reading from config.

## Design Principles (from OWASP 2025-2026)

1. **Reject invalid, don't sanitize to fix** — if data doesn't match the allowlist, reject it. Normalize (trim, Unicode NFC) but never "clean" bad data into acceptability.
2. **Server-side validation is mandatory** — client-side is UX convenience; the Go layer is the canonical enforcement point.
3. **Allowlist, not denylist** — validate against what IS acceptable, not known-bad patterns.
4. **Validate at every trust boundary** — form fields, URL params, file uploads, API bodies.
5. **Defense in depth** — HTML5 attributes + JS validation + Go handlers + PL/pgSQL constraints.

## Architecture: Three-Layer Defense

```
Layer 1: HTML5 attributes         → browser-native guard (maxlength, type, required, minlength)
Layer 2: JS validation library    → user-friendly errors, Prism-styled, config-aware
Layer 3: Go + PL/pgSQL            → canonical enforcement, cannot be bypassed
```

Layers 1-2 are UX. Layer 3 is security. An attacker with curl bypasses layers 1-2 entirely.

## Frontend: Validation Library

**New file:** `mailserver/webmail/src/lib/validation.ts`

### Types

```typescript
type Validator = (value: string) => string | null;  // null = valid

type Rules = Record<string, Validator[]>;

type ValidationResult =
  | { valid: true }
  | { valid: false; errors: Record<string, string> };
```

### Built-in Validators

| Factory | Default error message |
|---------|----------------------|
| `required(msg?)` | "This field is required" |
| `maxLength(n, msg?)` | "Must be at most n characters" |
| `minLength(n, msg?)` | "Must be at least n characters" |
| `isEmail(msg?)` | "Invalid email format" |
| `isURL(msg?)` | "Invalid URL format" |
| `isNumber(msg?)` | "Must be a number" |
| `matches(pattern, msg)` | Custom message required |

Every factory accepts an optional `msg` parameter for context-specific messages.

### Usage Pattern (Every Form)

```typescript
import { validate, required, maxLength, isEmail, normalize } from '$lib/validation';

let fields = $state({ email: '', subject: '' });
let errors = $state<Record<string, string>>({});

function handleSubmit() {
    errors = {};
    const normalized = Object.fromEntries(
        Object.entries(fields).map(([k, v]) => [k, normalize(v)])
    );
    const result = validate({
        email:   [required('Email is required'), isEmail(), maxLength(254)],
        subject: [required('Subject is required'), maxLength(998)],
    }, normalized);
    if (!result.valid) { errors = result.errors; return; }
    // proceed...
}
```

Template per-field:
```svelte
<input type="email" bind:value={fields.email} maxlength="254"
       class:input-error={errors.email} />
{#if errors.email}<span class="field-error">{errors.email}</span>{/if}
```

### `normalize()`

Pre-validation normalization only. Does NOT "fix" bad data:
- Trim leading/trailing whitespace
- Strip null bytes (`\x00`)
- Unicode NFC normalization
- Does NOT strip HTML tags, SQL fragments, or escaping — rejects those via validators

### Dynamic Config

Some validators read limits from server config rather than hardcoding:

**Upload/attachment size** — from JMAP session capabilities:
```typescript
const caps = getSessionCapabilities();
const MAX_UPLOAD = caps.maxSizeUpload;  // admin-configurable, defaults to 50MB
```

**Password policy** — from `GET /auth/password-policy`:
```typescript
let policy = $state<PasswordPolicy>({ minLength: 8, requireUppercase: true, ... });
onMount(async () => {
    policy = await fetch('/auth/password-policy').then(r => r.json());
});
```

**Error messages include the live config value**, so if admin changes max upload to 100MB, users see "maximum 100 MB" without a code change.

## Max Length Reference Table

Every limit has a documented source — shown in error messages and in the reference doc:

| Field | Limit | Source |
|-------|-------|--------|
| Email address | 254 chars | RFC 5321 §4.5.3.1 max reverse path |
| Email subject | 998 chars | RFC 2822 §2.1.1 max header field |
| Display name | 255 chars | Database `VARCHAR(255)` column |
| Password | 128 chars | bcrypt 72-byte input limit + safety margin |
| Calendar title | 255 chars | Database column + CalDAV `SUMMARY` limit |
| Calendar description | 10000 chars | Practical UI limit |
| Location (event) | 255 chars | Database column |
| Contact notes | 5000 chars | Practical UI limit |
| Phone number | 32 chars | ITU E.164 + extension |
| Company / job title / dept | 128 chars | Database `VARCHAR(128)` |
| URL fields | 2048 chars | Common browser URL bar limit |
| File attachment | Config-driven | Gateway `MAX_UPLOAD_SIZE` (default 50MB) |
| Email body | Config-driven | JMAP `maxSizeAttachmentsPerEmail` minus attachment overhead |
| Mailbox name | 255 chars | Database column |
| Domain name | 253 chars | RFC 1035 max FQDN |
| Rule/DLP name | 128 chars | Database column |
| DLP regex | 1000 chars | ReDoS protection + DB column |

## XSS Prevention

Svelte auto-escapes `{expression}` in templates — free protection for all plain text fields. The only risk is `{@html}` usage.

**Existing protection:** `sanitizeHTML()` in `$lib/sanitize.ts` wraps DOMPurify with a hardened config.

**Audit requirement:** Every `{@html}` site must be paired with `sanitizeHTML()`. The reference doc includes a grep command:
```bash
grep -rn '{@html' mailserver/webmail/src/ | grep -v 'sanitizeHTML\|DOMPurify'
```
Any output is a vulnerability and must be fixed.

**Current `{@html}` sites:**
- `inbox/+page.svelte` — email body via `<iframe srcdoc={sanitizedHTML}>` (safe)
- `ComposeModal.svelte` — Quill editor (sanitizes internally)

No additional DOMPurify work needed — existing `sanitizeHTML` coverage is complete.

## Go Backend Validation

**New helper in `shared/httputil`:**

```go
type FieldError struct {
    Field   string `json:"field"`
    Message string `json:"message"`
}

func WriteValidationErrors(w http.ResponseWriter, errors []FieldError) {
    WriteJSON(w, http.StatusUnprocessableEntity, map[string]any{
        "error":  "Validation failed",
        "fields": errors,
    })
}
```

Handler pattern — validate at boundary, before any business logic:
```go
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
    var req createUserRequest
    json.NewDecoder(r.Body).Decode(&req)

    var fe []FieldError
    if req.Email == "" {
        fe = append(fe, FieldError{"email", "Email is required"})
    } else if !isEmail(req.Email) || len(req.Email) > 254 {
        fe = append(fe, FieldError{"email", "Invalid email format"})
    }
    if req.Password != "" && len(req.Password) < 8 {
        fe = append(fe, FieldError{"password", "Password must be at least 8 characters"})
    }
    if req.DisplayName != "" && len(req.DisplayName) > 255 {
        fe = append(fe, FieldError{"displayName", "Display name is too long (maximum 255 characters)"})
    }
    if len(fe) > 0 {
        slog.Warn("validation failed", "errors", fe)
        WriteValidationErrors(w, fe)
        return
    }
    // proceed...
}
```

Frontend parses structured errors:
```typescript
catch (e) {
    if (e.fields) {
        errors = Object.fromEntries(e.fields.map(f => [f.field, f.message]));
    } else {
        error = parseError(e).message;
    }
}
```

**Endpoints receiving server-side validation:**

| Endpoint | Fields validated |
|----------|-----------------|
| `POST /admin/users` | email, password, displayName |
| `PUT /admin/users/{id}` | displayName |
| `POST /admin/domains` | domain name |
| `POST /admin/mailboxes` | name, quota |
| `POST /admin/departments` | name, ldapOu |
| `POST /admin/rules` | name, regex |
| `POST /auth/me/migration` | imapHost, imapPort, imapUser |
| `POST /setup/preflight` | provider, bucket, accessKey |
| `POST /setup/restore` | bucket, backupPath |

Internal JMAP handlers validate through PL/pgSQL constraints — no additional Go layer needed.

## New Endpoint: `GET /auth/password-policy`

No auth required (needed on login/registration page). Returns current policy from `system_config`:

```json
{
  "minLength": 8,
  "requireUppercase": true,
  "requireLowercase": true,
  "requireDigit": true,
  "requireSpecial": true
}
```

Reads from `system_config` table — admin changes take effect immediately, no restart. The existing `validate_password()` PL/pgSQL function already reads from the same config keys.

## JMAP Session — Read Limits from Config

Currently hardcoded in `jmap.go`. The JMAP session handler should read from gateway config:

```go
// Before:
"maxSizeUpload": 52428800,  // hardcoded 50MB

// After:
"maxSizeUpload": h.cfg.MaxUploadSize,
```

The frontend already calls `loadSession()` on mount and caches the session. Validators read `session.capabilities['urn:ietf:params:jmap:core'].maxSizeUpload` to get the live limit.

## Before/After Summary — Every Form

| Form | File | Fields added | Validation |
|------|------|-------------|------------|
| **Login** | `routes/+page.svelte` | email, password, newPassword, confirmPassword | Already good — add dynamic policy |
| **MFA verify** | `routes/+page.svelte` | totpCode | Already good (maxlength=6) |
| **Setup** | `routes/setup/+page.svelte` | bucket, accessKey, secretKey | Add isURL to endpoint, maxLength to keys |
| **Compose** | `lib/components/ComposeModal.svelte` | to, cc, bcc, subject, attachments | Required, email format, maxLength, file size |
| **Calendar event** | `routes/calendar/+page.svelte` | title, dates, attendees, location, description | Email per-attendee, end-after-start, maxLengths |
| **Calendar scheduling** | `routes/calendar/+page.svelte` | attendees, duration | Email validation per attendee |
| **Contact** | `routes/contacts/+page.svelte` | displayName, emails[], phones[], notes, company | Email/phone validation, maxLengths |
| **Contact photo** | `routes/contacts/+page.svelte` | file | Image type only, max 5MB |
| **Task** | `routes/tasks/+page.svelte` | title, description, categories[] | Required title, maxLengths |
| **Recover** | `routes/recover/+page.svelte` | (checkboxes only) | Confirm dialog exists — sufficient |
| **Settings: TOTP** | `routes/settings/+page.svelte` | totpConfirmCode | Already good (maxlength=6) |
| **Settings: IMAP** | `routes/settings/+page.svelte` | imapSeparator | Already constrained (select) |
| **Settings: Migration** | `routes/settings/migration/+page.svelte` | imapHost, imapPort, customPort, imapUser, imapPass | Required, port range 1-65535, host max 253 |
| **Settings: Migration upload** | `routes/settings/migration/+page.svelte` | ics-file, vcf-file | File extension .ics/.vcf only, max 25MB |
| **Settings: Rules** | `routes/settings/rules/+page.svelte` | template params | Already use required attribute per-template |
| **Admin: Users create** | `routes/admin/users/+page.svelte` | email, password, displayName | Email format, password policy, maxLengths |
| **Admin: Users edit** | `routes/admin/users/+page.svelte` | displayName, department | maxLengths |
| **Admin: Users password** | `routes/admin/users/+page.svelte` | newPassword | Dynamic password policy |
| **Admin: Users aliases** | `routes/admin/users/+page.svelte` | newAlias | Email format, maxLength |
| **Admin: Users quota** | `routes/admin/users/+page.svelte` | quotaBytes, sendQuota | Positive integers |
| **Admin: Users import** | `routes/admin/users/+page.svelte` | csv file | .csv extension, max 10MB |
| **Admin: Domains** | `routes/admin/domains/+page.svelte` | domainName, maxMessageBytes | Domain format, positive int |
| **Admin: Mailboxes create** | `routes/admin/mailboxes/+page.svelte` | name, quota | Required name, positive quota |
| **Admin: Mailboxes import** | `routes/admin/mailboxes/+page.svelte` | file | .mbox/.eml/.zip, max 100MB |
| **Admin: Mailboxes folders** | `routes/admin/mailboxes/+page.svelte` | folderName | Required, max 255 |
| **Admin: Departments** | `routes/admin/departments/+page.svelte` | name, ldapOu | Required name, maxLengths |
| **Admin: DLP patterns** | `routes/admin/rules/+page.svelte` | name, regex | Required, regex max 1000 (ReDoS) |
| **Admin: Identity AD** | `routes/admin/identity/+page.svelte` | domain, bindDn | maxLengths |
| **Admin: System backup** | `routes/admin/system/+page.svelte` | endpoint, bucket, keys, lockDays | URL format, positive days |
| **Admin: System config import** | `routes/admin/system/+page.svelte` | json file | .json extension, max 5MB |
| **Admin: Retention** | `routes/admin/retention/+page.svelte` | name, retainDays | Required name, days ≥ 1 unless forever |
| **Admin: Trace** | `routes/admin/trace/+page.svelte` | from, to, subject, dates | maxLengths on text fields |
| **Admin: eDiscovery** | `routes/admin/ediscovery/+page.svelte` | keywords, fromAddr | At least one field required |
| **Admin: Content Search** | `routes/admin/content-search/+page.svelte` | keywords, fromAddr, deleteReason | Reason min 10 chars (already good) |
| **Admin: DNS** | `routes/admin/dns/+page.svelte` | domain | Domain format |
| **Admin: Quarantine** | Both pages | (filters/select only) | Already constrained |
| **Admin: Queue** | `routes/admin/queue/+page.svelte` | (select only) | Already constrained |
| **Admin: Migration** | `routes/admin/migration/+page.svelte` | (select only) | Already constrained |
| **Admin: Audit** | `routes/admin/audit/+page.svelte` | query | maxLength |
| **Admin: DMARC** | `routes/admin/dmarc/+page.svelte` | (read-only) | N/A |
| **Admin: Storage/Features/Alerts** | 3 files | (read-only) | N/A |
| **Search (all pages)** | inbox, contacts | searchQuery, dirSearch | maxLength |

## XSS: `{@html}` Audit

| File | Location | Sanitized? |
|------|----------|-----------|
| `inbox/+page.svelte` | `<iframe srcdoc={sanitizedHTML}>` | Yes — `sanitizeHTML()` |
| `ComposeModal.svelte` | Quill editor | Yes — Quill sanitizes internally |

No additional fixes needed.

## Reference Doc

A companion reference document `docs/specs/INPUT_VALIDATION.md` will be created with:
- The max length reference table
- The validator API reference
- Audit grep commands
- The password policy config reference
- Before/after code snippets for the major forms

## Verification

1. `cd mailserver/webmail && npm run check` — 0 errors, 0 warnings
2. `cd mailserver/webmail && npx vitest run` — all tests pass
3. `cd mailserver/gateway && go build ./cmd/gateway` — builds clean
4. `cd mailserver/gateway && go test ./...` — all tests pass
5. `cd shared && go test ./...` — all tests pass
6. Visual: every form shows validation errors with Prism styling, admin changes to `password_min_length` reflect in UI without restart
