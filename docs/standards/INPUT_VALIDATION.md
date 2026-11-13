# Input Validation Conventions

Every form field must have validation. This document is the canonical reference — new forms must follow these patterns; code review must verify them.

## Checklist

For every form field:

| # | Criterion | What to check |
|---|-----------|---------------|
| 1 | **Required fields enforced** | `required()` validator + HTML `required` attribute |
| 2 | **Max length prevents overflow** | `maxLength(n)` validator + HTML `maxlength` attribute, limit documented with source (RFC/DB/config) |
| 3 | **Email/URL formats validated** | `isEmail()` / `isURL()` for format fields |
| 4 | **Special chars sanitized** | `normalize()` strips null bytes, trims whitespace, Unicode NFC. Svelte auto-escapes `{expression}` |
| 5 | **Numeric inputs reject non-numbers** | `isNumber()` validator + HTML `type="number"` |

## Usage

### Single Form

```typescript
import { validate, required, maxLength, isEmail, normalize } from '$lib/validation';

let formErrors = $state<Record<string, string>>({});

async function handleSubmit() {
    formErrors = {};
    const result = validate({
        email:   [required('Email is required'), isEmail(), maxLength(254)],
        subject: [required('Subject is required'), maxLength(998)],
    }, {
        email:   normalize(email),
        subject: normalize(subject),
    });
    if (!result.valid) { formErrors = result.errors; return; }
    // proceed...
}
```

Template:
```svelte
<input type="email" bind:value={email} maxlength="254"
       class:input-error={formErrors.email} />
{#if formErrors.email}<span class="field-error">{formErrors.email}</span>{/if}
```

### Validator API

| Factory | Default message | Example |
|---------|----------------|---------|
| `required(msg?)` | "This field is required" | `required('Email is required')` |
| `maxLength(n, msg?)` | "Must be at most n characters" | `maxLength(254)` |
| `minLength(n, msg?)` | "Must be at least n characters" | `minLength(8)` |
| `isEmail(msg?)` | "Invalid email format" | `isEmail()` |
| `isURL(msg?)` | "Invalid URL format" | `isURL('Must be a valid URL')` |
| `isNumber(msg?)` | "Must be a number" | `isNumber()` |
| `matches(pattern, msg)` | Custom message required | `matches(/^[a-z]+$/, 'Only lowercase letters')` |

### Error Styling

```css
.input-error {
  border-color: var(--color-danger) !important;
  box-shadow: 0 0 0 3px var(--red-light);
}
.field-error {
  color: var(--color-danger);
  font-size: var(--font-size-xs);
  display: block;
  margin-top: 0.2rem;
}
```

## Max Length Reference

Every limit has a documented source:

| Field | Limit | Source |
|-------|-------|--------|
| Email address | 254 chars | RFC 5321 §4.5.3.1 |
| Email subject | 998 chars | RFC 2822 §2.1.1 |
| Display name | 255 chars | Database `VARCHAR(255)` |
| Password | 128 chars | bcrypt 72-byte limit + margin |
| Phone number | 32 chars | ITU E.164 + extension |
| URL fields | 2048 chars | Browser URL bar limit |
| Domain name | 253 chars | RFC 1035 |
| DLP regex | 1000 chars | ReDoS protection + DB column |
| File attachment | Config-driven | `MAX_UPLOAD_SIZE` |

## Dynamic Config

Some limits come from server config, not hardcoded:

**Upload size** — from JMAP session: `session.capabilities['urn:ietf:params:jmap:core'].maxSizeUpload`

**Password policy** — from `GET /auth/password-policy`: `{ minLength, requireUppercase, requireLowercase, requireDigit, requireSpecial }`

## Anti-Patterns

| Don't | Do |
|-------|-----|
| Zero validation on form fields | At minimum: `maxlength` + `required` on critical fields |
| Hardcoded limits without documented source | Document every limit with its RFC/DB/config source |
| `catch { }` on validation | Show `formErrors` inline per field |
| Client-only validation | Go server validates at boundary via `WriteValidationErrors` |

## Audit Commands

```bash
# Find forms missing maxlength
grep -rn "<input\|<textarea" mailserver/webmail/src/routes/ | grep -v "maxlength\|disabled\|readonly\|hidden\|type=.checkbox\|type=.radio\|type=.file\|type=.submit"

# Find forms without validation import
grep -L "from '\$lib/validation'" mailserver/webmail/src/routes/*/+page.svelte mailserver/webmail/src/lib/components/*.svelte
```
