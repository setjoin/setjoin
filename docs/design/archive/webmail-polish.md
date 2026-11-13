# Webmail UX Polish — Design Spec

Date: 2026-06-05
Status: Design

## Goal

Fix 54 webmail UX findings from the quality audit: i18n coverage, HTML5 form validation, JS validation, accessibility, confirmation dialogs, and loading/error states.

## i18n — Replace Hardcoded Strings

### Login page (`routes/+page.svelte`) — 20 strings

Current: every string hardcoded in English. Keys exist in `en.ts`/`zh.ts`/`de.ts` but unused.

```svelte
<!-- Before -->
<h1>Sign in to SetJoin</h1>
<input placeholder="Email address" />

<!-- After -->
<h1>{$t('login.title')}</h1>
<input placeholder={$t('login.email')} />
```

| Current string | i18n key |
|---------------|----------|
| "Sign in to SetJoin" | `login.title` |
| "Email address" | `login.email` |
| "Password" | `login.password` |
| "Sign in" | `login.submit` |
| "Signing in…" | `login.loading` |
| "Two-factor verification" | `mfa.title` |
| "Verifying…" | `mfa.loading` |
| "Verify" | `mfa.submit` |
| "Back to sign in" | `mfa.back` |
| "Change password" | `password.title` |
| "New password" | `password.new` |
| "Change" | `password.submit` |
| "集合 · Self-hosted workspace" | `brand.tagline` |
| + 7 more strings | |

### Apps page (`routes/apps/+page.svelte`) — 6 strings

| Current string | i18n key |
|---------------|----------|
| "Apps" | `apps.title` |
| "Inbox, compose, and manage email" | `apps.mail.desc` |
| "Events, scheduling, and free/busy" | `apps.calendar.desc` |
| "Address book and global directory" | `apps.contacts.desc` |
| "Track work in lists and boards" | `apps.tasks.desc` |
| "System management and configuration" | `apps.admin.desc` |
| "No apps available" | `apps.empty` |
| "Contact your administrator" | `apps.empty_hint` |

### Settings pages — 2 strings

Admin settings labels already use `t()`. But user-facing settings (appearance, language, about) have hardcoded section titles.

## HTML5 Validation — 14 Missing Attributes

Every input field must have `maxlength`, `required`, and `type` at minimum. Specific validators where applicable.

| Page | Field | Missing |
|------|-------|---------|
| Create user | Email | `type="email"`, `maxlength="254"` |
| Create user | Display name | `maxlength="128"` |
| Create user | Password | `minlength="8"`, `maxlength="128"` |
| Create domain | Domain name | `maxlength="253"`, `pattern="[a-zA-Z0-9.-]+"` |
| Create department | Name | `maxlength="128"` |
| Create mailbox | Name | `maxlength="64"`, `pattern="[a-zA-Z0-9._-]+"` |
| Add alias | Email | `type="email"`, `maxlength="254"` |
| Compose | To/Cc/Bcc | `type="email"` (multiple), `maxlength="254"` |
| Settings → profile | Display name | `maxlength="128"` |
| Setup page | All fields | Missing `required`, `maxlength`, email `type` |

## JS Validation — Update `validation.ts`

### Current `isEmail` — too permissive

```typescript
// Current (line 32):
/^[^\s@]+@[^\s@]+\.[^\s@]+$/

// Accepts: 'a@b', '..@test..com', '@example.com', 'user@domain.'
```

**Fix:** Add RFC 5321 compliance:
```typescript
export function isEmail(): Validator {
  return (value: string) => {
    if (!value) return null
    if (value.length > 254) return { isEmail: 'Email must be 254 characters or less' }
    // Reject: consecutive dots, leading/trailing dots, spaces
    if (/\.{2,}/.test(value)) return { isEmail: 'Email cannot contain consecutive dots' }
    if (/^\.|\.@|\.$/.test(value.split('@')[0] || '')) return { isEmail: 'Email local part cannot start or end with a dot' }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(value)) return { isEmail: 'Invalid email format' }
    return null
  }
}
```

### New validators

```typescript
export function isDomain(): Validator {
  return (value: string) => {
    if (!value) return null
    if (value.length > 253) return { isDomain: 'Domain must be 253 characters or less' }
    if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/.test(value))
      return { isDomain: 'Invalid domain format' }
    return null
  }
}

export function isDisplayName(): Validator {
  return (value: string) => {
    if (!value || !value.trim()) return { isDisplayName: 'Display name is required' }
    if (value.length > 128) return { isDisplayName: 'Display name must be 128 characters or less' }
    if (/[\x00-\x1f]/.test(value)) return { isDisplayName: 'Display name cannot contain control characters' }
    return null
  }
}

export function isResourceName(): Validator {
  return (value: string) => {
    if (!value || !value.trim()) return { isResourceName: 'Name is required' }
    if (value.length > 128) return { isResourceName: 'Name must be 128 characters or less' }
    if (/[/\\\x00]/.test(value)) return { isResourceName: 'Name cannot contain /, \\, or null characters' }
    if (value === '.' || value === '..') return { isResourceName: 'Invalid name' }
    return null
  }
}
```

Apply to forms: create user, create domain, create department, create mailbox, add alias, compose, settings.

## Accessibility — 6 Fixes

| # | Issue | Location | Fix |
|---|-------|----------|-----|
| 1 | Sidebar hamburger has no `aria-label` | `+layout.svelte` | `aria-label="Toggle navigation"` |
| 2 | Avatar button has no `aria-label` | `+layout.svelte` | `aria-label="User menu"` |
| 3 | Search input has no `aria-label` | `+layout.svelte` | `aria-label="Search"` |
| 4 | Compose Cc/Bcc toggle keyboard-inaccessible | Compose page | Make toggle a `<button>` not a `<div onclick>` |
| 5 | Modal close button missing `aria-label` | All modals | `aria-label="Close"` |
| 6 | Color contrast below 4.5:1 on some `text-dim` surfaces | tokens.css | Bump `text-dim` luminance by 5% |

## Confirmation Dialogs — Replace `confirm()`

### Two destructive actions use native `confirm()`:

1. **Delete user** (`admin/users/+page.svelte` line 239): `confirm("Permanently delete {email}?")` 
2. **Delete policy** (`admin/conditional-access/+page.svelte` line 94): `confirm("Delete {name}?")`

**Fix:** Replace with glass modal component:
```svelte
<ConfirmModal
  title="Delete user"
  message="Permanently delete {email}? All messages, aliases, and data will be removed. This cannot be undone."
  confirmText="Delete {email}"
  requireTyping={email}
  onconfirm={doDelete}
/>
```

The `requireTyping` prop disables the confirm button until the user types the email to confirm.

## Loading/Error States — 2 Fixes

| # | Page | Issue | Fix |
|---|------|-------|-----|
| 1 | User list | Shows blank table during load — no skeleton/spinner | Add loading skeleton rows (3 grey placeholder rows) |
| 2 | Some admin pages | Swallow fetch errors silently — no toast, no inline error | Add `<ErrorBanner message={error} />` component used consistently |

## Files Modified

```
mailserver/webmail/src/
  routes/+page.svelte                          — i18n all strings
  routes/apps/+page.svelte                     — i18n all strings
  routes/settings/                             — i18n + validators
  routes/admin/users/+page.svelte              — HTML5 attrs, validators, modal confirm, loading
  routes/admin/departments/+page.svelte        — HTML5 attrs, validators
  routes/admin/domains/+page.svelte            — HTML5 attrs, validators
  routes/admin/mailboxes/+page.svelte          — HTML5 attrs, validators
  lib/validation.ts                            — Update isEmail, add isDomain, isDisplayName, isResourceName
  lib/components/ConfirmModal.svelte           — New component
  lib/components/ErrorBanner.svelte            — New component
  lib/components/LoadingSkeleton.svelte        — New component
  lib/theme/tokens.css                         — Bump text-dim contrast
```

## References

- `mailserver/webmail/src/lib/i18n/en.ts`, `zh.ts`, `de.ts` — existing translation keys
- `mailserver/webmail/src/lib/validation.ts` — current validators (isEmail needs update)
- `mailserver/webmail/src/lib/theme/tokens.css` — design tokens
- `docs/design/standards/validation-email-policy.md` — Spec A (defines validators)
- `docs/design/standards/error-handling-logging.md` — Spec B (defines Problem format for error responses)
