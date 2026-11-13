# E2E Test Locator Correction & CSP Fix — Design Spec

## Problem

301 E2E Playwright tests were written against an idealized DOM. When run against the live stack:
1. **CSP blocks SPA API calls** — The gateway injects `connect-src 'self' wss: https:` (no `http:`) via `SecurityHeaders` middleware. In h2c dev mode (port 8080, no TLS), the SPA's `fetch('/jmap/session')` is blocked by CSP. The SPA silently fails, the login form never renders, and every test times out.
2. **Locators don't match real DOM** — Tests use generic guesses (`getByRole('button', { name: /send/i })`) without verification against the actual SvelteKit app.

## Design

### 1. CSP Fix — SecurityHeaders middleware

**File:** `mailserver/gateway/internal/middleware/security.go:21-31`

Add `http:` to `connect-src` only when the request is NOT over TLS (h2c dev mode):

```go
isTLS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
connectSrc := "'self' wss: https:"
if !isTLS {
    connectSrc += " http:"
}
w.Header().Set("Content-Security-Policy",
    "default-src 'self'; "+
        "script-src 'self'; "+
        "style-src 'self' 'unsafe-inline'; "+
        "img-src 'self' data: blob:; "+
        "font-src 'self'; "+
        "connect-src "+connectSrc+"; "+
        "media-src 'self' blob:; "+
        "object-src 'none'; "+
        "base-uri 'self'; "+
        "form-action 'self';")
```

**Guard:** `isTLS` mirrors the existing `HSTS` middleware pattern (`mailserver/gateway/internal/middleware/security.go:41`). Ensures `http:` is NEVER added in production — whether direct TLS or behind a reverse proxy with `X-Forwarded-Proto: https`.

**Response header** (`http://` URLs, no `X-Forwarded-Proto: https`):
```
Content-Security-Policy: connect-src 'self' wss: https: http:;
```

### 2. Codegen-based locator verification

**Workflow per test file:**
1. Start the stack (gateway on :8080 with CSP fixed, authserver on :8443)
2. Run `npx playwright codegen http://localhost:8080`
3. Perform the user flow in the browser window (login → compose → send → read → logout)
4. codegen records exact `getByRole()` and `getByLabel()` calls matching real DOM
5. Compare recorded locators against the test file's locators
6. Update test locators to match real DOM
7. Run the corrected test to verify it passes

### 3. Fix priority order

| Order | Files | Rationale |
|-------|-------|-----------|
| 1 | `smoke.spec.ts`, `logout.spec.ts` | Doorstep — every other test depends on login/logout working |
| 2 | `compose-send.spec.ts`, `inbox-read.spec.ts`, `reply-forward.spec.ts` | Core mail — the product's primary function |
| 3 | `mail-actions.spec.ts`, `tags.spec.ts`, `attachments.spec.ts`, `drafts.spec.ts` | Mail depth |
| 4 | `calendar-crud.spec.ts`, `calendar-advanced.spec.ts` | Calendar |
| 5 | `contacts-crud.spec.ts`, `tasks-crud.spec.ts` | Contacts + Tasks |
| 6 | `settings.spec.ts` | Settings |
| 7 | `admin.spec.ts` through `admin-ediscovery.spec.ts` (4 files) | Admin (use `admin-chromium` project) |
| 8 | `security.spec.ts`, `setup-wizard.spec.ts` | Auth edge cases |
| 9 | `edge-cases/*` (3 files), `push-offline.spec.ts` | Edge cases |
| 10 | `authenticated-a11y.spec.ts` | A11y |

### 4. SPA hydration performance

**Root cause of slow render:** 820KB total JS across all routes. The login page needs ~50KB (root layout + login page chunk), which should load in <2s over localhost. The observed 10s+ failure was due to CSP blocking the SPA's API calls, not JS bundle size.

After CSP fix, no additional performance work needed — the SPA renders in <1s over localhost.

If performance becomes an issue in CI:
- Enable HTTP/2 server push for critical JS chunks
- Add `preload` headers for `_app/immutable/entry/start.js`
- Consider `vite build --ssr` for server-side rendering (reduces time-to-interactive)

### 5. Test timeout adjustment

After CSP fix and locator correction, reduce test timeouts:
- Login page render: 10s → 5s (should render in <1s)
- API calls: 10s → 5s (localhost, no network latency)
- Navigation: 5s → 3s

This catches real failures faster instead of waiting full timeouts.
