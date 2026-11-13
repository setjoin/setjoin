# Unified E2E Testing Platform — Design Spec

> Phase 1: Unified pipeline. Phase 2+: Incremental test coverage by feature priority.
> All patterns validated against Playwright best practices (webServer, project dependencies, storageState auth).

---

## 1. Architecture

### Single command, full stack

```
npm run test:e2e
  └─ playwright.config.ts
       ├─ webServer[0]: authserver  (Go binary, :8443)
       ├─ webServer[1]: gateway      (Go binary, :80/443)
       ├─ webServer[2]: webmail      (vite dev, :5173)
       ├─ projects:
       │   ├─ "setup"      → global.setup.ts (DB seed + auth state capture)
       │   ├─ "chromium"   → dependencies: ["setup"], storageState from setup
       │   └─ "firefox"    → dependencies: ["setup"], storageState from setup
       ├─ globalTeardown     → cleanup seeded data
       └─ spec files          → organized by feature domain
```

**Comparison with Playwright best practices:**

| Practice | Playwright Recommendation | Our Design |
|----------|--------------------------|------------|
| Server startup | `webServer` config with `command` + `url` + `timeout` | ✅ Three webServer entries (authserver, gateway, webmail) |
| Auth reuse | Setup project with `storageState` saved to `playwright/.auth/` | ✅ `global.setup.ts` logs in via API, saves JWT cookies |
| DB seeding | `globalSetup` or project dependency | ✅ Setup project seeds DB before tests run |
| Isolation | Each test in isolated browser context | ✅ `storageState` provides auth; data mutations cleaned in teardown |
| Test data | Control the data — test against known state | ✅ Seed script creates known fixtures before each run |
| Parallelism | Tests in files can run in parallel with `test.describe.configure({ mode: 'parallel' })` | ✅ Read-only tests parallel; mutating tests sequential per domain |

### Why not reuse existing `scripts/dev.sh` or `scripts/e2e.sh`?

- `dev.sh` starts a long-lived stack for development — not suitable for test isolation (between-test cleanup needed)
- `e2e.sh` uses Docker containers for IMAP/SMTP/LDAP — but doesn't start authserver, gateway, or webmail
- Playwright's built-in `webServer` config handles process lifecycle (start, health check, graceful shutdown) better than shell scripts

---

## 2. Test Infrastructure

### Directory structure

```
mailserver/webmail/
  e2e/
    global.setup.ts              # DB seed + auth state capture
    global.teardown.ts           # Data cleanup
    fixtures/
      test-data.ts               # Test user factories, known passwords
    auth/
      auth.setup.ts              # Login via API, save storageState
    specs/
      smoke/                     # Critical path tests
      mail/                      # Compose, read, reply, forward, delete, search
      calendar/                  # Create, edit, delete, views, recurrence
      contacts/                  # CRUD, import, GAL
      tasks/                     # CRUD, Kanban, list
      admin/                     # Users, domains, mailboxes, DLP, eDiscovery
      settings/                  # Profile, password, TOTP, identities, rules, vacation
      security/                  # MFA, logout, token refresh, rate limiting
      a11y/                      # WCAG scans (authenticated for all pages)
      offline/                   # IndexedDB queue, reconnect
  playwright.config.ts
  playwright/
    .auth/                       # gitignored — browser state files
```

### Config

```ts
// playwright.config.ts
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  timeout: 60000,
  retries: process.env.CI ? 2 : 0,
  use: {
    baseURL: 'https://localhost',
    ignoreHTTPSErrors: true,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },
  webServer: [
    {
      command: 'cd ../../authserver && go build -o /tmp/test-authserver ./cmd/authserver && DB_DSN=... /tmp/test-authserver',
      url: 'https://localhost:8443/health',
      timeout: 30000,
      reuseExistingServer: !process.env.CI,
      name: 'authserver',
    },
    {
      command: 'cd ../gateway && go build -o /tmp/test-gateway ./cmd/gateway && DB_DSN=... /tmp/test-gateway',
      url: 'https://localhost/health',
      timeout: 30000,
      reuseExistingServer: !process.env.CI,
      name: 'gateway',
    },
    {
      command: 'npm run dev',
      url: 'http://localhost:5173',
      timeout: 15000,
      reuseExistingServer: !process.env.CI,
      name: 'webmail',
    },
  ],
  projects: [
    { name: 'setup', testMatch: /global\.setup\.ts/ },
    {
      name: 'chromium',
      use: { storageState: 'playwright/.auth/user.json' },
      dependencies: ['setup'],
    },
    {
      name: 'admin-chromium',
      use: { storageState: 'playwright/.auth/admin.json' },
      dependencies: ['setup'],
    },
  ],
});
```

### Auth strategy: API-based login (not browser-based)

```ts
// e2e/global.setup.ts
import { test as setup } from '@playwright/test';
import path from 'path';

const USER_AUTH = path.join(__dirname, '../playwright/.auth/user.json');
const ADMIN_AUTH = path.join(__dirname, '../playwright/.auth/admin.json');

setup('seed database and create auth states', async ({ request }) => {
  // 1. Seed test data via admin API
  await request.post('https://localhost/admin/setup', {
    data: { /* test users, mailboxes, etc. */ }
  });

  // 2. Login as regular user via API
  const userLogin = await request.post('https://localhost/auth/login', {
    data: { email: 'alice@test.local', password: 'TestPass123!' }
  });
  await request.storageState({ path: USER_AUTH });

  // 3. Login as admin via API
  const adminLogin = await request.post('https://localhost/auth/login', {
    data: { email: 'admin@test.local', password: 'AdminPass123!' }
  });
  await request.storageState({ path: ADMIN_AUTH });
});
```

**Why API-based:** Playwright doc recommends API auth when the app supports it. Faster than browser clicks, more reliable (no UI timing races), and the `storageState` captures JWT cookies exactly as a real browser would.

### Test data seeding

**Approach: SQL script executed before test run.** The webServer startup script runs a seed SQL file against the test database via `psql`. No dedicated API endpoint needed — test data is injected at the database level. A shell script wrapper starts all services, runs the seed, then launches Playwright.

```bash
# e2e/scripts/start-test-stack.sh (called by webServer.command)
go build -o /tmp/test-authserver ../../authserver/cmd/authserver
go build -o /tmp/test-gateway ../gateway/cmd/gateway
/tmp/test-authserver &
/tmp/test-gateway &
# Wait for health checks
# Seed test data
psql -h 127.0.0.1 -U mail -d mailserver -f e2e/fixtures/seed.sql
```

Test data fixtures are defined as a SQL file:

```sql
-- e2e/fixtures/seed.sql
-- Test users (bcrypt hash of known passwords)
INSERT INTO users (id, email, display_name, password_hash, is_admin, admin_role)
VALUES
  (1001, 'alice@test.local', 'Alice Test', '$2a$10$...', FALSE, NULL),
  (1002, 'bob@test.local',   'Bob Test',   '$2a$10$...', FALSE, NULL),
  (1003, 'admin@test.local', 'Admin Test', '$2a$10$...', TRUE, 'super_admin');

-- Test mailboxes
INSERT INTO mailboxes (id, user_id, email, is_primary) VALUES
  (2001, 1001, 'alice@test.local', TRUE),
  (2002, 1002, 'bob@test.local', TRUE),
  (2003, 1003, 'admin@test.local', TRUE);

-- Seed 3 inbox messages for Alice via deliver() reducer
SELECT deliver(p_raw_mime := '...', p_from_addr := 'bob@test.local', ...);
```

**Known passwords** (stored in `e2e/fixtures/test-data.ts`):
```ts
export const TEST_USERS = {
  alice: { email: 'alice@test.local', password: 'TestPass123!', role: 'user' },
  bob:   { email: 'bob@test.local',   password: 'TestPass123!', role: 'user' },
  admin: { email: 'admin@test.local', password: 'AdminPass123!', role: 'super_admin' },
};
```

---

## 3. Test Organization & Priority

### Phase 2a — Critical User Journeys (Week 1)

| Test file | What it covers | Why first |
|-----------|---------------|-----------|
| `specs/smoke/login.spec.ts` | Login success, login failure, rate limiting | Gatekeeper for everything else |
| `specs/smoke/navigation.spec.ts` | All sidebar nav items load without errors | Verifies app shell works |
| `specs/mail/compose-send.spec.ts` | Compose new email, fill fields, send, verify in Sent | Core product function |
| `specs/mail/inbox-read.spec.ts` | Inbox loads, email list renders, click to read, back | Core product function |
| `specs/mail/reply-forward.spec.ts` | Reply, reply-all, forward, verify threading | Core product function |
| `specs/smoke/logout.spec.ts` | Logout clears session, redirects to login | Secures auth state |

### Phase 2b — Feature Domain Tests (Week 2-3)

| Domain | Tests |
|--------|-------|
| **Mail** | Delete, archive (tag removal), flag/unflag, search, attachments upload/download, draft auto-save |
| **Calendar** | Create event, edit event, delete event, month/week/day/agenda views, recurrence (weekly), all-day toggle |
| **Contacts** | Create contact, edit contact, delete contact, bulk import vCard, GAL search |
| **Tasks** | Create task, move between Kanban columns, task with due date, task with assignee |
| **Settings** | Change display name, change password, vacation auto-reply toggle, rule create/edit/delete, signature edit |
| **Tags** | Create tag, assign tag to email via multi-select, filter by tag, nested tag tree |

### Phase 2c — Admin + Security (Week 3-4)

| Domain | Tests |
|--------|-------|
| **Admin Users** | Create user, disable user, reset password, bulk CSV import |
| **Admin Domains** | Add domain, set as primary, verify DNS records |
| **Admin Mailboxes** | Create mailbox, set quota, litigation hold, delegate |
| **Admin DLP** | Create DLP pattern, test pattern against sample text |
| **Admin eDiscovery** | Search messages, export MBOX |
| **MFA** | TOTP setup, TOTP verify on login, backup codes generate/use |
| **Security** | Logout from all devices, refresh token rotation, JWT expiry |

### Phase 2d — Edge Cases + Polish (Week 4+)

| Domain | Tests |
|--------|-------|
| **Offline** | Queue mutation in IndexedDB, reconnect, verify replay |
| **Push** | WebSocket connect, receive state change notification |
| **A11y** | Authenticated axe-core scan of every page + modal state |
| **Mobile** | Mobile viewport smoke test (responsive layout) |
| **Error states** | Network failure on send, server 500 on compose, 404 page, expired token redirect |

### Go E2E tests — handled separately

Existing Go E2E tests (IMAP connector, EWS, M365) stay as `//go:build e2e` tests in their packages. They are NOT part of the Playwright pipeline — they test protocol-level integration, not browser UI. The stub SMTP/LDAP tests are fixed as part of this work.

---

## 4. Test Patterns

### Every test follows the same structure

```ts
import { test, expect } from '@playwright/test';
import { TEST_USERS } from '../fixtures/test-data';

test('compose and send email', async ({ page }) => {
  // ARRANGE
  await page.goto('/inbox');

  // ACT
  await page.getByRole('button', { name: 'Compose' }).click();
  await page.getByLabel('To').fill('bob@test.local');
  await page.getByLabel('Subject').fill('Test subject');
  await page.getByRole('textbox', { name: 'Email body' }).fill('Test body');
  await page.getByRole('button', { name: 'Send' }).click();

  // ASSERT
  await expect(page.getByText('Message sent')).toBeVisible();
  await page.goto('/inbox?tag=sent');
  await expect(page.getByText('Test subject')).toBeVisible();
});
```

### Test isolation rules

1. **Each test is independent** — no test depends on state from a previous test
2. **Read-only tests** (viewing pages) can parallelize freely
3. **Mutating tests** (create/send/delete) must use unique identifiers (timestamped subjects, unique email aliases) to avoid cross-test interference, OR use `test.describe.serial` within a domain when a sequence matters (e.g., "create event → edit event → delete event")
4. **Teardown** cleans any created test data at the test level, not suite level

### Locator strategy (matching Playwright best practices)

Priority order for element selection:
1. `page.getByRole('button', { name: 'Send' })` — preferred, based on accessibility roles
2. `page.getByLabel('Subject')` — for form fields with associated labels
3. `page.getByPlaceholder('Search emails...')` — for inputs
4. `page.getByTestId('compose-modal')` — as last resort for dynamic elements
5. Never use CSS class selectors or XPath — they break on refactor

---

## 5. What happens to existing tests

| Current | Disposition |
|---------|------------|
| `e2e/smoke.spec.ts` (170 lines) | Rewritten with new auth + seed pattern, expanded to cover more flows |
| `e2e/migration.spec.ts` (63 lines) | Moved to `specs/admin/migration.spec.ts`, expanded |
| `e2e/a11y.spec.ts` (55 lines) | Moved to `specs/a11y/accessibility.spec.ts`, authenticated for all pages |
| `scripts/e2e.sh` (Go E2E) | Kept as `make test-e2e-go` or `bash scripts/test-e2e-go.sh`. SMTP/LDAP stub tests fixed (add real test functions or remove dead test patterns) |
| Vitest component tests | Unchanged — unit tests stay in Vitest, E2E tests go to Playwright |
| Webmail unit tests | Unchanged |

---

## 6. CI Integration

```
.github/workflows/e2e.yml (future)
  └─ jobs:
       ├─ postgres: start PG container, run migrations
       ├─ seaweedfs: start SeaweedFS
       ├─ e2e-chromium: npm run test:e2e -- --project=chromium
       └─ e2e-firefox: npm run test:e2e -- --project=firefox
```

Trace artifacts saved on failure via `trace: 'on-first-retry'`.

---

## 7. Out of Scope

- **Visual regression testing** (screenshot comparison) — deferred until Phase 3+ when UI is stable
- **Load / performance testing** — k6 or artillery, separate concern
- **Cross-browser mobile device emulation** — just desktop Chromium + Firefox initially, mobile viewport smoke test later
- **Production monitoring / synthetic tests** — separate from CI E2E
- **Go protocol-level E2E** (SMTP, IMAP bridge, CalDAV, CardDAV) — kept as `//go:build e2e` tests, NOT in the Playwright pipeline
