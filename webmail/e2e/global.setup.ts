import { test as setup, type APIRequestContext } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { mkdirSync, writeFileSync } from 'node:fs';
import { TEST_USERS, AUTH_FILE_USER, AUTH_FILE_ADMIN, AUTH_FILE_LIMITED_ADMIN } from './fixtures/test-data';
import { psql } from './helpers';

const __dirname = dirname(fileURLToPath(import.meta.url));

const BASE = process.env.E2E_SERVER ?? 'http://localhost:8080';

/**
 * Persist the API login's cookies AND pre-mark the welcome tour as seen for the
 * given users. The first-run coachmarks are intentionally non-modal, but seeding
 * keeps unrelated authenticated specs deterministic and prevents them from
 * depending on onboarding state. welcome-tour.spec.ts clears the flag itself.
 */
async function saveState(request: APIRequestContext, file: string, emails: string[]) {
  const state = await request.storageState();
  state.origins = [
    {
      origin: BASE,
      localStorage: emails.map((email) => ({ name: `sj-welcome-tour:${email}`, value: '1' })),
    },
  ];
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify(state));
}

// Run hygiene BEFORE the logins: every run starts from the seed baseline.
// Specs create uniquely-named artifacts (Date.now() suffixes) — without this,
// repeated local runs against a long-lived stack accumulate rows until caps
// bite (a month cell shows 3 pills + "+N more"; the tag picker grows unbounded)
// and the auth-noise window trips authLimit / the auth_failure_rate health
// check. One place, pattern-scoped to test-generated names only.
setup('reset run-generated data to the seed baseline', async () => {
  psql(`
    DELETE FROM mailbox_delegates d
    USING mailboxes owner_mailbox, users owner_user, users delegate_user
    WHERE d.mailbox_id = owner_mailbox.id
      AND owner_mailbox.user_id = owner_user.id
      AND d.user_id = delegate_user.id
      AND owner_user.email = 'alice@test.local'
      AND delegate_user.email IN ('bob@test.local', 'admin@test.local');
    DELETE FROM reminders WHERE title LIKE 'E2E %';
    DELETE FROM calendar_events WHERE title LIKE 'E2E %';
    DELETE FROM tasks WHERE title LIKE 'E2E %' OR title LIKE 'e2e-%';
    DELETE FROM tags WHERE name LIKE 'e2e-label-%' OR name LIKE 'dbg-%';
    DELETE FROM contacts WHERE display_name LIKE 'E2E %';
    DELETE FROM login_events WHERE user_id IN (
      SELECT id FROM users WHERE email LIKE '%@test.local'
    );
    INSERT INTO login_events
      (user_id, success, client, protocol, auth_method, source_ip, location, device_name, occurred_at)
    SELECT id, TRUE, 'web', 'http', 'password', '203.0.113.10'::inet,
           'Test City, TC', 'E2E Browser', now() - interval '1 hour'
      FROM users WHERE email LIKE '%@test.local';
    INSERT INTO login_events
      (user_id, success, fail_reason, client, protocol, auth_method, source_ip, location, occurred_at)
    SELECT id, FALSE, 'bad_password', 'web', 'http', 'password',
           '198.51.100.5'::inet, 'Other City, OC', now() - interval '2 hour'
      FROM users WHERE email LIKE '%@test.local';
  `);
});

setup('login as regular user', async ({ request }) => {
  const resp = await request.post(`${BASE}/auth/login`, {
    data: { email: TEST_USERS.alice.email, password: TEST_USERS.alice.password },
  });
  if (resp.status() !== 200) {
    throw new Error(`User login failed: ${resp.status()} ${await resp.text()}`);
  }
  // Seed the tour flag for EVERY test user (not just this project's default), so a
  // spec that switches users mid-test (e.g. compose-roundtrip's loginAsUser under a
  // non-user project) does not inherit first-run onboarding state. Harmless to
  // over-seed: welcome-tour.spec clears the flag itself to exercise the tour.
  await saveState(request, join(__dirname, '..', AUTH_FILE_USER), [
    TEST_USERS.alice.email,
    TEST_USERS.bob.email,
    TEST_USERS.admin.email,
    TEST_USERS.limitedAdmin.email,
  ]);
});

setup('login as limited admin user', async ({ request }) => {
  const resp = await request.post(`${BASE}/auth/login`, {
    data: { email: TEST_USERS.limitedAdmin.email, password: TEST_USERS.limitedAdmin.password },
  });
  if (resp.status() !== 200) {
    throw new Error(`Limited admin login failed: ${resp.status()} ${await resp.text()}`);
  }
  await saveState(request, join(__dirname, '..', AUTH_FILE_LIMITED_ADMIN), [
    TEST_USERS.limitedAdmin.email,
  ]);
});

setup('login as admin user', async ({ request }) => {
  const resp = await request.post(`${BASE}/auth/login`, {
    data: { email: TEST_USERS.admin.email, password: TEST_USERS.admin.password },
  });
  if (resp.status() !== 200) {
    throw new Error(`Admin login failed: ${resp.status()} ${await resp.text()}`);
  }
  await saveState(request, join(__dirname, '..', AUTH_FILE_ADMIN), [
    TEST_USERS.admin.email,
    TEST_USERS.alice.email,
    TEST_USERS.bob.email,
  ]);
});
