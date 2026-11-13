import { test, expect } from '@playwright/test';
import { TEST_USERS } from './fixtures/test-data';
import { loginAsUser } from './helpers';

test.describe('Login flow @user', () => { // once per run — its deliberate bad login feeds the tarpit
  // These run logged-OUT. The chromium/admin-chromium projects inject a
  // logged-in storageState (cookies AND localStorage); clearCookies() alone
  // leaves the localStorage token, so '/' would redirect to /apps and the login
  // form would never render. An empty storageState gives a clean anonymous
  // context so the login page actually appears.
  test.use({ storageState: { cookies: [], origins: [] } });

  test('login page renders form fields and submit button', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('button', { name: /continue/i })).toBeVisible({ timeout: 10000 });
    await expect(page.getByLabel(/email/i)).toBeVisible();
    await expect(page.getByLabel(/password/i)).toBeVisible();
  });

  test('valid credentials redirect away from login', async ({ page }) => {
    await page.goto('/');
    await page.getByLabel(/email/i).fill(TEST_USERS.alice.email);
    await page.getByLabel(/password/i).fill(TEST_USERS.alice.password);
    await page.getByRole('button', { name: /continue/i }).click();
    // SPA lands on /apps then the first enabled app; the authenticated shell rail
    // appears and the login form is gone.
    await expect(page.getByRole('navigation', { name: 'Main navigation' })).toBeVisible({ timeout: 15000 });
    await expect(page.getByLabel(/password/i)).toHaveCount(0);
  });

  test('invalid credentials show error message', async ({ page }) => {
    await page.goto('/');
    await page.getByLabel(/email/i).fill('nobody@nowhere.local');
    await page.getByLabel(/password/i).fill('not-a-real-password');
    await page.getByRole('button', { name: /continue/i }).click();
    // The login error is a role="alert" region; assert it surfaces. Generous
    // timeout: the authserver TARPITS repeated failures (in-memory progressive
    // delay — anti-brute-force), and back-to-back local runs accumulate this
    // spec's own deliberate failures. The alert must still appear; only later.
    await expect(page.getByRole('alert')).toBeVisible({ timeout: 45000 });
  });
});

test.describe('Authenticated pages', () => {
  test('inbox reachable from the rail without redirect to login', async ({ page }) => {
    await loginAsUser(page); // lands on /apps inside the authenticated shell
    const rail = page.getByRole('navigation', { name: 'Main navigation' });
    await rail.getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);
    await expect(rail.getByRole('button', { name: 'Mail' })).toHaveAttribute('aria-current', 'page');
  });
  // Per-route load coverage for Mail/Calendar/Contacts/Tasks/Settings lives in
  // a11y.spec.ts ("authenticated shell"); not duplicated here.
});

test.describe('Public health endpoints', () => {
  test('GET /health returns 200', async ({ request }) => {
    const resp = await request.get('/health');
    expect(resp.status()).toBe(200);
  });

  test('GET /ready returns 200', async ({ request }) => {
    const resp = await request.get('/ready');
    expect(resp.status()).toBe(200);
  });

});

test.describe('Unauthenticated API access', () => {
  // Empty storageState makes the `request` fixture genuinely anonymous (the
  // chromium/admin-chromium projects otherwise inject a logged-in cookie, and a
  // fresh playwright.request.newContext() inherits it under the runner).
  test.use({ storageState: { cookies: [], origins: [] } });

  test('protected API endpoints reject unauthenticated requests', async ({ request }) => {
    // A bare GET to an SPA-routed path returns index.html (200); assert the real
    // API GETs that must enforce auth. (POST /jmap body-validates before auth,
    // returning 400 for an empty envelope — not a clean auth signal.)
    expect((await request.get('/auth/me')).status()).toBe(401);
    expect((await request.get('/.well-known/jmap')).status()).toBe(401);
  });
});
