import { test, expect } from '@playwright/test';

/**
 * e2e: custom (non-AD) LDAP directory sync console (WAVE-5 #15).
 *
 * No live LDAP server is available in CI, so the ERROR-path journey IS the
 * e2e per this program's scoping (mirrors AD's console pattern; unlike AD,
 * "Test connection" here is a true dry-run — it must never write to the
 * users table, proven separately by the Go suite in internal/ldapsync). The
 * happy path (a directory that actually answers) is covered by
 * internal/ldapsync's Go tests against the real test DB.
 *
 * @admin — admin-chromium project supplies the admin storageState.
 */
test.describe('Custom LDAP sync console @admin', () => {
  test('test connection against an unreachable host shows the network error class', async ({ page }) => {
    await page.goto('/admin/identity');
    await page.getByRole('tab', { name: 'Custom LDAP' }).click();

    await page.getByLabel('Host').fill('127.0.0.1');
    await page.getByLabel('Port').fill('1'); // nothing listens on port 1 — deterministic refusal
    await page.getByLabel('Bind DN').fill('cn=svc,dc=e2e-ldap,dc=test');
    await page.getByLabel('Base DN').fill('dc=e2e-ldap,dc=test');
    await page.getByLabel('Filter').fill('');
    await page.getByLabel('Sync interval (min)').selectOption('15');

    const saveAck = page.waitForResponse(
      (r) => r.url().includes('/api/admin/ldap/config') && r.request().method() === 'PUT',
    );
    await page.getByRole('button', { name: 'Save config' }).click();
    expect((await saveAck).status()).toBe(204);

    const testAck = page.waitForResponse(
      (r) => r.url().includes('/api/admin/ldap/test-connection') && r.request().method() === 'POST',
    );
    await page.getByRole('button', { name: 'Test connection' }).click();
    expect((await testAck).status()).toBe(500);

    // The network error class, not the generic "could not connect" fallback
    // and not a bind-credentials message — proves the classification reached
    // the console (admin_ldap.go's ldapConnErrorMessage).
    await expect(page.getByText(/reach the directory server/i)).toBeVisible({ timeout: 10000 });
  });

  test('saved config redacts the password and the sync log renders', async ({ page, request }) => {
    await page.goto('/admin/identity');
    await page.getByRole('tab', { name: 'Custom LDAP' }).click();

    await page.getByLabel('Host').fill('127.0.0.1');
    await page.getByLabel('Password (encrypted at rest)').fill(`hunter2-${Date.now()}`);

    const saveAck = page.waitForResponse(
      (r) => r.url().includes('/api/admin/ldap/config') && r.request().method() === 'PUT',
    );
    await page.getByRole('button', { name: 'Save config' }).click();
    expect((await saveAck).status()).toBe(204);

    // The raw secret must never round-trip on GET — this is the redaction
    // contract admin_ldap_test.go's TestLDAPGetConfigRedactsSecret proves at
    // the Go layer; here it's proven over the real HTTP boundary.
    const res = await request.get('/api/admin/ldap/config');
    expect(res.ok()).toBeTruthy();
    const cfg = (await res.json()) as Record<string, string>;
    expect(cfg['ldap_sync_password_enc']).toBe('[ENCRYPTED]');

    // Sync log renders — either populated rows or the empty state, never a
    // crash (no live directory has ever synced in this environment).
    await expect(page.getByText(/sync log/i)).toBeVisible();
  });
});
