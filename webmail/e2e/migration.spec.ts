import { test, expect } from '@playwright/test';
import { loginAsUser } from './helpers';

// The user-facing data-migration page lives at /settings/migration. Navigate to
// it directly: the redesigned app shell uses <button> nav (not <a href>), so the
// old click-through-the-sidebar approach (a[href*="settings"] → a[href*="migration"])
// never matches. A hard nav to the route serves the SPA (verified: the gateway has
// no API handler shadowing this path), so page.goto is deterministic.
test.describe('Migration page', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsUser(page);
    await page.goto('/settings/migration');
  });

  test('migration page loads', async ({ page }) => {
    await expect(page).toHaveURL(/migration/);
    await expect(page.getByText(/data migration/i).first()).toBeVisible({ timeout: 10000 });
  });

  test('migration page shows source selection', async ({ page }) => {
    await expect(page.getByText(/data migration/i).first()).toBeVisible({ timeout: 10000 });
    await expect(page.getByRole('button', { name: /imap/i })).toBeVisible({ timeout: 5000 });
  });

  test('migration page shows IMAP configuration form', async ({ page }) => {
    await expect(page.getByText(/data migration/i).first()).toBeVisible({ timeout: 10000 });
    // IMAP is the default source, so its "Test connection" button is rendered.
    await expect(page.getByRole('button', { name: /test connection/i })).toBeVisible({ timeout: 10000 });
  });
});
