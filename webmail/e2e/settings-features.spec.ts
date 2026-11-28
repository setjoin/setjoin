import { test, expect } from '@playwright/test';
import { loginAsUser } from './helpers';

/**
 * WAVE-5 tail smoke specs (settings surfaces). ONE cheap "surface renders /
 * happy action acks" assertion — send-as alias (shared-mailbox.spec.ts) and
 * custom labels (labels-apply.spec.ts) already have full coverage, so they're
 * skipped here. See retired-docs:superpowers/plans/archive/2026-07-03-wave5-tail-program.md (W4).
 */

test.describe('Settings features smoke @user', () => {
  test('quick-parts/templates: creating a template shows it in the list', async ({ page }) => {
    const name = `E2E template ${Date.now()}`;

    await loginAsUser(page);
    await page.goto('/settings/templates');
    await expect(page.getByRole('button', { name: 'New template' })).toBeVisible({ timeout: 15000 });

    await page.getByRole('button', { name: 'New template' }).click();
    await page.getByLabel('Name').fill(name);
    await page.getByLabel('Subject').fill('E2E template subject');
    await page.getByLabel('Body').fill('E2E template body.');
    await page.getByRole('button', { name: 'Save', exact: true }).click();

    await expect(page.getByText(name)).toBeVisible({ timeout: 10000 });
  });
});
