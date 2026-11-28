import { test, expect } from '@playwright/test';
import { loginAsUser, reloadAfterServiceWorkerControl } from './helpers';

/**
 * User mail-filter rules manager (/settings/rules, WAVE5). Create a rule with
 * one condition + one action, RELOAD, and assert the row re-renders from a
 * fresh listRules() fetch with the condition AND action still present — guards
 * the field-silently-dropped-on-create regression class (ebeeb267), not just
 * the success toast. The list row renders summarize(r):
 * "<field> <op> <value> · <action> → <param>".
 */

test.describe('Filter rules @user', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsUser(page);
    await page.goto('/settings/rules');
    await expect(page.getByRole('heading', { name: 'Rules' })).toBeVisible({ timeout: 15000 });
  });
  test('create a rule; its condition and action survive a reload', async ({ page }) => {
    const ts = Date.now();
    const name = `E2E rule ${ts}`;
    const match = `e2e-match-${ts}`;

    await page.getByRole('button', { name: 'New rule' }).click();
    await page.getByLabel('Name').fill(name);

    // Default condition row is Subject / contains — set only its value.
    await page.getByPlaceholder('Value').fill(match);
    // Default action row is Move to folder — set its parameter.
    await page.getByPlaceholder('Folder or tag name').fill('Trash');

    await page.getByRole('button', { name: 'Save rule' }).click();
    await expect(page.getByText('Rule created')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText(name)).toBeVisible({ timeout: 10000 });

    // PERSISTENCE: reload → fresh fetch reflects the DB; the summary line proves
    // the stored condition value AND the action parameter both round-tripped.
    page = await reloadAfterServiceWorkerControl(page);
    await expect(page.getByRole('heading', { name: 'Rules' })).toBeVisible({ timeout: 15000 });
    await expect(page.getByText(name)).toBeVisible({ timeout: 10000 });
    await expect(page.getByText(`Subject contains ${match} · Move to folder → Trash`)).toBeVisible();
  });
});
