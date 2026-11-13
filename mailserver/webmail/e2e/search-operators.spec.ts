import { test, expect } from '@playwright/test';
import { loginAsUser, reloadAfterServiceWorkerControl } from './helpers';

/**
 * Search operators + saved searches. The seed delivers 'E2E seeded message 1..3'
 * from partner1/2/3@partner.test to alice, so `from:partner1` must keep message 1
 * and drop message 2 (searchQuery.ts: from: is a substring match on the sender).
 *
 * Saved searches are server-persisted (store.saveSearch → loadSavedSearches on
 * mount), so the reload proves the create wasn't a toast-only optimistic write.
 * Unique name per run — saved searches accumulate harmlessly across runs.
 */
test.describe('Search operators @user', () => {
  test('from: filters the list and a saved search restores it after reload', async ({ page }, testInfo) => {

    const savedName = `E2E saved ${Date.now()}`;

    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);
    // Baseline: the seeded inbox has loaded before we filter.
    await expect(page.getByText('E2E seeded message 1')).toBeVisible({ timeout: 15000 });

    const search = page.getByRole('textbox', { name: 'Search mail' });
    await search.fill('from:partner1');
    await search.press('Enter');

    // partner1's message stays; partner2's is filtered out (asserted only after
    // the partner1 row proves the filtered list has rendered).
    await expect(page.getByText('E2E seeded message 1')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('E2E seeded message 2')).not.toBeVisible();

    // Save the search from the topbar affordance (appears once rawSearch is non-empty).
    await page.getByRole('button', { name: 'Save search' }).click();
    const nameInput = page.getByRole('textbox', { name: 'Name this saved search' });
    await nameInput.fill(savedName);
    await nameInput.press('Enter');

    // It lands in the sidebar's saved-search section.
    await expect(page.getByText('Saved searches')).toBeVisible({ timeout: 10000 });
    await expect(page.getByRole('button', { name: savedName })).toBeVisible();

    // PERSISTENCE: reload — the saved search is server-side, not page state.
    page = await reloadAfterServiceWorkerControl(page);
    const savedItem = page.getByRole('button', { name: savedName });
    await expect(savedItem).toBeVisible({ timeout: 15000 });

    // Re-running it restores the raw query and the filtered result set.
    await savedItem.click();
    await expect(page.getByRole('textbox', { name: 'Search mail' })).toHaveValue('from:partner1');
    await expect(page.getByText('E2E seeded message 1')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('E2E seeded message 2')).not.toBeVisible();
  });
});
