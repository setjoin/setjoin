/**
 * E2E: admin per-user sign-in activity section (Task 13).
 *
 * These tests require a live admin session + a running mailserver.
 * They are skipped in unit-test (vitest) runs — only executed via
 * `npm run test:e2e` with a real browser (Playwright).
 *
 * Guards:
 *  - sign-in activity section is visible
 *  - Tier-2 dangerous-action arc: commit disabled until SECURE typed
 */

import { test, expect } from '@playwright/test';
import { AUTH_FILE_LIMITED_ADMIN } from './fixtures/test-data';

// Use the admin session the global setup writes (e2e/global.setup.ts →
// playwright/.auth/admin.json, the same file the admin-chromium project loads).
test.describe('@admin admin sign-in activity authorization matrix', () => {
test('admin per-user page shows a sign-in activity section with a guarded secure-account', async ({ page }) => {
	// Navigate to the identity console with user=1
	await page.goto('/admin/identity?user=1');

	// Section is visible
	await expect(page.getByTestId('admin-signin-activity')).toBeVisible();

	// Aria-live region present for async outcomes
	await expect(page.getByTestId('admin-secure-live')).toBeAttached();

	// Tier-2 arc: the trigger button is always rendered
	const trigger = page.getByTestId('admin-secure-trigger');
	await expect(trigger).toBeVisible();

	// Open the dialog
	await trigger.click();

	// Confirm button exists but is disabled before typing
	const confirmBtn = page.getByTestId('admin-secure-confirm');
	await expect(confirmBtn).toBeVisible();
	await expect(confirmBtn).toBeDisabled();

	// Type the confirmation word
	await page.getByTestId('admin-secure-type').fill('SECURE');

	// Commit is now enabled
	await expect(confirmBtn).toBeEnabled();
});

test.describe('limited administrator', () => {
	test.use({ storageState: AUTH_FILE_LIMITED_ADMIN });

	test('sign-in history is 403 and the unavailable identity console does not render', async ({ page }) => {
		const response = await page.request.get('/api/admin/users/1/sign-ins');
		expect(response.status()).toBe(403);

		await page.goto('/admin/identity?user=1');
		await expect(page).toHaveURL(/\/admin\/system$/);
		await expect(page.getByRole('heading', { name: 'System', exact: true })).toBeVisible();
		await expect(page.getByTestId('admin-signin-activity')).toHaveCount(0);
	});
});
});
