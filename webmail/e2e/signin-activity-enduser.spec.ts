/**
 * E2E: settings → security end-user sign-in activity [signin-activity, D-C].
 *
 * The History tab lists the signed-in user's own sign-ins from
 * GET /user/login-history (login_events). Distinct from the ADMIN per-user view in
 * signin-activity.spec.ts (/admin/identity). Each row carries a descriptive
 * aria-label and localized outcome/badge copy; a failed-attempt summary surfaces
 * when failures exist (the seed plants one success + one failure per test user).
 *
 * Gate: E2E_CA_LIVE=1 (self-skips otherwise).
 */
import { test, expect } from '@playwright/test';

const LIVE = !!process.env.E2E_CA_LIVE;

test.describe('settings/security — end-user sign-in activity', () => {
	test.skip(!LIVE, 'E2E_CA_LIVE not set — skipping live signin-activity spec');

	test('History tab lists sign-in rows with localized labels + row aria-label', async ({ page }) => {
		await page.goto('/settings/security');

		// Switch to the History tab (default tab is Devices).
		await page.getByRole('tab', { name: 'Login history' }).click();

		// Section heading (localized) + the seeded failed-attempt summary.
		await expect(page.getByText('Your sign-ins')).toBeVisible({ timeout: 15_000 });
		await expect(page.getByTestId('failed-summary')).toBeVisible();

		// At least one sign-in row with a non-empty descriptive aria-label.
		const rows = page.locator('[data-testid^="signin-row-"]');
		await expect(rows.first()).toBeVisible({ timeout: 15_000 });
		const aria = await rows.first().getAttribute('aria-label');
		expect(aria && aria.trim().length).toBeTruthy();
	});
});
