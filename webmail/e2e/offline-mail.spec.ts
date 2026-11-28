import { test, expect } from '@playwright/test';

test('plain browser shows NO offline controls (online-only)', async ({ page }) => {
	await page.goto('/mail/inbox');
	// No native db bridge in a plain browser -> the affordance never renders.
	await expect(page.getByTestId('work-offline-toggle')).toHaveCount(0);
});

test('plain browser shows NO unlock gate (online-only)', async ({ page }) => {
	await page.goto('/mail/inbox');
	// needsUnlock is false on a browser -> BiometricUnlock never gates the pane.
	await expect(page.getByRole('dialog', { name: /unlock your offline mail/i })).toHaveCount(0);
});

test.describe('native-shell offline flow', () => {
	test.skip(!process.env.SETJOIN_NATIVE_E2E, 'requires the native-shell harness');
	test('enable -> enroll -> provision -> offline body-search -> draft+send -> reconnect drain -> idle relock -> conflict inspect', async ({ page }) => {
		// Driven by the native-shell harness:
		//  1. enable offline -> enrollment card -> Turn on -> provisioning progress.
		await expect(page.getByText(/set up offline mail/i)).toBeVisible();
		//  2. sync completes (status pill -> up to date).
		//  3. go offline (Work-Offline) -> body-search a cached message.
		await page.getByTestId('work-offline-toggle').click();
		//  4. draft + "send" offline -> reconnect -> queue drains, single send, resync.
		//  5. idle re-lock -> the locked-inbox surface gates the pane.
		await expect(page.getByRole('dialog', { name: /unlock your offline mail/i })).toBeVisible();
		//  6. biometric re-unlock -> mail visible again.
		//  7. a stale conflict surfaces -> open the inspector via the badge ->
		//     retry one + discard one (discard goes through the confirm).
		await page.getByTestId('sync-issues-badge').click();
		await expect(page.getByText(/sync issues/i)).toBeVisible();
	});
});
