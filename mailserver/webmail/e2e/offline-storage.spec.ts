/**
 * E2E: settings → storage, the native-only Offline section [offline #1].
 *
 * The Offline card renders ONLY in a native shell whose bridge advertises the
 * offline-core 'mail' store (isOfflineAvailable → window.setjoinNative.db). In a
 * plain browser the section must be ABSENT and only the Cloud card renders. The
 * active offline path is native-shell-only and out of browser-E2E scope — we do
 * NOT fabricate a native bridge to force it; we assert the browser contract.
 *
 * Gate: E2E_CA_LIVE=1. Without it the spec self-skips so the default suite stays
 * green. Runs against the real gateway (the Cloud card's /offline/size-estimate +
 * /settings/view loads must succeed for the page to leave its loading state).
 */
import { test, expect } from '@playwright/test';

const LIVE = !!process.env.E2E_CA_LIVE;

test.describe('settings/storage — native-only Offline section', () => {
	test.skip(!LIVE, 'E2E_CA_LIVE not set — skipping live offline-storage spec');

	test('plain browser: Cloud card renders, Offline section is absent', async ({ page }) => {
		await page.goto('/settings/storage');

		// Cloud card always renders (its data comes from endpoints that exist).
		await expect(page.getByText('Cloud (mailbox)')).toBeVisible({ timeout: 15_000 });

		// Offline card + its controls are gated on the native db bridge → absent here.
		await expect(page.getByText('Offline (this device)')).toHaveCount(0);
		await expect(page.getByText('Offline mail window')).toHaveCount(0);

		// And the page is NOT stuck in the load-error state (cards rendered, not the alert).
		await expect(page.getByText('Cloud (mailbox)')).toBeVisible();
	});
});
