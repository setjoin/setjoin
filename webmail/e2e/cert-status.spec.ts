/**
 * E2E: settings → security CertStatusCard [CA-3b Task E].
 *
 * The card fetches GET /user/cert-status and renders valid/expiring/expired/none.
 * Over the E2E stack (plain HTTP, no client cert presented) the endpoint returns
 * {"status":"none"} so the card shows its informational no-cert empty state — the
 * real backend path, not a mock.
 *
 * Gate: E2E_CA_LIVE=1 (self-skips otherwise so the default suite stays green).
 */
import { test, expect } from '@playwright/test';

const LIVE = !!process.env.E2E_CA_LIVE;

test.describe('settings/security — CertStatusCard', () => {
	test.skip(!LIVE, 'E2E_CA_LIVE not set — skipping live cert-status spec');

	test('renders the no-cert informational state (no client cert over plain HTTP)', async ({ page }) => {
		await page.goto('/settings/security');

		// Card heading is always present (aria-labelledby csc-title).
		await expect(page.getByRole('heading', { name: 'Security certificate' })).toBeVisible({ timeout: 15_000 });

		// No client cert → {"status":"none"} → the informational empty state, NOT the
		// error state. Asserting the none title distinguishes the two (error shows
		// cert.load_failed instead).
		await expect(page.getByText('No security certificate detected')).toBeVisible();
	});
});
