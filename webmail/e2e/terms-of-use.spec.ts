/**
 * E2E: Terms-of-Use remediation (require_terms) [CA-3b].
 *
 * Real backend + real SPA, no mocks:
 *   (1) a gated request for a user under a require_terms policy returns
 *       403 { remediation: "terms", remediation_tou_id } — proven directly.
 *   (2) the SPA, hitting that same 403 on a real route, mounts TermsAcceptance
 *       (http.ts interceptor → touRemediation store → layout fetches /terms/pending).
 *   (3) Accept is disabled until the document is scrolled to the end (require_scroll).
 *   (4) POST /terms/accept clears the block (TermsPendingResolver sees the
 *       acceptance) → the interstitial dismisses and access flows.
 *
 * Seed: terms@test.local + an enabled scroll-required ToU + an 'on' require_terms
 * policy scoped to that user; feature.cae_runtime + feature.conditional_access ON.
 *
 * Gate: E2E_CA_LIVE=1 (self-skips otherwise so the default suite stays green).
 */
import { test, expect } from '@playwright/test';
import { apiLogin, psql } from './helpers';

const LIVE = !!process.env.E2E_CA_LIVE;
const SERVER = process.env.E2E_SERVER ?? 'http://localhost:8080';

test.describe('Terms-of-Use remediation (require_terms) @user', () => {
	test.skip(!LIVE, 'E2E_CA_LIVE not set — skipping live terms-of-use spec');

	// Re-runnable: clear any prior acceptance so terms@ is freshly gated each run.
	test.beforeEach(() => {
		psql(`DELETE FROM terms_of_use_acceptance a USING users u WHERE a.user_id = u.id AND u.email = 'terms@test.local'`);
	});

	test('403 remediation=terms → TermsAcceptance mounts → scroll→accept→access flows', async ({ page }, testInfo) => {
		// Mutates persistent acceptance state — run once (under the user project).

		const token = await apiLogin(page, 'terms@test.local', 'TestPass123!');

		// (1) REAL backend: a gated request returns 403 remediation=terms.
		const resp = await page.request.post(`${SERVER}/jmap`, {
			headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
			data: JSON.stringify({
				using: ['urn:ietf:params:jmap:core'],
				methodCalls: [['Core/echo', { ping: 'pong' }, 'r1']],
			}),
		});
		expect(resp.status()).toBe(403);
		const body = await resp.json();
		expect(body.remediation).toBe('terms');
		expect(typeof body.remediation_tou_id).toBe('number');

		// (2) SPA mounts the interstitial when its own real traffic hits the same
		// 403. Use a settings route (one-shot gated GETs) rather than the mailbox:
		// the inbox opens a JMAP websocket whose reconnects keep refetching
		// /terms/pending, which re-derives the doc and resets the in-DOM scroll
		// latch — a 403 storm that makes the scroll→click race flaky.
		await page.goto('/settings/storage');
		const touBody = page.getByTestId('tou-body');
		await expect(touBody).toBeVisible({ timeout: 15_000 });

		// (3) Accept is gated on scroll-to-end (require_scroll).
		const accept = page.getByRole('button', { name: 'Accept' });
		await expect(accept).toBeDisabled();
		await touBody.evaluate((el) => {
			el.scrollTop = el.scrollHeight;
			el.dispatchEvent(new Event('scroll'));
		});
		await expect(accept).toBeEnabled({ timeout: 5_000 });

		// (4) Accept → real POST /terms/accept → block clears → interstitial dismisses.
		const [acceptResp] = await Promise.all([
			page.waitForResponse(
				(r) => r.url().includes('/terms/accept') && r.request().method() === 'POST',
				{ timeout: 15_000 }
			),
			accept.click(),
		]);
		expect(acceptResp.ok()).toBe(true);
		await expect(page.getByTestId('tou-body')).toHaveCount(0, { timeout: 15_000 });

		// Access now flows: the acceptance is recorded, so a fresh gated request passes.
		const after = await page.request.post(`${SERVER}/jmap`, {
			headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
			data: JSON.stringify({
				using: ['urn:ietf:params:jmap:core'],
				methodCalls: [['Core/echo', { ping: 'pong' }, 'r1']],
			}),
		});
		expect(after.status()).toBe(200);
	});
});
