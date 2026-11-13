/**
 * E2E: Risk remediation (require_risk_remediation) [CA-3b].
 *
 * Real backend + real SPA, no mocks:
 *   (1) a user at an elevated risk band (user_risk.level='high', embedded in the
 *       JWT Risk claim at login) under an 'on' require_risk_remediation policy gets
 *       403 { remediation: "risk" } on a gated request — proven directly.
 *   (2) the SPA, hitting that same 403 on a real route, mounts RiskRemediation
 *       (http.ts interceptor → riskRemediation store → layout interstitial).
 *
 * Seed: risky@test.local + user_risk(level=high) + an 'on'
 * require_risk_remediation policy scoped to that user; feature.cae_runtime +
 * feature.conditional_access + feature.user_risk ON.
 *
 * Gate: E2E_CA_LIVE=1 (self-skips otherwise so the default suite stays green).
 */
import { test, expect } from '@playwright/test';
import { apiLogin, psql } from './helpers';

const LIVE = !!process.env.E2E_CA_LIVE;
const SERVER = process.env.E2E_SERVER ?? 'http://localhost:8080';

test.describe('Risk remediation (require_risk_remediation) @user', () => {
	test.skip(!LIVE, 'E2E_CA_LIVE not set — skipping live risk-remediation spec');

	// Re-assert the elevated risk row in case the 15-min user-risk cron recomputed it.
	test.beforeEach(() => {
		psql(`INSERT INTO user_risk (user_id, score, level, signals)
		      SELECT id, 80, 'high', '["impossible_travel"]'::jsonb FROM users WHERE email = 'risky@test.local'
		      ON CONFLICT (user_id) DO UPDATE SET score = 80, level = 'high', signals = '["impossible_travel"]'::jsonb`);
	});

	test('403 remediation=risk → RiskRemediation interstitial mounts', async ({ page }, testInfo) => {

		const token = await apiLogin(page, 'risky@test.local', 'TestPass123!');

		// Sanity: the JWT carries the elevated risk band the gate keys off.
		const claim = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString('utf-8')) as {
			risk?: { level?: string };
		};
		expect(claim.risk?.level).toBe('high');

		// (1) REAL backend: a gated request returns 403 remediation=risk.
		const resp = await page.request.post(`${SERVER}/jmap`, {
			headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
			data: JSON.stringify({
				using: ['urn:ietf:params:jmap:core'],
				methodCalls: [['Core/echo', { ping: 'pong' }, 'r1']],
			}),
		});
		expect(resp.status()).toBe(403);
		const body = await resp.json();
		expect(body.remediation).toBe('risk');

		// (2) SPA mounts the RiskRemediation interstitial when its real traffic 403s.
		await page.goto('/inbox');
		const dialog = page.getByRole('dialog', { name: /verify it.s you/i });
		await expect(dialog).toBeVisible({ timeout: 15_000 });
		await expect(page.getByRole('button', { name: "Verify it's you" })).toBeVisible();
	});
});
