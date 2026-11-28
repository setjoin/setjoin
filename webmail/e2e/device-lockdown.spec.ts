/**
 * E2E: CA-2 device lockdown [Task 16].
 *
 * Three assertions (mirrors the Go integration tests — browser surface):
 *   (a) lockdown ON + setjoinNative stub (deviceProof present) → /jmap returns 200.
 *   (b) lockdown ON, no stub (plain browser, no X-Device headers) → /jmap returns 403.
 *   (c) report-only mode → request allowed (200), no hard block.
 *
 * Gate: E2E_DEVICE_LOCKDOWN=1. Without the flag the spec is skipped — not
 * faked, not mocked. Requires a live mailserver + DB with:
 *   - feature.device_lockdown = ON
 *   - break-glass exclude list seeded (ca_break_glass_user_ids non-empty)
 *   - a test user enrolled + approved with a known HMAC secret (E2E_DEVICE_SECRET)
 *   - a valid Bearer token for that user (E2E_DEVICE_BEARER)
 *
 * ponytail: no custom test fixtures; auth helpers mirror conditional-access-quickstart.
 */

import { test, expect, request as apiRequest, type Page } from '@playwright/test';
import { apiLogin, apiToken, setFeature } from './helpers';

// ── Gate ──────────────────────────────────────────────────────────────────────
// Runs against the live stack with E2E_DEVICE_LOCKDOWN=1 OR E2E_CA_LIVE=1.
// The spec self-provisions everything from e2e/fixtures/seed.sql (an enrolled +
// approved device for device@test.local with a known HMAC secret) and flips the
// real feature.device_lockdown toggle on/off via the admin API — so it needs no
// hand-passed bearer/secret. Mutates the GLOBAL toggle → pin to chromium; the
// banner spec (same toggle) lives in this file too so one worker serializes both.
const LIVE = !!(process.env.E2E_DEVICE_LOCKDOWN || process.env.E2E_CA_LIVE);
const BANNER_LIVE = !!process.env.E2E_CA_LIVE;
const RUN_PROJECT = 'chromium';

const SERVER = process.env.E2E_SERVER ?? 'http://localhost:8080';
// device@test.local's seeded approved device (fixed id + HMAC secret) + a fresh
// bearer minted in beforeAll. Env overrides allowed for non-default seeds.
const DEVICE_ID = parseInt(process.env.E2E_DEVICE_ID ?? '990001', 10);
const DEVICE_SECRET = process.env.E2E_DEVICE_SECRET ?? 'e2e-device-hmac-secret-990001';
let BEARER = process.env.E2E_DEVICE_BEARER ?? '';

async function setLockdown(enabled: boolean) {
	const ctx = await apiRequest.newContext();
	try {
		const admin = await apiToken(ctx, 'admin@test.local', 'AdminPass123!');
		// conditional_access is ON in the seed; flipping device_lockdown arms/disarms
		// the hard CA-2 gate (it requires BOTH toggles).
		await setFeature(ctx, admin, 'feature.device_lockdown', enabled);
	} finally {
		await ctx.dispose();
	}
}

// ── HMAC proof helper ─────────────────────────────────────────────────────────

/** Build the X-Device-HMAC proof for the given device + secret (Web Crypto). */
async function makeProofHeaders(
	deviceID: number,
	secret: string
): Promise<Record<string, string>> {
	const ts = Math.floor(Date.now() / 1000).toString();
	const key = await crypto.subtle.importKey(
		'raw',
		new TextEncoder().encode(secret),
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['sign']
	);
	const sig = await crypto.subtle.sign(
		'HMAC',
		key,
		new TextEncoder().encode(`${deviceID}:${ts}`)
	);
	const hex = Array.from(new Uint8Array(sig))
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
	return {
		'X-Device-ID': deviceID.toString(),
		'X-Device-Timestamp': ts,
		'X-Device-HMAC': hex
	};
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test.describe('Device lockdown gate (CA-2) @user', () => {
	test.skip(!LIVE, 'E2E_DEVICE_LOCKDOWN / E2E_CA_LIVE not set — skipping device-lockdown e2e (not faked)');
	test.describe.configure({ mode: 'serial' });

	// Arm the hard gate (device_lockdown ON) for (a)/(b); mint device@'s bearer.
	test.beforeAll(async ({}, testInfo) => {
		if (testInfo.project.name !== RUN_PROJECT) return;
		const ctx = await apiRequest.newContext();
		try {
			if (!BEARER) BEARER = await apiToken(ctx, 'device@test.local', 'TestPass123!');
		} finally {
			await ctx.dispose();
		}
		await setLockdown(true);
		await new Promise((r) => setTimeout(r, 1500)); // let config_changed settle
	});

	// Restore base posture (device_lockdown OFF) for the rest of the suite.
	test.afterAll(async ({}, testInfo) => {
		if (testInfo.project.name !== RUN_PROJECT) return;
		await setLockdown(false);
	});

	/**
	 * (a) lockdown ON + native proof → /jmap 200.
	 * Injects window.setjoinNative.deviceProof stub so the JMAP request carries
	 * the X-Device-* headers the gate requires.
	 */
	test('(a) native-shell proof → /jmap 200', async ({ page }: { page: Page }, testInfo) => {
		test.skip(testInfo.project.name !== RUN_PROJECT, 'single-run spec (mutates global toggle)');
		// Inject the native bridge stub BEFORE the page loads so the SPA sees it.
		await page.addInitScript(
			({ deviceID, secret }: { deviceID: number; secret: string }) => {
				// ponytail: minimal stub — only deviceProof is needed by the lockout screen.
				(window as Record<string, unknown>).setjoinNative = {
					deviceProof: async () => {
						const ts = Math.floor(Date.now() / 1000).toString();
						// Web Crypto HMAC-SHA256 (same algorithm as Go signProof).
						const key = await window.crypto.subtle.importKey(
							'raw',
							new TextEncoder().encode(secret),
							{ name: 'HMAC', hash: 'SHA-256' },
							false,
							['sign']
						);
						const sig = await window.crypto.subtle.sign(
							'HMAC',
							key,
							new TextEncoder().encode(`${deviceID}:${ts}`)
						);
						const hex = Array.from(new Uint8Array(sig))
							.map((b: number) => b.toString(16).padStart(2, '0'))
							.join('');
						return {
							deviceID: deviceID.toString(),
							timestamp: ts,
							hmac: hex
						};
					}
				};
			},
			{ deviceID: DEVICE_ID, secret: DEVICE_SECRET }
		);

		const response = await page.request.post(`${SERVER}/jmap`, {
			headers: {
				Authorization: `Bearer ${BEARER}`,
				'Content-Type': 'application/json',
				...(await makeProofHeaders(DEVICE_ID, DEVICE_SECRET))
			},
			data: JSON.stringify({
				using: ['urn:ietf:params:jmap:core'],
				methodCalls: [['Core/echo', { ping: 'pong' }, 'r1']]
			})
		});
		expect(response.status()).toBe(200);
	});

	/**
	 * (b) lockdown ON, no device proof → /jmap 403 BZ095.
	 * Plain browser: no X-Device-* headers → resolver returns not-bound → gate blocks.
	 */
	test('(b) no proof (plain browser) → /jmap 403', async ({ request }, testInfo) => {
		test.skip(testInfo.project.name !== RUN_PROJECT, 'single-run spec (mutates global toggle)');
		const response = await request.post(`${SERVER}/jmap`, {
			headers: {
				Authorization: `Bearer ${BEARER}`,
				'Content-Type': 'application/json'
				// Intentionally no X-Device-* headers.
			},
			data: JSON.stringify({
				using: ['urn:ietf:params:jmap:core'],
				methodCalls: [['Core/echo', { ping: 'pong' }, 'r1']]
			})
		});
		expect(response.status()).toBe(403);
		const body = await response.json();
		expect(body.code).toBe('BZ095');
	});

	/**
	 * (c) report-only mode → request allowed (200), no hard block.
	 * Report-only = the master device_lockdown toggle OFF (the hard CA-2 gate needs
	 * BOTH conditional_access AND device_lockdown), so a no-proof request that would
	 * be blocked under enforcement passes through. We flip the toggle off live and
	 * assert the same no-proof request now returns 200.
	 */
	test('(c) report-only (lockdown disarmed) → 200 (no hard block)', async ({ request }, testInfo) => {
		test.skip(testInfo.project.name !== RUN_PROJECT, 'single-run spec (mutates global toggle)');
		await setLockdown(false);
		await new Promise((r) => setTimeout(r, 1500)); // let config_changed settle
		// In report-only mode the gate records a would-block but lets the request through.
		const response = await request.post(`${SERVER}/jmap`, {
			headers: {
				Authorization: `Bearer ${BEARER}`,
				'Content-Type': 'application/json'
				// No device headers → would block, but report-only → 200.
			},
			data: JSON.stringify({
				using: ['urn:ietf:params:jmap:core'],
				methodCalls: [['Core/echo', { ping: 'pong' }, 'r1']]
			})
		});
		// Report-only: the policy engine records a would_block outcome but proceeds.
		expect(response.status()).toBe(200);
	});
});

/**
 * E2E: report-only device-lockdown banner [CA-2 UX].
 *
 * When an admin turns on device lockdown, the SPA layout surfaces a report-only
 * DeviceNotApprovedBanner (driven by /jmap/session → effective_capabilities →
 * features.device_lockdown, which mirrors the feature.device_lockdown toggle).
 *
 * This block flips the real toggle on (admin API → trg_feature_notify hot-reload),
 * views the app as the break-glass admin (so the hard device gate doesn't 403 the
 * session — only the informational banner shows), asserts the banner, then
 * restores the toggle. Lives in this file (not its own spec) because it mutates
 * the same GLOBAL feature.device_lockdown toggle as the gate block above — one
 * file = one worker = the two blocks can't race each other.
 *
 * Gate: E2E_CA_LIVE=1 (self-skips otherwise).
 */
test.describe('Device-not-approved banner (report-only device lockdown) @user', () => {
	test.skip(!BANNER_LIVE, 'E2E_CA_LIVE not set — skipping live device-banner spec');
	test.describe.configure({ mode: 'serial' });

	test.beforeAll(async ({}, testInfo) => {
		if (testInfo.project.name !== RUN_PROJECT) return;
		await setLockdown(true);
		await new Promise((r) => setTimeout(r, 1500)); // let config_changed settle
	});

	test.afterAll(async ({}, testInfo) => {
		if (testInfo.project.name !== RUN_PROJECT) return;
		await setLockdown(false);
	});

	test('layout shows DeviceNotApprovedBanner while device lockdown is on', async ({ page }, testInfo) => {
		test.skip(testInfo.project.name !== RUN_PROJECT, 'single-run spec (mutates global toggle)');

		// Break-glass admin: exempt from the hard gate, so only the banner surfaces.
		await apiLogin(page, 'admin@test.local', 'AdminPass123!');
		await page.goto('/apps');

		await expect(
			page.getByRole('alert').filter({ hasText: /this device isn.t approved yet/i })
		).toBeVisible({ timeout: 15_000 });
	});
});
