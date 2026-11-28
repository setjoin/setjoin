import { spawnSync } from 'node:child_process';
import { test, expect } from '@playwright/test';

const SETUP_URL = process.env.E2E_BASE_URL || 'https://localhost';
const ADMIN_EMAIL = 'admin@onboarding-test.local';
const ADMIN_PASSWORD = 'Test12345678!';
const MAILCTL_BIN = process.env.MAILCTL_BIN;
const OWNER_DSN = process.env.DB_DIRECT_OWNER_DSN;

test.skip(!process.env.E2E_ONBOARDING, 'E2E_ONBOARDING not set — needs a fresh uninitialized instance');

test.describe.serial('First-boot onboarding', () => {
	test('redirect from / to the read-only setup page when uninitialized', async ({ page }) => {
		await page.goto(`${SETUP_URL}/`);
		await page.waitForURL('**/setup');
		await expect(page.getByRole('heading', { name: 'Setjoin setup' })).toBeVisible();
	});

	test('setup page exposes local instructions but no credential form', async ({ page }) => {
		await page.goto(`${SETUP_URL}/setup`);
		await expect(page.getByText('Local administrator action required')).toBeVisible();
		await expect(page.getByText('mailctl bootstrap-admin --email admin@example.com')).toBeVisible();
		await expect(page.getByText('mailctl restore')).toBeVisible();
		await expect(page.locator('input')).toHaveCount(0);
		await expect(page.getByRole('button')).toHaveCount(0);
	});

	test('public setup mutation paths do not exist', async ({ request }) => {
		for (const path of ['/setup/create-admin', '/setup/preflight', '/setup/restore']) {
			const response = await request.post(`${SETUP_URL}${path}`, { data: {} });
			expect(response.status(), path).toBe(404);
		}
	});

	test('local mailctl creates the only first administrator', async ({ page }) => {
		test.skip(!MAILCTL_BIN || !OWNER_DSN, 'onboarding harness did not provide local mailctl and owner DSN');
		await page.goto(`${SETUP_URL}/setup`);
		const result = spawnSync(
			MAILCTL_BIN!,
			['bootstrap-admin', '--email', ADMIN_EMAIL, '--password-stdin'],
			{
				input: `${ADMIN_PASSWORD}\n`,
				encoding: 'utf8',
				env: { ...process.env, DB_DIRECT_OWNER_DSN: OWNER_DSN!, CRYPTO_PROFILE: 'standard' },
			},
		);
		expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
		await page.waitForURL('**/auth/login', { timeout: 10_000 });
	});

	test('login with the locally created administrator', async ({ page }) => {
		await page.goto(`${SETUP_URL}/`);
		await page.getByLabel(/email/i).fill(ADMIN_EMAIL);
		await page.getByLabel(/password/i).fill(ADMIN_PASSWORD);
		await page.getByRole('button', { name: /continue/i }).click();
		await expect(page.getByText(/apps|inbox|mail/i).first()).toBeVisible({ timeout: 15_000 });
	});

	test('initialized system does not return to setup', async ({ page }) => {
		await page.goto(`${SETUP_URL}/`);
		expect(page.url()).not.toContain('/setup');
		await expect(page.getByLabel(/email/i)).toBeVisible();
	});
});
