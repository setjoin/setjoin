import { expect, test, type Page } from '@playwright/test';

const now = '2026-08-02T00:00:00Z';
const status = {
	installationId: 'installation-1', localTimelineGeneration: '8', lastWallClock: now,
	lastBootEpoch: 'boot-local', lastBootAt: now, restoreDeclaredAt: now,
	signals: [{
		mailboxId: '42', email: 'owner@example.test', tokenSha256: 'a'.repeat(64),
		timelineGeneration: '11', stateWatermark: '99', bootEpoch: 'boot-new',
		issuedAt: now, observedAt: now, signalClass: 'client_observed_newer_timeline',
	}],
};
const incident = {
	id: '11111111-1111-4111-8111-111111111111', status: 'open', minimumTimeline: '9', maximumTimeline: '12',
	reason: 'Verified rollback evidence', openedBy: '1', approvalRequired: true, approvedBy: '2',
	expiresAt: '2099-08-03T00:00:00Z', createdAt: now, mailboxCount: 1,
	counts: { uploading: 0, quarantined: 1, accepted: 0, rejected: 0, deduplicated: 0 },
};
const artifact = {
	id: '22222222-2222-4222-8222-222222222222', mailboxId: '42', uploadingUserId: '7', deviceId: 'device-1',
	artifactIdentity: 'b'.repeat(64), rawMimeSha256: 'c'.repeat(64), rawMimeSize: '512',
	signedTimeline: '11', signedBootEpoch: 'boot-new',
	headers: { subject: 'Recovered subject', from: 'sender@example.test' },
	malwareStatus: 'clean', status: 'quarantined', rejectionReason: null,
	forkConsented: false, createdAt: now, terminalAt: null,
};

async function installMocks(page: Page) {
	await page.addInitScript(() => localStorage.setItem('sj-welcome-tour:admin@test.local', '1'));
	await page.route(/\/auth\/me(?:\?|$)/, (route) => route.fulfill({
		status: 200, contentType: 'application/json',
		body: JSON.stringify({
			email: 'admin@test.local', display_name: 'Admin', is_admin: true,
			has_mailbox: true, totp_enabled: true, delegates: [], impersonating: false,
		}),
	}));
	await page.route(/(?:\.well-known\/jmap|\/jmap\/session)(?:\?|$)/, (route) => route.fulfill({
		status: 200, contentType: 'application/json', body: JSON.stringify({
			apiUrl: '/jmap', downloadUrl: '/blobs/{blobId}', uploadUrl: '/upload', eventSourceUrl: '/events',
			state: 'state-1', username: 'admin@test.local', accounts: {}, primaryAccounts: {},
			capabilities: { 'urn:setjoin:params:jmap:mail': { admin: { consoles: ['access'], permissions: ['system.recovery'] } } },
		}),
	}));
	// The authenticated shell warms its ordinary mail stores even on an admin
	// console. Keep this mocked visual contract fully authenticated: letting the
	// batch fall through to the real gateway produces a 401, logs the synthetic
	// user out, and turns a recovery screenshot into a login-page flake.
	await page.route(/^https?:\/\/[^/]+\/jmap(?:\?|$)/, (route) => route.fulfill({
		status: 503,
		contentType: 'application/problem+json',
		body: '{"title":"mail warm-up unavailable"}',
	}));
	await page.route(/\/api\/user\/vip-senders(?:\?|$)/, (route) => route.fulfill({
		status: 200,
		contentType: 'application/json',
		body: '{"list":[]}',
	}));
	await page.route(/\/api\/admin\/system\/recovery\/signals(?:\?|$)/, (route) => route.fulfill({
		status: 200, contentType: 'application/json', body: JSON.stringify(status),
	}));
	await page.route(/\/api\/admin\/system\/recovery\/incidents\/[^/]+\/artifacts(?:\?|$)/, (route) => route.fulfill({
		status: 200, contentType: 'application/json', body: JSON.stringify({ list: [artifact] }),
	}));
	await page.route(/\/api\/admin\/system\/recovery\/incidents(?:\?|$)/, (route) => route.fulfill({
		status: 200, contentType: 'application/json', body: JSON.stringify({ list: [incident] }),
	}));
	await page.route(/\/api\/user\/offline\/caps(?:\?|$)/, (route) => route.fulfill({
		status: 200, contentType: 'application/json', body: '{"allowed":false}',
	}));
}

async function show(page: Page, locale: 'en' | 'zh', viewport: { width: number; height: number }) {
	await page.setViewportSize(viewport);
	await page.goto('/admin/recovery');
	await expect(page.getByRole('heading', { level: 1 })).toHaveText(locale === 'en' ? 'Mail recovery' : '邮件恢复');
	if (viewport.width >= 768) {
		await expect(page.getByText(locale === 'en' ? 'Access' : '访问控制', { exact: true }).first()).toBeVisible();
	}
	await page.getByRole('button', { name: locale === 'en' ? 'Review artifacts' : '审核副本' }).click();
	await expect(page.getByText('Recovered subject')).toBeVisible();
	await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
	await page.evaluate(() => document.fonts.ready);
	await page.evaluate(() => {
		window.scrollTo(0, 0);
		for (const node of document.querySelectorAll<HTMLElement>('*')) node.scrollTop = 0;
	});
}

test.describe('Client-assisted recovery visual contract @admin', () => {
	test.use({ storageState: { cookies: [], origins: [] }, timezoneId: 'UTC', reducedMotion: 'reduce', serviceWorkers: 'block' });

	test('pins the English desktop evidence and quarantine state', async ({ page }) => {
		await page.addInitScript(() => localStorage.setItem('locale', 'en'));
		await installMocks(page);
		await show(page, 'en', { width: 1440, height: 900 });
		await expect(page).toHaveScreenshot('mail-recovery-en-desktop.png', {
			fullPage: true,
			// Desktop navigation changes are structurally significant even when
			// they occupy only a small fraction of the full-page screenshot.
			maxDiffPixelRatio: 0.001,
		});
	});

	test('pins the Chinese mobile evidence and quarantine state', async ({ page }) => {
		await page.addInitScript(() => localStorage.setItem('locale', 'zh'));
		await installMocks(page);
		await show(page, 'zh', { width: 375, height: 812 });
		await expect(page).toHaveScreenshot('mail-recovery-zh-mobile.png', { fullPage: true });
		await page.getByText('Recovered subject').scrollIntoViewIfNeeded();
		await expect(page).toHaveScreenshot('mail-recovery-zh-mobile-quarantine.png');
	});
});
