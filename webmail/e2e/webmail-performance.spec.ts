import { expect, test, type BrowserContext, type Page, type TestInfo } from '@playwright/test';

import { AUTH_FILE_USER } from './fixtures/test-data';

const PRODUCT_MARKS = [
	'public-visible',
	'public-interactive',
	'shell-visible',
	'inbox-list-visible',
	'inbox-interactive',
] as const;

type ProductMark = (typeof PRODUCT_MARKS)[number];

type PageSample = {
	scenario: string;
	ordinal: number;
	marks: Partial<Record<ProductMark, number>>;
	navigation: Record<string, number>;
	resources: Array<{
		name: string;
		initiatorType: string;
		transferSize: number;
		duration: number;
	}>;
};

const samples = Number.parseInt(process.env.PERF_SAMPLES ?? '1', 10);
const warmups = Number.parseInt(process.env.PERF_WARMUP ?? '0', 10);

async function waitForMark(page: Page, name: ProductMark): Promise<void> {
	await expect.poll(
		() => page.evaluate((mark) => performance.getEntriesByName(mark, 'mark').length, name),
		{ message: `waiting for product mark ${name}` },
	).toBe(1);
}

async function collectSample(page: Page, scenario: string, ordinal: number): Promise<PageSample> {
	return page.evaluate(({ scenario: pageScenario, ordinal: pageOrdinal, markNames }) => {
		const nav = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming | undefined;
		const marks = Object.fromEntries(markNames.map((name) => [name, performance.getEntriesByName(name, 'mark')[0]?.startTime]).filter(([, value]) => typeof value === 'number'));
		const resources = performance.getEntriesByType('resource').map((entry) => {
			const resource = entry as PerformanceResourceTiming;
			return {
				name: new URL(resource.name).pathname,
				initiatorType: resource.initiatorType,
				transferSize: resource.transferSize,
				duration: Math.round(resource.duration * 100) / 100,
			};
		});
		return {
			scenario: pageScenario,
			ordinal: pageOrdinal,
			marks,
			navigation: nav ? {
				ttfb: nav.responseStart - nav.requestStart,
				domInteractive: nav.domInteractive - nav.startTime,
				domComplete: nav.domComplete - nav.startTime,
				load: nav.loadEventEnd - nav.startTime,
			} : {},
			resources,
		};
	}, { scenario, ordinal, markNames: PRODUCT_MARKS });
}

async function newPublicContext(context: BrowserContext, locale: 'en' | 'zh'): Promise<Page> {
	await context.clearCookies();
	await context.addInitScript((selectedLocale) => localStorage.setItem('locale', selectedLocale), locale);
	return context.newPage();
}

test.describe('@user @performance real Go-gateway readiness', () => {
	test('cold and warm public login stay usable and compressed', async ({ browser }, testInfo) => {
		const observedHeaders: Array<Record<string, string>> = [];
		const results: PageSample[] = [];
		for (let ordinal = -warmups; ordinal < samples; ordinal += 1) {
			const context = await browser.newContext({ locale: 'en-US', viewport: { width: 1440, height: 900 } });
			const page = await newPublicContext(context, 'en');
			page.on('response', async (response) => {
				if (response.url().includes('/_app/immutable/') && /\.(?:js|css)(?:\?|$)/.test(response.url())) {
					observedHeaders.push(await response.allHeaders());
				}
			});
			await page.goto('/', { waitUntil: 'load' });
			await expect(page.getByRole('textbox', { name: /email/i })).toBeVisible();
			await waitForMark(page, 'public-visible');
			await waitForMark(page, 'public-interactive');
			if (ordinal >= 0) results.push(await collectSample(page, 'public-login-cold-en', ordinal));

			await page.reload({ waitUntil: 'load' });
			await waitForMark(page, 'public-interactive');
			if (ordinal >= 0) results.push(await collectSample(page, 'public-login-warm-en', ordinal));
			if (ordinal === 0) {
				await page.screenshot({ path: testInfo.outputPath('public-login-en.png'), fullPage: true });
			}
			await context.close();
		}

		expect(observedHeaders.some((headers) => headers['content-encoding'] === 'br')).toBe(true);
		expect(observedHeaders.some((headers) => headers['cache-control']?.includes('immutable'))).toBe(true);
		await testInfo.attach('public-login-performance.json', { body: JSON.stringify(results, null, 2), contentType: 'application/json' });
	});

	test('Chinese public login uses the system CJK stack without bundled fallback on this host', async ({ browser }, testInfo) => {
		const context = await browser.newContext({ locale: 'zh-CN', viewport: { width: 360, height: 800 } });
		const page = await newPublicContext(context, 'zh');
		await page.goto('/', { waitUntil: 'load' });
		await waitForMark(page, 'public-interactive');
		await expect(page.locator('html')).toHaveAttribute('lang', 'zh');
		await expect(page.getByRole('textbox').first()).toBeVisible();
		const fallbackRequests = await page.evaluate(() => performance.getEntriesByType('resource')
			.map((entry) => (entry as PerformanceResourceTiming).name)
			.filter((name) => /noto-sans-sc-\d+-(?:core|r\d+)\.woff2/.test(name)));
		if (process.env.PERF_REQUIRE_SYSTEM_CJK_ZERO === '1') expect(fallbackRequests).toEqual([]);
		await page.screenshot({ path: testInfo.outputPath('public-login-zh-mobile.png'), fullPage: true });
		await testInfo.attach('cjk-network.json', { body: JSON.stringify({ fallbackRequests }, null, 2), contentType: 'application/json' });
		await context.close();
	});

	test('authenticated Inbox exposes cold/warm readiness marks and keeps CacheStorage public', async ({ browser }, testInfo) => {
		const results: PageSample[] = [];
		let cacheAudit: { names: string[]; urls: string[] } | undefined;
		for (let ordinal = -warmups; ordinal < samples; ordinal += 1) {
			const context = await browser.newContext({
				storageState: AUTH_FILE_USER,
				viewport: { width: 1440, height: 900 },
				serviceWorkers: 'allow',
			});
			const page = await context.newPage();
			await page.goto('/inbox', { waitUntil: 'load' });
			await waitForMark(page, 'shell-visible');
			await waitForMark(page, 'inbox-list-visible');
			await waitForMark(page, 'inbox-interactive');
			await expect(page.locator('.sj-inbox')).toBeVisible();
			if (ordinal >= 0) results.push(await collectSample(page, 'inbox-cold', ordinal));

			await page.reload({ waitUntil: 'load' });
			await waitForMark(page, 'shell-visible');
			await waitForMark(page, 'inbox-list-visible');
			await waitForMark(page, 'inbox-interactive');
			if (ordinal >= 0) results.push(await collectSample(page, 'inbox-warm', ordinal));

			if (ordinal === 0) {
				await expect.poll(() => page.evaluate(() => navigator.serviceWorker?.ready.then(() => true).catch(() => false))).toBe(true);
				cacheAudit = await page.evaluate(async () => {
					const names = await caches.keys();
					const urls: string[] = [];
					for (const name of names) {
						const cache = await caches.open(name);
						urls.push(...(await cache.keys()).map((request) => request.url));
					}
					return { names, urls };
				});
				await page.screenshot({ path: testInfo.outputPath('inbox-ready.png'), fullPage: true });
			}
			await context.close();
		}

		if (!cacheAudit) throw new Error('performance run did not produce a CacheStorage audit');
		expect(cacheAudit.urls.filter((url) => /\/(?:api|auth|jmap|updates|blobs?)(?:\/|\?|$)/.test(new URL(url).pathname))).toEqual([]);
		await testInfo.attach('inbox-performance.json', { body: JSON.stringify(results, null, 2), contentType: 'application/json' });
		await testInfo.attach('cache-audit.json', { body: JSON.stringify(cacheAudit, null, 2), contentType: 'application/json' });
	});
});
