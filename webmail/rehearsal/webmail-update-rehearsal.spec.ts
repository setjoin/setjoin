import { expect, test, type Page } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { AUTH_FILE_USER } from '../e2e/fixtures/test-data';
import {
	SHELL_CACHE_PREFIX,
	SHELL_STATE_CACHE,
	SHELL_STATE_KEY,
	type ShellGenerationState,
} from '../src/lib/native/sw-generation';

// Retained-prior-artifact update rehearsal (retired-docs:superpowers/plans/
// 2026-08-09-webmail-loading-performance.md, release closure): one browser
// session boots from the retained PRIOR artifact, acknowledges its shell
// generation, survives a real gateway flip to the CANDIDATE artifact, and
// proves the prior acknowledged generation stays recoverable afterwards.
// This is upgrade evidence only — it measures no timing population and must
// never be represented as the 20-sample timing run.

const PRIOR_BUILD_ID = process.env.PERF_REHEARSAL_PRIOR_BUILD_ID as string;
const CANDIDATE_BUILD_ID = process.env.PERF_REHEARSAL_CANDIDATE_BUILD_ID as string;
const CONTROL_DIR = process.env.PERF_REHEARSAL_CONTROL_DIR as string;

const INBOX_MARKS = ['shell-visible', 'inbox-list-visible', 'inbox-interactive'] as const;
const FLIP_WAIT_MS = 300_000;
const GENERATION_WAIT_MS = 120_000;

async function waitForMark(page: Page, name: (typeof INBOX_MARKS)[number]): Promise<void> {
	await expect.poll(
		() => page.evaluate((mark) => performance.getEntriesByName(mark, 'mark').length, name),
		{ message: `waiting for product mark ${name}` },
	).toBe(1);
}

async function readGenerationState(page: Page): Promise<ShellGenerationState | null> {
	return page.evaluate(async ({ cacheName, stateKey }) => {
		const cache = await caches.open(cacheName);
		const response = await cache.match(stateKey);
		return response ? ((await response.json()) as ShellGenerationState) : null;
	}, { cacheName: SHELL_STATE_CACHE, stateKey: SHELL_STATE_KEY });
}

async function servedBuildId(page: Page): Promise<string | null> {
	// page.request bypasses the service worker, so this always observes what the
	// gateway currently serves rather than a cache-first copy.
	const response = await page.request.get('/_app/version.json', { maxRedirects: 0 });
	if (!response.ok()) return null;
	const body = (await response.json()) as { version?: unknown };
	return typeof body.version === 'string' ? body.version : null;
}

async function shellCacheAudit(page: Page, buildId: string): Promise<{ present: boolean; urlCount: number }> {
	return page.evaluate(async ({ prefix, expectedBuildId }) => {
		const names = await caches.keys();
		const name = names.find((candidate) => candidate === `${prefix}${expectedBuildId}`);
		if (!name) return { present: false, urlCount: 0 };
		const cache = await caches.open(name);
		return { present: true, urlCount: (await cache.keys()).length };
	}, { prefix: SHELL_CACHE_PREFIX, expectedBuildId: buildId });
}

test.describe('@user @performance retained-prior-artifact update rehearsal', () => {
	test('updates one acknowledged browser session from the prior artifact to the candidate and keeps the prior generation recoverable', async ({ browser }, testInfo) => {
		const context = await browser.newContext({
			storageState: AUTH_FILE_USER,
			viewport: { width: 1440, height: 900 },
			serviceWorkers: 'allow',
		});
		const page = await context.newPage();

		// Phase prior: boot from the retained prior artifact and acknowledge it.
		await page.goto('/inbox', { waitUntil: 'load' });
		for (const mark of INBOX_MARKS) await waitForMark(page, mark);
		await expect.poll(
			() => page.evaluate(() => navigator.serviceWorker?.ready.then(() => true).catch(() => false)),
		).toBe(true);
		await expect.poll(async () => (await servedBuildId(page)) === PRIOR_BUILD_ID, {
			timeout: GENERATION_WAIT_MS,
			message: `gateway must serve the retained prior build ${PRIOR_BUILD_ID} before acknowledgment`,
		}).toBe(true);
		await expect.poll(
			async () => {
				const state = await readGenerationState(page);
				return state?.currentBuildId === PRIOR_BUILD_ID && state?.generations?.[PRIOR_BUILD_ID]?.acknowledged === true;
			},
			{ timeout: GENERATION_WAIT_MS, message: `prior generation ${PRIOR_BUILD_ID} must install and be acknowledged` },
		).toBe(true);
		const priorAudit = await shellCacheAudit(page, PRIOR_BUILD_ID);
		expect(priorAudit.present).toBe(true);
		const priorState = await readGenerationState(page);
		mkdirSync(CONTROL_DIR, { recursive: true });
		writeFileSync(
			join(CONTROL_DIR, 'prior-acknowledged.json'),
			`${JSON.stringify({ servedBuildId: PRIOR_BUILD_ID, generationState: priorState, shellCache: priorAudit }, null, 2)}\n`,
		);
		await testInfo.attach('prior-generation.json', {
			body: JSON.stringify({ servedBuildId: PRIOR_BUILD_ID, generationState: priorState, shellCache: priorAudit }, null, 2),
			contentType: 'application/json',
		});

		// Mid-rehearsal the harness flips the gateway web root from the retained
		// prior artifact to the candidate build; wait until the flip is live.
		await expect.poll(async () => await servedBuildId(page), {
			timeout: FLIP_WAIT_MS,
			intervals: [2_000],
			message: `gateway must flip to the candidate build ${CANDIDATE_BUILD_ID}`,
		}).toBe(CANDIDATE_BUILD_ID);

		// Phase candidate: reload through the real update path and acknowledge the
		// candidate generation with the prior generation retained as previous.
		await page.reload({ waitUntil: 'load' });
		for (const mark of INBOX_MARKS) await waitForMark(page, mark);
		await expect.poll(
			async () => {
				const state = await readGenerationState(page);
				return state?.currentBuildId === CANDIDATE_BUILD_ID &&
					state?.previousBuildId === PRIOR_BUILD_ID &&
					state?.generations?.[CANDIDATE_BUILD_ID]?.acknowledged === true;
			},
			{
				timeout: GENERATION_WAIT_MS,
				message: `candidate ${CANDIDATE_BUILD_ID} must be acknowledged with prior ${PRIOR_BUILD_ID} retained as previous`,
			},
		).toBe(true);
		const candidateState = await readGenerationState(page);
		const candidateAudit = await shellCacheAudit(page, CANDIDATE_BUILD_ID);
		const retainedPriorAudit = await shellCacheAudit(page, PRIOR_BUILD_ID);
		expect(candidateAudit.present).toBe(true);
		expect(retainedPriorAudit.present, 'previous acknowledged generation cache must remain retained').toBe(true);
		expect(retainedPriorAudit.urlCount, 'previous generation cache must keep recoverable members').toBeGreaterThan(0);
		const cacheNames = await page.evaluate(() => caches.keys());
		expect(cacheNames.filter((name) => name.startsWith(SHELL_CACHE_PREFIX)).every((name) =>
			name === `${SHELL_CACHE_PREFIX}${PRIOR_BUILD_ID}` || name === `${SHELL_CACHE_PREFIX}${CANDIDATE_BUILD_ID}`,
		)).toBe(true);
		const audit = { servedBuildId: CANDIDATE_BUILD_ID, generationState: candidateState, shellCache: candidateAudit, retainedPrior: retainedPriorAudit };
		writeFileSync(
			join(CONTROL_DIR, 'update-complete.json'),
			`${JSON.stringify(audit, null, 2)}\n`,
		);
		await testInfo.attach('update-audit.json', {
			body: JSON.stringify(audit, null, 2),
			contentType: 'application/json',
		});
		await context.close();
	});
});
