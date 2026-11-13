import { test, expect, type APIRequestContext } from '@playwright/test';
import { createHash } from 'node:crypto';
import { apiLogin, apiToken, loginAsAdmin, loginAsUser, psql, setFeature } from './helpers';
import { TEST_USERS } from './fixtures/test-data';

const MIME = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
const ts = Date.now();

type Launch = {
	launchId: string;
	sessionId: string;
	expiresAt: string;
	accessToken: string;
	wopiSrc: string;
	editorUrl: string;
};

async function setProvider(
	request: APIRequestContext,
	adminToken: string,
	providerId: string,
	input: { enabled: boolean; draining: boolean; entitlementState?: string },
) {
	const response = await request.put(`/api/admin/office/providers/${providerId}`, {
		headers: {
			Authorization: `Bearer ${adminToken}`,
			'Content-Type': 'application/json',
			'X-Audit-Reason': `E2E provider lifecycle ${providerId}`,
		},
		data: {
			enabled: input.enabled,
			draining: input.draining,
			entitlementState: input.entitlementState ?? 'valid',
			buildId: 'e2e-build',
			config: {
				proofDiscoveryUrl: 'https://office.test/hosting/discovery',
				wopiPublicBaseUrl: 'https://setjoin.test',
				editorUrl: 'https://office.test/browser/editor',
			},
		},
	});
	expect(response.ok(), `set provider ${providerId}: ${await response.text()}`).toBeTruthy();
}

async function removeProvider(request: APIRequestContext, adminToken: string, providerId: string) {
	return request.delete(`/api/admin/office/providers/${providerId}`, {
		headers: {
			Authorization: `Bearer ${adminToken}`,
			'X-Audit-Reason': `E2E remove provider ${providerId}`,
		},
	});
}

test.describe('Office foundation and Drive History continuity @admin', () => {
	let adminToken = '';
	const fakeProvider = `e2e_fake_${ts}`;
	const drainProvider = `e2e_drain_${ts}`;
	const featureKeys = [
		'feature.office_local_open',
		'feature.office_editing',
		'feature.drive_history',
		'feature.drive',
	] as const;

	test.afterEach(async ({ request }) => {
		if (adminToken) {
			await removeProvider(request, adminToken, fakeProvider).catch(() => null);
			await removeProvider(request, adminToken, drainProvider).catch(() => null);
			for (const key of featureKeys) {
				await setFeature(request, adminToken, key, false).catch(() => null);
			}
		}
	});

	test('OFF → history/local/web combinations → WOPI save/replay/branch → provider removal preserves Drive', async ({ page, request }) => {
		test.setTimeout(120_000);
		adminToken = await apiToken(request, TEST_USERS.admin.email, TEST_USERS.admin.password);
		for (const key of featureKeys) await setFeature(request, adminToken, key, false);
		await new Promise((resolve) => setTimeout(resolve, 1200));

		await loginAsAdmin(page);
		await page.goto('/admin/office');
		await expect(page.getByRole('heading', { name: 'Office', exact: true })).toBeVisible();
		await expect(page.getByText('Drive History', { exact: true })).toBeVisible();
		await expect(page.getByText('Web editing', { exact: true })).toBeVisible();
		await expect(page.getByText('App local open', { exact: true })).toBeVisible();
		await expect(page.getByText('Off', { exact: true })).toHaveCount(3);

		await setFeature(request, adminToken, 'feature.drive', true);
		await new Promise((resolve) => setTimeout(resolve, 1200));
		await loginAsUser(page);

		const spaceResponse = await page.request.post('/api/drive/spaces', {
			data: { name: `E2E Office ${ts}`, classification: 'regular' },
		});
		expect(spaceResponse.status(), `create space: ${await spaceResponse.text()}`).toBe(201);
		const spaceId = ((await spaceResponse.json()) as { id: number }).id;
		const fileName = `office-continuity-${ts}.docx`;
		const nodeResponse = await page.request.post('/api/drive/nodes', {
			data: { spaceId, parentId: null, kind: 'file', name: fileName, contentType: MIME },
		});
		expect(nodeResponse.status(), `create file: ${await nodeResponse.text()}`).toBe(201);
		const fileId = ((await nodeResponse.json()) as { id: number }).id;
		const original = Buffer.from(`office original ${ts}`);
		const originalSha = createHash('sha256').update(original).digest('hex');
		expect((await page.request.put(`/api/drive/chunks/${originalSha}?space=${spaceId}`, { data: original })).ok()).toBeTruthy();
		const versionResponse = await page.request.post(`/api/drive/files/${fileId}/versions`, {
			data: {
				contentSha256: originalSha,
				size: original.length,
				contentType: MIME,
				baseVersionId: null,
				manifest: [{ sha256: originalSha, size: original.length }],
			},
		});
		expect(versionResponse.status(), `create version: ${await versionResponse.text()}`).toBe(201);
		const baseVersionId = ((await versionResponse.json()) as { versionId: number }).versionId;

		expect((await page.request.get(`/api/drive/files/${fileId}/history`)).status(), 'history OFF').toBe(404);
		expect((await page.request.get(`/api/drive/files/${fileId}/office/choices?platform=web`)).status(), 'Office OFF').toBe(404);

		await setFeature(request, adminToken, 'feature.drive_history', true);
		await setFeature(request, adminToken, 'feature.office_editing', true);
		await setFeature(request, adminToken, 'feature.office_local_open', true);
		await new Promise((resolve) => setTimeout(resolve, 1200));

		psql(`INSERT INTO office_provider_policies(provider_id,enabled,entitlement_state,build_id,config)
			VALUES ('${fakeProvider}',true,'valid','e2e-fake',
			'{"proofMode":"test_disabled","proofDiscoveryUrl":"https://office.test/hosting/discovery","editorUrl":"https://office.test/browser/editor","wopiPublicBaseUrl":"https://setjoin.test"}'::jsonb)`);

		const webChoicesResponse = await page.request.get(`/api/drive/files/${fileId}/office/choices?platform=web`);
		expect(webChoicesResponse.ok()).toBeTruthy();
		const webChoices = (await webChoicesResponse.json()) as { localOpenAllowed: boolean; choices: Array<{ providerId: string }> };
		expect(webChoices.localOpenAllowed).toBe(false);
		expect(webChoices.choices.map((choice) => choice.providerId)).toContain(fakeProvider);
		const electronChoices = (await (await page.request.get(`/api/drive/files/${fileId}/office/choices?platform=electron`)).json()) as {
			localOpenAllowed: boolean;
		};
		expect(electronChoices.localOpenAllowed).toBe(true);
		await setFeature(request, adminToken, 'feature.office_local_open', false);
		await new Promise((resolve) => setTimeout(resolve, 1200));
		const localOffChoices = (await (await page.request.get(`/api/drive/files/${fileId}/office/choices?platform=electron`)).json()) as {
			localOpenAllowed: boolean;
		};
		expect(localOffChoices.localOpenAllowed).toBe(false);

		const bobEmail = TEST_USERS.bob.email.replaceAll("'", "''");
		const aliceEmail = TEST_USERS.alice.email.replaceAll("'", "''");
		const bobId = psql(`SELECT id FROM users WHERE email='${bobEmail}'`);
		psql(`SELECT drive_member_grant((SELECT id FROM users WHERE email='${aliceEmail}'),${spaceId},${bobId},'viewer')`);
		const bobToken = await apiToken(request, TEST_USERS.bob.email, TEST_USERS.bob.password);
		const bobChoices = await request.get(`/api/drive/files/${fileId}/office/choices?platform=web`, {
			headers: { Authorization: `Bearer ${bobToken}` },
		});
		expect(bobChoices.ok(), 'viewer can discover an authorized viewing context').toBeTruthy();
		const bobLaunch = await request.post(`/api/drive/files/${fileId}/office/launches`, {
			headers: { Authorization: `Bearer ${bobToken}` },
			data: { baseVersionId, providerId: fakeProvider, deviceId: 'e2e-viewer', cohortKey: 'viewer-denied' },
		});
		expect(bobLaunch.status(), 'viewer cannot mint a write launch').toBe(403);

		const launch = async (cohortKey: string): Promise<Launch> => {
			const response = await page.request.post(`/api/drive/files/${fileId}/office/launches`, {
				data: { baseVersionId, providerId: fakeProvider, deviceId: `e2e-${cohortKey}`, cohortKey },
			});
			expect(response.status(), `launch ${cohortKey}: ${await response.text()}`).toBe(201);
			return (await response.json()) as Launch;
		};
		const mainLaunch = await launch('main-save');
		const staleLaunch = await launch('stale-save');
		expect(mainLaunch.editorUrl).toContain('WOPISrc=');
		expect(mainLaunch.editorUrl).not.toContain('access_token');

		const wopi = (token: string, suffix = '') => `/api/office/wopi/files/${fileId}${suffix}?access_token=${encodeURIComponent(token)}`;
		const info = await page.request.get(wopi(mainLaunch.accessToken));
		expect(info.ok()).toBeTruthy();
		expect((await info.json()) as { BaseFileName: string; UserCanWrite: boolean }).toMatchObject({
			BaseFileName: fileName,
			UserCanWrite: true,
		});
		const originalRead = await page.request.get(wopi(mainLaunch.accessToken, '/contents'));
		expect(Buffer.from(await originalRead.body())).toEqual(original);

		const lock = async (token: string, value: string) => page.request.post(wopi(token), {
			headers: { 'X-WOPI-Override': 'LOCK', 'X-WOPI-Lock': value },
		});
		expect((await lock(mainLaunch.accessToken, 'main-lock')).status()).toBe(200);
		const conflict = await lock(mainLaunch.accessToken, 'other-lock');
		expect(conflict.status()).toBe(409);
		expect(conflict.headers()['x-wopi-lock']).toBe('main-lock');
		expect((await lock(staleLaunch.accessToken, 'stale-lock')).status()).toBe(200);

		const mainBytes = Buffer.from(`office accepted ${ts}`);
		const save = async (launchValue: Launch, lockValue: string, operationKey: string, bytes: Buffer) =>
			page.request.post(wopi(launchValue.accessToken, '/contents'), {
				headers: {
					'Content-Type': 'application/octet-stream',
					'X-WOPI-Lock': lockValue,
					'X-Setjoin-Operation-Key': operationKey,
				},
				data: bytes,
			});
		const acceptedResponse = await save(mainLaunch, 'main-lock', 'e2e-main-save', mainBytes);
		expect(acceptedResponse.ok(), `accepted save: ${await acceptedResponse.text()}`).toBeTruthy();
		const accepted = (await acceptedResponse.json()) as { versionId: number; conflict: boolean; replayed: boolean };
		expect(accepted).toMatchObject({ conflict: false, replayed: false });
		const replayResponse = await save(mainLaunch, 'main-lock', 'e2e-main-save', mainBytes);
		expect(replayResponse.ok(), `save replay: ${await replayResponse.text()}`).toBeTruthy();
		expect((await replayResponse.json()) as { versionId: number; replayed: boolean }).toMatchObject({
			versionId: accepted.versionId,
			replayed: true,
		});

		const staleBytes = Buffer.from(`office stale branch ${ts}`);
		const staleResponse = await save(staleLaunch, 'stale-lock', 'e2e-stale-save', staleBytes);
		expect(staleResponse.ok(), `stale save: ${await staleResponse.text()}`).toBeTruthy();
		const stale = (await staleResponse.json()) as { versionId: number; branchId: number; conflict: boolean };
		expect(stale.conflict).toBe(true);
		expect(stale.branchId).toBeGreaterThan(0);
		expect(psql(`SELECT head_version_id FROM drive_files WHERE node_id=${fileId}`)).toBe(String(accepted.versionId));

		const historyResponse = await page.request.get(`/api/drive/files/${fileId}/history?limit=2`);
		expect(historyResponse.ok()).toBeTruthy();
		const firstHistory = (await historyResponse.json()) as {
			items: Array<{ source: string }>;
			hasMore: boolean;
			nextCursor: string | null;
		};
		expect(firstHistory.hasMore).toBe(true);
		expect(firstHistory.nextCursor).toBeTruthy();
		const secondHistory = await page.request.get(`/api/drive/files/${fileId}/history?limit=100&cursor=${encodeURIComponent(firstHistory.nextCursor!)}`);
		expect(secondHistory.ok()).toBeTruthy();
		const tamperedCursor = `${firstHistory.nextCursor!.slice(0, -1)}x`;
		expect((await page.request.get(`/api/drive/files/${fileId}/history?cursor=${encodeURIComponent(tamperedCursor)}`)).status()).toBe(400);
		expect(psql(`SELECT count(*) FROM office_save_receipts WHERE file_node_id=${fileId}`)).toBe('2');

		await page.addInitScript(() => {
			(window as unknown as { __officeSubmissions: Array<{ action: string; fields: Record<string, string> }> }).__officeSubmissions = [];
			HTMLFormElement.prototype.submit = function submit() {
				const fields = Object.fromEntries(new FormData(this).entries()) as Record<string, string>;
				(window as unknown as { __officeSubmissions: Array<{ action: string; fields: Record<string, string> }> }).__officeSubmissions.push({ action: this.action, fields });
			};
		});
		await page.goto('/drive');
		await page.getByText(`E2E Office ${ts}`, { exact: true }).click();
		await page.getByText(fileName, { exact: true }).click();
		await expect(page.getByRole('tab', { name: 'Current' })).toBeVisible();
		await page.getByRole('tab', { name: 'Timeline' }).click();
		await expect(page.getByRole('list', { name: 'File timeline' })).toBeVisible();
		await page.getByRole('tab', { name: 'Details' }).click();
		await expect(page.getByText('office', { exact: true }).first()).toBeVisible();
		await page.getByRole('button', { name: `Edit in ${fakeProvider}` }).click();
		await expect.poll(() => page.evaluate(() =>
			(window as unknown as { __officeSubmissions: unknown[] }).__officeSubmissions.length)).toBe(1);
		const submitted = await page.evaluate(() =>
			(window as unknown as { __officeSubmissions: Array<{ action: string; fields: Record<string, string> }> }).__officeSubmissions[0]);
		expect(submitted.action).toContain('WOPISrc=');
		expect(submitted.action).not.toContain('access_token');
		expect(submitted.fields.access_token).toBeTruthy();

		await setProvider(request, adminToken, drainProvider, { enabled: true, draining: false });
		const bothChoices = (await (await page.request.get(`/api/drive/files/${fileId}/office/choices?platform=web`)).json()) as {
			choices: Array<{ providerId: string }>;
		};
		expect(bothChoices.choices.map((choice) => choice.providerId)).toEqual(expect.arrayContaining([fakeProvider, drainProvider]));
		await setProvider(request, adminToken, drainProvider, { enabled: true, draining: true });
		const drainedChoices = (await (await page.request.get(`/api/drive/files/${fileId}/office/choices?platform=web`)).json()) as {
			choices: Array<{ providerId: string }>;
		};
		expect(drainedChoices.choices.map((choice) => choice.providerId)).not.toContain(drainProvider);

		const removed = await removeProvider(request, adminToken, fakeProvider);
		expect(removed.ok(), `remove provider: ${await removed.text()}`).toBeTruthy();
		expect((await page.request.get(wopi(mainLaunch.accessToken))).status(), 'provider removal fences existing WOPI tokens').toBe(404);
		expect(psql(`SELECT status FROM office_editor_sessions WHERE id='${mainLaunch.sessionId}'`)).toBe('revoked');
		expect((await page.request.get(`/api/drive/files/${fileId}/history`)).ok(), 'provider removal preserves history').toBeTruthy();
		const preserved = await page.request.get(`/api/drive/versions/${accepted.versionId}/content`);
		expect(preserved.ok(), 'provider removal preserves Drive bytes').toBeTruthy();
		expect(Buffer.from(await preserved.body())).toEqual(mainBytes);

		await setFeature(request, adminToken, 'feature.office_editing', false);
		await new Promise((resolve) => setTimeout(resolve, 1200));
		expect((await page.request.get(`/api/drive/files/${fileId}/office/choices?platform=web`)).status()).toBe(404);
		expect((await page.request.get(`/api/drive/files/${fileId}/history`)).ok(), 'history remains independent of editing').toBeTruthy();
		await setFeature(request, adminToken, 'feature.drive_history', false);
		await new Promise((resolve) => setTimeout(resolve, 1200));
		expect((await page.request.get(`/api/drive/files/${fileId}/history`)).status()).toBe(404);
		expect((await page.request.get(`/api/drive/files/${fileId}/versions`)).ok(), 'ordinary Drive versioning survives every Office flag OFF').toBeTruthy();

		await apiLogin(page, TEST_USERS.admin.email, TEST_USERS.admin.password);
		await page.goto('/admin/office');
		await expect(page.getByRole('heading', { name: 'Office', exact: true })).toBeVisible();
		await expect(page.getByText(fakeProvider, { exact: true })).toBeVisible();
		await expect(page.getByText(drainProvider, { exact: true })).toBeVisible();
		await expect(page.getByText('Removed', { exact: true }).last()).toBeVisible();
		await expect(page.getByText('Draining', { exact: true }).last()).toBeVisible();
	});
});
