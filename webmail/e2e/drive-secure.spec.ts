import { test, expect } from '@playwright/test';
import { createHash } from 'node:crypto';
import { loginAsUser, apiToken, setFeature, psql } from './helpers';
import { TEST_USERS } from './fixtures/test-data';

/**
 * Drive P3 secure-vault render path.
 *
 * I-11 honest split (per clients/AGENTS.md — there is no Playwright-Electron
 * harness in this repo yet): I-11(a) "no plaintext on disk" is proven where
 * the bytes live — offline-core's Rust marker-scan gate
 * (clients/rust/offline-core/tests/drive_test.rs's
 * no_plaintext_on_disk_after_import) plus the existing SQLCipher wrong-key
 * probing. I-11(c) "downloadURL never invoked for secure content" is the
 * Electron session-lockdown unit spy
 * (clients/desktop/electron/src/security/session-lockdown.test.ts's
 * will-download predicate tests). THIS spec proves I-11(b) — the in-browser
 * viewer renders from a blob: URL only, never a raw /content link or a
 * downloaded file — plus the server-side governed-export-only original gate and the
 * G3 view-audit dedupe. Any new SecureViewer render path should re-run this
 * three-way mapping before considering the security story covered (the code
 * review checklist note the plan calls for).
 *
 * feature.drive is DEFAULT OFF (V114) — enabled/disabled inline (the
 * mail-features.spec.ts "summarize" pattern: an admin-minted bearer flips the
 * toggle while `page` stays alice's session, so the UI flow below runs as a
 * normal user, not the admin project).
 */

const ts = Date.now();

// The smallest valid PNG (1x1, transparent) — a real image so the viewer's
// <img> actually decodes, not just a byte-count placeholder.
const PNG_BYTES = Buffer.from(
	'89504e470d0a1a0a0000000d4948445200000001000000010802000000907753de' +
		'0000000c4944415478da6360600000000200015dc02efe0000000049454e44ae426082',
	'hex',
);
const pngSha256 = createHash('sha256').update(PNG_BYTES).digest('hex');

const DOCX_BYTES = Buffer.from(`e2e docx stub ${ts}`);
const docxSha256 = createHash('sha256').update(DOCX_BYTES).digest('hex');

test.describe('Drive authenticated journeys @user', () => {
	let adminToken = '';
	let toggleOn = false;
	let pngNodeId = 0;
	let docxNodeId = 0;
	let pngVersionId = 0;
	let pngSourceVersionId = 0;
	let docxVersionId = 0;
	let memberSpaceId = 0;
	let grantedBobId = 0;

	test.afterEach(async ({ page, request }) => {
		// Teardown through the product API (trash-then-destroy — drive_node_destroy
		// requires the trash leg first, BZ141 otherwise).
		for (const nodeId of [pngNodeId, docxNodeId]) {
			if (!nodeId) continue;
			await page.request.post(`/api/drive/nodes/${nodeId}/trash`).catch(() => {});
			await page.request.delete(`/api/drive/nodes/${nodeId}`).catch(() => {});
		}
		pngNodeId = 0;
		docxNodeId = 0;
		if (memberSpaceId && grantedBobId) {
			const revoke = await page.request.delete(`/api/drive/spaces/${memberSpaceId}/members/${grantedBobId}`);
			expect(revoke.status(), 'revoke the E2E member through the product API').toBe(204);
		}
		// A created space has append-only audit evidence and no product delete
		// endpoint, so retain this uniquely named E2E artifact. Never bypass the
		// database's audit immutability trigger merely to make cleanup cosmetic.
		memberSpaceId = 0;
		grantedBobId = 0;
		// No product delete-space endpoint exists. Retain the uniquely named,
		// now-empty space because its append-only audit evidence deliberately
		// prevents raw-SQL deletion.
		// Belt-and-suspenders: leave the toggle OFF even if the test failed
		// before reaching its own setFeature(..., false) call.
		if (toggleOn) {
			await setFeature(request, adminToken, 'feature.drive', false).catch(() => {});
			toggleOn = false;
		}
	});

	test('secure original gate, governed export fallback, office rendition fallback', async ({ page, request }) => {
		adminToken = await apiToken(request, TEST_USERS.admin.email, TEST_USERS.admin.password);
		await setFeature(request, adminToken, 'feature.drive', true);
		toggleOn = true;
		await new Promise((r) => setTimeout(r, 1200)); // toggle hot-reload settle (helpers contract)

		await loginAsUser(page); // fresh session picks up the now-enabled capability

		// ── Arrange: a secure space, one PNG version, one docx-typed version ──
		const spaceRes = await page.request.post('/api/drive/spaces', {
			data: { name: `E2E secure ${ts}`, classification: 'secure' },
		});
		expect(spaceRes.status(), 'create space').toBe(201);
		const spaceId = ((await spaceRes.json()) as { id: number }).id;

		const nodeRes = await page.request.post('/api/drive/nodes', {
			data: { spaceId, parentId: null, kind: 'file', name: 'photo.png', contentType: 'image/png' },
		});
		expect(nodeRes.status(), 'create png node').toBe(201);
		pngNodeId = ((await nodeRes.json()) as { id: number }).id;

		const chunkRes = await page.request.put(`/api/drive/chunks/${pngSha256}?space=${spaceId}`, {
			headers: { 'Content-Type': 'application/octet-stream' },
			data: PNG_BYTES,
		});
		expect(chunkRes.ok(), 'put png chunk').toBeTruthy();

		const versionRes = await page.request.post(`/api/drive/files/${pngNodeId}/versions`, {
			data: {
				contentSha256: pngSha256,
				size: PNG_BYTES.length,
				contentType: 'image/png',
				baseVersionId: null,
				manifest: [{ sha256: pngSha256, size: PNG_BYTES.length }],
			},
		});
		expect(versionRes.status(), `put png version: ${await versionRes.text()}`).toBe(201);
		pngSourceVersionId = ((await versionRes.json()) as { versionId: number }).versionId;

		// Make a second head from the same source using the server-only clone
		// endpoint. This is both the API-level proof and the setup required for
		// the real UI to offer "Restore as new version" on the older row.
		const initialRestore = await page.request.post(
			`/api/drive/files/${pngNodeId}/versions/${pngSourceVersionId}/restore`,
			{ data: { baseVersionId: pngSourceVersionId, note: 'E2E server-side restore setup' } },
		);
		expect(initialRestore.status(), `server-side restore setup: ${await initialRestore.text()}`).toBe(201);
		pngVersionId = ((await initialRestore.json()) as { versionId: number }).versionId;

		const docxNodeRes = await page.request.post('/api/drive/nodes', {
			data: {
				spaceId,
				parentId: null,
				kind: 'file',
				name: 'report.docx',
				contentType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
			},
		});
		docxNodeId = ((await docxNodeRes.json()) as { id: number }).id;
		await page.request.put(`/api/drive/chunks/${docxSha256}?space=${spaceId}`, {
			headers: { 'Content-Type': 'application/octet-stream' },
			data: DOCX_BYTES,
		});
		const docxVersionRes = await page.request.post(`/api/drive/files/${docxNodeId}/versions`, {
			data: {
				contentSha256: docxSha256,
				size: DOCX_BYTES.length,
				contentType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
				baseVersionId: null,
				manifest: [{ sha256: docxSha256, size: DOCX_BYTES.length }],
			},
		});
		expect(docxVersionRes.status(), `put docx version: ${await docxVersionRes.text()}`).toBe(201);
		docxVersionId = ((await docxVersionRes.json()) as { versionId: number }).versionId;

		// ── Secure gate: non-regular originals never accept a client-selected
		// render-header bypass; preview/export is the only governed path. ──
		const noHeader = await page.request.get(`/api/drive/versions/${pngVersionId}/content`);
		expect(noHeader.status(), 'raw secure original -> rejected').toBe(403);
		const withHeader = await page.request.get(`/api/drive/versions/${pngVersionId}/content`, {
			headers: { 'X-Setjoin-Render': '1' },
		});
		expect(withHeader.status(), 'client header cannot bypass governed export').toBe(403);

		// ── Protected non-office content never attempts a browser render from
		// original bytes; the viewer gives the governed export path instead. ──
		const attachmentResponses: string[] = [];
		const originalContentRequests: string[] = [];
		page.on('response', (r) => {
			if ((r.headers()['content-disposition'] ?? '').includes('attachment')) attachmentResponses.push(r.url());
			if (/\/api\/drive\/versions\/\d+\/content$/.test(new URL(r.url()).pathname)) originalContentRequests.push(r.url());
		});

		await page.goto('/drive');
		await page.getByText(`E2E secure ${ts}`).click();
		await page.getByRole('button', { name: 'photo.png' }).click();
		await page.getByRole('button', { name: 'View', exact: true }).first().click();

		await expect(page.getByText(/governed export request/i)).toBeVisible({ timeout: 10000 });
		await expect(page.getByAltText('photo.png')).toHaveCount(0);
		expect(originalContentRequests, 'viewer never requests protected original bytes').toEqual([]);
		expect(attachmentResponses, 'no attachment-disposition response during the open').toEqual([]);

		await page.getByRole('dialog', { name: 'photo.png' }).getByRole('button', { name: 'Close' }).click();

		// The UI restore must call the server clone endpoint and must not fall
		// back to GET original -> browser Blob -> upload. The restored version
		// remains subject to the protected-original gate.
		const restoreAck = page.waitForResponse((r) =>
			r.request().method() === 'POST' &&
			new URL(r.url()).pathname === `/api/drive/files/${pngNodeId}/versions/${pngSourceVersionId}/restore`,
		);
		await page.getByRole('button', { name: 'Restore as new version', exact: true }).click();
		const restored = await restoreAck;
		expect(restored.status(), `UI server-side restore: ${await restored.text()}`).toBe(201);
		pngVersionId = ((await restored.json()) as { versionId: number }).versionId;
		expect(originalContentRequests, 'restore never fetches original bytes into the browser').toEqual([]);
		const versionList = await page.request.get(`/api/drive/files/${pngNodeId}/versions`);
		expect((await versionList.json()) as unknown[]).toHaveLength(3);
		expect((await page.request.get(`/api/drive/versions/${pngVersionId}/content`)).status()).toBe(403);

		// Reopening remains export-only and cannot create a misleading successful
		// view audit for content the browser never received.
		await page.getByRole('button', { name: 'photo.png' }).click();
		await page.getByRole('button', { name: 'View', exact: true }).first().click();
		await expect(page.getByText(/governed export request/i)).toBeVisible({ timeout: 10000 });
		await page.getByRole('dialog', { name: 'photo.png' }).getByRole('button', { name: 'Close' }).click();

		const viewCount = psql(
			`SELECT count(*) FROM drive_audit_log WHERE action = 'view' AND target_id IN (SELECT id FROM drive_file_versions WHERE file_node_id = ${pngNodeId})`,
		);
		expect(viewCount, 'rejected original renders do not create successful view audits').toBe('0');

		// ── Office fallback: no preview sidecar in the e2e env -> pending state,
		// never a broken viewer. Force 'unsupported' and confirm the localized
		// metadata-card copy. Esc closes the viewer and returns focus (a11y). ──
		await page.getByRole('button', { name: 'report.docx' }).click();
		const viewButton = page.getByRole('button', { name: 'View', exact: true });
		await viewButton.click();
		await expect(page.getByText('Rendition preview is not ready yet.')).toBeVisible({ timeout: 10000 });

		psql(`UPDATE drive_file_versions SET preview_status = 'unsupported' WHERE id = ${docxVersionId}`);
		await page.getByRole('button', { name: 'Retry' }).click();
		await expect(page.getByText('A preview is not available for this file type.')).toBeVisible({ timeout: 10000 });

		await page.keyboard.press('Escape');
		await expect(page.getByRole('dialog')).toHaveCount(0);
		await expect(viewButton).toBeFocused();

		// ── CSP live: the served meta still hash-locks script-src and carries
		// the media-src loopback token (re-using csp.spec.ts's extraction idiom). ──
		const html = await (await page.request.get('/drive')).text();
		const meta = html.match(/http-equiv="content-security-policy"\s+content="([^"]*)"/i)?.[1] ?? '';
		const scriptSrc = meta.match(/script-src([^;]*)/)?.[1] ?? '';
		const mediaSrc = meta.match(/media-src([^;]*)/)?.[1] ?? '';
		expect(scriptSrc, 'script-src still hash-locked, no unsafe-inline').not.toContain('unsafe-inline');
		expect(mediaSrc, 'media-src still carries the Drive loopback').toContain('http://127.0.0.1:*');

		await setFeature(request, adminToken, 'feature.drive', false);
		toggleOn = false;
	});

	test('member picker excludes guests, resets grant context, and grants an employee', async ({ page, request }) => {
		adminToken = await apiToken(request, TEST_USERS.admin.email, TEST_USERS.admin.password);
		await setFeature(request, adminToken, 'feature.drive', true);
		toggleOn = true;
		await new Promise((r) => setTimeout(r, 1200)); // toggle hot-reload settle (helpers contract)

		await loginAsUser(page);
		const spaceName = `E2E members ${Date.now()}`;
		const spaceRes = await page.request.post('/api/drive/spaces', {
			data: { name: spaceName, classification: 'regular' },
		});
		expect(spaceRes.status(), 'create member-picker space').toBe(201);
		memberSpaceId = ((await spaceRes.json()) as { id: number }).id;
		const bobUserId = Number(psql(`SELECT id FROM users WHERE email = '${TEST_USERS.bob.email}'`));
		expect(Number.isSafeInteger(bobUserId) && bobUserId > 0, 'seeded Bob user id').toBe(true);

		await page.goto('/drive');
		await page.getByText(spaceName, { exact: true }).click();
		await page.getByRole('button', { name: 'Members', exact: true }).click();
		const members = page.getByRole('dialog', { name: 'Members' });
		await expect(members).toBeVisible();
		const person = members.getByPlaceholder('Search by name or email');

		const guestSearchAck = page.waitForResponse(
			(r) => r.url().includes('/jmap') && r.request().method() === 'POST' &&
				(r.request().postData() ?? '').includes('ContactCard/directorySearch'),
		);
		await person.fill('e2e-drive-guest@external.test');
		const guestSearch = await guestSearchAck;
		expect(guestSearch.status(), 'guest directory search JMAP ACK').toBe(200);
		expect(JSON.stringify(await guestSearch.json()), 'JMAP directory response does not disclose the guest').not.toContain(
			'e2e-drive-guest@external.test',
		);
		await expect(members.getByText('e2e-drive-guest@external.test', { exact: true })).toHaveCount(0);

		const firstBobSearchAck = page.waitForResponse(
			(r) => r.url().includes('/jmap') && r.request().method() === 'POST' &&
				(r.request().postData() ?? '').includes('ContactCard/directorySearch'),
		);
		await person.fill(TEST_USERS.bob.email);
		await firstBobSearchAck;
		await members.getByRole('button', { name: /Bob Test/ }).click();
		await members.getByLabel('Role').selectOption('editor');

		// Closing without submitting must discard the person and role. Reopening
		// the still-mounted sheet proves the lifecycle reset in the real browser.
		await members.getByLabel('Close').click();
		await expect(members).not.toBeVisible();
		await page.getByRole('button', { name: 'Members', exact: true }).click();
		await expect(members.getByPlaceholder('Search by name or email')).toHaveValue('');
		await expect(members.getByLabel('Role')).toHaveValue('viewer');
		await expect(members.getByRole('button', { name: 'Add member' })).toBeDisabled();

		const secondBobSearchAck = page.waitForResponse(
			(r) => r.url().includes('/jmap') && r.request().method() === 'POST' &&
				(r.request().postData() ?? '').includes('ContactCard/directorySearch'),
		);
		await members.getByPlaceholder('Search by name or email').fill(TEST_USERS.bob.email);
		await secondBobSearchAck;
		await members.getByRole('button', { name: /Bob Test/ }).click();
		await members.getByLabel('Role').selectOption('editor');

		const grantAck = page.waitForResponse(
			(r) => r.request().method() === 'POST' &&
				new URL(r.url()).pathname === `/api/drive/spaces/${memberSpaceId}/members`,
		);
		await members.getByRole('button', { name: 'Add member' }).click();
		const grant = await grantAck;
		expect(grant.status(), 'Drive member grant ACK').toBe(200);
		grantedBobId = bobUserId;
		await expect(members.getByText('Bob Test')).toBeVisible();
		expect(
			psql(`SELECT role FROM drive_space_members WHERE space_id = ${memberSpaceId} AND user_id = ${bobUserId}`),
			'employee grant persisted through the authoritative reducer',
		).toBe('editor');

	});
});
