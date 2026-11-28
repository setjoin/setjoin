import { expect, test, type APIRequestContext } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { apiToken, loginAsAdmin, psql, setFeature } from './helpers';
import { TEST_USERS } from './fixtures/test-data';

const EVIDENCE = process.env.GUEST_E2E_EVIDENCE ?? '/tmp/setjoin-guest-e2e-evidence';

let adminToken = '';
let allowlistedDomain = '';

function authHeaders() {
  return { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' };
}

async function waitForGuestFeature(request: APIRequestContext, expectedStatus: number) {
  await expect.poll(async () => {
    const response = await request.get('/api/admin/guests', { headers: authHeaders() });
    return response.status();
  }, { timeout: 10_000 }).toBe(expectedStatus);
}

test.describe('Guest invitation terminal lifecycle @admin', () => {
  test.beforeEach(async ({ request }) => {
    mkdirSync(EVIDENCE, { recursive: true });
    adminToken = await apiToken(request, TEST_USERS.admin.email, TEST_USERS.admin.password);
    await setFeature(request, adminToken, 'feature.guest_accounts', true);
    await waitForGuestFeature(request, 200);
  });

  test.afterEach(async ({ request }) => {
    if (adminToken && allowlistedDomain) {
      await request.delete(`/api/admin/guest-invite-domains/${encodeURIComponent(allowlistedDomain)}`, {
        headers: authHeaders(),
      }).catch(() => undefined);
    }
    if (adminToken) {
      await setFeature(request, adminToken, 'feature.guest_accounts', false).catch(() => undefined);
      await waitForGuestFeature(request, 404).catch(() => undefined);
    }
    adminToken = '';
    allowlistedDomain = '';
  });

  test('pending → superseded replacement → exact revoke is visible and audited', async ({ page, request }) => {
    const run = Date.now();
    const displayName = `E2E Guest ${run}`;
    allowlistedDomain = `e2e-${run}.guest.test`;
    const email = `invite@${allowlistedDomain}`;

    const domainResponse = await request.post('/api/admin/guest-invite-domains', {
      headers: authHeaders(),
      data: { domain: allowlistedDomain },
    });
    expect(domainResponse.status()).toBe(201);

    const createResponse = await request.post('/api/admin/guests', {
      headers: authHeaders(),
      data: {
        email,
        displayName,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      },
    });
    expect([202, 503]).toContain(createResponse.status());
    const created = await createResponse.json() as { guestUserId: number; inviteId: string };
    expect(created.guestUserId).toBeGreaterThan(0);
    expect(created.inviteId).toMatch(/^[1-9][0-9]*$/);

    await loginAsAdmin(page);
    await page.goto('/admin/guests');
    await expect(page.getByRole('heading', { name: 'Guests' })).toBeVisible();
    await page.getByRole('button', { name: displayName }).click();

    const detail = page.getByRole('dialog', { name: displayName });
    await expect(detail).toBeVisible();
    const currentInvite = detail.getByRole('region', { name: 'Current invitation' });
    const history = detail.getByRole('region', { name: 'Invitation history' });
    await expect(currentInvite).toContainText(created.inviteId);
    await expect(currentInvite).toContainText('Pending');
    await expect(history).toContainText(created.inviteId);
    await page.screenshot({ path: join(EVIDENCE, '01-pending.png'), fullPage: true });

    await detail.getByRole('button', { name: 'Re-invite', exact: true }).click();
    const replaceDialog = page.getByRole('dialog', { name: 'Re-invite guest' });
    await expect(replaceDialog).toBeVisible();
    const replaceAck = page.waitForResponse((response) =>
      response.url().includes(`/api/admin/guests/${created.guestUserId}/reinvite`)
      && response.request().method() === 'POST',
    );
    await replaceDialog.getByRole('button', { name: 'Send replacement invitation' }).click();
    const replaceResponse = await replaceAck;
    expect([202, 503]).toContain(replaceResponse.status());
    const replacement = await replaceResponse.json() as { inviteId: string };
    expect(replacement.inviteId).toMatch(/^[1-9][0-9]*$/);
    expect(replacement.inviteId).not.toBe(created.inviteId);

    await expect(currentInvite).toContainText(replacement.inviteId);
    await expect(history).toContainText(created.inviteId);
    await expect(history).toContainText('Superseded');
    if (replaceResponse.status() === 503) {
      await expect(detail.getByRole('status')).toContainText('Delivery not confirmed');
      await expect(detail.getByRole('status')).toContainText(replacement.inviteId);
    }
    await page.screenshot({ path: join(EVIDENCE, '02-superseded.png'), fullPage: true });

    const revokeAck = page.waitForResponse((response) =>
      response.url().includes(`/api/admin/guests/${created.guestUserId}/invite`)
      && response.request().method() === 'DELETE',
    );
    await currentInvite.getByRole('button', { name: 'Revoke invitation' }).click();
    expect((await revokeAck).status()).toBe(200);

    await expect(currentInvite).toContainText('No pending invitation.');
    await expect(history).toContainText(replacement.inviteId);
    await expect(history).toContainText('Revoked');
    await expect(history).toContainText('Superseded');
    await page.screenshot({ path: join(EVIDENCE, '03-revoked.png'), fullPage: true });

    const auditCount = Number(psql(`
      SELECT count(*)
        FROM admin_audit_log
       WHERE target_type = 'guest_invite'
         AND target_id IN (${created.inviteId}, ${replacement.inviteId})
         AND action IN ('guest.invite_create','guest.invite_supersede','guest.invite_revoke')
    `));
    expect(auditCount).toBeGreaterThanOrEqual(4);
  });
});
