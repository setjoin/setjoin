import { test, expect } from '@playwright/test';
import { loginAs, loginAsAdmin, psql } from './helpers';

/**
 * Admin provisioning journey (W3): create a domain → create a user in it →
 * that user can log in and reach /apps. This is the REFERENCE implementation
 * of the e2e contract documented in e2e/AGENTS.md (tag routing, network-ack,
 * dedicated fixtures, psql cleanup).
 *
 * Includes the sad path that motivated the in-dialog error fix: a server-side
 * create rejection (password policy) must render INSIDE the dialog with
 * role="alert" — it used to land in a page banner BEHIND the modal overlay,
 * leaving the admin staring at a dead Create button.
 */

const ts = Date.now();
const DOMAIN = `e2e-admin-${ts}.test`;
const USER_EMAIL = `probe@${DOMAIN}`;
const USER_PASSWORD = 'Zx9#Quorum2026'; // policy: 4 char classes, no email-substring overlap

// Captured from the create ACKs; afterEach tears down through the PRODUCT's
// own delete endpoints (raw SQL teardown fights the primary-mailbox trigger
// and the welcome email's FK web — the API path owns that cascade).
let createdUserId = 0;
let createdDomainId = 0;

test.describe('Admin provisioning journey @admin', () => {
  test.afterEach(async ({ request }) => {
    // STRICT teardown: user deletion through the product API is itself part of
    // the journey's contract — it was broken THREE layers deep when this spec
    // first ran (retention-tag FK, primary-mailbox trigger timing, audit-log
    // FK vs append-only guard; fixed in V084/V085/V086).
    if (createdUserId) {
      const res = await request.delete(`/api/admin/users/${createdUserId}`);
      expect(res.status(), 'admin user delete must succeed').toBe(204);
    }
    if (createdDomainId) {
      const res = await request.delete(`/api/admin/domains/${createdDomainId}`);
      expect(res.status(), 'admin domain delete must succeed').toBe(204);
    }
    createdUserId = 0;
    createdDomainId = 0;
  });

  test('create domain → create user (sad path in-dialog) → new user reaches /apps', async ({ page }) => {
    await loginAsAdmin(page);

    // ── Domain ──
    await page.goto('/admin/domains');
    await page.getByRole('button', { name: 'Add domain' }).click();
    await page.getByLabel('Domain name').fill(DOMAIN);
    const domainAck = page.waitForResponse(
      (r) => r.url().includes('/api/admin/domains') && r.request().method() === 'POST',
      { timeout: 10000 },
    );
    await page.getByRole('dialog').getByRole('button', { name: /^(save|add|create)/i }).click();
    createdDomainId = ((await (await domainAck).json()) as { id: number }).id;
    await expect(page.getByRole('cell', { name: DOMAIN })).toBeVisible({ timeout: 10000 });

    // ── User: sad path first — a policy-rejected password must surface IN the
    // dialog (role=alert), not behind it. ──
    await page.goto('/admin/users');
    await page.getByRole('button', { name: 'Add user' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('Email').fill(USER_EMAIL);
    await dialog.getByLabel('Password').fill('weakpassword1'); // ≥8 chars: passes client, fails server policy
    await dialog.getByRole('button', { name: 'Create', exact: true }).click();
    const inDialogAlert = dialog.getByRole('alert');
    await expect(inDialogAlert).toBeVisible({ timeout: 10000 });
    await expect(inDialogAlert).toContainText(/uppercase/i);

    // ── Happy path: fix the password in the SAME dialog and create. ──
    await dialog.getByLabel('Password').fill(USER_PASSWORD);
    const userAck = page.waitForResponse(
      (r) => r.url().includes('/api/admin/users') && r.request().method() === 'POST' && r.status() < 300,
      { timeout: 10000 },
    );
    await dialog.getByRole('button', { name: 'Create', exact: true }).click();
    createdUserId = ((await (await userAck).json()) as { id: number }).id;

    // ── The filter box is wired to the server-side ?q= filter (debounced
    // re-fetch), so the fresh user must be findable regardless of pagination. ──
    const filterAck = page.waitForResponse(
      (r) => r.url().includes('/api/admin/users?') && r.url().includes(encodeURIComponent(USER_EMAIL)),
      { timeout: 10000 },
    );
    await page.getByPlaceholder(/filter by name/i).fill(USER_EMAIL);
    await filterAck;
    await expect(page.getByRole('cell', { name: USER_EMAIL }).first()).toBeVisible({ timeout: 10000 });

    // ── The provisioned user can actually log in and reach the app shell. ──
    await page.context().clearCookies();
    await loginAs(page, USER_EMAIL, USER_PASSWORD);
    await expect(page).toHaveURL(/\/apps/);
  });
});
