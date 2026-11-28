import { test, expect } from '@playwright/test';
import { loginAsAdmin } from './helpers';

// Admin approval-policy console (approval engine, Task 13 — spec §11).
// Tabbed by consumer type (RBAC/JIT · External send · Group moderation) + an
// Audit log tab. Read gate: approvals.view; write gate: approvals.manage — both
// held by the seeded Super Admin. Mirrors the admin auth/setup of the other
// admin specs (email-address-policies, conditional-access). Requires the full
// running stack (gateway + DB).

const ROUTE = '/admin/approvals';
const rx = (s: string) => new RegExp(s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));

test.describe('Approval policies console @admin', () => {
  test.beforeEach(async ({ page }) => {
    // Admin console — every test logs in as admin anyway, so the user-storage
    // project run is redundant. Pin to one project to avoid two projects
    // mutating the shared policy list in parallel.
    await loginAsAdmin(page);
    await page.goto(ROUTE);
    // h1 from i18n key admin.approvals.title = "Approval policies".
    await expect(page.getByRole('heading', { name: /approval polic/i })).toBeVisible({ timeout: 15000 });
  });

  test('create, edit, and delete a policy', async ({ page }) => {
    const name = `E2E Approval Policy ${Date.now()}`;

    // ── Create ── (defaults: enabled + requires-approval + default_admin approver)
    await page.getByRole('button', { name: /add policy/i }).first().click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible({ timeout: 10000 });
    await dialog.getByLabel(/^name$/i).first().fill(name);
    await dialog.getByRole('button', { name: /^save$/i }).click();
    await expect(dialog).toBeHidden({ timeout: 10000 });

    // ── Appears in the list ──
    await expect(page.getByText(name)).toBeVisible({ timeout: 10000 });

    // ── Edit opens the editor in edit mode ──
    const row = page.getByRole('row', { name: rx(name) });
    await row.getByRole('button', { name: /^edit$/i }).click();
    const editDialog = page.getByRole('dialog');
    await expect(editDialog).toBeVisible({ timeout: 10000 });
    await expect(editDialog.getByText(/edit policy/i)).toBeVisible();
    await editDialog.getByRole('button', { name: /^cancel$/i }).click();
    await expect(editDialog).toBeHidden({ timeout: 10000 });

    // ── Delete (with confirm dialog) ──
    const row2 = page.getByRole('row', { name: rx(name) });
    await row2.getByRole('button', { name: /^delete$/i }).click();
    // The delete confirm is its own overlay (aria-label "Confirm delete"),
    // distinct from the PolicyEditor dialog — scope to it so the right Delete fires.
    const delDialog = page.getByRole('dialog', { name: /confirm delete/i });
    await expect(delDialog).toBeVisible({ timeout: 5000 });
    await delDialog.getByRole('button', { name: /^delete$/i }).click();
    await expect(delDialog).toBeHidden({ timeout: 10000 });
    // Reload to assert the delete PERSISTED — a fresh fetch reflects the DB,
    // independent of the in-app list-refresh timing right after the mutation.
    // (Scope to the row: a bare getByText(name) also matches the confirm message.)
    await page.goto(ROUTE);
    await expect(page.getByRole('heading', { name: /approval polic/i })).toBeVisible({ timeout: 15000 });
    await expect(page.getByRole('row', { name: rx(name) })).toBeHidden({ timeout: 10000 });
  });

  test('navigates all consumer tabs and the audit log', async ({ page }) => {
    // Every policy tab offers the Add-policy action (admin can manage).
    for (const tab of [/external send/i, /group moderation/i, /rbac/i]) {
      await page.getByRole('tab', { name: tab }).click();
      await expect(page.getByRole('button', { name: /add policy/i }).first()).toBeVisible({ timeout: 10000 });
    }
    // The audit tab shows the audit table heading or its empty state.
    await page.getByRole('tab', { name: /audit log/i }).click();
    await expect(page.getByRole('heading', { name: 'All approval requests' })).toBeVisible({ timeout: 10000 });
  });

  test('console exposes accessible controls', async ({ page }) => {
    await expect(page.getByRole('button', { name: /add policy/i }).first()).toBeVisible();
    await page.getByRole('button', { name: /add policy/i }).first().click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible({ timeout: 10000 });
    await expect(dialog).toHaveAttribute('aria-modal', 'true');
  });
});
