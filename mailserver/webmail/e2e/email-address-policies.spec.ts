import { test, expect } from '@playwright/test';
import { loginAsAdmin, psql } from './helpers';

// Email Address Policies admin console (Task 12).
// Mirrors the admin auth/setup of the other admin e2e specs. Requires the full
// running stack (gateway + DB); intended to run in CI. Kept well-formed and
// consistent with smoke.spec.ts / a11y.spec.ts.

const ROUTE = '/admin/email-address-policies';
// Unique name per run so re-runs don't collide on a leftover row.
const POLICY_NAME = `E2E Policy ${Date.now()}`;

test.describe('Email Address Policies console @admin', () => {
  // Runs once under the admin project — this console mutates the shared
  // email_address_policies table (UNIQUE enabled-priority index), so running it
  // concurrently under both projects races on priority 100 and the beforeEach reset.
  test.beforeEach(async ({ page }, testInfo) => {
    // HERMETIC: the table starts empty in the seed, and there is a UNIQUE index on
    // priority WHERE enabled — so a policy left at priority 100 by an earlier run
    // (or a crashed run that never reached its delete step) makes the create at the
    // form's default priority 100 fail with a duplicate, surfacing as a 500-ish
    // dialog error and a flake. Reset to the seeded baseline before each test.
    psql('DELETE FROM email_address_policies;');
    await loginAsAdmin(page);
    await page.goto(ROUTE);
    // Page heading from i18n key admin.eap.title.
    await expect(page.getByRole('heading', { name: /email address polic/i })).toBeVisible({ timeout: 15000 });
  });

  test('create, preview, apply, and delete a policy', async ({ page }) => {
    // ── Create ──
    await page.getByRole('button', { name: /new policy/i }).first().click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible({ timeout: 10000 });

    // Target the two text fields by their unique placeholders — the "Name" and
    // "Primary Template" labels each collide with a section <h3> of the same text,
    // and the template must use a REAL variable ({user_name}/{domain}; {local}
    // is not in the allowed set, so it fails server validation).
    await dialog.getByPlaceholder('Engineering staff').fill(POLICY_NAME);
    await dialog.getByPlaceholder('{first_initial}{surname}@{domain}').fill('{user_name}@{domain}');

    // A condition: tick the "personal" mailbox-type checkbox.
    const personal = dialog.getByLabel(/^personal$/i).first();
    if (await personal.isVisible({ timeout: 3000 }).catch(() => false)) {
      await personal.check();
    }

    await dialog.getByRole('button', { name: /^save$/i }).click();
    await expect(dialog).toBeHidden({ timeout: 10000 });

    // ── Appears in the list ── (.first(): the name can render in more than one
    // cell/tooltip; strict mode would otherwise reject the multi-match.)
    await expect(page.getByText(POLICY_NAME).first()).toBeVisible({ timeout: 10000 });

    // ── Open it and trigger Preview ──
    const row = page.getByRole('row', { name: new RegExp(POLICY_NAME.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) });
    await row.getByRole('button', { name: /^edit$/i }).click();
    const editDialog = page.getByRole('dialog');
    await expect(editDialog).toBeVisible({ timeout: 10000 });
    // Preview section is present (sample-user search) once editing a saved policy.
    await expect(editDialog.getByPlaceholder(/sample user/i)).toBeVisible({ timeout: 5000 });
    await editDialog.getByRole('button', { name: /^cancel$/i }).click();
    await expect(editDialog).toBeHidden({ timeout: 10000 });

    // ── Apply now → job completes → done banner ──
    // The eapjobs worker ticks every 3s (slower on a cold stack), so a fixed-
    // timeout text assertion races it. Instead: capture the enqueue ACK's jobId,
    // poll the SAME status endpoint the page's own 1.5s poll uses until the job
    // settles, THEN assert the deterministic done-state banner.
    const applyAck = page.waitForResponse(
      (r) =>
        r.url().includes('/api/admin/email-address-policies/apply') &&
        r.request().method() === 'POST',
      { timeout: 10000 },
    );
    await page.getByRole('button', { name: /apply now/i }).first().click();
    const { jobId } = (await (await applyAck).json()) as { jobId: number };
    await expect
      .poll(
        async () => {
          const res = await page.request.get(`/api/admin/email-address-policies/apply/${jobId}`);
          if (!res.ok()) return `http-${res.status()}`;
          const s = (await res.json()) as { status: string; error: string | null };
          if (s.status === 'error' || s.status === 'failed') {
            throw new Error(`eap apply job ${jobId} failed: ${s.error}`);
          }
          return s.status;
        },
        { timeout: 30000, message: 'eap apply job did not complete' },
      )
      .toMatch(/^(done|completed)$/);
    // The page's own poll flips the banner to the done state within ~1.5s.
    await expect(page.getByText(/applied to \d+ mailbox/i).first()).toBeVisible({ timeout: 10000 });

    // ── Delete ──
    const row2 = page.getByRole('row', { name: new RegExp(POLICY_NAME.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) });
    await row2.getByRole('button', { name: /^delete$/i }).click();
    const delDialog = page.getByRole('dialog');
    await expect(delDialog).toBeVisible({ timeout: 5000 });
    await delDialog.getByRole('button', { name: /^delete$/i }).click();
    // Assert the row leaves the TABLE — the name also appears in the confirm
    // dialog's body, so an unscoped getByText matches 2 elements (strict-mode).
    await expect(page.getByRole('table').getByText(POLICY_NAME)).toBeHidden({ timeout: 10000 });
  });

  test('editor renders as a full-height sheet on a narrow viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 720 });
    await page.getByRole('button', { name: /new policy/i }).first().click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible({ timeout: 10000 });
    // Under 640px the sheet spans (near) the full viewport width.
    const box = await dialog.boundingBox();
    expect(box).not.toBeNull();
    if (box) {
      expect(box.width).toBeGreaterThan(340);
    }
  });

  test('console exposes accessible controls', async ({ page }) => {
    // Primary actions are real buttons with accessible names.
    await expect(page.getByRole('button', { name: /new policy/i }).first()).toBeVisible();
    await expect(page.getByRole('button', { name: /apply now/i }).first()).toBeVisible();
    // The editor dialog is a labelled modal.
    await page.getByRole('button', { name: /new policy/i }).first().click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible({ timeout: 10000 });
    await expect(dialog).toHaveAttribute('aria-modal', 'true');
  });
});
