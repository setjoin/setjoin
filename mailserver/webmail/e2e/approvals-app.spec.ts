import { test, expect } from '@playwright/test';
import { loginAsAdmin, psql } from './helpers';

// Standalone Approvals app — split-view decide (the "DD1" detail panel).
// The three CONSUMER triggers (RBAC/JIT activation, outbound external send,
// inbound group moderation) are covered end-to-end by pgTAP; here we seed
// approval_requests directly and drive the REAL decide UI through the real
// POST /me/approvals/{id}/decide → consumer-wrapper reducers, proving every
// consumer type surfaces in the queue and the approve/deny wiring works.
//
// Seed choices match the wrapper apply-semantics:
//   • group_moderation with NO held_inbound_messages row applies CLEANLY on
//     approve (the wrapper guards `IF deliver_params IS NOT NULL` before
//     deliver()), so approve → status 'applied'.
//   • rbac with requester != approver denies cleanly (the deny path applies
//     nothing), so deny → status 'denied'. requester = alice keeps SoD happy
//     (admin, the approver, is not the requester).

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const sq = (s: string) => s.replace(/'/g, "''");

function userId(email: string): string {
  return psql(`SELECT id FROM users WHERE email = '${sq(email)}'`);
}

function seedRequest(opts: {
  consumer: 'rbac.jit_activation' | 'mail.group_moderation';
  subject: string;
  approverId: string;
  requesterId?: string;
}): string {
  const requester = opts.requesterId ?? 'NULL';
  // CTE-wrap so psql -tA returns ONLY the id; a bare INSERT...RETURNING also
  // emits the "INSERT 0 1" command tag on stdout, corrupting the captured id.
  return psql(`
    WITH ins AS (
      INSERT INTO approval_requests
        (consumer_type, requester_user_id, subject, payload, status,
         approver_kind, approver_ref, expires_at)
      VALUES ('${opts.consumer}', ${requester}, '${sq(opts.subject)}', '{}'::jsonb, 'pending',
              'user', ${opts.approverId}, now() + interval '1 hour')
      RETURNING id
    ) SELECT id FROM ins`);
}

const statusOf = (id: string): string => psql(`SELECT status FROM approval_requests WHERE id = ${id}`);

test.describe('Approvals app — decide @admin', () => {
  let admin: string;
  let alice: string;

  test.beforeAll(() => {
    admin = userId('admin@test.local');
    alice = userId('alice@test.local');
    // NB: do NOT broadly DELETE 'E2E %' requests here — the approve-by-email spec
    // runs in parallel with 'E2E email …' subjects; a broad delete clobbers its
    // seeded row. Each test uses a unique Date.now() subject, so no cleanup needed.
  });

  test.beforeEach(async ({ page }) => {
    // Approver console — pin to one project (both runs log in as admin anyway;
    // running both projects in parallel races on the shared pending queue).
    await loginAsAdmin(page);
  });

  test('pending requests for me are listed with their consumer label', async ({ page }) => {
    const subj = `E2E pending ${Date.now()}`;
    seedRequest({ consumer: 'mail.group_moderation', subject: subj, approverId: admin });

    await page.goto('/approvals');
    // The queue renders as a labelled listbox of options.
    await expect(page.getByRole('listbox').first()).toBeVisible({ timeout: 15000 });
    await expect(page.getByText(subj)).toBeVisible({ timeout: 10000 });
    // Consumer label for mail.group_moderation = "Group Mail".
    await expect(page.getByText(/group mail/i).first()).toBeVisible();
  });

  test('approving a group-moderation request marks it applied', async ({ page }) => {
    const subj = `E2E approve ${Date.now()}`;
    const id = seedRequest({ consumer: 'mail.group_moderation', subject: subj, approverId: admin });

    await page.goto('/approvals');
    await page.getByRole('option', { name: new RegExp(esc(subj)) }).click();
    // Anchor ^approve: the aria-label is "Approve: {subject}"; an unanchored
    // /approve/i also matches "Deny: {subject}" when the subject contains "approve".
    const approve = page.getByRole('button', { name: /^approve/i });
    await expect(approve).toBeEnabled({ timeout: 10000 });
    await approve.click();

    // UI POST → group_moderation_approval_decide → status 'applied'.
    await expect.poll(() => statusOf(id), { timeout: 10000 }).toBe('applied');
  });

  test('denying requires a comment, then denies', async ({ page }) => {
    const subj = `E2E deny ${Date.now()}`;
    const id = seedRequest({
      consumer: 'rbac.jit_activation',
      subject: subj,
      approverId: admin,
      requesterId: alice,
    });

    await page.goto('/approvals');
    await page.getByRole('option', { name: new RegExp(esc(subj)) }).click();

    const deny = page.getByRole('button', { name: /^deny/i });
    // Wait for the detail panel to load (the decision buttons render) before
    // asserting the disabled-until-comment state.
    await expect(deny).toBeVisible({ timeout: 10000 });
    await expect(deny).toBeDisabled();
    await page.locator('#ad-comment-input').fill('Not this time (e2e).');
    await expect(deny).toBeEnabled();
    await deny.click();

    await expect.poll(() => statusOf(id), { timeout: 10000 }).toBe('denied');
  });

  test('queue and decision controls are accessible', async ({ page }) => {
    const subj = `E2E a11y ${Date.now()}`;
    seedRequest({ consumer: 'mail.group_moderation', subject: subj, approverId: admin });

    await page.goto('/approvals');
    await expect(page.getByRole('listbox').first()).toBeVisible({ timeout: 15000 });
    await page.getByRole('option', { name: new RegExp(esc(subj)) }).click();
    // Decision actions are real buttons with accessible names (anchored ^ so the
    // approve matcher doesn't also catch "Deny: {subject}" and vice-versa).
    await expect(page.getByRole('button', { name: /^approve/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /^deny/i })).toBeVisible();
  });
});
