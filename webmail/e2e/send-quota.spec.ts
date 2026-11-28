import { test, expect } from '@playwright/test';
import { loginAs, psql } from './helpers';
import { TEST_USERS } from './fixtures/test-data';

/**
 * W2′ — the daily send-quota moment, end to end. Guards two fixed defects:
 *
 * 1. Classification: send() raises BZ004, but the submission reducer flattened
 *    it to invalidArguments+SQLERRM, so the UI showed "Couldn't send this
 *    message. Please try again." — actively wrong copy for a quota that resets
 *    tomorrow. The reducer now emits the RFC 8621 SetError type `overQuota`
 *    and the compose maps it to quota-specific copy in a role="alert" surface.
 * 2. Data loss: the compose bundled draft-destruction into the create call, so
 *    a failed submission had already destroyed the draft, orphaned the staged
 *    message, and every retry staged another orphan. Destruction is now
 *    deferred until the submission succeeds, and a failed submission cleans up
 *    its staged row — asserted here via psql row counts.
 *
 * Sender is BOB (dedicated-sender rule: alice is the shared protagonist of the
 * user-journey suite; mutating HER quota mid-suite would poison parallel specs).
 */

const ts = Date.now();
const SUBJECT_OK = `E2E quota send-1 ${ts}`;
const SUBJECT_BLOCKED = `E2E quota send-2 ${ts}`;

// LIVE rows only: JMAP Email/set destroy is a soft delete (deleted_at
// tombstone), so the cleanup of a failed submission leaves a tombstoned row.
const STAGED_COUNT_SQL = `
  SELECT count(*) FROM messages m
  JOIN mailboxes mb ON mb.id = m.mailbox_id
  WHERE mb.email = 'bob@test.local' AND m.subject = '${SUBJECT_BLOCKED}'
    AND m.deleted_at IS NULL`;

test.describe('Send quota surfaces to the sender @user', () => {
  test.beforeEach(() => {
    psql(`UPDATE mailboxes SET sending_quota_day = 1, sending_sent_today = 0,
          sending_quota_reset_at = CURRENT_DATE WHERE email = 'bob@test.local'`);
  });

  test.afterEach(() => {
    psql(`UPDATE mailboxes SET sending_quota_day = 500, sending_sent_today = 0
          WHERE email = 'bob@test.local'`);
  });

  test('over-quota send shows quota copy, keeps the compose, and orphans nothing on retry', async ({ page }) => {
    await loginAs(page, TEST_USERS.bob.email, TEST_USERS.bob.password);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);

    // Send 1 of 1 — within quota; await the submission ACK, not just the UI.
    await page.getByRole('button', { name: 'Compose' }).click();
    await page.getByRole('combobox', { name: 'To' }).fill(TEST_USERS.alice.email);
    await page.getByRole('textbox', { name: 'Subject' }).fill(SUBJECT_OK);
    await page.locator('.ProseMirror').click();
    await page.keyboard.type('within quota');
    const ack = page.waitForResponse(
      (r) => r.url().includes('/jmap') && r.request().method() === 'POST' &&
        (r.request().postData() ?? '').includes('EmailSubmission/set'),
      { timeout: 15000 },
    );
    await page.getByRole('button', { name: 'Send', exact: true }).click();
    await ack;
    await expect(page.getByRole('button', { name: /undo/i })).toBeVisible({ timeout: 10000 });
    // Let send-1's undo window drain fully — the "Sending in Ns…" toast
    // physically overlaps the compose footer and intercepts the next Send
    // click until it dismisses. Park the mouse away first: the toast pauses
    // its dismissal timer on hover, and Playwright's cursor rests exactly
    // where the Send click landed — under the toast — pinning it alive.
    await page.mouse.move(0, 0);
    await expect(page.getByText(/Sending in/)).toHaveCount(0, { timeout: 45000 }); // toast + aria-live twin

    // Send 2 — over quota. The quota copy must appear (role=alert), NOT the
    // generic "try again" the flattened classification used to produce.
    await page.getByRole('button', { name: 'Compose' }).click();
    await page.getByRole('combobox', { name: 'To' }).fill(TEST_USERS.alice.email);
    await page.getByRole('textbox', { name: 'Subject' }).fill(SUBJECT_BLOCKED);
    await page.locator('.ProseMirror').click();
    await page.keyboard.type('over quota');
    await page.getByRole('button', { name: 'Send', exact: true }).click();

    const alert = page.getByRole('alert');
    await expect(alert).toBeVisible({ timeout: 15000 });
    await expect(alert).toContainText(/daily sending limit/i);

    // The compose survives the failure with its content intact.
    await expect(page.getByRole('textbox', { name: 'Subject' })).toHaveValue(SUBJECT_BLOCKED);

    // Orphan invariant: after a failed send at most ONE live row carries this
    // subject — the autosaved DRAFT, which the fix deliberately preserves (the
    // old code had already destroyed it). The staged send copy is tombstoned
    // (wire-verified: the cleanup destroy fires before the error surfaces).
    const afterFail = Number(psql(STAGED_COUNT_SQL));
    expect(afterFail).toBeLessThanOrEqual(1);

    // Retry: the count must NOT GROW — pre-fix, every retry staged another
    // orphaned message row. Poll: attempt #1's alert is still on screen, so
    // the visible-alert signal can fire before the retry's cleanup lands.
    await page.getByRole('button', { name: 'Send', exact: true }).click();
    await expect(page.getByRole('alert')).toBeVisible({ timeout: 15000 });
    await expect.poll(() => Number(psql(STAGED_COUNT_SQL)), { timeout: 10000 }).toBeLessThanOrEqual(afterFail);
  });
});
