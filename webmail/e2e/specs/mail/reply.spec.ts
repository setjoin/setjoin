import { test, expect } from '@playwright/test';
import { loginAsUser, psql } from '../../helpers';

/**
 * Real reply journey: open an inbound message → Reply → the full composer opens
 * prefilled (To = original sender, "Re:" subject) → send → it lands in Sent.
 *
 * Proves the cross-layer wiring UI → gateway → send reducer → state push → UI.
 * Mail logic is covered exhaustively at the pgTAP/vitest layer; this only checks
 * the seam. Self-contained: delivers its own message FROM a LOCAL user (bob), so
 * the reply target is a local mailbox — the proven send path (compose-roundtrip).
 *
 * Tall viewport so the To-field GAL overlay never reaches Send (no blur/Escape
 * close) — same trick as compose-roundtrip.
 */
test.use({ viewport: { width: 1280, height: 2000 } });

test.describe('Reply @user', () => {
  // Shrink the undo-send window to its 5s floor so the send completes promptly and
  // the Sent assertion isn't racing the default 30s hold.
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      try { localStorage.setItem('sj-undo-window', '5'); } catch { /* ignore */ }
    });
  });

  test('replying to a message opens a prefilled composer and lands in Sent', async ({ page }, testInfo) => {

    const stamp = Date.now();
    const subject = `Reply target ${stamp}`;
    // Deliver FROM bob@test.local (a local mailbox) so the reply addresses a local
    // recipient — the same send path compose-roundtrip exercises.
    psql(
      `SELECT deliver('reply-${stamp}', '<reply-${stamp}@test.local>', ` +
      `'bob@test.local', 'Bob Test', 'alice@test.local', ` +
      `'[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '${subject}', NULL, NULL, ` +
      `'Please reply to this.', NULL, 100, FALSE, now(), 'pass', 'pass', 'pass', 0.0, NULL)`
    );

    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);

    // Open the delivered message (match the row by its unique subject).
    await page.getByRole('button', { name: new RegExp(subject) }).click();
    await expect(page.getByText(subject, { exact: false }).first()).toBeVisible();

    // Reply lives in the sender block (label "Reply"; exact avoids "Reply all").
    await page.getByRole('button', { name: 'Reply', exact: true }).click();

    // The full composer opens prefilled: To = original sender, "Re:" subject.
    await expect(page.getByRole('combobox', { name: 'To' })).toHaveValue('bob@test.local');
    await expect(page.getByRole('textbox', { name: 'Subject' })).toHaveValue('Re: ' + subject);

    // Add a body and send. Scope Send to the compose dialog: the ReadingPane
    // underneath still carries its (disabled) inline-reply "Send" button, so an
    // unscoped getByRole would be a strict-mode violation.
    const compose = page.getByTestId('compose-screen');
    const body = compose.locator('.ProseMirror');
    await body.click();
    await page.keyboard.type('Replying via the reply e2e journey.');
    await compose.getByRole('button', { name: 'Send', exact: true }).click();

    // Send accepted: the inline undo-send affordance appears.
    await expect(page.getByRole('button', { name: /undo/i })).toBeVisible({ timeout: 10000 });

    // ...and the reply materialises in Sent (timeout outlasts the undo-send window).
    await page.getByRole('button', { name: /^sent/i }).click();
    await expect(page.getByText('Re: ' + subject)).toBeVisible({ timeout: 35000 });
  });
});
