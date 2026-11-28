import { test, expect } from '@playwright/test';
import { loginAsUser, psql } from '../../helpers';

/**
 * Real forward journey: open an inbound message → Forward → the full composer
 * opens with a "Fwd:" subject and an EMPTY To (the forward distinction vs reply,
 * which prefills To with the sender) → fill To → send → it lands in Sent.
 *
 * Proves the cross-layer seam UI → gateway → send reducer → state push → UI for
 * the forward path. Mirrors reply.spec.ts. Self-contained: delivers its own
 * message FROM a LOCAL user (bob) so the forward addresses a local mailbox — the
 * proven send path (compose-roundtrip).
 *
 * This journey found a real bug (now fixed): the forwarded original body didn't
 * render in the composer — RichTextEditor snapshots its `content` prop only at
 * mount and stays mounted across opens, so forward's open-$effect assignment to
 * bodyHtml left the editor empty (body sent but invisible, lost on first keystroke).
 * Fixed by pushing the prefilled body via editorRef.setContent() once ready, like
 * the reply quote. The second test below asserts that.
 *
 * Tall viewport so the To-field GAL overlay never reaches Send (no blur/Escape
 * close) — same trick as compose-roundtrip / reply.
 */
test.use({ viewport: { width: 1280, height: 2000 } });

function deliverFromBob(subject: string, body: string, stamp: number) {
  psql(
    `SELECT deliver('fwd-${stamp}', '<fwd-${stamp}@test.local>', ` +
    `'bob@test.local', 'Bob Test', 'alice@test.local', ` +
    `'[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '${subject}', NULL, NULL, ` +
    `'${body}', NULL, 100, FALSE, now(), 'pass', 'pass', 'pass', 0.0, NULL)`
  );
}

test.describe('Forward @user', () => {
  // Shrink the undo-send window to its 5s floor so the message actually sends
  // promptly and the Sent assertion isn't racing the default 30s hold.
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      try { localStorage.setItem('sj-undo-window', '5'); } catch { /* ignore */ }
    });
  });

  test('forwarding opens an empty-To "Fwd:" composer and lands in Sent', async ({ page }, testInfo) => {

    const stamp = Date.now();
    const subject = `Forward target ${stamp}`;
    deliverFromBob(subject, `Forward me original body ${stamp}`, stamp);

    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);

    // Open the delivered message (match the row by its unique subject).
    await page.getByRole('button', { name: new RegExp(subject) }).click();
    await expect(page.getByText(subject, { exact: false }).first()).toBeVisible();

    // Forward lives in the reading-pane sender block (IconButton label="Forward").
    await page.getByRole('button', { name: 'Forward', exact: true }).click();

    // The full composer opens: "Fwd:" subject and an EMPTY To (vs reply's prefill).
    const compose = page.getByTestId('compose-screen');
    await expect(page.getByRole('textbox', { name: 'Subject' })).toHaveValue('Fwd: ' + subject);
    await expect(page.getByRole('combobox', { name: 'To' })).toHaveValue('');

    // Address it to a local mailbox and send. Scope Send to the compose dialog:
    // the ReadingPane underneath still carries its (disabled) inline Send button.
    await page.getByRole('combobox', { name: 'To' }).fill('bob@test.local');
    await compose.getByRole('button', { name: 'Send', exact: true }).click();

    // Send accepted: the inline undo-send affordance appears.
    await expect(page.getByRole('button', { name: /undo/i })).toBeVisible({ timeout: 10000 });

    // ...and the forward materialises in Sent (timeout outlasts the undo-send window).
    await page.getByRole('button', { name: /^sent/i }).click();
    await expect(page.getByText('Fwd: ' + subject)).toBeVisible({ timeout: 35000 });
  });

  // Regression: the forwarded original body is quoted into the composer for
  // review/edit (the open-$effect now pushes it via editorRef.setContent() once the
  // editor is ready — it snapshots its content prop only at mount and stays mounted
  // across opens, so the state assignment alone left it empty).
  test('forwarded composer shows the quoted original body', async ({ page }, testInfo) => {

    const stamp = Date.now();
    const subject = `Forward quote ${stamp}`;
    const bodyMarker = `Forward quote original body ${stamp}`;
    deliverFromBob(subject, bodyMarker, stamp);

    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await page.getByRole('button', { name: new RegExp(subject) }).click();
    await page.getByRole('button', { name: 'Forward', exact: true }).click();

    // Expected: the original body is quoted into the composer for review/edit.
    await expect(page.getByTestId('compose-screen').locator('.ProseMirror')).toContainText(bodyMarker);
  });
});
