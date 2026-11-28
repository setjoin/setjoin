import { test, expect } from '@playwright/test';
import { loginAsUser, psql } from '../../helpers';

/**
 * Quoted-text collapse + read-on-expand (WAVE-5 #6). Two independent journeys:
 *  1. a plain-text reply's `> `-quoted tail collapses behind a "Show quoted text"
 *     pill and expands on click (plain text is the DEFAULT render mode, so this
 *     needs no "Show HTML" toggle — the html-mode splitter is covered at the
 *     vitest layer, quoteSplit.test.ts).
 *  2. opening a 2-message thread auto-expands + marks $seen ONLY the newest
 *     message; the older collapsed card stays unread until the user expands it.
 */
test.describe('Quoted-text collapse @user', () => {
  test('a plain-text quoted tail collapses behind a pill and expands on click', async ({ page }) => {
    const ts = Date.now();
    const subject = `E2E quote pill ${ts}`;

    psql(
      `SELECT deliver('quotepill-${ts}', '<quotepill-${ts}@test.local>', 'partner-quote@partner.test', ` +
      `'Partner Quote', 'alice@test.local', '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '${subject}', NULL, NULL, ` +
      `'Thanks for confirming!\n\nOn Tue, Jul 1, 2025 Ada wrote:\n> Old line one\n> Old line two', ` +
      `NULL, 200, FALSE, now(), 'pass', 'pass', 'pass', 0.0, NULL)`
    );

    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);

    await page.getByRole('button', { name: new RegExp(subject) }).click();
    // Scope to the reading-pane body — the list row carries the same snippet text.
    const body = page.locator('.sj-reading-body__text');
    await expect(body).toContainText('Thanks for confirming!', { timeout: 10000 });

    // Collapsed by default: the quoted tail is not in the DOM at all.
    await expect(body).not.toContainText('Old line one');
    const pill = page.getByRole('button', { name: 'Show quoted text' });
    await expect(pill).toBeVisible({ timeout: 10000 });

    await pill.click();
    await expect(body).toContainText('Old line one', { timeout: 10000 });
    await expect(page.getByRole('button', { name: 'Hide quoted text' })).toBeVisible();
  });

  test('opening a thread marks only the auto-expanded newest message as read', async ({ page }) => {
    const ts = Date.now();
    const subjectBase = `E2E readexpand ${ts}`;
    const aMsgId = `<readexpand-a-${ts}@test.local>`;
    const bMsgId = `<readexpand-b-${ts}@test.local>`;

    // A: the thread root, older. B: a reply (In-Reply-To → same thread), newer —
    // ReadingPane auto-expands the newest on open (existing behavior); #6 pins
    // that read-on-expand rides ONLY that auto-expansion, never the collapsed peer.
    psql(
      `SELECT deliver('readexpand-a-${ts}', '${aMsgId}', 'partner-a@partner.test', 'Partner A', ` +
      `'alice@test.local', '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '${subjectBase}', NULL, NULL, ` +
      `'Root message body ${ts}.', NULL, 100, FALSE, now() - INTERVAL '2 hours', ` +
      `'pass', 'pass', 'pass', 0.0, NULL)`
    );
    psql(
      `SELECT deliver('readexpand-b-${ts}', '${bMsgId}', 'partner-b@partner.test', 'Partner B', ` +
      `'alice@test.local', '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, 'Re: ${subjectBase}', '${aMsgId}', NULL, ` +
      `'Reply message body ${ts}.', NULL, 100, FALSE, now() - INTERVAL '1 hour', ` +
      `'pass', 'pass', 'pass', 0.0, NULL)`
    );

    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);

    // The default Threaded list tab renders one GROUP row for the thread; clicking
    // it expands the group inline into its per-message sub-rows (list-only — this
    // does not itself open a ReadingPane). Opening the newest sub-row is what
    // actually navigates into the thread's ReadingPane (auto-expand + mark seen).
    await page.getByRole('button', { name: new RegExp(subjectBase) }).click();
    const newestRow = page.getByRole('button', { name: /message from Partner B/ });
    await expect(newestRow).toBeVisible({ timeout: 10000 });

    const openAck = page.waitForResponse(
      (r) =>
        r.url().includes('/jmap') &&
        r.request().method() === 'POST' &&
        (r.request().postData() ?? '').includes('Email/set'),
      { timeout: 10000 }
    );
    await newestRow.click();
    // Scope to the reading pane — the list row still carries the same snippet text.
    await expect(page.locator('.sj-reading-pane').getByText(`Reply message body ${ts}.`)).toBeVisible({
      timeout: 10000,
    });
    await openAck;

    expect(psql(`SELECT is_read FROM messages WHERE message_id = '${bMsgId}'`)).toBe('t');
    expect(psql(`SELECT is_read FROM messages WHERE message_id = '${aMsgId}'`)).toBe('f');

    // Expand the collapsed older card — only NOW does it become seen.
    const expandAck = page.waitForResponse(
      (r) =>
        r.url().includes('/jmap') &&
        r.request().method() === 'POST' &&
        (r.request().postData() ?? '').includes('Email/set'),
      { timeout: 10000 }
    );
    await page.locator('.sj-reading-pane').locator('.sj-msg-card__summary').click();
    await expect(page.locator('.sj-reading-pane').getByText(`Root message body ${ts}.`)).toBeVisible({
      timeout: 10000,
    });
    await expandAck;

    expect(psql(`SELECT is_read FROM messages WHERE message_id = '${aMsgId}'`)).toBe('t');
  });
});
