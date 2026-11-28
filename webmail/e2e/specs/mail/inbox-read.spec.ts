import { test, expect } from '@playwright/test';
import { loginAsUser, psql, reloadAfterServiceWorkerControl } from '../../helpers';

// Real inbox reading journey over the seeded messages (seed.sql delivers alice 3
// inbound messages). Rail nav (button-based), web-first assertions, no fixed
// sleeps. The previous version was theater (a[href*=] nav, asserted "no messages"
// which is now wrong, "/new email/" button that no longer exists).
test.describe('Inbox reading @user', () => {
  test.beforeEach(async ({ page }, testInfo) => {
    // The seeded messages belong to alice (the user project); admin's inbox is
    // empty, so this user-data journey only runs under the user project.
    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);
  });

  test('seeded messages render as rows in the list', async ({ page }) => {
    // MailRow is role=button, aria-label="[Unread, ]message from <sender>: <subject>[, <time>]".
    // Exact count: the numbered messages belong to THIS spec (pile moves use the
    // dedicated 'E2E pile probe' fixture, so nothing else relocates these rows).
    await expect(page.getByRole('button', { name: /E2E seeded message 1/ })).toBeVisible();
    await expect(page.getByRole('button', { name: /message from .*E2E seeded message/ })).toHaveCount(3);
  });

  test('opening a message shows its subject and body in the reading pane', async ({ page }) => {
    await page.getByRole('button', { name: /E2E seeded message 1/ }).click();
    // Subject renders in the main frame (reading-pane header).
    await expect(page.getByText('E2E seeded message 1', { exact: false }).first()).toBeVisible();
    // The plain-text seeded body renders in the reading pane (HTML bodies sandbox
    // into an iframe; plain text shows directly). Scope to the reading-pane body
    // so it's not the list-row snippet that carries the same preview text.
    await expect(page.locator('.sj-reading-body__text')).toContainText('Body of seeded message 1', { timeout: 10000 });
  });

  test('an HTML message renders as HTML, not the 256-char preview (regression)', async ({ page }) => {
    // emailGet under-fetched (no bodyHTML) and openEmail reused the list item, so the
    // reading pane fell back to the truncated preview and HTML never rendered. Opening
    // an HTML message must now surface the HTML/plain toggle — present only when
    // bodyHTML was actually fetched — and the body marker beyond the 256-char cap.
    await page.getByRole('button', { name: /E2E HTML render check/ }).click();
    await expect(page.getByText('E2E HTML render check', { exact: false }).first()).toBeVisible();
    await expect(page.getByRole('button', { name: /Show (HTML|Plain Text)/ })).toBeVisible({ timeout: 10000 });
  });

  test('archiving a message removes it from the inbox list', async ({ page }) => {
    // Self-contained: deliver a dedicated message (unique subject) so we don't
    // consume the shared seed — archive mutates persistent e2e-DB state.
    const subject = `Archive me ${Date.now()}`;
    psql(
      `SELECT deliver('triage-${Date.now()}', '<triage-${Date.now()}@test.local>', ` +
      `'triager@partner.test', 'T', 'alice@test.local', ` +
      `'[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '${subject}', NULL, NULL, ` +
      `'archive me body', NULL, 100, FALSE, now(), 'pass', 'pass', 'pass', 0.0, NULL)`
    );
    page = await reloadAfterServiceWorkerControl(page);

    await page.getByRole('button', { name: new RegExp(subject) }).click();
    await expect(page.getByText(subject, { exact: false }).first()).toBeVisible();
    // Scope to the reading-pane toolbar — "Archive" also matches the sidebar view
    // and the per-row hover buttons.
    await page.locator('.sj-reading-pane__toolbar').getByRole('button', { name: 'Archive', exact: true }).click();

    // Archive strips the location tag, so the row leaves the Inbox view.
    await expect(page.getByRole('button', { name: new RegExp('message from .*' + subject) }))
      .toHaveCount(0, { timeout: 10000 });
  });
});
