import { test, expect } from '@playwright/test';
import { loginAsUser, psql } from '../../helpers';

/**
 * Real snooze journey: open an inbound message → Snooze (preset) → it leaves the
 * Inbox list → it appears in the Snoozed view. (Resurface-on-due is covered at the
 * pgTAP layer — it needs a future-time round trip the UI can't drive here.)
 *
 * This journey found a product bug: the SnoozePicker self-positioned (absolute;
 * right:0) inside an already-absolute zero-width wrapper, so the preset dropdown
 * shot 200px left into the overflow-clipped message list and was unclickable. Fixed
 * by making the wrapper the sole positioning context and the picker in-flow (it now
 * opens rightward into the reading pane).
 */
test.use({ viewport: { width: 1920, height: 1200 } });

test.describe('Snooze @user', () => {
  test('snoozing a message removes it from the Inbox and shows it in Snoozed', async ({ page }, testInfo) => {

    const stamp = Date.now();
    const subject = `Snooze me ${stamp}`;
    psql(
      `SELECT deliver('snooze-${stamp}', '<snooze-${stamp}@test.local>', ` +
      `'partner@partner.test', 'Partner', 'alice@test.local', ` +
      `'[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '${subject}', NULL, NULL, ` +
      `'Snooze this body.', NULL, 100, FALSE, now(), 'pass', 'pass', 'pass', 0.0, NULL)`
    );

    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);

    // Open the delivered message and snooze it from the reading-pane toolbar.
    await page.getByRole('button', { name: new RegExp(subject) }).click();
    await expect(page.getByText(subject, { exact: false }).first()).toBeVisible();

    await page.locator('.sj-reading-pane__toolbar').getByRole('button', { name: 'Snooze', exact: true }).click();
    // SnoozePicker dropdown — pick an always-present preset. (Blocked: see header.)
    await page.getByRole('button', { name: 'Tomorrow, 8:00' }).click();

    // Snooze moves the location tag off Inbox, so the row leaves the Inbox list.
    await expect(page.getByRole('button', { name: new RegExp('message from .*' + subject) }))
      .toHaveCount(0, { timeout: 10000 });

    // ...and it now lives in the Snoozed view. The sidebar has two /Snoozed/
    // buttons — the VIEW nav (first, carries a count badge) and the system Snoozed
    // tag in the Tags list below — so take the first (the view).
    await page.locator('.sj-mail-sidebar').getByRole('button', { name: /Snoozed/ }).first().click();
    await expect(page.getByRole('button', { name: new RegExp(subject) }))
      .toBeVisible({ timeout: 10000 });
  });
});
