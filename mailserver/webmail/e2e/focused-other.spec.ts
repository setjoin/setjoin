import { test, expect } from '@playwright/test';
import { loginAsUser, psql, reloadAfterServiceWorkerControl } from './helpers';

/**
 * Focused/Other split (V078). classify_focus is deterministic, first-match-wins:
 * the seed calls deliver() WITHOUT p_is_external (defaults FALSE), so the cold
 * first-contact rule (rule 5: first-time AND external → Other) never fires for
 * the partner*.test senders and every seeded message classifies FOCUSED via the
 * rule-6 default — despite the senders being unknown external addresses.
 *
 * "Other" is a single system tag on the message; the per-row move button POSTs
 * /messages/{id}/focus, which both re-tags the message and learns a per-sender
 * focus_sender_overrides row — the reload proves both persisted.
 */
test.describe('Focused/Other split @user', () => {
  // Deterministic re-runs: drop alice's per-sender overrides and strip the Other
  // tag from her messages so the seeded mail is back in Focused before we start.
  test.beforeEach(() => {
    psql(`DELETE FROM focus_sender_overrides
          WHERE user_id = (SELECT id FROM users WHERE email = 'alice@test.local')`);
    psql(`DELETE FROM message_tags mt
          USING tags t, mailboxes mb
          WHERE mt.tag_id = t.id AND t.name = 'Other'
            AND t.mailbox_id = mb.id AND mb.email = 'alice@test.local'`);
  });

  test('seeded mail lands in Focused; a per-row move to Other persists across reload', async ({ page }, testInfo) => {

    const subject = 'E2E pile probe'; // dedicated fixture — inbox-read owns the numbered messages

    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);

    // The two-tab header renders on the plain Inbox view, Focused active.
    const focusedTab = page.getByRole('tab', { name: 'Focused' });
    const otherTab = page.getByRole('tab', { name: /^Other/ }); // name may carry an unread count
    await expect(focusedTab).toBeVisible({ timeout: 15000 });
    await expect(focusedTab).toHaveAttribute('aria-selected', 'true');

    // Seeded messages classify Focused (see header comment); Other starts empty.
    await expect(page.getByText(subject)).toBeVisible({ timeout: 10000 });
    await otherTab.click();
    await expect(page.getByText(/Nothing here/)).toBeVisible({ timeout: 10000 });
    await expect(page.getByText(subject)).not.toBeVisible();
    await focusedTab.click();
    await expect(page.getByText(subject)).toBeVisible({ timeout: 10000 });

    // The action cluster is display:none until the row is hovered.
    const row = page.getByRole('button', { name: new RegExp(`message from .*${subject}`) });
    await row.hover();
    await row.getByRole('button', { name: 'Move to Other' }).click();

    // Optimistic move: gone from Focused, present under Other.
    await expect(page.getByText(subject)).not.toBeVisible();
    await otherTab.click();
    await expect(page.getByText(subject)).toBeVisible({ timeout: 10000 });

    // PERSISTENCE: full reload — back on Focused by default; message 1 proves the
    // Focused list rendered before we assert message 3's absence; the moved
    // message is still in Other (tag + per-sender override are rows, not state).
    page = await reloadAfterServiceWorkerControl(page);
    await expect(page.getByRole('tab', { name: 'Focused' })).toBeVisible({ timeout: 15000 });
    await expect(page.getByText('E2E seeded message 1')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText(subject)).not.toBeVisible();
    await page.getByRole('tab', { name: /^Other/ }).click();
    await expect(page.getByText(subject)).toBeVisible({ timeout: 10000 });
  });
});
