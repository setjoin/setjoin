import { test, expect } from '@playwright/test';
import { TEST_USERS } from './fixtures/test-data';
import { loginAsUser } from './helpers';

/**
 * Compose → send → appears in Sent. The #1 P0 interaction: the seed has no
 * messages, so this is the only spec that drives the real mail-mutation path end
 * to end (alice sends to bob) — it creates its own data, so needs no seed.
 *
 * Template for the e2e/specs/mail rewrite: current shell (rail buttons, TipTap
 * .ProseMirror, "Compose"), web-first assertions, tour pre-dismissed in setup,
 * and a tall viewport so the To-field GAL autocomplete overlay never reaches the
 * Send button at the bottom (the GAL has no blur/Escape close).
 */
test.use({ viewport: { width: 1280, height: 2000 } });

test.describe('Compose round-trip @user', () => {
  test('alice composes and sends a message that lands in Sent', async ({ page }, testInfo) => {
    // Project name in the subject: both projects run this AS ALICE concurrently
    // and Date.now() collides across the two worker processes within the same
    // millisecond — two identical Sent rows then trip getByText's strict mode.
    const subject = `E2E round-trip ${testInfo.project.name} ${Date.now()}`;

    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);

    await page.getByRole('button', { name: 'Compose' }).click();

    await page.getByRole('combobox', { name: 'To' }).fill(TEST_USERS.bob.email);
    await page.getByRole('textbox', { name: 'Subject' }).fill(subject);
    const body = page.locator('.ProseMirror');
    await body.click();
    await page.keyboard.type('Sent from the compose round-trip e2e.');

    await page.getByRole('button', { name: 'Send', exact: true }).click();

    // Send accepted: the inline undo-send affordance appears.
    await expect(page.getByRole('button', { name: /undo/i })).toBeVisible({ timeout: 10000 });

    // ...and the message materialises in the Sent view (timeout outlasts the 30s
    // undo-send window in case delivery is deferred until it closes).
    await page.getByRole('button', { name: /^sent/i }).click();
    await expect(page.getByText(subject)).toBeVisible({ timeout: 35000 });
  });
});
