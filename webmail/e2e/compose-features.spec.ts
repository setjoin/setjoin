import { test, expect } from '@playwright/test';
import { loginAsUser } from './helpers';
import { TEST_USERS } from './fixtures/test-data';

/**
 * WAVE-5 tail smoke specs (compose-body rich-editor features). ONE cheap
 * "surface renders / happy action acks" assertion per feature — not a deep
 * journey. See retired-docs:superpowers/plans/archive/2026-07-03-wave5-tail-program.md (W4).
 *
 * Tall viewport so the To-field GAL overlay never reaches Send (same trick as
 * compose-roundtrip.spec.ts / attachment.spec.ts).
 */
test.use({ viewport: { width: 1280, height: 2000 } });

test.describe('Compose features smoke @user', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);
    // Wait for the inbox's own onMount sequence (loadSession → refreshMailboxes →
    // loadEmails) to finish before opening Compose — jmap/client.ts's accountId
    // singleton isn't populated until loadSession() resolves, and the mention/GAL
    // picker reads that same singleton with no fallback of its own.
    await expect(page.getByText('E2E seeded message 1')).toBeVisible({ timeout: 15000 });
    await page.getByRole('button', { name: 'Compose' }).click();
    await expect(page.getByTestId('compose-screen')).toBeVisible({ timeout: 10000 });
  });

  test('@mentions: typing @bob offers the GAL match and inserts a mention chip', async ({ page }) => {
    const compose = page.getByTestId('compose-screen');
    const body = compose.locator('.ProseMirror');
    await body.click();
    await page.keyboard.type('@bob');

    const option = page.getByRole('option', { name: /bob@test\.local/ });
    await expect(option).toBeVisible({ timeout: 10000 });
    await option.click();

    await expect(body.locator('.mention')).toBeVisible({ timeout: 10000 });
    await expect(body.locator('.mention')).toContainText('Bob');
  });

  test('insert-table: the toolbar dialog inserts a table into the body', async ({ page }) => {
    const compose = page.getByTestId('compose-screen');
    await compose.getByRole('button', { name: 'Insert table' }).click();

    const dialog = page.getByRole('dialog', { name: 'Insert table' });
    await expect(dialog).toBeVisible({ timeout: 10000 });
    await dialog.getByRole('button', { name: 'Insert', exact: true }).click();
    await expect(dialog).not.toBeVisible({ timeout: 10000 });

    await expect(compose.locator('.ProseMirror table')).toBeVisible({ timeout: 10000 });
  });

  test('voting: toggling Voting buttons and sending acks', async ({ page }, testInfo) => {
    const subject = `E2E voting probe ${testInfo.project.name} ${Date.now()}`;
    const compose = page.getByTestId('compose-screen');

    await page.getByRole('combobox', { name: 'To' }).fill(TEST_USERS.alice.email);
    await page.getByRole('textbox', { name: 'Subject' }).fill(subject);
    await compose.locator('.ProseMirror').click();
    await page.keyboard.type('Voting probe body.');

    // Priority/Sensitivity/Voting/S-MIME live behind the "More" disclosure. The
    // Switch's native checkbox is visually hidden (0×0) — click the wrapping
    // label (same trick as labels-apply.spec.ts's color-swatch pattern).
    await compose.getByRole('button', { name: 'More', exact: true }).click();
    await page.locator('.sj-switch', { hasText: 'Voting buttons' }).click();
    await compose.getByLabel('Voting option 1').fill('Yes');

    await compose.getByRole('button', { name: 'Send', exact: true }).click();
    await expect(page.getByRole('button', { name: /undo/i })).toBeVisible({ timeout: 10000 });
  });
});
