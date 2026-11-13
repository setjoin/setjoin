import { test, expect } from '@playwright/test';
import { loginAsUser } from '../../helpers';
import { TEST_USERS } from '../../fixtures/test-data';

/**
 * Attachment journeys — the compose upload pipeline + the full outbound round-trip.
 *
 * Both pass end to end: P0 implemented outbound attachments (ComposeScreen.buildMsg →
 * Email/set attachments → jmap_email_set_create writes message_attachments → the Go
 * Email/submission MIME assembler streams the blobs into multipart/mixed → swap seam →
 * the Sent copy carries the rows), and the e2e stack got a SeaweedFS S3 identity config
 * so signed blob PUT/GET work. This drove that whole vertical slice.
 *
 * Tall viewport so the To-field GAL overlay never reaches Send (same trick as
 * compose-roundtrip).
 */
test.use({ viewport: { width: 1280, height: 2000 } });

const FILE = {
  name: 'e2e-attachment.txt',
  mimeType: 'text/plain',
  buffer: Buffer.from('Attachment payload from the e2e attachment journey.'),
};

test.describe('Attachment @user', () => {
  test('choosing a file runs the compose upload pipeline to a rendered attachment chip', async ({ page }, testInfo) => {

    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);

    await page.getByRole('button', { name: 'Compose' }).click();
    const compose = page.getByTestId('compose-screen');

    // The attach affordances target a single hidden <input id="cmp-file"> (the
    // "Attach files" IconButton and the drop-zone both .click() it). Drive it
    // directly with an in-memory buffer — no real file on disk.
    await expect(compose.getByRole('button', { name: 'Attach files' })).toBeVisible();
    await compose.locator('input[type="file"][multiple]').setInputFiles(FILE);

    // The pick → handleFiles → uploadBlob pipeline fired and the composer
    // rendered the named chip for the uploaded blob. This is the SUCCESS
    // assertion only — the stack's SeaweedFS S3 identity config makes the
    // signed PUT work, so the chip is the expected outcome. The upload-error
    // banner is a DIFFERENT surface and must not satisfy this test: its
    // appearance here is an explicit failure below.
    await expect(compose.locator('.att-name')).toHaveText(FILE.name, { timeout: 15000 });
    // Error-surface guard (split from the disjunction this test used to use):
    // if the blob PUT is ever rejected again, THIS line fails the suite with
    // the banner present, instead of a green run masking the rejection.
    await expect(compose.locator('.compose-error-text')).toHaveCount(0);
  });

  // The full attachment round-trip: pick → upload → chip → send → the Sent copy
  // carries the file and downloads. This drove the whole P0 backend (Go-at-submission
  // MIME assembler) + the SeaweedFS S3 signing fix + the reducer message_attachments
  // write + the reading-pane download chips.
  test('a sent message carries its attachment (round-trip)', async ({ page }, testInfo) => {
    // Shrink the undo-send window so the message actually sends before the Sent assertion.
    await page.addInitScript(() => {
      try { localStorage.setItem('sj-undo-window', '5'); } catch { /* ignore */ }
    });

    const subject = `Attachment round-trip ${Date.now()}`;

    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await page.getByRole('button', { name: 'Compose' }).click();
    const compose = page.getByTestId('compose-screen');

    await compose.locator('input[type="file"][multiple]').setInputFiles(FILE);
    // The pick→upload→chip pipeline (PUT /blobs stores to SeaweedFS, blobs row created).
    await expect(compose.locator('.att-name')).toHaveText(FILE.name, { timeout: 8000 });

    await page.getByRole('combobox', { name: 'To' }).fill(TEST_USERS.bob.email);
    await page.getByRole('textbox', { name: 'Subject' }).fill(subject);
    const body = compose.locator('.ProseMirror');
    await body.click();
    await page.keyboard.type('Round-trip body.');
    await compose.getByRole('button', { name: 'Send', exact: true }).click();
    await expect(page.getByRole('button', { name: /undo/i })).toBeVisible({ timeout: 10000 });

    // The Sent copy carries the attachment (submission copies message_attachments to it).
    await page.getByRole('button', { name: /^sent/i }).click();
    await page.getByRole('button', { name: new RegExp('message from .*' + subject) }).click({ timeout: 35000 });
    await expect(page.locator('.sj-reading-body__attachment-name')).toContainText(FILE.name, { timeout: 8000 });
  });
});
