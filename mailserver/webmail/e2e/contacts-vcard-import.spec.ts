import { test, expect } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { loginAsUser, psql, reloadAfterServiceWorkerControl } from './helpers';

// e2e/fixtures/sample.vcf: two cards — FN 'Alice Test' (EMAIL alice@test.local,
// ORG Test Corp, TEL) and FN 'Bob Test' (EMAIL bob@test.local).
const VCF = fileURLToPath(new URL('./fixtures/sample.vcf', import.meta.url));

/**
 * Contacts vCard import. The import modal (CsvImportModal) routes a .vcf through
 * POST /contacts/import/vcf — self-describing, so it skips the CSV column-map and
 * goes straight to the strategy step. The default 'skip existing' strategy makes
 * the run idempotent (a re-run imports 0 / skips 2 but the cards still render).
 */
test.describe('Contacts vCard import @user', () => {
  // The seed provisions no addressbook (contacts start EMPTY for alice) and the
  // import endpoint requires an owned addressBookId, so arrange the default book
  // idempotently — exactly what first-run provisioning would have created.
  test.beforeEach(() => {
    psql(`INSERT INTO addressbooks (mailbox_id, name, is_default)
          SELECT m.id, 'Contacts', TRUE FROM mailboxes m
          WHERE m.email = 'alice@test.local'
            AND NOT EXISTS (SELECT 1 FROM addressbooks ab WHERE ab.mailbox_id = m.id)`);
  });
  test('sample.vcf imports and the contacts persist across reload', async ({ page }, testInfo) => {

    await loginAsUser(page);
    // ContactsApp defaults to the Directory tab (localStorage 'directoryMode',
    // default true); Import CSV lives on the personal Contacts tab. Seed the
    // flag pre-navigation — the toggle button's AX exposure is viewport-dependent.
    await page.evaluate(() => localStorage.setItem('directoryMode', 'false'));
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Contacts' }).click();
    await expect(page).toHaveURL(/contacts/);

    await page.getByRole('button', { name: 'Import CSV' }).click();
    const dialog = page.getByRole('dialog', { name: 'Import contacts' });
    await expect(dialog).toBeVisible();

    // A .vcf pick flips the wizard to the strategy step (no column map).
    await dialog.locator('#csv-file-input').setInputFiles(VCF);
    await expect(dialog.getByText(/self-describing/)).toBeVisible();
    await dialog.getByRole('button', { name: 'Import', exact: true }).click();

    // onDone closes the modal and refreshes the contact list.
    await expect(dialog).not.toBeVisible({ timeout: 15000 });

    const aliceCard = page.locator('.contact-card', { hasText: 'Alice Test' });
    await expect(aliceCard).toBeVisible({ timeout: 10000 });
    await expect(aliceCard).toContainText('alice@test.local');
    const bobCard = page.locator('.contact-card', { hasText: 'Bob Test' });
    await expect(bobCard).toBeVisible();
    await expect(bobCard).toContainText('bob@test.local');

    // PERSISTENCE: reload — the contacts are rows, not page state.
    page = await reloadAfterServiceWorkerControl(page);
    const aliceAfter = page.locator('.contact-card', { hasText: 'Alice Test' });
    await expect(aliceAfter).toBeVisible({ timeout: 15000 });
    await expect(aliceAfter).toContainText('alice@test.local');
    await expect(page.locator('.contact-card', { hasText: 'Bob Test' })).toContainText('bob@test.local');
  });
});
