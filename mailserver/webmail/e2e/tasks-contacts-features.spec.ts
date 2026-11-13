import { test, expect } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { loginAsUser, psql } from './helpers';

/**
 * WAVE-5 tail smoke specs (tasks + contacts). ONE cheap "surface renders /
 * happy action acks" assertion per previously-unspecced feature — assign/
 * recurring/subtasks (tasks) and vCard import (contacts) already have full
 * coverage (tasks-crud.spec.ts, contacts-vcard-import.spec.ts), so they're
 * skipped here. See retired-docs:superpowers/plans/archive/2026-07-03-wave5-tail-program.md (W4).
 */

// e2e/fixtures/inline-image.png — reused from inline-image.spec.ts (a tiny real
// PNG for the file-upload path; not spec-owned data, just a shared fixture).
const INLINE_PNG = fileURLToPath(new URL('./fixtures/inline-image.png', import.meta.url));

test.describe('Tasks features smoke @user', () => {
  test('start date: the field round-trips through the Edit dialog', async ({ page }) => {
    const title = `E2E start date ${Date.now()}`;
    const startAt = '2027-01-15T09:30';

    await loginAsUser(page);
    await page.goto('/tasks');
    await expect(page.getByRole('button', { name: 'New task' })).toBeVisible({ timeout: 15000 });

    await page.getByRole('button', { name: 'New task' }).click();
    const dialog = page.getByRole('dialog', { name: 'New task' });
    await expect(dialog).toBeVisible({ timeout: 10000 });
    await dialog.getByLabel('Title').fill(title);
    await dialog.getByLabel('Start date').fill(startAt);
    const committed = page.waitForResponse(
      (res) => res.url().includes('/jmap') && res.request().method() === 'POST' &&
        (res.request().postData() ?? '').includes('Task/set')
    );
    await dialog.getByRole('button', { name: 'Save', exact: true }).click();
    await committed;
    await expect(dialog).toBeHidden({ timeout: 10000 });

    await page.getByText(title).first().click();
    const detail = page.getByRole('dialog', { name: title });
    await expect(detail).toBeVisible({ timeout: 10000 });
    await detail.getByRole('button', { name: 'Edit', exact: true }).click();
    const edit = page.getByRole('dialog', { name: 'Edit task' });
    await expect(edit.getByLabel('Start date')).toHaveValue(startAt);
  });
});

test.describe('Contacts features smoke @user', () => {
  // The seed provisions no addressbook for alice (same arrangement as
  // contacts-vcard-import.spec.ts).
  test.beforeEach(() => {
    psql(`INSERT INTO addressbooks (mailbox_id, name, is_default)
          SELECT m.id, 'Contacts', TRUE FROM mailboxes m
          WHERE m.email = 'alice@test.local'
            AND NOT EXISTS (SELECT 1 FROM addressbooks ab WHERE ab.mailbox_id = m.id)`);
  });

  test('photo: uploading an image renders the avatar preview', async ({ page }) => {
    await loginAsUser(page);
    // ContactsApp defaults to the Directory tab; "New contact" lives on the
    // personal Contacts tab (same flag contacts-vcard-import.spec.ts sets).
    await page.evaluate(() => localStorage.setItem('directoryMode', 'false'));
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Contacts' }).click();
    await expect(page).toHaveURL(/contacts/);

    await page.getByRole('button', { name: 'New contact' }).click();
    const dialog = page.getByRole('dialog', { name: 'New contact' });
    await expect(dialog).toBeVisible({ timeout: 10000 });

    const uploadAck = page.waitForResponse((r) => /\/api\/blobs\//.test(r.url()) && r.request().method() === 'PUT');
    await dialog.locator('#contact-photo').setInputFiles(INLINE_PNG);
    await uploadAck;

    await expect(dialog.locator('img.preview')).toBeVisible({ timeout: 10000 });
  });
});
