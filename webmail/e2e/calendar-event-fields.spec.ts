import { test, expect } from '@playwright/test';
import { loginAsUser, psql, reloadAfterServiceWorkerControl } from './helpers';

/**
 * Calendar event optional fields — guards the "optional field silently dropped on
 * create" class (ebeeb267): color, Show-As (freeBusyStatus) and Private (privacy)
 * are set in the create editor, then re-read from a FRESH page load through the
 * detail → Edit path, so a reducer/client mapping that drops any of them fails here.
 */
test.describe('Calendar event optional fields @user', () => {
  // The seed provisions no calendar for alice (calendar starts EMPTY) and both the
  // editor's Calendar select and the create reducer need one; arrange the default
  // calendar idempotently.
  test.beforeEach(() => {
    psql(`INSERT INTO calendars (mailbox_id, name, color, is_default)
          SELECT m.id, 'Calendar', '#3b82f6', TRUE FROM mailboxes m
          WHERE m.email = 'alice@test.local'
            AND NOT EXISTS (SELECT 1 FROM calendars c WHERE c.mailbox_id = m.id)`);
  });
  test('color + show-as + private survive save and reopen after reload', async ({ page }, testInfo) => {

    const title = `E2E event fields ${Date.now()}`;

    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Calendar' }).click();
    await expect(page).toHaveURL(/calendar/);

    await page.getByRole('button', { name: 'New event' }).click();
    const editor = page.getByRole('dialog', { name: 'New event' });
    await expect(editor).toBeVisible();

    await editor.getByLabel('Title').fill(title);
    // Playwright refuses fill() on input[type=color]; set the value and fire the
    // input event the component's oninput handler listens for.
    await editor.locator('input[type="color"]').evaluate((el, v) => {
      const input = el as HTMLInputElement;
      input.value = v;
      input.dispatchEvent(new Event('input', { bubbles: true }));
    }, '#aa3366');
    await editor.getByLabel('Show as').selectOption('free'); // non-default ('busy' is the default)
    // The native checkbox input is visually hidden (0×0); click the label text.
    await editor.getByText('Private', { exact: true }).click();
    await expect(editor.getByLabel('Private')).toBeChecked();

    await editor.getByRole('button', { name: 'Create' }).click();
    await expect(editor).not.toBeVisible({ timeout: 10000 });

    // Live UI update: the pill renders from the post-create refresh (no reload).
    // The under-load failure this once masked was a real bug — an empty
    // calendarId was server-rejected and silently discarded; both are fixed.
    await expect(page.locator('button.event-pill', { hasText: title })).toBeVisible({ timeout: 10000 });

    // PERSISTENCE: fresh load → pill → detail dialog → Edit → fields round-trip.
    page = await reloadAfterServiceWorkerControl(page);
    const pill = page.locator('button.event-pill', { hasText: title });
    await expect(pill).toBeVisible({ timeout: 15000 });
    await pill.click();

    const detail = page.getByRole('dialog', { name: title });
    await expect(detail).toBeVisible();
    await detail.getByRole('button', { name: 'Edit', exact: true }).click();

    const edit = page.getByRole('dialog', { name: 'Edit event' });
    await expect(edit).toBeVisible();
    await expect(edit.getByLabel('Title')).toHaveValue(title);
    await expect(edit.locator('input[type="color"]')).toHaveValue('#aa3366');
    await expect(edit.getByLabel('Show as')).toHaveValue('free');
    await expect(edit.getByLabel('Private')).toBeChecked();
  });
});
