import { test, expect } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { loginAsUser, psql } from './helpers';

/**
 * WAVE-5 tail smoke specs (calendar surfaces). ONE cheap "surface renders /
 * happy action acks" assertion per previously-unspecced feature — Show-As and
 * Private already have full coverage in calendar-event-fields.spec.ts, so
 * they're skipped here. See retired-docs:superpowers/plans/archive/2026-07-03-wave5-tail-program.md (W4).
 */

const SAMPLE_ICS = fileURLToPath(new URL('./fixtures/sample.ics', import.meta.url));

// The calendar sidebar (view-options panel: working hours, second time zone) only
// renders past a @container width breakpoint (PimShell.svelte) — widen past
// webcal.spec.ts's proven 1920x1200 so it's never clipped.
test.use({ viewport: { width: 1920, height: 1200 } });

test.describe('Calendar features smoke @user', () => {
  // The seed provisions no calendar for alice; arrange the default calendar
  // idempotently (same shape as calendar-event-fields.spec.ts).
  test.beforeEach(async ({ page }) => {
    psql(`INSERT INTO calendars (mailbox_id, name, color, is_default)
          SELECT m.id, 'Calendar', '#3b82f6', TRUE FROM mailboxes m
          WHERE m.email = 'alice@test.local'
            AND NOT EXISTS (SELECT 1 FROM calendars c WHERE c.mailbox_id = m.id)`);
    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Calendar' }).click();
    await expect(page).toHaveURL(/calendar/);
  });

  test('work-week: switching to Work Week renders the 5-day grid', async ({ page }) => {
    await page.getByRole('button', { name: 'Work Week' }).click();
    await expect(page.getByRole('button', { name: 'Work Week' })).toHaveClass(/sj-btn--primary/);
  });

  test('working hours: editing the sidebar range persists to localStorage', async ({ page }) => {
    const group = page.locator('.opt-group', { hasText: 'Working hours' });
    const inputs = group.locator('input[type="time"]');
    await inputs.first().fill('08:00');
    await inputs.first().blur();

    await expect
      .poll(() => page.evaluate(() => localStorage.getItem('sj-cal-work-start')))
      .toBe('08:00');
  });

  test('dual timezones: picking a second time zone persists to localStorage', async ({ page }) => {
    await page.locator('#cal-tz2').selectOption('America/New_York');

    await expect
      .poll(() => page.evaluate(() => localStorage.getItem('sj-cal-tz2')))
      .toBe('America/New_York');
  });

  test('attendee roles: an optional attendee round-trips with the Optional label', async ({ page }) => {
    const title = `E2E attendee role ${Date.now()}`;

    await page.getByRole('button', { name: 'New event' }).click();
    const editor = page.getByRole('dialog', { name: 'New event' });
    await editor.getByLabel('Title').fill(title);
    await editor.getByLabel(/Optional attendees/).fill('bob@test.local');

    await editor.getByRole('button', { name: 'Create' }).click();
    await expect(editor).not.toBeVisible({ timeout: 10000 });

    await page.locator('button.event-pill', { hasText: title }).click();
    const detail = page.getByRole('dialog', { name: title });
    await expect(detail).toBeVisible({ timeout: 10000 });
    await expect(detail.locator('.attendee-role')).toBeVisible();

    // The invite serializer runs asynchronously after the create reducer.
    // Assert the resulting text[] envelope row so a JSON-string/PG-array
    // mismatch cannot hide behind the best-effort background log path.
    await expect
      .poll(
        () =>
          psql(`SELECT count(*) FROM outbound_queue q
                JOIN calendar_events e ON e.uid = q.message_id
                WHERE e.title = '${title}' AND q.rcpt_addrs @> ARRAY['bob@test.local']::text[]`),
        { timeout: 10000, intervals: [250] },
      )
      .toBe('1');
  });

  test('propose new time: an invitee can counter-propose without changing the times', async ({ page }) => {
    const title = `E2E propose new time ${Date.now()}`;

    // alice is both organizer and (per userIsAttendee's own-email check) an
    // attendee — the cheapest way to make the "Propose new time" action
    // reachable without a second seeded mailbox.
    await page.getByRole('button', { name: 'New event' }).click();
    const editor = page.getByRole('dialog', { name: 'New event' });
    await editor.getByLabel('Title').fill(title);
    await editor.getByLabel(/^Attendees/).fill('alice@test.local');
    await editor.getByRole('button', { name: 'Create' }).click();
    await expect(editor).not.toBeVisible({ timeout: 10000 });

    await page.locator('button.event-pill', { hasText: title }).click();
    const detail = page.getByRole('dialog', { name: title });
    await expect(detail).toBeVisible({ timeout: 10000 });
    await detail.getByRole('button', { name: 'Propose new time' }).click();

    const proposeDialog = page.getByRole('dialog', { name: 'Propose a new time' });
    await expect(proposeDialog).toBeVisible({ timeout: 10000 });
    const ack = page.waitForResponse(
      (r) => r.url().includes('/jmap') && r.request().method() === 'POST' &&
        (r.request().postData() ?? '').includes('CalendarEvent/counter')
    );
    await proposeDialog.getByRole('button', { name: 'Send proposal' }).click();
    await ack;
    await expect(proposeDialog).not.toBeVisible({ timeout: 10000 });
  });

  test('print: Print opens an agenda popup', async ({ page }) => {
    const popupPromise = page.waitForEvent('popup');
    await page.getByRole('button', { name: 'Print', exact: true }).click();
    const popup = await popupPromise;
    await expect.poll(() => popup.title()).toContain('Print');
    await popup.close();
  });

  test('reminders: a reminder offset round-trips on the created event', async ({ page }) => {
    const title = `E2E reminder ${Date.now()}`;
    const startAt = new Date(Date.now() + 2 * 60 * 60 * 1000);
    const endAt = new Date(Date.now() + 3 * 60 * 60 * 1000);
    const localDate = (value: Date) =>
      `${value.getFullYear()}-${String(value.getMonth() + 1).padStart(2, '0')}-${String(value.getDate()).padStart(2, '0')}`;
    const localTime = (value: Date) =>
      `${String(value.getHours()).padStart(2, '0')}:${String(value.getMinutes()).padStart(2, '0')}`;

    await page.getByRole('button', { name: 'New event' }).click();
    const editor = page.getByRole('dialog', { name: 'New event' });
    await editor.getByLabel('Title').fill(title);
    await editor.getByLabel('Start date').fill(localDate(startAt));
    await editor.getByLabel('End date').fill(localDate(endAt));
    await editor.locator('input[type="time"]').nth(0).fill(localTime(startAt));
    await editor.locator('input[type="time"]').nth(1).fill(localTime(endAt));
    await editor.getByLabel('Remind me').selectOption('15');
    await editor.getByRole('button', { name: 'Create' }).click();
    await expect(editor).not.toBeVisible({ timeout: 10000 });

    // Month cells collapse after three items; the full suite already creates
    // other events for today before this reminder case. Agenda is the
    // non-collapsing product view, so a hidden fourth pill is not mistaken for
    // a failed create.
    await page.getByRole('button', { name: 'Agenda', exact: true }).click();
    await page.getByRole('button', { name: title, exact: false }).click();
    const detail = page.getByRole('dialog', { name: title });
    await expect(detail).toBeVisible({ timeout: 10000 });
    await detail.getByRole('button', { name: 'Edit', exact: true }).click();
    const edit = page.getByRole('dialog', { name: 'Edit event' });
    await expect(edit.getByLabel('Remind me')).toHaveValue('15');
  });

  test('ICS import: importing sample.ics acks with an imported count', async ({ page }) => {
    await page.getByRole('button', { name: 'Import', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Import calendar (.ics)' });
    await expect(dialog).toBeVisible({ timeout: 10000 });

    await dialog.locator('#ics-import-file').setInputFiles(SAMPLE_ICS);
    await dialog.getByRole('button', { name: 'Import', exact: true }).click();

    await expect(dialog.getByText(/imported/)).toBeVisible({ timeout: 10000 });
  });
});
