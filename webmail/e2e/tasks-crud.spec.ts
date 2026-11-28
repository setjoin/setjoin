import { test, expect } from '@playwright/test';
import { loginAsUser, reloadAfterServiceWorkerControl } from './helpers';

/**
 * Tasks CRUD (TasksApp): create a task with a GAL-picked assignee + a
 * recurrence preset, nest one subtask under it (Parent task select — the UI's
 * subtask mechanism), toggle the done-checkbox, RELOAD, and assert every field
 * survived — guards the field-silently-dropped-on-create regression class
 * (ebeeb267).
 *
 * Two deliberate shapes (both verified against the component/reducer):
 * - The done-toggle targets the SUBTASK, not the recurring parent: completing a
 *   task that carries an rrule spawns the NEXT occurrence as a new task with
 *   the SAME title (jmap_task.sql), which would break title-scoped row lookups.
 * - Recurrence renders only in the detail dialog (the list has no Repeat
 *   column), so the Weekly assertion opens the parent's detail.
 */

test.describe('Tasks CRUD @user', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsUser(page);
    await page.goto('/tasks');
    // PimShell renders the title as a span (no heading role) — the topbar
    // "New task" button is the ready signal.
    await expect(page.getByRole('button', { name: 'New task' })).toBeVisible({ timeout: 15000 });
  });
  test('task with assignee, recurrence, and subtask persists all fields across a reload', async ({ page }) => {
    const ts = Date.now();
    const title = `E2E task ${ts}`;
    const subTitle = `E2E subtask ${ts}`;

    // ── Create the parent: title + GAL-picked assignee + weekly recurrence ──
    await page.getByRole('button', { name: 'New task' }).click();
    const dialog = page.getByRole('dialog', { name: 'New task' });
    await expect(dialog).toBeVisible({ timeout: 10000 });
    await dialog.getByLabel('Title').fill(title);
    // Debounced galSearch dropdown (role=listbox/option) — pick bob from the GAL.
    await dialog.getByLabel('Assignee').fill('bob');
    await dialog.getByRole('option', { name: /bob@test\.local/ }).click();
    await dialog.getByLabel('Repeat').selectOption('WEEKLY');
    await dialog.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(dialog).toBeHidden({ timeout: 10000 });
    await expect(page.getByText(title).first()).toBeVisible({ timeout: 10000 });

    // ── Create one subtask nested under it (Parent task select) ──
    await page.getByRole('button', { name: 'New task' }).click();
    const dialog2 = page.getByRole('dialog', { name: 'New task' });
    await expect(dialog2).toBeVisible({ timeout: 10000 });
    await dialog2.getByLabel('Title').fill(subTitle);
    await dialog2.getByLabel('Parent task').selectOption({ label: title });
    await dialog2.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(dialog2).toBeHidden({ timeout: 10000 });

    // ── Toggle the subtask's done-checkbox (list view is where it renders) ──
    await page.getByRole('button', { name: 'List view' }).click();
    const subRow = page.locator('tr', { hasText: subTitle });
    await expect(subRow).toBeVisible({ timeout: 10000 });
    // Await the Task/set network ACK, not just the checked state: the checkbox
    // flips optimistically and the reload below would abort an in-flight POST.
    const committed = page.waitForResponse(
      (res) => res.url().includes('/jmap') && res.request().method() === 'POST' &&
        (res.request().postData() ?? '').includes('Task/set'),
      { timeout: 10000 },
    );
    await subRow.getByRole('checkbox', { name: 'Mark task done' }).click();
    await committed;
    await expect(subRow.getByRole('checkbox', { name: 'Mark task done' })).toBeChecked({ timeout: 10000 });

    // ── PERSISTENCE: reload (viewMode resets to kanban), re-enter list view ──
    page = await reloadAfterServiceWorkerControl(page);
    await expect(page.getByRole('button', { name: 'New task' })).toBeVisible({ timeout: 15000 });
    await page.getByRole('button', { name: 'List view' }).click();

    const parentRow = page.locator('tr', { hasText: title });
    await expect(parentRow).toBeVisible({ timeout: 10000 });
    // Assignee persisted (row shows assigneeName || assigneeEmail).
    await expect(parentRow).toContainText(/Bob Test|bob@test\.local/);
    // Subtask linkage persisted: parent shows "1/1 done" child progress...
    await expect(parentRow).toContainText('1/1 done');
    // ...and the subtask's own done-state persisted.
    await expect(
      page.locator('tr', { hasText: subTitle }).getByRole('checkbox', { name: 'Mark task done' })
    ).toBeChecked({ timeout: 10000 });

    // Recurrence persisted: detail dialog shows the Weekly preset.
    await parentRow.click();
    const detail = page.getByRole('dialog', { name: title });
    await expect(detail).toBeVisible({ timeout: 10000 });
    await expect(detail.getByText('Weekly')).toBeVisible();
  });
});
