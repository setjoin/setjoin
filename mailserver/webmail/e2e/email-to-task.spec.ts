import { test, expect } from '@playwright/test';
import { loginAsUser, psql } from './helpers';

/**
 * Email → task: the reading-pane "Create task" action (inbox +page.svelte
 * createTaskFromEmail) creates a task titled with the message subject and linked
 * back to the message via linkedMessageId + linkedMessageReceivedAt. The
 * load-bearing assertion is the PERSISTED linkage, not the toast — guards the
 * field-silently-dropped-on-create regression class (ebeeb267): the FK
 * tasks(linked_message_id, linked_message_received_at) is MATCH SIMPLE, so a
 * dropped received_at silently unenforces the link.
 *
 * The round trip closes through the UI (2026-07-02): the task detail dialog
 * renders a "Linked email" field with an Open-email button that deep-links
 * /inbox?t=<messageId> (selectionFromUrl resolves message ids too).
 */

const SUBJECT = 'E2E seeded message 1';

// Tasks for alice titled with the subject that carry BOTH linkage fields.
const LINKED_COUNT_SQL = `
  SELECT count(*) FROM tasks t
  JOIN mailboxes mb ON mb.id = t.mailbox_id
  WHERE mb.email = 'alice@test.local'
    AND t.title = '${SUBJECT}'
    AND t.linked_message_id IS NOT NULL
    AND t.linked_message_received_at IS NOT NULL`;

test.describe('Email to task @user', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsUser(page);
  });

  test('Create task from a message persists the linkage and links back to the email', async ({ page }) => {
    const before = Number(psql(LINKED_COUNT_SQL));

    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);

    // Open the seeded message (MailRow accessible name carries the subject).
    await page.getByRole('button', { name: new RegExp(SUBJECT) }).first().click();
    await expect(page.getByRole('heading', { name: SUBJECT })).toBeVisible({ timeout: 10000 });

    await page.getByRole('button', { name: 'Create task' }).click();
    await expect(page.getByText('Task created').first()).toBeVisible({ timeout: 10000 });

    // PERSISTENCE (load-bearing): exactly one new task row, titled with the
    // subject, with BOTH linkage fields intact.
    expect(Number(psql(LINKED_COUNT_SQL))).toBe(before + 1);

    // The task materialises in the Tasks app on a fresh navigation (kanban
    // card title). `.first()` — prior suite runs may have created same-titled
    // tasks; the exact new-row count is asserted above.
    await page.goto('/tasks');
    await expect(page.getByRole('button', { name: 'New task' })).toBeVisible({ timeout: 15000 });
    await page.getByText(SUBJECT).first().click();

    // Round trip: the detail dialog surfaces the linkage and Open email
    // deep-links back to the message in the inbox.
    const detail = page.getByRole('dialog').filter({ hasText: 'Linked email' });
    await expect(detail).toBeVisible({ timeout: 10000 });
    await detail.getByRole('button', { name: 'Open email' }).click();
    await expect(page).toHaveURL(/\/inbox\?t=/);
    await expect(page.getByRole('heading', { name: SUBJECT })).toBeVisible({ timeout: 10000 });
  });
});
