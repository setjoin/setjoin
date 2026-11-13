import { test, expect, type Page } from '@playwright/test';
import { loginAsUser, reloadAfterServiceWorkerControl } from './helpers';

/**
 * Custom labels: create colored labels from the MailSidebar inline new-tag
 * block, apply them to a seeded message via the reading-pane Tags region
 * (role="region"[aria-label="Tags"]), RELOAD, and assert the message still
 * carries the labels AND the color persisted — the field-silently-dropped-
 * on-create regression class (ebeeb267).
 *
 * LABEL_A is applied as the message's FIRST tag entirely through the UI —
 * this regression-tests the 2026-07-02 fix where ReadingPane rendered the
 * Tags row (and its "+ tag" picker opener) only when the message already
 * carried a tag, making the first tag unreachable.
 *
 * applyLabel awaits the Email/set network ACK, not just the chip: the chip
 * renders optimistically before the write commits, and this spec's reload
 * would abort an in-flight POST (net::ERR_ABORTED) and silently lose the
 * apply — the tag races the reload, not a product bug.
 */

const ts = Date.now();
const LABEL_A = `e2e-label-a-${ts}`; // FIRST tag on the message, applied via UI
const LABEL_B = `e2e-label-b-${ts}`; // second tag via the same picker
const SUBJECT = 'E2E seeded message 2'; // message 1 belongs to email-to-task.spec.ts

/** Create a tag from the sidebar's inline new-tag block (name + hue swatch + Enter). */
async function createSidebarLabel(page: Page, name: string, hue: string) {
  await page.getByRole('button', { name: 'New tag' }).click();
  const input = page.getByPlaceholder('Tag name');
  await input.fill(name);
  await page.getByRole('group', { name: 'Color' }).getByRole('button', { name: hue, exact: true }).click();
  await input.press('Enter'); // submitNewTag → Mailbox/set create → sidebar reload
  await expect(page.getByText(name, { exact: true })).toBeVisible({ timeout: 10000 });
}

/** Open the seeded message and wait for the reading pane. */
async function openMessage(page: Page) {
  await page.getByRole('button', { name: new RegExp(SUBJECT) }).first().click();
  await expect(page.getByRole('heading', { name: SUBJECT })).toBeVisible({ timeout: 10000 });
}

/** Apply a label through the reading-pane "+ tag" picker and wait for the COMMIT. */
async function applyLabel(page: Page, name: string) {
  await page.getByRole('button', { name: '+ tag' }).click();
  const picker = page.getByRole('region', { name: 'Tags' });
  await expect(picker).toBeVisible();
  const committed = page.waitForResponse(
    (res) =>
      res.url().includes('/jmap') &&
      res.request().method() === 'POST' &&
      (res.request().postData() ?? '').includes('Email/set'),
    { timeout: 10000 },
  );
  await picker.getByRole('button', { name: name }).click();
  await committed; // server ACK — safe to reload after this
  await expect(page.getByRole('button', { name: `Remove tag ${name}` })).toBeVisible({ timeout: 10000 });
}

test.describe('Labels: create and apply @user', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);
  });

  test('labels applied via the reading-pane Tags region survive a reload (color too)', async ({ page }) => {
    await createSidebarLabel(page, LABEL_A, 'rose');
    await createSidebarLabel(page, LABEL_B, 'teal');

    await openMessage(page);

    // FIRST tag on an untagged message, applied purely through the UI.
    await applyLabel(page, LABEL_A);
    await applyLabel(page, LABEL_B);

    // PERSISTENCE (load-bearing): a fresh JMAP fetch still carries both labels.
    page = await reloadAfterServiceWorkerControl(page);
    await openMessage(page);
    await expect(page.getByRole('button', { name: `Remove tag ${LABEL_A}` })).toBeVisible({ timeout: 10000 });
    await expect(page.getByRole('button', { name: `Remove tag ${LABEL_B}` })).toBeVisible({ timeout: 10000 });

    // Color persisted too: the sidebar edit form re-reads the stored hue —
    // the chosen swatch is the pressed one (guards a dropped color field).
    const rowA = page.locator('.sj-mail-sidebar__tag-row', { hasText: LABEL_A });
    await rowA.getByRole('button', { name: 'Edit label' }).click();
    await expect(
      page.getByRole('group', { name: 'Color' }).getByRole('button', { name: 'rose', exact: true })
    ).toHaveAttribute('aria-pressed', 'true');
  });
});
