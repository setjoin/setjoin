import { test, expect } from '@playwright/test';
import { loginAsUser, reloadAfterServiceWorkerControl } from '../../helpers';

/**
 * Real draft-autosave journey: open Compose → type a subject + body → the 5s
 * debounce fires saveDraft → the "Draft saved" banner appears → reload (navigate
 * away) → the draft is in the Drafts view with the typed subject.
 *
 * Proves the cross-layer wiring UI (autosave debounce) → gateway → set reducer
 * (draft persisted) → Drafts query → UI. No fixed sleeps: we wait on the banner
 * and the persisted row. Tall viewport keeps the GAL overlay clear of the editor.
 */
test.use({ viewport: { width: 1280, height: 2000 } });

test.describe('Draft autosave @user', () => {
  test('an autosaved compose draft persists and shows in Drafts', async ({ page }, testInfo) => {

    const subject = `Draft autosave ${Date.now()}`;

    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);

    await page.getByRole('button', { name: 'Compose' }).click();
    await page.getByRole('textbox', { name: 'Subject' }).fill(subject);

    // Typing in the body schedules the 5s autosave debounce (handleUpdate).
    const body = page.locator('.ProseMirror');
    await body.click();
    await page.keyboard.type('Body that should be autosaved as a draft.');

    // The debounce (5s) fires saveDraft, which flashes the "Draft saved" banner
    // for 2s — wait it out (timeout outlasts the debounce + the flash window).
    await expect(page.getByText('Draft saved')).toBeVisible({ timeout: 20000 });

    // Navigate away (the persisted draft survives a reload), then open Drafts.
    page = await reloadAfterServiceWorkerControl(page);
    await page.getByRole('button', { name: 'Drafts' }).click();

    // The autosaved draft appears in the Drafts list, keyed by the typed subject.
    await expect(page.getByRole('button', { name: new RegExp(subject) }))
      .toBeVisible({ timeout: 10000 });
  });
});
