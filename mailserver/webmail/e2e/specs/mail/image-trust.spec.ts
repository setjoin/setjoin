import { test, expect } from '@playwright/test';
import { loginAsUser, psql, reloadAfterServiceWorkerControl } from '../../helpers';

/**
 * Per-sender remote-image trust (WAVE-5 #5, V091 user_image_allow). Full journey:
 * banner blocks remote images → "Always load images from this sender" persists it
 * → a FRESH page load (new client-side imageTrust cache) auto-allows → the durable
 * undo surface (/settings/privacy "Trusted senders") lists + removes it → removal
 * re-blocks. Remote-image gating only applies in the HTML view (plain text is the
 * default render mode — see MessageCard's `{#if htmlMode && remoteImagesBlocked}`),
 * so each open explicitly switches to "Show HTML" first.
 */
test.describe('Remote-image per-sender trust @user', () => {
  test('banner → always load → survives reload → removable from Settings → banner returns', async ({ page }) => {
    const ts = Date.now();
    const sender = `imgtrust-${ts}@partner.test`;
    const subject = `E2E image trust ${ts}`;

    psql(
      `SELECT deliver('imgtrust-${ts}', '<imgtrust-${ts}@test.local>', '${sender}', 'Img Trust', ` +
      `'alice@test.local', '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '${subject}', NULL, NULL, ` +
      `'Plain fallback for the image-trust check.', ` +
      `'<p>Hello</p><img src="https://example.test/pixel.png">', 300, FALSE, now(), ` +
      `'pass', 'pass', 'pass', 0.0, NULL)`
    );

    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);

    async function openInHTMLMode() {
      await page.getByRole('button', { name: new RegExp(subject) }).click();
      await expect(page.getByText(subject, { exact: false }).first()).toBeVisible({ timeout: 10000 });
      await page.getByRole('button', { name: 'Show HTML' }).click();
    }

    await openInHTMLMode();
    await expect(page.getByText('Remote images were blocked to protect your privacy.')).toBeVisible({
      timeout: 10000,
    });

    const addAck = page.waitForResponse(
      (r) => r.url().includes('/api/settings/trusted-senders') && r.request().method() === 'POST',
      { timeout: 10000 }
    );
    await page.getByRole('button', { name: 'Always load images from this sender' }).click();
    await addAck;
    // The toast text is duplicated (visual + a11y live-region echo) — .first() is enough.
    await expect(page.getByText(`Images from ${sender} will always load`).first()).toBeVisible({
      timeout: 10000,
    });
    // A toast under the cursor never auto-dismisses; move off it (rule 6, e2e/AGENTS.md).
    await page.mouse.move(0, 0);

    // Fresh load → a new imageTrust store instance must fetch the server list and
    // auto-allow. Persistence, not the optimistic client state from the click above.
    page = await reloadAfterServiceWorkerControl(page);
    await openInHTMLMode();
    await expect(page.getByText('Remote images were blocked to protect your privacy.')).not.toBeVisible({
      timeout: 10000,
    });

    // The durable undo surface (design pin: a one-way door otherwise).
    await page.goto('/settings/privacy');
    await expect(page.getByText('Trusted senders', { exact: true })).toBeVisible({ timeout: 15000 });
    await expect(page.getByText(sender)).toBeVisible({ timeout: 10000 });

    const removeAck = page.waitForResponse(
      (r) =>
        r.url().includes(`/api/settings/trusted-senders/${encodeURIComponent(sender)}`) &&
        r.request().method() === 'DELETE',
      { timeout: 10000 }
    );
    await page.getByRole('button', { name: `Remove ${sender}` }).click();
    await removeAck;
    await expect(page.getByText(sender)).not.toBeVisible({ timeout: 10000 });

    // Back in Mail: removal un-trusts the sender again (no reload needed — the
    // imageTrust cache is a process-wide singleton the settings page just mutated).
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await openInHTMLMode();
    await expect(page.getByText('Remote images were blocked to protect your privacy.')).toBeVisible({
      timeout: 10000,
    });
  });
});
