import { test, expect, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { TEST_USERS } from './fixtures/test-data';
import { loginAsUser } from './helpers';

// e2e/fixtures/inline-image.png — a tiny real PNG for the paste-a-file path.
const INLINE_PNG = fileURLToPath(new URL('./fixtures/inline-image.png', import.meta.url));

/**
 * Expand EVERY message card in the open reading-pane conversation stack and
 * assert EACH renders its inline image via `/api/blobs/<sha>` (never a raw
 * `cid:` src). A self-send produces TWO copies of the same message — the Sent
 * copy and the locally-delivered Inbox copy — that TIE on `receivedAt` (both
 * rows are written inside the same DB transaction, so `now()` is identical for
 * both). ReadingPane auto-expands only `cards[cards.length - 1]` ("the newest
 * card"), and with a tied sort that pick is effectively arbitrary (it follows
 * whatever order the thread's Email/get happened to return) — so asserting only
 * the auto-expanded card let a broken Inbox copy hide behind a correctly
 * rendering Sent copy (or vice versa) depending on which side won the tie-break
 * on a given run. Expanding every card and checking every frame removes that
 * coin flip and asserts the Inbox copy explicitly rather than trusting it.
 */
async function assertEveryCardRendersInlineImage(page: Page) {
  const cards = page.locator('.sj-msg-card');
  // loadThread (Thread/get + Email/get) runs async right after the row click —
  // the subject heading appears from the click's synchronous context, but the
  // card stack itself can still be in flight. Poll for both copies (Sent + the
  // locally-delivered Inbox copy) rather than racing a single count() snapshot.
  await expect.poll(() => cards.count(), { timeout: 15000 }).toBeGreaterThanOrEqual(2);

  // Click every still-collapsed card's summary toggle. Re-query on each
  // iteration: expanding a card re-renders the stack, so a captured locator
  // list can go stale after the first click.
  const collapsedToggle = page.locator('.sj-msg-card:not(.sj-msg-card--expanded) .sj-msg-card__summary');
  while (await collapsedToggle.count()) {
    await collapsedToggle.first().click();
  }

  const cardCount = await cards.count();
  // Sent copy + the locally-delivered Inbox copy must both be present in the thread.
  expect(cardCount).toBeGreaterThanOrEqual(2);

  for (let i = 0; i < cardCount; i++) {
    const card = cards.nth(i);
    // htmlMode defaults to plain text per card — switch to the sanitized-HTML
    // render (the sandboxed iframe is the actual rendering surface recipients
    // see). click() auto-waits for the button to become actionable — an
    // immediate isVisible()/count() snapshot right after expanding the card
    // races the re-render and can miss it.
    await card.getByRole('button', { name: 'Show HTML' }).click();
    const frame = card.frameLocator('.sj-reading-body__html-frame');
    await expect(frame.locator('img')).toHaveAttribute('src', /\/api\/blobs\//, { timeout: 10000 });
  }
}

/**
 * WAVE-5 #2 — compose inline-cid images. Pastes a small PNG directly into the
 * compose body (not the attach-file drop zone) and sends to self: the load-
 * bearing assertion is that the SENT message's rendered HTML references the
 * image via `/api/blobs/<sha>` — the inbound cid: rewrite (renderEmailBodyHTML,
 * $lib/sanitize.ts) proves the outbound blob:→cid: rewrite + the
 * {cid, disposition:'inline'} attachment entry round-tripped through the real
 * gateway/reducer/assembler, not just the vitest-mocked JMAP boundary.
 *
 * The paste is simulated via a synthetic ClipboardEvent dispatched on the
 * `.ProseMirror` node (a real DataTransfer/File in Chromium — no mocking): our
 * own RichTextEditor.handlePaste reads `event.clipboardData.files` directly,
 * so this exercises the exact same code path a real OS-clipboard paste would.
 */
test.use({ viewport: { width: 1280, height: 2000 } });

test.describe('Compose inline image @user', () => {
  test('paste a PNG into the body sends inline; the reading pane renders it via /api/blobs', async ({ page }, testInfo) => {
    const subject = `E2E inline image ${testInfo.project.name} ${Date.now()}`;
    const pngBase64 = readFileSync(INLINE_PNG).toString('base64');

    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);

    await page.getByRole('button', { name: 'Compose' }).click();
    await page.getByRole('combobox', { name: 'To' }).fill(TEST_USERS.alice.email); // send to self
    await page.getByRole('textbox', { name: 'Subject' }).fill(subject);

    const body = page.locator('.ProseMirror');
    await body.click();

    // Paste a real File via a synthetic ClipboardEvent — the upload PUT fires
    // as soon as our handlePaste stages it; wait for that ACK before Send so
    // the message isn't gated ("Uploading…") or, worse, sent without the blob.
    const uploadAck = page.waitForResponse(
      (r) => /\/api\/blobs\//.test(r.url()) && r.request().method() === 'PUT'
    );
    await page.evaluate(async (base64) => {
      const bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
      const file = new File([bytes], 'inline.png', { type: 'image/png' });
      const dt = new DataTransfer();
      dt.items.add(file);
      const el = document.querySelector('.ProseMirror');
      if (!el) throw new Error('ProseMirror editor not found');
      const evt = new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true });
      el.dispatchEvent(evt);
    }, pngBase64);
    await uploadAck;

    // The placeholder <img> is in the body, tagged with its upload id.
    await expect(body.locator('img[data-upload-id]')).toBeVisible({ timeout: 10000 });
    // Not gated on an in-flight inline upload (extends the existing "Uploading…" gate).
    await expect(page.getByRole('button', { name: 'Send', exact: true })).toBeEnabled({ timeout: 10000 });

    await page.getByRole('button', { name: 'Send', exact: true }).click();
    // Send accepted: the inline undo-send affordance appears (compose-roundtrip's
    // proven synchronization signal — no waitForResponse race against the
    // autosave-draft timer sharing the same /jmap endpoint).
    await expect(page.getByRole('button', { name: /undo/i })).toBeVisible({ timeout: 10000 });

    await page.getByRole('button', { name: /^sent/i }).click();
    await page.getByRole('button', { name: new RegExp(subject) }).first().click();
    await expect(page.getByRole('heading', { name: subject })).toBeVisible({ timeout: 35000 });
    await assertEveryCardRendersInlineImage(page);

    // Also open the SAME message from the Inbox view explicitly — the locally-
    // delivered copy send()'s deliver() fan-out wrote — rather than inferring its
    // correctness only from whichever card the Sent-side reading pane auto-expanded.
    await page.getByRole('button', { name: /^inbox/i }).click();
    await page.getByRole('button', { name: new RegExp(subject) }).first().click();
    await expect(page.getByRole('heading', { name: subject })).toBeVisible({ timeout: 35000 });
    await assertEveryCardRendersInlineImage(page);
  });
});
