import { test, expect, type Page, type APIRequestContext } from '@playwright/test';
import { loginAsUser, loginAs, apiToken } from './helpers';
import { TEST_USERS } from './fixtures/test-data';

/**
 * Shared-mailbox USE surface (#13, WAVE-5 tail — 2026-07-03 design). The
 * delegation substrate (mailbox_delegates + /api/me/sharing) shipped earlier
 * this session (sharing-delegation.spec.ts covers the grant/revoke UI); this
 * spec covers the OTHER side: the delegate actually USING alice's mailbox —
 * sidebar section, context-guard signals, read, attachment download (the
 * blob.go Download delegate arm), send-as landing in the SHARED Sent, and
 * the revoked-mid-session danger state.
 *
 * Arrange is API-first per the binding contract ("alice grants the delegate
 * full_access (API arrange)") — the grant UI itself is sharing-delegation
 * .spec.ts's job, not this one's. The read/attachment fixtures are alice
 * COMPOSING to the delegate (real send path, real S3-backed blob — not a
 * raw-SQL attachment stub), per e2e/AGENTS.md rule 5: never repurpose
 * alice's 3 numbered/pile/HTML seeded messages (this spec also marks-as-read
 * whatever it opens — read-on-expand — so touching a shared fixture message
 * would poison another spec's unread-count assertion).
 *
 * Delegate identity: ADMIN, not bob. sharing-delegation.spec.ts's own grant/
 * revoke-UI test already owns the real alice→bob mailbox_delegates row
 * (same table, same key) and send-quota.spec.ts owns a real login session as
 * bob (its dedicated destructive-mutation account, per that file's own
 * "Sender is BOB" note) — reusing bob here raced BOTH under full-suite
 * parallelism (a stray second delegate row / a stray login mid-quota-drain).
 * admin has its own ordinary personal mailbox (like any user) and no other
 * @user-tagged spec logs into it as a real mail actor, so it's uncontended.
 */
test.use({ viewport: { width: 1280, height: 2000 } });

const ts = Date.now();

async function composeAndSend(
  page: Page,
  opts: { to: string; subject: string; body: string; fileName?: string; fileBody?: string },
) {
  await page.getByRole('button', { name: 'Compose' }).click();
  await page.getByRole('combobox', { name: 'To' }).fill(opts.to);
  await page.getByRole('textbox', { name: 'Subject' }).fill(opts.subject);
  await page.locator('.ProseMirror').click();
  await page.keyboard.type(opts.body);
  if (opts.fileName) {
    await page.getByTestId('compose-screen').locator('input[type="file"][multiple]').setInputFiles({
      name: opts.fileName,
      mimeType: 'text/plain',
      buffer: Buffer.from(opts.fileBody ?? 'e2e attachment body'),
    });
    await expect(page.getByText(opts.fileName)).toBeVisible({ timeout: 10000 });
  }
  // Scoped to the compose overlay: a reply-while-reading (or, here, composing
  // over an already-open message in the shared workspace) leaves the reading
  // pane's OWN inline-reply Send button mounted behind the compose overlay —
  // an unscoped Send locator resolves to both and Playwright strict-mode 403s.
  await page.getByTestId('compose-screen').getByRole('button', { name: 'Send', exact: true }).click();
  await expect(page.getByRole('button', { name: /undo/i })).toBeVisible({ timeout: 10000 });
  await page.mouse.move(0, 0); // toast hygiene (e2e/AGENTS.md rule 6)
}

/** Grant `granteeEmail` `permission` on the caller (alice)'s own mailbox via
 *  the real /api/me/sharing/delegates API — the #13 binding contract's "API
 *  arrange" step. Returns the grantee's userId (mailbox_delegates row key,
 *  used for strict teardown). */
async function grantDelegate(
  request: APIRequestContext,
  granterToken: string,
  granteeEmail: string,
  permission: string,
): Promise<number> {
  const res = await request.post('/api/me/sharing/delegates', {
    headers: { Authorization: `Bearer ${granterToken}`, 'Content-Type': 'application/json' },
    data: { granteeEmail, permission },
  });
  expect(res.status(), 'grant delegate must succeed').toBe(201);
  const overview = (await (
    await request.get('/api/me/sharing', { headers: { Authorization: `Bearer ${granterToken}` } })
  ).json()) as { delegates: { userId: number; email: string }[] };
  const id = overview.delegates.find((d) => d.email === granteeEmail)?.userId ?? 0;
  expect(id, 'grant must be visible in GET /me/sharing').toBeGreaterThan(0);
  return id;
}

async function revokeDelegate(
  request: APIRequestContext,
  granterToken: string,
  granteeUserId: number,
): Promise<void> {
  const res = await request.delete(`/api/me/sharing/delegates/${granteeUserId}`, {
    headers: { Authorization: `Bearer ${granterToken}` },
  });
  expect(res.status()).toBe(204);
}

test.describe('Shared-mailbox use surface @user', () => {
  let leakedDelegateId = 0; // strict teardown if a test fails before its own revoke

  test.afterEach(async ({ request }) => {
    if (leakedDelegateId) {
      const aliceToken = await apiToken(request, TEST_USERS.alice.email, TEST_USERS.alice.password);
      const res = await request.delete(`/api/me/sharing/delegates/${leakedDelegateId}`, {
        headers: { Authorization: `Bearer ${aliceToken}` },
      });
      expect([204, 404]).toContain(res.status());
      leakedDelegateId = 0;
    }
  });

  test('full_access: sidebar → read → download attachment → send-as → shared Sent → revoke → access removed', async ({
    page,
    request,
  }) => {
    const readSubject = `E2E shared-mailbox read ${ts}`;
    const sendAsSubject = `E2E shared-mailbox send-as ${ts}`;
    const fileName = `shared-e2e-${ts}.txt`;

    // ── Arrange: alice sends herself→admin a message WITH a real attachment
    // (lands in alice's Sent — one of the 4 shared-context views admin will see). ──
    await loginAsUser(page); // alice (project storageState — cheap no-op re-check)
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);
    await composeAndSend(page, {
      to: TEST_USERS.admin.email,
      subject: readSubject,
      body: 'Attachment round-trip for the shared-mailbox e2e.',
      fileName,
      fileBody: `shared mailbox attachment body ${ts}`,
    });

    // ── Arrange: alice grants admin full_access on HER OWN mailbox (API). ──
    const aliceToken = await apiToken(request, TEST_USERS.alice.email, TEST_USERS.alice.password);
    const delegateId = await grantDelegate(request, aliceToken, TEST_USERS.admin.email, 'full_access');
    leakedDelegateId = delegateId;

    // ── The delegate's session: USING alice's shared mailbox. ──
    await loginAs(page, TEST_USERS.admin.email, TEST_USERS.admin.password);
    await page.goto('/inbox');
    await expect(page).toHaveURL(/inbox/);

    const sidebar = page.locator('.sj-mail-sidebar');
    await expect(sidebar.getByText('Shared mailboxes')).toBeVisible({ timeout: 10000 });
    await sidebar.getByRole('button', { name: TEST_USERS.alice.email }).click();
    await expect(page).toHaveURL(/mbx=/);

    // Context-guard SIGNAL 1 (sidebar header) + SIGNAL 2 (persistent info strip):
    // mailbox name AND permission level, both visible.
    await expect(sidebar.locator('.sj-mail-sidebar__shared-badge')).toHaveText('Shared');
    const infoStrip = page.locator('.sj-inbox__shared-strip');
    await expect(infoStrip).toContainText(TEST_USERS.alice.email);
    await expect(infoStrip).toContainText('Full access');

    // Read the message + download its attachment (exercises blob.go Download's
    // delegate arm — any mail grant on the SHARED mailbox admits the download).
    await sidebar.getByRole('button', { name: 'Sent', exact: true }).click();
    await page.getByRole('button', { name: new RegExp(readSubject) }).first().click();
    await expect(page.getByRole('heading', { name: readSubject })).toBeVisible({ timeout: 10000 });
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('link', { name: `Download ${fileName}` }).click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toBe(fileName);

    // Compose send-as: SIGNAL 3 (From Select) presets to alice's address + the
    // "Sending as" caption; send lands the copy in the SHARED mailbox's Sent
    // (sending-mailbox semantics — the accountId used for the submission).
    await sidebar.getByRole('button', { name: 'Compose' }).click();
    await expect(page.locator('.cp-from-caption')).toContainText(TEST_USERS.alice.email);
    await page.getByRole('combobox', { name: 'To' }).fill(TEST_USERS.alice.email); // arbitrary peer (self); keeps this spec bob-free
    await page.getByRole('textbox', { name: 'Subject' }).fill(sendAsSubject);
    await page.locator('.ProseMirror').click();
    await page.keyboard.type('Sending as the shared mailbox.');
    // Scoped to the compose overlay (see composeAndSend's comment above) — the
    // already-open message's reading pane keeps its own inline-reply Send
    // mounted behind the compose overlay.
    await page.getByTestId('compose-screen').getByRole('button', { name: 'Send', exact: true }).click();
    await expect(page.getByRole('button', { name: /undo/i })).toBeVisible({ timeout: 10000 });
    await page.mouse.move(0, 0);

    await sidebar.getByRole('button', { name: 'Sent', exact: true }).click();
    await expect(page.getByText(sendAsSubject)).toBeVisible({ timeout: 15000 });

    // ── Revoke via API — the NEXT action (manual refresh; no push in shared
    // context) must show the full-pane "access removed" danger state, never a
    // toast loop. ──
    await revokeDelegate(request, aliceToken, delegateId);
    leakedDelegateId = 0; // revoked in-test; afterEach has nothing to do

    await infoStrip.getByRole('button', { name: 'Refresh' }).click();
    await expect(page.getByText('You no longer have access to this mailbox')).toBeVisible({ timeout: 10000 });
    await page.getByRole('button', { name: 'Back to my mail' }).click();
    await expect(page).toHaveURL(/\/inbox$/);
  });

  test('read-only grant: compose/reply/forward render disabled with a tooltip', async ({ page, request }) => {
    const subject = `E2E shared-mailbox read-only ${ts}`;

    await loginAsUser(page); // alice
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);
    await composeAndSend(page, {
      to: TEST_USERS.alice.email, // arbitrary peer (self); keeps this spec bob-free
      subject,
      body: 'Read-only shared-mailbox danger-state check.',
    });

    const aliceToken = await apiToken(request, TEST_USERS.alice.email, TEST_USERS.alice.password);
    const delegateId = await grantDelegate(request, aliceToken, TEST_USERS.admin.email, 'read');
    leakedDelegateId = delegateId;

    await loginAs(page, TEST_USERS.admin.email, TEST_USERS.admin.password);
    await page.goto('/inbox');
    const sidebar = page.locator('.sj-mail-sidebar');
    await sidebar.getByRole('button', { name: TEST_USERS.alice.email }).click();
    await expect(page).toHaveURL(/mbx=/);
    await expect(page.locator('.sj-inbox__shared-strip')).toContainText('Read only');

    // Danger state: the global Compose button is disabled (not hidden), with a
    // tooltip explaining why.
    const composeBtn = sidebar.getByRole('button', { name: 'Compose' });
    await expect(composeBtn).toBeDisabled();
    await expect(composeBtn).toHaveAttribute('title', /read-only access/i);

    // Per-message Reply/Forward render disabled too (never hidden).
    await sidebar.getByRole('button', { name: 'Sent', exact: true }).click();
    await page.getByRole('button', { name: new RegExp(subject) }).first().click();
    await expect(page.getByRole('heading', { name: subject })).toBeVisible({ timeout: 10000 });
    const senderActions = page.locator('.sj-reading-body__sender-actions button');
    await expect(senderActions.first()).toBeDisabled();

    // The inline-reply box is disabled too.
    await expect(page.locator('.sj-reading-body__reply textarea')).toBeDisabled();

    await revokeDelegate(request, aliceToken, delegateId);
    leakedDelegateId = 0;
  });
});
