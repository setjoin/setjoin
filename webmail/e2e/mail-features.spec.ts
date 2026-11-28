import { test, expect } from '@playwright/test';
import { loginAsUser, apiToken, setFeature, psql } from './helpers';
import { TEST_USERS } from './fixtures/test-data';

/**
 * WAVE-5 tail smoke specs (mail/read surfaces, batches 1-3 of the full-cycle
 * ledger). ONE cheap "surface renders / happy action acks" assertion per
 * previously-unspecced feature — not a deep journey (those already exist per-
 * feature elsewhere: focused-other.spec.ts, labels-apply.spec.ts, etc.). See
 * retired-docs:superpowers/plans/archive/2026-07-03-wave5-tail-program.md (W4).
 */

test.use({ viewport: { width: 1280, height: 2000 } });

const ts = Date.now();

/** Seed one dedicated inbound message via the real deliver() reducer (never
 *  repurposing another spec's numbered fixture — e2e/AGENTS.md rule 5). */
function seedMessage(ref: string, subject: string, body: string): void {
  psql(`SELECT deliver('${ref}', '<${ref}@test.local>', 'partner-wave5@partner.test',
    'Partner Wave5', 'alice@test.local', '[]'::JSONB, '[]'::JSONB, '[]'::JSONB,
    '${subject}', NULL, NULL, '${body}', NULL, 200, FALSE, now(),
    'pass', 'pass', 'pass', 0.0, NULL)`);
}

test.describe('Mail features smoke @user', () => {
  test('mute: muting a thread strips it from the inbox list', async ({ page }) => {
    const subject = `E2E mute probe ${ts}`;
    seedMessage(`e2e-mute-${ts}`, subject, 'Body of the mute probe.');

    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);
    await expect(page.getByText(subject)).toBeVisible({ timeout: 10000 });

    // The list row's own "Mute thread" hover-button only renders for a grouped
    // multi-message thread (MessageList.svelte: viewMode==='threaded' && emails.length>1);
    // a single seeded message has no thread header, so drive the ReadingPane's
    // "Mute" toolbar action instead — same emailActionStore.mute() call either way.
    await page.getByRole('button', { name: new RegExp(`message from .*${subject}`) }).click();
    await expect(page.getByRole('heading', { name: subject })).toBeVisible({ timeout: 10000 });

    const committed = page.waitForResponse(
      (r) => r.url().includes('/jmap') && r.request().method() === 'POST' &&
        (r.request().postData() ?? '').includes('Email/set')
    );
    await page.getByRole('button', { name: 'Mute', exact: true }).click();
    await committed;
    // Muting archives the thread (strips the Inbox tag) — the LIST ROW disappears;
    // the still-open reading pane keeps showing the same subject as a heading, so
    // scope the "gone" assertion to the row, not a page-wide text search.
    await expect(page.getByRole('button', { name: new RegExp(`message from .*${subject}`) })).not.toBeVisible({ timeout: 10000 });
  });

  test('search highlighting: a free-text query renders <mark> around the matched term', async ({ page }) => {
    // SearchSnippet/get's highlighting depends on the optional pg_search/ParadeDB
    // extension (sql/tests/pg_search_bm25.pg skips its own suite the same way when
    // absent). Without it the reducer 500s and the client's documented best-effort
    // fallback (inboxStore.svelte.ts) renders the plain, unhighlighted preview —
    // search itself still works, just without <mark>. Assert whichever contract
    // this environment actually has, rather than asserting a hard dependency this
    // spec doesn't control.
    const hasParadeDB = psql(
      `SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_search')`
    ) === 't';

    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);
    await expect(page.getByText('E2E seeded message 1')).toBeVisible({ timeout: 15000 });

    const search = page.getByRole('textbox', { name: 'Search mail' });
    await search.fill('seeded');
    await search.press('Enter');

    // The mechanism always holds: the free-text query still filters the list.
    await expect(page.getByText('E2E seeded message 1')).toBeVisible({ timeout: 10000 });

    if (hasParadeDB) {
      await expect(page.locator('.sj-mailrow__subject mark').first()).toBeVisible({ timeout: 10000 });
    }
  });

  test('save-all attachments: a 2-attachment message renders the bulk download link', async ({ page }, testInfo) => {
    const subject = `E2E save-all ${testInfo.project.name} ${ts}`;

    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await page.getByRole('button', { name: 'Compose' }).click();
    const compose = page.getByTestId('compose-screen');

    await compose.locator('input[type="file"][multiple]').setInputFiles([
      { name: 'e2e-saveall-a.txt', mimeType: 'text/plain', buffer: Buffer.from('A') },
      { name: 'e2e-saveall-b.txt', mimeType: 'text/plain', buffer: Buffer.from('B') },
    ]);
    await expect(compose.locator('.att-name')).toHaveCount(2, { timeout: 10000 });

    await page.getByRole('combobox', { name: 'To' }).fill(TEST_USERS.alice.email);
    await page.getByRole('textbox', { name: 'Subject' }).fill(subject);
    await compose.locator('.ProseMirror').click();
    await page.keyboard.type('Save-all probe body.');
    await compose.getByRole('button', { name: 'Send', exact: true }).click();
    await expect(page.getByRole('button', { name: /undo/i })).toBeVisible({ timeout: 10000 });

    await page.getByRole('button', { name: /^sent/i }).click();
    await page.getByRole('button', { name: new RegExp('message from .*' + subject) }).click({ timeout: 35000 });

    const saveAll = page.getByRole('link', { name: /Save all/ });
    await expect(saveAll).toBeVisible({ timeout: 10000 });
    await expect(saveAll).toHaveAttribute('href', /\/attachments\.zip$/);
  });

  test('summarize: the Assist menu opens the summary panel', async ({ page, request }) => {
    const subject = `E2E summarize probe ${ts}`;
    seedMessage(`e2e-summarize-${ts}`, subject, 'Body long enough to summarize.');

    const adminToken = await apiToken(request, TEST_USERS.admin.email, TEST_USERS.admin.password);
    await setFeature(request, adminToken, 'feature.assist', true);

    await loginAsUser(page); // fresh session picks up the now-enabled capability
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await page.getByRole('button', { name: new RegExp(`message from .*${subject}`) }).click();
    await expect(page.getByRole('heading', { name: subject })).toBeVisible({ timeout: 10000 });

    await page.getByRole('button', { name: 'Assist' }).click();
    await page.getByRole('menuitem', { name: 'Summarize' }).click();
    await expect(page.getByRole('region', { name: 'Summary' })).toBeVisible({ timeout: 10000 });

    await setFeature(request, adminToken, 'feature.assist', false);
  });

  test('sort: changing the sort property and direction re-queries the list', async ({ page }) => {
    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await expect(page).toHaveURL(/inbox/);
    await expect(page.getByText('E2E seeded message 1')).toBeVisible({ timeout: 15000 });

    const queryAck = page.waitForResponse(
      (r) => r.url().includes('/jmap') && r.request().method() === 'POST' &&
        (r.request().postData() ?? '').includes('Email/query')
    );
    await page.getByLabel('Sort by').selectOption('subject');
    await queryAck;
    await expect(page.getByLabel('Sort by')).toHaveValue('subject');

    const dirAck = page.waitForResponse(
      (r) => r.url().includes('/jmap') && r.request().method() === 'POST' &&
        (r.request().postData() ?? '').includes('Email/query')
    );
    await page.getByRole('button', { name: /^(Ascending|Descending)$/ }).click();
    await dirAck;
  });

  test('resend after NDR: a bounced recipient surfaces the Resend action', async ({ page }) => {
    const subject = `E2E resend-ndr ${ts}`;

    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Mail' }).click();
    await page.getByRole('button', { name: 'Compose' }).click();
    const compose = page.getByTestId('compose-screen');
    await page.getByRole('combobox', { name: 'To' }).fill(TEST_USERS.bob.email);
    await page.getByRole('textbox', { name: 'Subject' }).fill(subject);
    await compose.locator('.ProseMirror').click();
    await page.keyboard.type('Body that will be marked bounced for the resend probe.');
    await compose.getByRole('button', { name: 'Send', exact: true }).click();
    await expect(page.getByRole('button', { name: /undo/i })).toBeVisible({ timeout: 10000 });

    await page.getByRole('button', { name: /^sent/i }).click();
    await expect(page.getByText(subject)).toBeVisible({ timeout: 15000 });

    // Arrange (psql, per e2e/AGENTS.md rule 4): mark bob's delivery bounced —
    // no live SMTP bounce needed to exercise the client's "bounced>0" render path.
    psql(`INSERT INTO delivery_attempts (message_pk, received_at, mailbox_id, recipient_email, attempt_number, outcome)
          SELECT m.id, m.received_at, m.mailbox_id, '${TEST_USERS.bob.email}', 1, 'rejected'
          FROM messages m
          WHERE m.subject = '${subject}'
            AND m.mailbox_id = (SELECT id FROM mailboxes WHERE email = 'alice@test.local')
          ORDER BY m.received_at DESC LIMIT 1`);

    await page.getByRole('button', { name: new RegExp('message from .*' + subject) }).click();
    await expect(page.getByRole('button', { name: 'More actions' })).toBeVisible({ timeout: 10000 });
    await page.getByRole('button', { name: 'More actions' }).click();
    await page.getByRole('menuitem', { name: 'Inspect delivery' }).click();
    await expect(page.getByRole('button', { name: 'Resend', exact: true })).toBeVisible({ timeout: 10000 });
  });
});
