import { test, expect, type Page } from '@playwright/test';

// E2E for the SP1 S/MIME web functions, fully mocked (no live gateway/DB/S3).
// Drives the REAL Svelte components in a real Chromium browser against page.route
// mocks of the exact HTTP shapes the SPA uses (mapped from the data layer):
//   - boot/auth:  GET /auth/me, GET /jmap/session, GET /.well-known/jmap
//   - inbox:      POST /jmap → Mailbox/get, Email/query, Email/get (cryptoType/decryptState/bodyText)
//   - certs:      GET/POST/DELETE /auth/me/smime/recipient-certs, GET /auth/me/smime/certs
//   - compose:    POST /jmap → EmailSubmission/set notCreated{type,addresses} (fail-closed)

const ACCOUNT = 'u1';

const SESSION = {
  apiUrl: '/jmap',
  downloadUrl: '/blobs/{blobId}',
  uploadUrl: '/upload',
  eventSourceUrl: '/events',
  state: 'state-1',
  accounts: { [ACCOUNT]: { name: 'alice@test.local', isPersonal: true, accountCapabilities: {} } },
  primaryAccounts: { 'urn:ietf:params:jmap:mail': ACCOUNT },
  username: 'alice@test.local',
  capabilities: {},
};

const MAILBOXES = [
  { id: 'inbox-id', name: 'Inbox', role: 'inbox', sortOrder: 1, totalEmails: 2, unreadEmails: 2 },
  { id: 'sent-id', name: 'Sent', role: 'sent', sortOrder: 2, totalEmails: 0, unreadEmails: 0 },
  { id: 'drafts-id', name: 'Drafts', role: 'drafts', sortOrder: 3, totalEmails: 0, unreadEmails: 0 },
  { id: 'trash-id', name: 'Trash', role: 'trash', sortOrder: 4, totalEmails: 0, unreadEmails: 0 },
];

const iso = (deltaDays: number) => new Date(Date.now() + deltaDays * 86400 * 1000).toISOString();

// Per-test mutable state the JMAP dispatcher + REST mocks read.
type MockState = {
  emails: any[];
  emailIds: string[];
  recipientCerts: any[];
  submissionNotCreated: Record<string, any> | null;
  lastSubmissionCreate: any;
};

async function installMocks(page: Page, state: MockState) {
  if ((globalThis as any).process?.env?.E2E_DEBUG) {
    page.on('console', (m) => console.log('PAGE', m.type(), m.text()));
    page.on('requestfailed', (r) => console.log('REQFAIL', r.method(), r.url(), r.failure()?.errorText));
    page.on('response', (r) => { if (!r.ok() && !r.url().includes('/events')) console.log('HTTP', r.status(), r.request().method(), r.url()); });
  }
  // A session cookie so any cookie-gate passes; /auth/me is the real auth probe.
  await page.context().addCookies([
    { name: 'access_token', value: 'e2e-mock-token', domain: 'localhost', path: '/', sameSite: 'Lax' },
  ]);
  // Mark the welcome tour as already-seen BEFORE the app boots, else its full-screen
  // sj-tour-blocker overlay intercepts every click.
  await page.addInitScript(() => {
    try {
      localStorage.setItem('sj-welcome-tour:alice@test.local', '1');
      // Shrink the undo-send window to its 5s floor so the post-window
      // EmailSubmission/set (where encrypt fail-closed surfaces) fires quickly.
      localStorage.setItem('sj-undo-window', '5');
    } catch { /* ignore */ }
  });

  // NOTE: anchored REGEX patterns (not globs) — vite preview proxies API paths to
  // the absent gateway, and Playwright globs don't match the leading-dot
  // `.well-known` segment. Regexes intercept reliably and disambiguate /jmap vs
  // /.well-known/jmap vs /jmap/session.

  // Catch-all for stray API paths (contacts/calendar/tasks/quickstep/etc.) so NO
  // request hangs on vite preview's dead proxy → no socket-hang-up/ERR_ABORTED
  // cascade. Registered FIRST = lowest precedence; the specific routes below win.
  await page.route(/^https?:\/\/[^/]+\/(jmap|auth|blobs|upload|contacts|calendar|tasks|api)\b/, (r) =>
    r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));

  await page.route(/^https?:\/\/[^/]+\/auth\/me(\?|$)/, (r) =>
    r.fulfill({ status: 200, contentType: 'application/json',
      body: JSON.stringify({ email: 'alice@test.local', is_admin: false, has_mailbox: true, totp_enabled: false, delegates: [], impersonating: false }) }));

  const sessionBody = JSON.stringify(SESSION);
  await page.route(/\/jmap\/session/, (r) => r.fulfill({ status: 200, contentType: 'application/json', body: sessionBody }));
  await page.route(/\.well-known\/jmap/, (r) => r.fulfill({ status: 200, contentType: 'application/json', body: sessionBody }));

  // MailTips (recipient hints when a recipient is added in compose) — empty.
  await page.route(/\/auth\/me\/mailtips/, (r) =>
    r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ tips: [] }) }));

  // Own S/MIME certs (ComposeScreen + settings own-cert section) — empty is fine.
  await page.route(/\/auth\/me\/smime\/certs(\?|$)/, (r) =>
    r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ certs: [] }) }));

  // Contacts' (recipient) certs REST — DELETE has a trailing /{id}.
  await page.route(/\/auth\/me\/smime\/recipient-certs\/\d+/, async (r) => {
    if (r.request().method() === 'DELETE') {
      const id = Number(r.request().url().split('/').pop());
      state.recipientCerts = state.recipientCerts.filter((c) => c.id !== id);
    }
    return r.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
  });
  await page.route(/\/auth\/me\/smime\/recipient-certs(\?|$)/, async (r) => {
    if (r.request().method() === 'POST') {
      state.recipientCerts.push({ id: 999, email: 'imported@test.local', label: 'Imported', source: 'imported', notBefore: iso(-10), notAfter: iso(365), fingerprint: 'ff:ff', isEncryptCapable: true });
      return r.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
    }
    return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ certs: state.recipientCerts }) });
  });

  // EventSource push — don't let it hang the page.
  await page.route(/\/events(\?|$)/, (r) => r.abort());

  // JMAP dispatcher (root /jmap only — NOT /.well-known/jmap or /jmap/session).
  await page.route(/^https?:\/\/[^/]+\/jmap(\?|$)/, async (r) => {
    if (r.request().method() !== 'POST') return r.continue();
    let body: any = {};
    try { body = JSON.parse(r.request().postData() || '{}'); } catch { /* ignore */ }
    const calls: any[] = body.methodCalls || [];
    if ((globalThis as any).process?.env?.E2E_DEBUG) console.log('JMAP', calls.map((c: any[]) => c[0]).join(','));
    const methodResponses = calls.map(([method, args, callId]: any[]) => {
      switch (method) {
        case 'Mailbox/get':
          return ['Mailbox/get', { accountId: ACCOUNT, state: 's', list: MAILBOXES, notFound: [] }, callId];
        case 'Email/query':
          return ['Email/query', { accountId: ACCOUNT, queryState: 'q', ids: state.emailIds, total: state.emailIds.length, position: 0 }, callId];
        case 'Email/get': {
          // A real JMAP server returns ONLY the requested ids. The list view asks
          // for all ids; opening a message asks for that one id (loadThread →
          // emailGet([id])). Filtering here keeps a single-message open from
          // stacking OTHER emails' bodies into the thread (which would leak the
          // decrypted body of message A into message B's no-key view).
          const wantIds: string[] | undefined = args?.ids ?? undefined;
          const list = wantIds ? state.emails.filter((e) => wantIds.includes(e.id)) : state.emails;
          return ['Email/get', { accountId: ACCOUNT, state: 's', list, notFound: [] }, callId];
        }
        case 'Email/changes':
          return ['Email/changes', { accountId: ACCOUNT, oldState: 's', newState: 's', hasMoreChanges: false, created: [], updated: [], destroyed: [] }, callId];
        case 'Thread/get':
          return ['Thread/get', { accountId: ACCOUNT, state: 's', list: [], notFound: [] }, callId];
        case 'EmailSubmission/set': {
          // Key created/notCreated by the app's ACTUAL creation ids, not a guess.
          state.lastSubmissionCreate = args?.create ?? null;
          const keys = Object.keys(args?.create ?? {});
          if (state.submissionNotCreated) {
            const failTemplate = Object.values(state.submissionNotCreated)[0];
            const notCreated: Record<string, any> = {};
            for (const k of keys) notCreated[k] = failTemplate;
            return ['EmailSubmission/set', { accountId: ACCOUNT, created: {}, notCreated }, callId];
          }
          const created: Record<string, any> = {};
          for (const k of keys) created[k] = { id: 'es-' + k };
          return ['EmailSubmission/set', { accountId: ACCOUNT, created, notCreated: {} }, callId];
        }
        case 'Email/set':
          return ['Email/set', { accountId: ACCOUNT, created: { 'draft-1': { id: 'newdraft' } }, updated: {}, destroyed: [] }, callId];
        default:
          return [method, { accountId: ACCOUNT, state: 's', list: [], notFound: [] }, callId];
      }
    });
    await r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ methodResponses, sessionState: 'state-1' }) });
  });
}

function makeState(over: Partial<MockState> = {}): MockState {
  return { emails: [], emailIds: [], recipientCerts: [], submissionNotCreated: null, lastSubmissionCreate: null, ...over };
}

test.describe('SP1 S/MIME web functions (mocked backend)', () => {
  test('inbox: decrypt-on-read renders decrypted body, no-key state, and the encrypted indicator', async ({ page }) => {
    const state = makeState({
      emailIds: ['msg-dec', 'msg-nokey'],
      emails: [
        {
          id: 'msg-dec', threadId: 't1', mailboxIds: { 'inbox-id': true }, keywords: {},
          from: [{ name: 'Bank', email: 'bank@trust.example' }], to: [{ email: 'alice@test.local' }],
          subject: 'Confidential Statement A', receivedAt: iso(-1), hasAttachment: false, preview: '',
          cryptoType: 'smime-encrypted', decryptState: 'decrypted',
          bodyText: 'SECRET-DECRYPTED-BODY-ALPHA', bodyHTML: null,
        },
        {
          id: 'msg-nokey', threadId: 't2', mailboxIds: { 'inbox-id': true }, keywords: {},
          from: [{ name: 'Bank', email: 'bank@trust.example' }], to: [{ email: 'alice@test.local' }],
          subject: 'Confidential Statement B', receivedAt: iso(-2), hasAttachment: false, preview: '',
          cryptoType: 'smime-encrypted', decryptState: 'no_key', bodyText: null, bodyHTML: null,
        },
      ],
    });
    await installMocks(page, state);
    await page.goto('/inbox');

    // Both rows render the encrypted placeholder (not a cleartext preview).
    await expect(page.getByText('Confidential Statement A')).toBeVisible({ timeout: 15000 });
    await expect(page.getByText('Encrypted message').first()).toBeVisible();

    // Open the rows via the row button at a top-left position. The hover action
    // cluster is absolutely positioned bottom-right and, in the narrow split-view
    // list column (once a message is open), overlaps the subject text — a center
    // click on the subject lands on the cluster and MailRow.handleRowClick bails.
    // A top-left click always hits the row body, never the cluster, so opening the
    // SECOND message is deterministic.
    const openRow = (subject: string) =>
      page.getByRole('button', { name: new RegExp(subject) }).click({ position: { x: 8, y: 8 } });

    // Open the decryptable one → ReadingPane shows the server-decrypted body.
    await openRow('Confidential Statement A');
    await expect(page.getByText('SECRET-DECRYPTED-BODY-ALPHA')).toBeVisible({ timeout: 10000 });

    // Open the no-key one → can't-decrypt state with the Settings → Security link.
    await openRow('Confidential Statement B');
    await expect(page.getByText(/private key isn't on the server/i)).toBeVisible({ timeout: 10000 });
    await expect(page.getByText(/Go to Settings/i)).toBeVisible();
    // The cleartext body of the OTHER message must NOT leak into this view.
    await expect(page.getByText('SECRET-DECRYPTED-BODY-ALPHA')).toHaveCount(0);
  });

  test('settings/security: contacts cert badges — signing-only, expiring-soon (F4), expired', async ({ page }) => {
    const state = makeState({
      // labels are non-colliding with badge text (so getByText asserts the badge).
      recipientCerts: [
        { id: 1, email: 'valid@test.local', label: 'AlphaCert', source: 'imported', notBefore: iso(-30), notAfter: iso(365), fingerprint: 'a1', isEncryptCapable: true },
        { id: 2, email: 'signonly@test.local', label: 'BetaCert', source: 'harvested', notBefore: iso(-30), notAfter: iso(365), fingerprint: 'b2', isEncryptCapable: false },
        { id: 3, email: 'soon@test.local', label: 'GammaCert', source: 'imported', notBefore: iso(-30), notAfter: iso(10), fingerprint: 'c3', isEncryptCapable: true },
        { id: 4, email: 'expired@test.local', label: 'DeltaCert', source: 'imported', notBefore: iso(-400), notAfter: iso(-1), fingerprint: 'd4', isEncryptCapable: true },
      ],
    });
    await installMocks(page, state);
    await page.goto('/settings/security');

    await expect(page.getByText('valid@test.local')).toBeVisible({ timeout: 15000 });
    // F4: the expiring-soon badge uses the dedicated copy, NOT the 'Expires' header label.
    await expect(page.getByText('Expiring soon')).toBeVisible();
    await expect(page.getByText('Signing only', { exact: false })).toBeVisible();
    await expect(page.getByText('Expired', { exact: true }).first()).toBeVisible();

    // Delete a cert → row goes away (re-fetch returns the trimmed list).
    const expiredRow = page.locator('tr', { hasText: 'expired@test.local' });
    await expiredRow.getByRole('button', { name: /delete|remove/i }).click();
    // A confirm step may appear; click any confirm/delete in a dialog if present.
    const dialog = page.getByRole('dialog');
    if (await dialog.isVisible({ timeout: 2000 }).catch(() => false)) {
      await dialog.getByRole('button', { name: /delete|remove|confirm/i }).click();
    }
    await expect(page.getByText('expired@test.local')).toHaveCount(0, { timeout: 10000 });
  });

  test('compose: the Encrypt (S/MIME) and Sign (S/MIME) controls render and toggle on', async ({ page }) => {
    // The full send→fail-closed flow is covered by ComposeScreen.test.ts (component)
    // + mail_encrypt_test.go (backend). In-browser, the send path reloads the JMAP
    // session (offline client), which can't complete under pure mocking — so this
    // verifies the SP1 compose controls themselves render and operate in a real
    // browser: open compose, reveal options, toggle Encrypt + Sign on.
    const state = makeState();
    await installMocks(page, state);
    await page.goto('/inbox');
    await page.getByRole('button', { name: /new message|compose|new mail|^new$/i }).first().click();

    const dialog = page.getByRole('dialog', { name: /new message/i });
    await expect(dialog).toBeVisible({ timeout: 10000 });
    const to = dialog.getByRole('combobox', { name: /to/i }).first();
    await to.click();
    await to.fill('nocert@ext.example');
    await to.press('Enter');

    // S/MIME switches live behind the "More" disclosure; their <input role=switch>
    // is visually hidden (the track is the visible control), so click the label.
    await dialog.getByRole('button', { name: /^more$/i }).first().click();
    const encryptLabel = page.locator('label', { hasText: 'Encrypt (S/MIME)' }).first();
    await encryptLabel.scrollIntoViewIfNeeded();
    await encryptLabel.click();
    await expect(page.getByRole('switch', { name: /encrypt \(s\/mime\)/i }).first()).toHaveAttribute('aria-checked', 'true');

    const signLabel = page.locator('label', { hasText: 'Sign (S/MIME)' }).first();
    await signLabel.click();
    await expect(page.getByRole('switch', { name: /sign \(s\/mime\)/i }).first()).toHaveAttribute('aria-checked', 'true');
  });
});
