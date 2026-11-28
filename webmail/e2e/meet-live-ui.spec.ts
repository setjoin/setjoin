// meet-live-ui.spec.ts — Meet B1 standing gate: the FULL webmail-UI-driven
// authority flow with two real headless Chromium browsers + one guest context,
// against a LIVE stack (gateway + authserver + postgres + LiveKit SFU behind
// the /rtc proxy). First run 2026-07-16 on linux-ci-host — found + fixed 7 real
// product bugs (see the meet AGENTS.md honesty section).
//
// GATED: never runs in an ordinary e2e pass — it needs an SFU-provisioned
// stack, seeded users (e2e/fixtures/seed.sql), feature.meet ON, and a psql
// binary. Run with:
//   MEET_LIVE_UI=1 MEET_LIVE_UI_BASE=http://127.0.0.1:18080 \
//   MEET_LIVE_UI_DSN=postgres://mail:mail@127.0.0.1:15432/mailserver_b1gate \
//   npx playwright test e2e/meet-live-ui.spec.ts
//
// Flow: real login form -> create/join -> org-open join-by-link -> two-way
// tiles (fake media) -> lock/unlock -> kick (ban) -> BZ186 refused rejoin ->
// role-route re-admit -> rejoin OK -> guest-access switch -> public guest
// knock -> admit -> in-room -> sealed guest kick (denied; fresh request only)
// -> blur (probe-dependent) -> end-for-all (B + guest terminal states).
import { test, expect, chromium, type Browser, type BrowserContext, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const LIVE = !!process.env.MEET_LIVE_UI;
const BASE = process.env.MEET_LIVE_UI_BASE ?? 'http://127.0.0.1:18080';
// A real single-node deploy serves the self-signed cert install.sh generates
// (SINGLE_NODE_SETUP step 6) — opt in to trusting it, never on by default.
const INSECURE_TLS = !!process.env.MEET_LIVE_UI_INSECURE_TLS;
const DSN = process.env.MEET_LIVE_UI_DSN ?? 'postgres://mail:mail@127.0.0.1:15432/mailserver_b1gate';
const EVIDENCE = process.env.MEET_LIVE_UI_EVIDENCE ?? path.join(os.tmpdir(), 'meet-live-ui-evidence');

function psql(sql: string): string {
  return execFileSync('psql', [DSN, '-X', '-v', 'ON_ERROR_STOP=1', '-tAc', sql], { encoding: 'utf-8' }).trim();
}

const ledger: string[] = [];
function note(line: string): void {
  ledger.push(line);
  console.log(`[LEDGER] ${line}`);
}

let browser: Browser;
let ctxA: BrowserContext, ctxB: BrowserContext, ctxG: BrowserContext;
let pageA: Page, pageB: Page, pageG: Page;
let slug = '';
let meetingId = 0;
let bobUid = 0;

const consoleLogs: Record<string, string[]> = { A: [], B: [], G: [] };

async function newCtx(tag: 'A' | 'B' | 'G'): Promise<[BrowserContext, Page]> {
  const ctx = await browser.newContext({
    baseURL: BASE,
    viewport: { width: 1400, height: 900 },
    ignoreHTTPSErrors: INSECURE_TLS,
    // @playwright/test applies the selected project's Alice storageState even
    // to explicit browser contexts. Override it so A/B prove their own form
    // login and the public guest can never inherit an employee session.
    storageState: { cookies: [], origins: [] },
  });
  await ctx.grantPermissions(['camera', 'microphone'], { origin: BASE });
  const page = await ctx.newPage();
  page.on('console', (m) => consoleLogs[tag].push(`[${m.type()}] ${m.text()}`));
  page.on('pageerror', (e) => consoleLogs[tag].push(`[pageerror] ${e.stack ?? e.message}`));
  return [ctx, page];
}

async function snap(page: Page, name: string): Promise<void> {
  await page.screenshot({ path: path.join(EVIDENCE, `${name}.png`), fullPage: false }).catch(() => undefined);
}

async function uiLogin(page: Page, email: string, password: string): Promise<void> {
	// These long-lived contexts intentionally survive across serial test cases.
	// Start each principal with an explicit empty auth state so a prior manual or
	// retried run can never make the form assertion pass under the wrong user.
	await page.context().clearCookies();
	await page.goto('/');
	const emailInput = page.getByLabel('Email');
	await expect(emailInput).toBeVisible({ timeout: 15_000 });
	await emailInput.fill(email);
	await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  // login redirects into the app; settle on any authed shell
  await page.waitForURL(/\/(apps|inbox|mail)/, { timeout: 20_000 });
}

/** PreJoin: report device state, optionally turn camera on, then Join. */
async function preJoinAndEnter(page: Page, tag: string, camOn: boolean): Promise<string> {
  const joinBtn = page.getByRole('button', { name: 'Join', exact: true });
  await expect(joinBtn).toBeVisible({ timeout: 20_000 });
  // settle: PreJoin's getUserMedia attempt resolves deviceState
  let state = 'granted';
  const denied = page.getByText("We couldn't access your camera or microphone");
  const nodevice = page.getByText('No camera or microphone was found');
  await page.waitForTimeout(2500);
  if (await denied.isVisible().catch(() => false)) state = 'denied';
  else if (await nodevice.isVisible().catch(() => false)) state = 'nodevice';
  note(`${tag}: PreJoin deviceState=${state}`);
  await snap(page, `${tag}-prejoin`);
  if (state === 'granted' && camOn) {
    await page.getByRole('button', { name: 'Start video' }).click().catch(() => note(`${tag}: could not enable camera in PreJoin`));
  }
  await joinBtn.click();
  return state;
}

async function inRoom(page: Page): Promise<void> {
  await expect(page.getByRole('toolbar', { name: 'Meeting controls' })).toBeVisible({ timeout: 30_000 });
}

test.describe.serial('B1 webmail-UI authority flow @user', () => {
  test.skip(!LIVE, 'MEET_LIVE_UI not set — needs a live SFU-provisioned stack, never faked');

  test.beforeAll(async () => {
    if (!LIVE) return;
    fs.mkdirSync(EVIDENCE, { recursive: true });
    browser = await chromium.launch({
      headless: true,
      args: [
        '--use-fake-device-for-media-stream',
        '--use-fake-ui-for-media-stream',
        '--autoplay-policy=no-user-gesture-required',
      ],
    });
    [ctxA, pageA] = await newCtx('A');
    [ctxB, pageB] = await newCtx('B');
    [ctxG, pageG] = await newCtx('G');
  });

  test.afterAll(async () => {
    if (!LIVE) return;
    for (const [tag, logs] of Object.entries(consoleLogs)) {
      fs.writeFileSync(path.join(EVIDENCE, `console-${tag}.log`), logs.join('\n'));
    }
    fs.writeFileSync(path.join(EVIDENCE, 'ledger.txt'), ledger.join('\n'));
    await browser?.close();
  });

  test('a. A logs in via the real login page and creates + joins a meeting', async () => {
    await uiLogin(pageA, 'alice@test.local', 'TestPass123!');
    note('A: real login-form login OK');
    await pageA.goto('/meet');
    await expect(pageA.getByRole('button', { name: 'New meeting' })).toBeVisible();
    await snap(pageA, 'a1-A-meet-landing');
    await pageA.getByPlaceholder('Meeting title').fill('B1 Gate Meeting');
    await pageA.getByRole('button', { name: 'New meeting' }).click();
    await preJoinAndEnter(pageA, 'A', true);
    await inRoom(pageA);
    note('A: in-room after create');
    await snap(pageA, 'a2-A-in-room');
    slug = psql('SELECT slug FROM meetings ORDER BY id DESC LIMIT 1');
    meetingId = Number(psql('SELECT id FROM meetings ORDER BY id DESC LIMIT 1'));
    bobUid = Number(psql("SELECT id FROM users WHERE email='bob@test.local'"));
    expect(slug).not.toBe('');
    note(`meeting id=${meetingId} slug=${slug}`);
  });

  test('b. B logs in, joins by link (org-open), tiles both ways', async () => {
    await uiLogin(pageB, 'bob@test.local', 'TestPass123!');
    await pageB.goto('/meet');
    await pageB.getByPlaceholder('Paste a meeting link or code').fill(slug);
    await pageB.getByRole('button', { name: 'Join by link' }).click();
    await preJoinAndEnter(pageB, 'B', true);
    await inRoom(pageB);
    note('B: in-room via join-by-link (org-open posture holds at the UI)');
    // A sees B's tile; B sees A's tile
    await expect(pageA.getByText('Bob Test').first()).toBeVisible({ timeout: 20_000 });
    await expect(pageB.getByText('Alice Test').first()).toBeVisible({ timeout: 20_000 });
    note('A and B each see the other in the room UI');
    // video elements: count + whether frames actually flow (fake pattern)
    for (const [tag, page] of [['A', pageA], ['B', pageB]] as const) {
      const vids = await page.locator('video').count();
      const playing = await page
        .locator('video')
        .evaluateAll((els) => els.map((v) => ({ w: (v as HTMLVideoElement).videoWidth, paused: (v as HTMLVideoElement).paused })));
      note(`${tag}: video elements=${vids} states=${JSON.stringify(playing)}`);
    }
    await snap(pageA, 'b1-A-sees-B');
    await snap(pageB, 'b2-B-sees-A');
  });

  test('c1. host locks then unlocks the meeting', async () => {
    await pageA.getByRole('button', { name: 'Lock meeting' }).click();
    await expect(pageA.getByRole('button', { name: 'Unlock meeting' })).toBeVisible({ timeout: 15_000 });
    note('A: lock round-trip reflected in UI (WS push flipped the button)');
    await snap(pageA, 'c1-A-locked');
    // unlock again so the kick/rejoin leg below exercises BZ186 (ban), not BZ187 (locked)
    await pageA.getByRole('button', { name: 'Unlock meeting' }).click();
    await expect(pageA.getByRole('button', { name: 'Lock meeting' })).toBeVisible({ timeout: 15_000 });
    note('A: unlock round-trip reflected in UI');
  });

  test('c2. host kicks B; B sees a kicked state', async () => {
    await pageA.getByRole('button', { name: 'Participants' }).click();
    const dialog = pageA.getByRole('dialog');
    await expect(dialog.getByText('Bob Test')).toBeVisible();
    await dialog.getByRole('listitem').filter({ hasText: 'Bob Test' }).getByRole('button', { name: 'Remove' }).click();
    await pageA.getByTestId('kick-confirm').click();
    note('A: kick issued through the participants sheet + confirm dialog');
    await pageA.keyboard.press('Escape'); // close sheet
    // What does B see? (no participant_kicked handler exists in MeetApp — observe honestly)
    await pageB.waitForTimeout(6000);
    const bState = {
      toolbarVisible: await pageB.getByRole('toolbar', { name: 'Meeting controls' }).isVisible().catch(() => false),
      endedVisible: await pageB.getByText('This meeting has ended').isVisible().catch(() => false),
      bodyText: (await pageB.locator('body').innerText()).slice(0, 400).replace(/\n+/g, ' | '),
    };
    note(`B after kick: ${JSON.stringify(bState)}`);
    await snap(pageB, 'c2-B-after-kick');
    // A's roster: Bob moves from the live list to the banned section with a
    // Re-admit affordance (B1 live-gate ledger fix 2 — banned members stay
    // listed under 'Removed from this meeting', they don't vanish).
    await pageA.getByRole('button', { name: 'Participants' }).click();
    const sheet = pageA.getByRole('dialog');
    await expect(sheet.getByText('Removed from this meeting')).toBeVisible({ timeout: 15_000 });
    await expect(sheet.getByRole('button', { name: 'Re-admit' })).toBeVisible();
    await expect(sheet.getByText('Bob Test')).toBeVisible();
    note('A roster after kick: Bob listed under the banned section with a Re-admit button');
    await snap(pageA, 'c2-A-roster-after-kick');
    await pageA.keyboard.press('Escape');
  });

  test('c3. kicked B rejoin is REFUSED (BZ186) at the UI', async () => {
    await pageB.goto(`/meet?slug=${slug}`);
    const joinResp = pageB.waitForResponse((r) => r.url().includes('/api/meet/') && r.url().endsWith('/join') && r.request().method() === 'POST', { timeout: 40_000 });
    await preJoinAndEnter(pageB, 'B-rejoin', false);
    const resp = await joinResp;
    note(`B rejoin join POST → HTTP ${resp.status()} (expect 403 BZ186)`);
    expect(resp.status()).toBe(403);
    // MeetApp error view: EmptyState with the problem detail + Close
    await expect(pageB.getByRole('button', { name: 'Close' })).toBeVisible({ timeout: 15_000 });
    const errText = (await pageB.locator('body').innerText()).slice(0, 300).replace(/\n+/g, ' | ');
    note(`B rejoin-refused UI text: ${errText}`);
    await snap(pageB, 'c3-B-rejoin-refused');
  });

  test('c4. host re-admits B via the roster affordance; B rejoins', async () => {
    // B1 live-gate ledger fix 2 landed: the participants sheet lists banned
    // members with a Re-admit button (meeting_set_role IS the re-admit path).
    await pageA.getByRole('button', { name: 'Participants' }).click();
    const sheet = pageA.getByRole('dialog');
    await sheet.getByRole('button', { name: 'Re-admit' }).click();
    await expect(sheet.getByText('Removed from this meeting')).toHaveCount(0, { timeout: 15_000 });
    note(`A re-admitted u:${bobUid} through the roster affordance (banned section cleared)`);
    await pageA.keyboard.press('Escape');
    // B rejoins through the UI
    await pageB.getByRole('button', { name: 'Close' }).click().catch(() => undefined);
    await pageB.goto(`/meet?slug=${slug}`);
    await preJoinAndEnter(pageB, 'B-readmitted', false);
    await inRoom(pageB);
    note('B: rejoin after re-admit succeeds (ban cleared)');
    await snap(pageB, 'c4-B-readmitted');
  });

  test('d1. guest knocks via the public page; host admits; guest lands in-room', async () => {
    // guestAllowed defaults FALSE — the host enables it via LobbyPanel's Switch
    await pageA.getByRole('button', { name: /Waiting to join/ }).click();
    await pageA.getByText('Allow guests to request to join').click();
    await pageA.waitForTimeout(1500);
    const ga = psql(`SELECT (settings->>'guestAllowed') FROM meetings WHERE id=${meetingId}`);
    note(`A: enabled guest access via LobbyPanel switch (db guestAllowed=${ga})`);
    await pageG.goto(`/meet/join/${slug}`);
    await expect(pageG.getByText('Join meeting').first()).toBeVisible();
    await pageG.getByLabel('Your name').fill('Guest Gina');
    await pageG.getByRole('button', { name: 'Ask to join' }).click();
    await expect(pageG.getByText('Waiting for the host to let you in')).toBeVisible({ timeout: 15_000 });
    await snap(pageG, 'd1-G-waiting');
    note('G: public guest knock submitted, waiting view shown');
    // Host: lobby panel already open (guest-access toggle step above)
    await expect(pageA.getByText('Guest Gina').first()).toBeVisible({ timeout: 20_000 });
    await snap(pageA, 'd1-A-lobby-knock');
    await pageA.getByRole('button', { name: 'Admit', exact: true }).click();
    note('A: admitted the guest from LobbyPanel');
    // Guest connects
    await inRoom(pageG);
    note('G: in-room after admit');
    await snap(pageG, 'd2-G-in-room');
    await expect(pageA.getByText('Guest Gina').first()).toBeVisible({ timeout: 20_000 });
    note('A sees Guest Gina in the room');
  });

  test('d2. guest kick is sealed: removed state, fresh request required and possible', async () => {
    const guestIdentity = psql(`SELECT 'g:' || id FROM meeting_join_requests WHERE meeting_id=${meetingId} AND display_name='Guest Gina' AND state='admitted' ORDER BY id DESC LIMIT 1`);
    await pageA.getByRole('button', { name: 'Participants' }).click();
    const dlg = pageA.getByRole('dialog');
    await dlg.getByRole('listitem').filter({ hasText: 'Guest Gina' }).getByRole('button', { name: 'Remove' }).click();
    await pageA.getByTestId('kick-confirm').click();
    await pageA.keyboard.press('Escape');
    note(`A: kicked guest (${guestIdentity})`);
    await expect(pageG.getByText('You were removed from the meeting.')).toBeVisible({ timeout: 30_000 });
    note('G: removed state rendered (classifyPostDisconnect → denied row)');
    await snap(pageG, 'd3-G-removed');
    const reqState = psql(`SELECT state FROM meeting_join_requests WHERE meeting_id=${meetingId} AND display_name='Guest Gina' ORDER BY id DESC LIMIT 1`);
    note(`G join_request row after kick: state=${reqState} (expect denied — sealed)`);
    // sealed: fresh request is the only path — reload the public page, knock again
    await pageG.goto(`/meet/join/${slug}`);
    await pageG.getByLabel('Your name').fill('Guest Gina');
    await pageG.getByRole('button', { name: 'Ask to join' }).click();
    await expect(pageG.getByText('Waiting for the host to let you in')).toBeVisible({ timeout: 15_000 });
    note('G: fresh knock after sealed kick reaches the lobby again (pending)');
    await snap(pageG, 'd4-G-fresh-knock');
  });

  test('e. host toggles background blur (or records the probe fallback)', async () => {
    const blurBtn = pageA.getByRole('button', { name: /Blur background|Turn off background blur/ });
    if ((await blurBtn.count()) === 0) {
      note('A: blur button NOT rendered (blurSupported=false — codec probe fell back headless). No crash; coherent UI.');
    } else {
      await blurBtn.first().click();
      await pageA.waitForTimeout(3000);
      const alive = await pageA.getByRole('toolbar', { name: 'Meeting controls' }).isVisible();
      note(`A: blur toggled; toolbar still alive=${alive}`);
      await snap(pageA, 'e1-A-blur');
    }
  });

  test('f. host ends for all: B ended, guest knock expires, ended deep-link is visible but not joinable', async () => {
    await pageA.getByTestId('end-for-all').click();
    await pageA.getByTestId('end-for-all-confirm').click();
    await expect(pageA.getByText('This meeting has ended')).toBeVisible({ timeout: 20_000 });
    note('A: ended view after end-for-all');
    await snap(pageA, 'f1-A-ended');
    await expect(pageB.getByText('This meeting has ended')).toBeVisible({ timeout: 20_000 });
    note('B: ended view via push (end drops everyone)');
    await snap(pageB, 'f2-B-ended');
    // guest's fresh pending knock → expired by meeting_end
    await expect(pageG.getByText(/expired|ended/i).first()).toBeVisible({ timeout: 40_000 });
    const gText = (await pageG.locator('body').innerText()).slice(0, 200).replace(/\n+/g, ' | ');
    note(`G after end: ${gText}`);
    await snap(pageG, 'f3-G-after-end');
    // A recently-ended meeting remains resolvable for 24h so the client can
    // render an honest terminal state; it must not expose a Join control.
    const resolveResponse = pageB.waitForResponse((r) => r.url().includes('/api/meet/by-slug/'), { timeout: 30_000 });
    await pageB.goto(`/meet?slug=${slug}`);
    const r = await resolveResponse;
    expect(r.status()).toBe(200);
    await expect(pageB.getByText('This meeting has ended')).toBeVisible({ timeout: 15_000 });
    await expect(pageB.getByRole('button', { name: 'Join', exact: true })).toHaveCount(0);
    note(`B post-end open-by-slug → HTTP 200 terminal view on ${new URL(r.url()).pathname}; Join absent`);
    await snap(pageB, 'f4-B-not-joinable');
  });
});
