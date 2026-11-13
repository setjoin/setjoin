import { test, expect, type APIRequestContext } from '@playwright/test';
import { loginAsUser, apiToken, psql, reloadAfterServiceWorkerControl } from './helpers';
import { TEST_USERS } from './fixtures/test-data';

/**
 * Webcal/ICS calendar subscribe (WAVE-5 #10). Import (.ics file upload) is
 * covered elsewhere; this spec covers the OTHER path — a live external URL
 * the calendarsync worker refreshes on a background tick.
 *
 * No static fixture server exists in this e2e harness to host a real .ics
 * feed (checked: e2e/fixtures is file-based, no HTTP static route) — per the
 * binding contract's own fallback, this spec:
 *   1. subscribes to a real (reachable-looking, DNS-dead) URL through the UI
 *      to exercise the actual subscribe→async-fetch→failure-dot path, and
 *   2. drives the diff-by-uid reducer directly via psql to exercise the
 *      render path (events appear) without needing a live feed.
 *
 * alice is the shared protagonist; this spec creates its own subscriptions
 * (never touching her seeded numbered messages) and tears down through the
 * real DELETE endpoint, with a psql fallback only if a test fails first.
 */
// The calendar sidebar (.calendar-list) only renders past a @container width
// breakpoint (PimShell.svelte), and the primary pane is only a FRACTION of the
// viewport (SplitPane defaultRatio 0.6, minus the nav rail) — 1280 leaves the
// primary pane just under the 768px breakpoint. Widen further than
// shared-mailbox.spec.ts's 1280 to comfortably clear it.
test.use({ viewport: { width: 1920, height: 1200 } });

const ts = Date.now();

async function listSubscriptions(
  request: APIRequestContext,
  token: string
): Promise<{ id: number; calendarId: string; lastStatus: string }[]> {
  const res = await request.get('/api/calendar/subscriptions', {
    headers: { Authorization: `Bearer ${token}` }
  });
  expect(res.status()).toBe(200);
  const body = (await res.json()) as { subscriptions: { id: number; calendarId: string; lastStatus: string }[] };
  return body.subscriptions ?? [];
}

test.describe('Webcal/ICS calendar subscribe @user', () => {
  let leakedSubId = 0; // strict teardown if a test fails before its own unsubscribe

  test.afterEach(async ({ request }) => {
    if (leakedSubId) {
      const token = await apiToken(request, TEST_USERS.alice.email, TEST_USERS.alice.password);
      const res = await request.delete(`/api/calendar/subscriptions/${leakedSubId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      expect([204, 404]).toContain(res.status());
      leakedSubId = 0;
    }
  });

  test('subscribing to an unreachable URL settles to the failure-dot state, then unsubscribe removes it', async ({
    page,
    request
  }) => {
    const name = `E2E webcal dead ${ts}`;
    // .invalid is RFC 2606-reserved — guaranteed never to resolve, so this
    // passes ssrf.ValidateURL (a public-looking https host, not a literal
    // blocked IP) but fails at the calendarsync worker's actual fetch/DNS step.
    const url = `https://e2e-webcal-dead-${ts}.invalid/feed.ics`;

    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Calendar' }).click();
    await expect(page).toHaveURL(/calendar/);

    await page.getByRole('button', { name: 'Subscribe to calendar' }).click();
    const dialog = page.getByRole('dialog', { name: 'Subscribe to a calendar' });
    await expect(dialog).toBeVisible();
    await dialog.getByLabel('Calendar URL').fill(url);
    await dialog.getByLabel('Name').fill(name);
    // Await the network ACK (e2e/AGENTS.md rule 1) so the created subscription
    // id is known precisely — never inferred by scanning the whole list, which
    // could collide with another leftover/parallel subscription.
    const createResp = page.waitForResponse(
      (r) => r.url().includes('/api/calendar/subscriptions') && r.request().method() === 'POST'
    );
    await dialog.getByRole('button', { name: 'Subscribe', exact: true }).click();
    const created = (await (await createResp).json()) as { id: number; calendarId: string };
    await expect(dialog).not.toBeVisible({ timeout: 10000 });
    leakedSubId = created.id;

    const token = await apiToken(request, TEST_USERS.alice.email, TEST_USERS.alice.password);
    await expect
      .poll(
        async () => {
          const subs = await listSubscriptions(request, token);
          return subs.find((s) => s.id === created.id)?.lastStatus;
        },
        { message: 'webcal subscription never settled to error status', timeout: 20000, intervals: [500] }
      )
      .toBe('error');

    // Reload so the sidebar re-fetches subscription status, then assert the
    // failure-dot + Globe icon render on this calendar's row.
    page = await reloadAfterServiceWorkerControl(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Calendar' }).click();
    const row = page.locator('.calendar-list li', { hasText: name });
    await expect(row).toBeVisible({ timeout: 10000 });
    await expect(row.locator('.cal-sub-icon')).toBeVisible();
    await expect(row.locator('.cal-sub-dot--error')).toBeVisible();

    // Unsubscribe via the UI (confirm dialog accepted).
    page.once('dialog', (d) => d.accept());
    await row.getByLabel('Unsubscribe').click();
    await expect(row).not.toBeVisible({ timeout: 10000 });
    leakedSubId = 0;

    const after = await listSubscriptions(request, token);
    expect(after.some((s) => s.id === created.id)).toBe(false);
  });

  test('a synced webcal calendar renders its events, and unsubscribe removes calendar + events', async ({
    page,
    request
  }) => {
    const name = `E2E webcal synced ${ts}`;
    const eventTitle = `E2E webcal event ${ts}`;
    const url = `https://e2e-webcal-synced-${ts}.invalid/feed.ics`;

    const token = await apiToken(request, TEST_USERS.alice.email, TEST_USERS.alice.password);
    const createRes = await request.post('/api/calendar/subscriptions', {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      data: { url, name }
    });
    expect(createRes.status()).toBe(201);
    const created = (await createRes.json()) as { id: number; calendarId: string };
    leakedSubId = created.id;

    // Drive the diff-by-uid reducer directly (the binding contract's explicit
    // fallback for the render path — no static fixture server hosts a real
    // feed in this harness). Mirrors exactly what the calendarsync worker
    // would call on a successful fetch.
    const uid = `e2e-webcal-uid-${ts}`;
    const start = new Date(Date.now() + 3600_000).toISOString();
    const end = new Date(Date.now() + 7200_000).toISOString();
    const eventsJSON = JSON.stringify([{ uid, title: eventTitle, start, end }]).replace(/'/g, "''");
    psql(`SELECT calendar_subscription_refresh(${created.id}, ${created.calendarId}, '${eventsJSON}'::jsonb)`);

    await loginAsUser(page);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Calendar' }).click();
    await expect(page).toHaveURL(/calendar/);

    const row = page.locator('.calendar-list li', { hasText: name });
    await expect(row).toBeVisible({ timeout: 10000 });
    await expect(row.locator('.cal-sub-icon')).toBeVisible();

    // Month cells intentionally collapse after three items. Earlier calendar
    // specs can therefore put this fourth event behind "+N more" even though
    // it loaded correctly. Agenda is the non-collapsing product view and makes
    // the subscribed event directly observable without depending on density.
    await page.getByRole('button', { name: 'Agenda', exact: true }).click();
    const eventItem = page.getByRole('button', { name: eventTitle, exact: false });
    await expect(eventItem).toBeVisible({ timeout: 10000 });

    // psql assert (rule 4): the event really landed via the reducer, not a
    // client-side mirage.
    const persisted = psql(
      `SELECT count(*) FROM calendar_events WHERE calendar_id = ${created.calendarId} AND uid = '${uid}'`
    );
    expect(persisted).toBe('1');

    // Unsubscribe via the UI — cascades to remove the calendar + its events.
    page.once('dialog', (d) => d.accept());
    await row.getByLabel('Unsubscribe').click();
    await expect(row).not.toBeVisible({ timeout: 10000 });
    leakedSubId = 0;

    await expect(eventItem).not.toBeVisible();
    const gone = psql(`SELECT count(*) FROM calendars WHERE id = ${created.calendarId}`);
    expect(gone).toBe('0');
  });
});
