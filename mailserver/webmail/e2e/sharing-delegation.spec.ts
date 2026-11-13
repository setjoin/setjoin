import { test, expect } from '@playwright/test';
import { loginAsUser, loginAsAdmin, apiToken, setFeature } from './helpers';
import { TEST_USERS } from './fixtures/test-data';

/**
 * Sharing & delegation (spec 2026-06-27-sharing-delegation-design.md §6/§7).
 *
 * @user: alice grants bob a send_on_behalf delegate through the §6-B dialog
 * (network-ack on the POST), sees it in the §6-C who-can-see card, and revokes
 * it (ack + aria-live announce). Strict API teardown if the grant leaks.
 *
 * @admin: enable sharing.defaults, create an org default through the §7
 * console, see it in per-user oversight for alice, delete it, disable the
 * toggle. Strict API teardown for the row + the toggle.
 */

// ── End-user delegation journey ──────────────────────────────────────────────

test.describe('Mailbox delegation — grant, review, revoke @user', () => {
  // Set while a grant exists; cleared once the in-test revoke lands. afterEach
  // deletes any leaked grant through the product API and asserts it worked.
  let leakedDelegateId = 0;

  test.afterEach(async ({ request }) => {
    if (leakedDelegateId) {
      const res = await request.delete(`/api/me/sharing/delegates/${leakedDelegateId}`);
      expect(res.status(), 'leaked delegate cleanup must succeed').toBe(204);
      leakedDelegateId = 0;
    }
  });

  test('grant bob send_on_behalf → who-can-see lists it → revoke announces', async ({ page, request }) => {
    await loginAsUser(page);
    await page.goto('/settings/sharing');

    // §6-C: nothing shared yet — both sections show the empty copy.
    await expect(page.getByText('Only you can see this').first()).toBeVisible({ timeout: 10000 });

    // §6-B dialog: grant bob send_on_behalf, awaiting the POST ack (rule 1).
    await page.getByRole('button', { name: 'Delegate access' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('No one else has access')).toBeVisible({ timeout: 10000 });
    await dialog.getByLabel('Person (email)').fill(TEST_USERS.bob.email);
    await dialog.getByLabel('Access level').selectOption('send_on_behalf');

    const grantAck = page.waitForResponse(
      (r) => r.url().includes('/api/me/sharing/delegates') && r.request().method() === 'POST',
      { timeout: 10000 },
    );
    await dialog.getByRole('button', { name: 'Grant access' }).click();
    expect((await grantAck).status()).toBe(201);

    // Row appears in the dialog's current-delegates list.
    await expect(dialog.getByText(TEST_USERS.bob.email, { exact: true })).toBeVisible({ timeout: 10000 });

    // Record the grantee id for strict teardown (from the same overview API the page reads).
    const overview = (await (await request.get('/api/me/sharing')).json()) as {
      delegates: { userId: number; email: string }[];
    };
    leakedDelegateId = overview.delegates.find((d) => d.email === TEST_USERS.bob.email)?.userId ?? 0;
    expect(leakedDelegateId, 'grant must be visible in GET /me/sharing').toBeGreaterThan(0);

    await dialog.getByRole('button', { name: 'Close', exact: true }).last().click(); // footer Close (the header X is aria-label "Close" too)
    await page.mouse.move(0, 0); // toast hygiene (rule 6)

    // §6-C card lists the delegate.
    const mailRow = page.locator('li', { hasText: TEST_USERS.bob.email }).first();
    await expect(mailRow).toBeVisible({ timeout: 10000 });
    await expect(mailRow).toContainText('Send on behalf');

    // Revoke: ack the DELETE, then assert the aria-live announce + row removal.
    const revokeAck = page.waitForResponse(
      (r) => /\/api\/me\/sharing\/delegates\/\d+$/.test(r.url()) && r.request().method() === 'DELETE',
      { timeout: 10000 },
    );
    await mailRow.getByRole('button', { name: 'Remove access' }).click();
    expect((await revokeAck).status()).toBe(204);
    leakedDelegateId = 0; // revoked in-test; teardown has nothing to do

    await expect(page.locator('.sj-sharing-announce')).toHaveText('Access removed', { timeout: 10000 });
    await expect(page.locator('li', { hasText: TEST_USERS.bob.email })).toHaveCount(0, { timeout: 10000 });
  });
});

// ── Admin defaults console journey ───────────────────────────────────────────

test.describe('Admin sharing defaults console @admin', () => {
  let adminToken = '';
  let createdDefaultId = 0;
  let toggleOn = false;

  test.afterEach(async ({ request }) => {
    // STRICT teardown through the product API.
    if (createdDefaultId) {
      const res = await request.delete(`/api/admin/sharing/defaults/${createdDefaultId}`);
      expect(res.status(), 'sharing default cleanup must succeed').toBe(204);
      createdDefaultId = 0;
    }
    if (toggleOn) {
      await setFeature(request, adminToken, 'sharing.defaults', false); // throws on failure
      toggleOn = false;
    }
  });

  test('enable toggle → create org default → per-user oversight shows it → delete → disable', async ({
    page,
    request,
  }) => {
    adminToken = await apiToken(request, TEST_USERS.admin.email, TEST_USERS.admin.password);
    await setFeature(request, adminToken, 'sharing.defaults', true);
    toggleOn = true;
    await new Promise((r) => setTimeout(r, 1200)); // toggle hot-reload settle (helpers contract)

    await loginAsAdmin(page);
    await page.goto('/admin/sharing');
    await expect(page.getByRole('heading', { name: 'Sharing' })).toBeVisible({ timeout: 10000 });

    // Defaults tab: create an org default (test.local → everyone, free-busy).
    await page.getByRole('button', { name: 'Add default' }).first().click();
    const editor = page.getByRole('dialog');
    // Wait for the domain pickers to populate before selecting (async load).
    await expect(editor.getByLabel('Domain', { exact: true }).locator('option', { hasText: 'test.local' })).toHaveCount(1, { timeout: 10000 });
    await editor.getByLabel('Domain', { exact: true }).selectOption({ label: 'test.local' });
    await editor.getByLabel('Audience domain').selectOption({ label: 'test.local' });
    await editor.getByRole('radio', { name: 'Free-busy' }).click();

    const createAck = page.waitForResponse(
      (r) => r.url().includes('/api/admin/sharing/defaults') && r.request().method() === 'POST',
      { timeout: 10000 },
    );
    await editor.getByRole('button', { name: 'Save' }).click();
    const createRes = await createAck;
    expect(createRes.status()).toBe(200);
    createdDefaultId = ((await createRes.json()) as { id: number }).id;
    await page.mouse.move(0, 0); // toast hygiene

    // Row renders with resolved labels.
    const row = page.locator('tr', { hasText: 'Whole domain — test.local' });
    await expect(row).toBeVisible({ timeout: 10000 });
    await expect(row).toContainText('Free-busy');

    // Per-user oversight: alice inherits the org default.
    await page.getByRole('tab', { name: 'Per-user' }).click();
    await page.getByLabel('Find a user').fill(TEST_USERS.alice.email);
    await page.getByRole('button', { name: 'Search', exact: true }).click();
    await page.getByRole('button', { name: new RegExp(TEST_USERS.alice.email) }).click();
    const oversight = page.locator('.shc-oversight');
    await expect(oversight).toContainText('Whole domain', { timeout: 10000 });
    await expect(oversight).toContainText('Free-busy');

    // Delete the default from the Defaults tab (ack the DELETE).
    await page.getByRole('tab', { name: 'Defaults' }).click();
    const deleteAck = page.waitForResponse(
      (r) => /\/api\/admin\/sharing\/defaults\/\d+$/.test(r.url()) && r.request().method() === 'DELETE',
      { timeout: 10000 },
    );
    await page.getByLabel('Delete default').click();
    expect((await deleteAck).status()).toBe(204);
    createdDefaultId = 0; // deleted in-test

    await expect(page.getByText('No sharing defaults')).toBeVisible({ timeout: 10000 });

    // Disable the toggle through the same admin API (asserted by setFeature).
    await setFeature(request, adminToken, 'sharing.defaults', false);
    toggleOn = false;
  });
});
