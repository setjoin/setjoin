import { expect, test } from '@playwright/test';
import { reloadAfterServiceWorkerControl } from './helpers';
import { bookingRequestStatus, arrangePendingBooking, bookingPage, createBookingPage, deleteBookingPage, firstBookingSlot, setBookingFeature } from './booking-fixtures';

test.describe('Booking confirmation and cancellation @user', () => {
  let adminToken = '';
  let ownerToken = '';
  const createdIds = new Set<string>();

  test.beforeEach(async ({ request }) => {
    ({ adminToken, ownerToken } = await setBookingFeature(request, true, adminToken, ownerToken));
  });

  test.afterEach(async ({ request }) => {
    for (const id of createdIds) {
      await deleteBookingPage(request, ownerToken, id);
    }
    createdIds.clear();
    if (adminToken) {
      await setBookingFeature(request, false, adminToken, ownerToken).catch(() => undefined);
    }
    adminToken = '';
    ownerToken = '';
  });

  test('confirms a reducer-arranged pending request, cancels it, and reloads to single-use invalid', async ({ page, request }) => {
    const suffix = `${Date.now()}`;
    const created = await createBookingPage(
      request,
      ownerToken,
      bookingPage(`e2e-confirm-${suffix}`),
    );
    createdIds.add(created.id);
    const slot = await firstBookingSlot(request, created.slug);
    const email = `booking-confirm-${suffix}@example.test`;
    const verifyToken = `e2e-confirm-token-${suffix}`;

    // This is a real reducer arrange, not a raw booking_requests INSERT. It
    // supplies a known token while keeping email/object-store delivery out of
    // the browser contract under test.
    arrangePendingBooking({
      slug: created.slug,
      start: slot.start,
      email,
      name: 'Confirm E2E User',
      verifyToken,
    });

    const confirmAck = page.waitForResponse((r) =>
      r.url().endsWith('/api/public/booking/confirm') && r.request().method() === 'POST',
    );
    await page.goto(`/book/confirm?token=${encodeURIComponent(verifyToken)}`);
    expect((await confirmAck).status()).toBe(200);
    await expect(page.getByText('Your booking is confirmed. A calendar invite is on its way.')).toBeVisible();

    const cancelAck = page.waitForResponse((r) =>
      r.url().endsWith('/api/public/booking/cancel') && r.request().method() === 'POST',
    );
    await page.getByRole('button', { name: 'Cancel this booking', exact: true }).click();
    expect((await cancelAck).status()).toBe(200);
    await expect(page.getByText('This booking has been cancelled.')).toBeVisible();
    await expect.poll(() => bookingRequestStatus(created.slug, email)).toBe('cancelled');

    // Reloading the original verify URL proves the token is single-use and
    // exercises the route's persisted invalid state, not only in-memory UI.
    let reloadConfirm: ReturnType<typeof page.waitForResponse>;
    page = await reloadAfterServiceWorkerControl(page, (reopened) => {
      reloadConfirm = reopened.waitForResponse((r) =>
        r.url().endsWith('/api/public/booking/confirm') && r.request().method() === 'POST',
      );
    });
    expect((await reloadConfirm!).status()).toBe(409);
    await expect(page.getByText('This link is invalid or has expired.')).toBeVisible();
  });

  test('renders invalid state for missing, bad-confirm, and bad-cancel tokens', async ({ page }) => {
    await page.goto('/book/confirm');
    await expect(page.getByText('This link is invalid or has expired.')).toBeVisible();

    const badVerify = page.waitForResponse((r) =>
      r.url().endsWith('/api/public/booking/confirm') && r.request().method() === 'POST',
    );
    await page.goto(`/book/confirm?token=e2e-invalid-${Date.now()}`);
    expect((await badVerify).status()).toBe(409);
    await expect(page.getByText('This link is invalid or has expired.')).toBeVisible();

    const badCancel = page.waitForResponse((r) =>
      r.url().endsWith('/api/public/booking/cancel') && r.request().method() === 'POST',
    );
    await page.goto(`/book/confirm?cancel=e2e-invalid-cancel-${Date.now()}`);
    expect((await badCancel).status()).toBe(409);
    await expect(page.getByText('This link is invalid or has expired.')).toBeVisible();
  });
});
