import { expect, type APIRequestContext } from '@playwright/test';
import { apiToken, psql, setFeature } from './helpers';
import { TEST_USERS } from './fixtures/test-data';

export interface BookingQuestionFixture {
  id: string;
  label: string;
  required: boolean;
}

export interface BookingAvailabilityFixture {
  dow: number;
  start: string;
  end: string;
}

export interface BookingPageFixture {
  id?: string;
  slug: string;
  title: string;
  description: string;
  durationMinutes: number;
  bufferMinutes: number;
  maxPerDay: number;
  minNoticeMinutes: number;
  maxAdvanceDays: number;
  availability: BookingAvailabilityFixture[];
  questions: BookingQuestionFixture[];
  timezone: string;
  enabled: boolean;
}

export interface BookingSlotFixture {
  start: string;
  end: string;
}

const BASE = process.env.E2E_SERVER ?? 'http://localhost:8080';

/** Availability on every day keeps public fixtures independent of the wall clock. */
export function everyDayAvailability(start = '00:00', end = '23:00'): BookingAvailabilityFixture[] {
  return Array.from({ length: 7 }, (_, dow) => ({ dow, start, end }));
}

/** A bounded page fixture with deterministic UTC scheduling and no questions. */
export function bookingPage(slug: string, overrides: Partial<BookingPageFixture> = {}): BookingPageFixture {
  return {
    slug,
    title: `E2E Booking ${slug}`,
    description: 'A disposable booking page for browser E2E.',
    durationMinutes: 30,
    bufferMinutes: 0,
    maxPerDay: 48,
    minNoticeMinutes: 0,
    maxAdvanceDays: 30,
    availability: everyDayAvailability(),
    questions: [],
    timezone: 'UTC',
    enabled: true,
    ...overrides,
  };
}

/**
 * Toggle the real feature and poll the owner route until the gateway's
 * config_changed notification has taken effect. No fixed sleep is used.
 */
export async function setBookingFeature(
  request: APIRequestContext,
  enabled: boolean,
  adminToken = '',
  ownerToken = '',
): Promise<{ adminToken: string; ownerToken: string }> {
	// The shared seed intentionally gives Alice no calendar. Booking correctly
	// exposes no slots without a default calendar, so arrange that prerequisite
	// exactly as the existing calendar E2E fixtures do before exercising pages.
	psql(`
		INSERT INTO calendars (mailbox_id, name, color, is_default)
		SELECT m.id, 'Booking E2E', '#2563eb', TRUE
		  FROM mailboxes m
		 WHERE m.email = '${TEST_USERS.alice.email}'
		   AND NOT EXISTS (SELECT 1 FROM calendars c WHERE c.mailbox_id = m.id)
	`);
  const admin = adminToken || await apiToken(request, TEST_USERS.admin.email, TEST_USERS.admin.password);
  const owner = ownerToken || await apiToken(request, TEST_USERS.alice.email, TEST_USERS.alice.password);
  await setFeature(request, admin, 'feature.booking_pages', enabled);
  await expect.poll(async () => {
    const response = await request.get('/api/booking/pages', {
      headers: { Authorization: `Bearer ${owner}` },
    });
    return response.status();
  }, {
    timeout: 15_000,
    intervals: [100, 250, 500, 1000],
  }).toBe(enabled ? 200 : 404);
  return { adminToken: admin, ownerToken: owner };
}

export async function createBookingPage(
  request: APIRequestContext,
  ownerToken: string,
  page: BookingPageFixture,
): Promise<BookingPageFixture & { id: string }> {
  const response = await request.put('/api/booking/pages', {
    headers: {
      Authorization: `Bearer ${ownerToken}`,
      'Content-Type': 'application/json',
    },
    data: page,
  });
  expect(response.status()).toBe(200);
  const body = await response.json() as { id?: string };
  expect(body.id).toMatch(/^[1-9][0-9]*$/);
  return { ...page, id: body.id! };
}

/** Product API teardown: owner DELETE, never a raw table delete. */
export async function deleteBookingPage(
  request: APIRequestContext,
  ownerToken: string,
  id: string,
): Promise<void> {
  const response = await request.delete(`/api/booking/pages?id=${encodeURIComponent(id)}`, {
    headers: { Authorization: `Bearer ${ownerToken}` },
  });
  expect(response.status()).toBe(200);
}

export function slotWindow(): { from: string; to: string } {
  const start = new Date();
  const end = new Date(start);
  end.setUTCDate(end.getUTCDate() + 6);
  return { from: start.toISOString().slice(0, 10), to: end.toISOString().slice(0, 10) };
}

export async function listBookingSlots(
  request: APIRequestContext,
  slug: string,
): Promise<BookingSlotFixture[]> {
  const { from, to } = slotWindow();
  const response = await request.get(
    `/api/public/booking/${encodeURIComponent(slug)}/slots?from=${from}&to=${to}`,
  );
  expect(response.status()).toBe(200);
  return await response.json() as BookingSlotFixture[];
}

/** Wait for an open slot without a fixed delay; all-day availability should converge quickly. */
export async function firstBookingSlot(
  request: APIRequestContext,
  slug: string,
): Promise<BookingSlotFixture> {
  let slots: BookingSlotFixture[] = [];
  await expect.poll(async () => {
    slots = await listBookingSlots(request, slug);
    return slots.length;
  }, {
    timeout: 15_000,
    intervals: [100, 250, 500, 1000],
  }).toBeGreaterThan(0);
  return slots[0];
}

function sql(value: string): string {
  return value.replaceAll("'", "''");
}

/**
 * Arrange a pending request through the authoritative reducer so confirm E2E
 * can use a known token without reading a private outbound email artifact.
 */
export function arrangePendingBooking(args: {
  slug: string;
  start: string;
  email: string;
  name: string;
  verifyToken: string;
}): void {
  const result = psql(`
    SELECT booking_create(
      '${sql(args.slug)}',
      '${sql(args.start)}',
      '${sql(args.email)}',
      '${sql(args.name)}',
      '{}'::jsonb,
      encode(sha256('${sql(args.verifyToken)}'::bytea), 'hex'),
      NULL
    )
  `);
  expect(result).not.toBe('');
}

export function bookingRequestCount(slug: string, email: string): number {
  return Number(psql(`
    SELECT count(*)
      FROM booking_requests r
      JOIN booking_pages p ON p.id = r.page_id
     WHERE p.slug = '${sql(slug)}'
       AND r.booker_email = '${sql(email)}'
  `));
}

export function bookingRequestStatus(slug: string, email: string): string {
  return psql(`
    SELECT r.status
      FROM booking_requests r
      JOIN booking_pages p ON p.id = r.page_id
     WHERE p.slug = '${sql(slug)}'
       AND r.booker_email = '${sql(email)}'
     ORDER BY r.created_at DESC
     LIMIT 1
  `);
}

export { BASE };
