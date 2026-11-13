// Booking pages owner-CRUD client — the /api/booking/pages surface (feature
// #6, feature.booking_pages). Mirrors sharing.ts's fetch style (httpRequest
// seam; auth cookie automatic). The gateway resolves the caller's own
// primary mailbox server-side — we never send an id.
//
// Toggle-off (or any other admin-disabled state) reaches the client as a bare
// 404, same as every route on this API — callers check for that explicitly
// (see BookingSettingsError / isBookingFeatureOff) rather than treating it as
// a generic load failure.

import { httpRequest } from '$lib/http';
import { problemDetail } from '$lib/errors';

export interface BookingQuestion {
	id: string;
	label: string;
	required: boolean;
}

export interface BookingAvailabilityWindow {
	dow: number; // 0=Sun..6=Sat
	start: string; // "HH:MM", page-local time
	end: string;
}

export interface BookingPage {
	id?: string;
	slug: string;
	title: string;
	description: string;
	durationMinutes: number;
	bufferMinutes: number;
	maxPerDay: number;
	minNoticeMinutes: number;
	maxAdvanceDays: number;
	availability: BookingAvailabilityWindow[];
	questions: BookingQuestion[];
	timezone: string;
	enabled: boolean;
}

export class BookingFeatureOffError extends Error {}

// httpRequest always re-throws onError's returned string wrapped in a plain
// Error (see http.ts) — it has no seam for a custom error class — so the
// sentinel is caught here and re-thrown as the typed BookingFeatureOffError
// the settings page branches on.
const FEATURE_OFF_SENTINEL = '__booking_feature_off__';

async function bookingError(r: Response): Promise<string> {
	if (r.status === 404) {
		// Could be "feature off" OR "page not found" — both are the same bare
		// 404 shape by design (enumeration parity). The settings page treats
		// any 404 on the LIST call as feature-off; a 404 on upsert/delete of a
		// page the user just saw in their own list is effectively unreachable.
		return FEATURE_OFF_SENTINEL;
	}
	return problemDetail(r, `Booking request failed (${r.status})`);
}

async function mapFeatureOff<T>(run: () => Promise<T>): Promise<T> {
	try {
		return await run();
	} catch (e) {
		if (e instanceof Error && e.message === FEATURE_OFF_SENTINEL) {
			throw new BookingFeatureOffError('Booking pages are disabled');
		}
		throw e;
	}
}

// Response-shape guard for listBookingPages: the gateway is same-origin and
// first-party, but this boundary validates the JSON instead of a blind cast so
// a regressed response surfaces as a calm request error, never as undefined
// field access downstream (stores/UI read these fields directly).
function isBookingAvailability(v: unknown): v is BookingAvailabilityWindow {
	if (typeof v !== 'object' || v === null) return false;
	const a = v as Partial<BookingAvailabilityWindow>;
	return (
		typeof a.dow === 'number' &&
		typeof a.start === 'string' &&
		typeof a.end === 'string'
	);
}

function isBookingQuestion(v: unknown): v is BookingQuestion {
	if (typeof v !== 'object' || v === null) return false;
	const q = v as Partial<BookingQuestion>;
	return typeof q.id === 'string' && typeof q.label === 'string' && typeof q.required === 'boolean';
}

function isBookingPage(v: unknown): v is BookingPage {
	if (typeof v !== 'object' || v === null) return false;
	const p = v as Partial<BookingPage>;
	return (
		typeof p.slug === 'string' &&
		typeof p.title === 'string' &&
		typeof p.description === 'string' &&
		typeof p.durationMinutes === 'number' &&
		typeof p.bufferMinutes === 'number' &&
		typeof p.maxPerDay === 'number' &&
		typeof p.minNoticeMinutes === 'number' &&
		typeof p.maxAdvanceDays === 'number' &&
		Array.isArray(p.availability) &&
		p.availability.every(isBookingAvailability) &&
		Array.isArray(p.questions) &&
		p.questions.every(isBookingQuestion) &&
		typeof p.timezone === 'string' &&
		typeof p.enabled === 'boolean'
	);
}

function parseBookingPages(body: unknown): BookingPage[] {
	if (!Array.isArray(body) || !body.every(isBookingPage)) {
		// Calm, non-leaking message — mirrors httpRequest's "authored messages
		// are display-safe" assumption (never echo the raw body).
		throw new Error('Booking request failed (unexpected response)');
	}
	return body;
}

export async function listBookingPages(signal?: AbortSignal): Promise<BookingPage[]> {
	return mapFeatureOff(async () => {
		const res = await httpRequest('/api/booking/pages', { method: 'GET', signal, onError: bookingError });
		return parseBookingPages(await res.json());
	});
}

export async function upsertBookingPage(page: Partial<BookingPage> & { slug: string; title: string }): Promise<{ id: string }> {
	return mapFeatureOff(async () => {
		const res = await httpRequest('/api/booking/pages', {
			method: 'PUT',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(page),
			onError: bookingError
		});
		return (await res.json()) as { id: string };
	});
}

export async function deleteBookingPage(id: string): Promise<void> {
	await mapFeatureOff(async () => {
		await httpRequest(`/api/booking/pages?id=${encodeURIComponent(id)}`, {
			method: 'DELETE',
			onError: bookingError
		});
	});
}
