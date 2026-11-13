// Public (unauthenticated) booking client — /api/public/booking/*. The FIRST
// unauth app surface: no session/JMAP fetch ever happens from these pages, so
// every call here passes loginRedirect: null (there is no login to redirect
// to on this surface, and there never should be a 401 from it).

import { httpRequest } from '$lib/http';
import { problemDetail } from '$lib/errors';

export interface PublicBookingQuestion {
	id: string;
	label: string;
	required: boolean;
}

export interface PublicBookingMeta {
	slug: string;
	title: string;
	description: string;
	durationMinutes: number;
	timezone: string;
	questions: PublicBookingQuestion[];
	ownerName: string;
}

export interface BookingSlot {
	start: string; // ISO instant
	end: string;
}

export class BookingNotFoundError extends Error {}
export class BookingSlotGoneError extends Error {}
export class BookingTokenInvalidError extends Error {}

const NOT_FOUND = '__booking_not_found__';
const SLOT_GONE = '__booking_slot_gone__';
const TOKEN_INVALID = '__booking_token_invalid__';

async function publicBookingError(r: Response): Promise<string> {
	if (r.status === 404) return NOT_FOUND;
	if (r.status === 409) return SLOT_GONE; // slot taken / no-longer-valid token, disambiguated by caller
	return problemDetail(r, `Request failed (${r.status})`);
}

async function mapSentinels<T>(run: () => Promise<T>, tokenMode = false): Promise<T> {
	try {
		return await run();
	} catch (e) {
		if (e instanceof Error) {
			if (e.message === NOT_FOUND) throw new BookingNotFoundError();
			if (e.message === SLOT_GONE) throw tokenMode ? new BookingTokenInvalidError() : new BookingSlotGoneError();
		}
		throw e;
	}
}

export async function getBookingPage(slug: string): Promise<PublicBookingMeta> {
	return mapSentinels(async () => {
		const res = await httpRequest(`/api/public/booking/${encodeURIComponent(slug)}`, {
			loginRedirect: null,
			onError: publicBookingError
		});
		return (await res.json()) as PublicBookingMeta;
	});
}

export async function getBookingSlots(slug: string, from: string, to: string): Promise<BookingSlot[]> {
	return mapSentinels(async () => {
		const res = await httpRequest(
			// from/to are ISO dates from the in-page calendar window, but they are
			// interpolated into an unauthenticated query string — encode them at
			// this boundary so no value can shape the query (slug already is).
			`/api/public/booking/${encodeURIComponent(slug)}/slots?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`,
			{ loginRedirect: null, onError: publicBookingError }
		);
		return (await res.json()) as BookingSlot[];
	});
}

export interface BookRequest {
	start: string;
	email: string;
	name: string;
	answers: Record<string, string>;
	website: string; // honeypot — always empty from a real browser
}

export async function submitBooking(slug: string, req: BookRequest): Promise<void> {
	await mapSentinels(async () => {
		await httpRequest(`/api/public/booking/${encodeURIComponent(slug)}/book`, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(req),
			loginRedirect: null,
			onError: publicBookingError
		});
	});
}

export interface ConfirmResult {
	ok: boolean;
	cancelToken?: string;
}

export async function confirmBooking(token: string): Promise<ConfirmResult> {
	return mapSentinels(async () => {
		const res = await httpRequest('/api/public/booking/confirm', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ token }),
			loginRedirect: null,
			onError: publicBookingError
		});
		return (await res.json()) as ConfirmResult;
	}, true);
}

export async function cancelBooking(token: string): Promise<void> {
	await mapSentinels(async () => {
		await httpRequest('/api/public/booking/cancel', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ token }),
			loginRedirect: null,
			onError: publicBookingError
		});
	}, true);
}
