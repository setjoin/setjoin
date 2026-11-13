import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { CalendarEvent } from '$lib/types/jmap';

const calendarEventQuery = vi.fn();
const calendarEventGet = vi.fn();

vi.mock('$lib/jmap/client', () => ({
	calendarEventQuery: (...a: unknown[]) => calendarEventQuery(...a),
	calendarEventGet: (...a: unknown[]) => calendarEventGet(...a),
}));

import { CalendarEventsStore } from './calendarEvents.svelte';

function ev(id: string, overrides: Partial<CalendarEvent> = {}): CalendarEvent {
	return { id, calendarId: 'cal1', title: id, start: '2026-07-06T09:00:00.000Z', ...overrides };
}

const RANGE = { start: new Date('2026-07-01'), end: new Date('2026-08-01') };

beforeEach(() => {
	calendarEventQuery.mockReset().mockResolvedValue(['e1']);
	calendarEventGet.mockReset().mockResolvedValue([ev('e1')]);
});

describe('CalendarEventsStore.load', () => {
	it('queries the range, fetches the ids, and sets events (loading toggles)', async () => {
		const store = new CalendarEventsStore();

		const p = store.load(RANGE.start, RANGE.end);
		expect(store.loading).toBe(true);
		await p;

		expect(calendarEventQuery).toHaveBeenCalledWith(
			{ after: RANGE.start.toISOString(), before: RANGE.end.toISOString() },
			500,
		);
		expect(store.events.map((e) => e.id)).toEqual(['e1']);
		expect(store.loading).toBe(false);
	});

	it('skips the get when the query matches nothing', async () => {
		calendarEventQuery.mockResolvedValueOnce([]);
		const store = new CalendarEventsStore();
		await store.load(RANGE.start, RANGE.end);
		expect(calendarEventGet).not.toHaveBeenCalled();
		expect(store.events).toEqual([]);
	});

	it('monotonic load token: an older load resolving AFTER a newer one never overwrites', async () => {
		// Load A starts first but resolves LAST (e.g. a pre-commit query racing the
		// post-save refresh). Only the newest load may write.
		let releaseA!: (ids: string[]) => void;
		calendarEventQuery
			.mockImplementationOnce(() => new Promise<string[]>((res) => { releaseA = res; }))
			.mockResolvedValueOnce(['fresh']);
		calendarEventGet.mockImplementation(async (ids: string[]) =>
			(ids as string[]).map((id) => ev(id)),
		);
		const store = new CalendarEventsStore();

		const a = store.load(RANGE.start, RANGE.end); // stale load, held open
		const b = store.load(RANGE.start, RANGE.end); // newer load
		await b;
		expect(store.events.map((e) => e.id)).toEqual(['fresh']);

		releaseA(['stale']);
		await a;
		expect(store.events.map((e) => e.id)).toEqual(['fresh']); // stale result dropped
	});

	it('reload re-runs the last load range', async () => {
		const store = new CalendarEventsStore();
		await store.load(RANGE.start, RANGE.end);
		calendarEventQuery.mockClear();

		await store.reload();

		expect(calendarEventQuery).toHaveBeenCalledWith(
			{ after: RANGE.start.toISOString(), before: RANGE.end.toISOString() },
			500,
		);
	});

	it('reload before any load is a no-op', async () => {
		const store = new CalendarEventsStore();
		await store.reload();
		expect(calendarEventQuery).not.toHaveBeenCalled();
	});
});

describe('CalendarEventsStore — patches', () => {
	it('patchEventTimes patches only the target event', () => {
		const store = new CalendarEventsStore();
		store.events = [ev('e1'), ev('e2')];

		store.patchEventTimes('e1', '2026-07-07T10:00:00.000Z', '2026-07-07T11:00:00.000Z');

		expect(store.events[0].start).toBe('2026-07-07T10:00:00.000Z');
		expect(store.events[0].end).toBe('2026-07-07T11:00:00.000Z');
		expect(store.events[1].start).toBe('2026-07-06T09:00:00.000Z');
	});

	it('mergeShared dedupes by id and tags the merged events read-only', () => {
		const store = new CalendarEventsStore();
		store.events = [ev('e1')];

		store.mergeShared([ev('e1', { title: 'dup' }), ev('shared-1')]);

		expect(store.events.map((e) => e.id)).toEqual(['e1', 'shared-1']);
		expect(store.events[0].isReadOnly).toBeUndefined(); // the existing event is untouched
		expect(store.events[1].isReadOnly).toBe(true);
	});

	it('reset clears events and invalidates any in-flight load', async () => {
		let release!: (ids: string[]) => void;
		calendarEventQuery.mockImplementationOnce(
			() => new Promise<string[]>((res) => { release = res; }),
		);
		calendarEventGet.mockImplementation(async (ids: string[]) =>
			(ids as string[]).map((id) => ev(id)),
		);
		const store = new CalendarEventsStore();

		const p = store.load(RANGE.start, RANGE.end);
		store.reset();
		release(['late']);
		await p;

		expect(store.events).toEqual([]); // the cleared bag was not resurrected
	});
});
