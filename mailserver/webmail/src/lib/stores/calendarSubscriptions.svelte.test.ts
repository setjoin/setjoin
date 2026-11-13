import { describe, it, expect, vi, beforeEach } from 'vitest';

const typedFetch = vi.fn();
const httpRequest = vi.fn();

vi.mock('$lib/http', () => ({
	typedFetch: (...a: unknown[]) => typedFetch(...a),
	httpRequest: (...a: unknown[]) => httpRequest(...a)
}));

import { calendarSubscriptions, formatSyncedAgo, type CalendarSubscription } from './calendarSubscriptions.svelte';

function sub(overrides: Partial<CalendarSubscription> = {}): CalendarSubscription {
	return {
		id: 1,
		calendarId: 'cal-sub-1',
		calendarName: 'Team Holidays',
		url: 'https://example.test/feed.ics',
		lastFetchAt: null,
		lastStatus: 'pending',
		lastError: null,
		refreshIntervalMinutes: 15,
		...overrides
	};
}

describe('calendarSubscriptions store', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		calendarSubscriptions.reset();
	});

	it('load() populates subscriptions from GET /api/calendar/subscriptions', async () => {
		typedFetch.mockResolvedValueOnce({ subscriptions: [sub()] });
		await calendarSubscriptions.load();
		expect(typedFetch).toHaveBeenCalledWith('/api/calendar/subscriptions', { loginRedirect: null });
		expect(calendarSubscriptions.subscriptions).toHaveLength(1);
		expect(calendarSubscriptions.loaded).toBe(true);
	});

	it('load() tolerates a null subscriptions field (treats as empty)', async () => {
		typedFetch.mockResolvedValueOnce({ subscriptions: null });
		await calendarSubscriptions.load();
		expect(calendarSubscriptions.subscriptions).toEqual([]);
	});

	it('forCalendar() finds the subscription for a given calendarId', async () => {
		typedFetch.mockResolvedValueOnce({ subscriptions: [sub({ calendarId: 'cal-42' })] });
		await calendarSubscriptions.load();
		expect(calendarSubscriptions.forCalendar('cal-42')?.calendarName).toBe('Team Holidays');
		expect(calendarSubscriptions.forCalendar('cal-99')).toBeUndefined();
	});

	it('subscribe() POSTs the url/name, then reloads the list', async () => {
		typedFetch
			.mockResolvedValueOnce({ id: 7, calendarId: 'cal-7', url: 'https://ex.test/a.ics', status: 'pending' })
			.mockResolvedValueOnce({ subscriptions: [sub({ id: 7, calendarId: 'cal-7' })] });

		const created = await calendarSubscriptions.subscribe('https://ex.test/a.ics', 'Team');

		expect(typedFetch).toHaveBeenNthCalledWith(1, '/api/calendar/subscriptions', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ url: 'https://ex.test/a.ics', name: 'Team' }),
			loginRedirect: null
		});
		expect(created.calendarId).toBe('cal-7');
		expect(calendarSubscriptions.subscriptions).toHaveLength(1);
	});

	it('subscribe() falls back to a synthetic pending row if the reload race misses it', async () => {
		typedFetch
			.mockResolvedValueOnce({ id: 8, calendarId: 'cal-8', url: 'https://ex.test/b.ics', status: 'pending' })
			.mockResolvedValueOnce({ subscriptions: [] }); // reload didn't see it yet

		const created = await calendarSubscriptions.subscribe('https://ex.test/b.ics');
		expect(created).toEqual(
			expect.objectContaining({ id: 8, calendarId: 'cal-8', lastStatus: 'pending' })
		);
	});

	it('unsubscribe() removes optimistically, then DELETEs', async () => {
		typedFetch.mockResolvedValueOnce({ subscriptions: [sub({ id: 3, calendarId: 'cal-3' })] });
		await calendarSubscriptions.load();
		httpRequest.mockResolvedValueOnce({});

		await calendarSubscriptions.unsubscribe(3);

		expect(httpRequest).toHaveBeenCalledWith('/api/calendar/subscriptions/3', {
			method: 'DELETE',
			loginRedirect: null
		});
		expect(calendarSubscriptions.subscriptions).toHaveLength(0);
	});

	it('unsubscribe() rolls back the optimistic removal on failure', async () => {
		typedFetch.mockResolvedValueOnce({ subscriptions: [sub({ id: 4, calendarId: 'cal-4' })] });
		await calendarSubscriptions.load();
		httpRequest.mockRejectedValueOnce(new Error('network error'));

		await expect(calendarSubscriptions.unsubscribe(4)).rejects.toThrow('network error');
		expect(calendarSubscriptions.subscriptions).toHaveLength(1);
	});
});

describe('formatSyncedAgo', () => {
	it('reports "not synced yet" when lastFetchAt is null', () => {
		expect(formatSyncedAgo(null)).toBe('Not synced yet');
	});

	it('reports "just now" for a fetch under a minute old', () => {
		const now = new Date().toISOString();
		expect(formatSyncedAgo(now)).toBe('Updated just now');
	});

	it('reports minutes for a fetch under an hour old', () => {
		const t = new Date(Date.now() - 5 * 60_000).toISOString();
		expect(formatSyncedAgo(t)).toBe('Updated 5m ago');
	});

	it('reports hours for a fetch under a day old', () => {
		const t = new Date(Date.now() - 3 * 3600_000).toISOString();
		expect(formatSyncedAgo(t)).toBe('Updated 3h ago');
	});

	it('reports days for a fetch a day or more old', () => {
		const t = new Date(Date.now() - 2 * 86400_000).toISOString();
		expect(formatSyncedAgo(t)).toBe('Updated 2d ago');
	});
});
