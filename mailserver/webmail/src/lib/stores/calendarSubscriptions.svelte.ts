// Webcal/ICS calendar subscribe (WAVE-5 #10) — a lazy client cache over
// /api/calendar/subscriptions (GET/POST/DELETE). Import (a one-shot .ics file
// upload, see importEvents in stores/calendar.ts) already ships; this is the
// OTHER path — a live external URL the calendarsync worker refreshes on a
// ~15-minute tick. Subscribing kicks an immediate first fetch server-side, so
// the row starts 'pending' and flips to 'ok'/'partial'/'error' shortly after
// (poll or reload to see it settle — no push in v1, matching the calendar
// push channel's per-event granularity, not a subscription-row concern).

import { typedFetch, httpRequest } from '$lib/http';

export interface CalendarSubscription {
	id: number;
	calendarId: string;
	calendarName: string;
	url: string;
	lastFetchAt: string | null;
	lastStatus: 'pending' | 'ok' | 'partial' | 'error';
	lastError: string | null;
	refreshIntervalMinutes: number;
}

class CalendarSubscriptionsStore {
	subscriptions = $state<CalendarSubscription[]>([]);
	loaded = $state(false);
	#loading: Promise<void> | null = null;

	/** The subscription for a given calendarId, if that calendar is a webcal
	 *  subscription (used to render the Globe icon / "Updated Xh ago" / failure
	 *  dot on its calendar-list row). */
	forCalendar(calendarId: string): CalendarSubscription | undefined {
		return this.subscriptions.find((s) => s.calendarId === calendarId);
	}

	async load(): Promise<void> {
		if (this.#loading) return this.#loading;
		this.#loading = (async () => {
			try {
				const data = await typedFetch<{ subscriptions: CalendarSubscription[] | null }>(
					'/api/calendar/subscriptions',
					{ loginRedirect: null }
				);
				this.subscriptions = data.subscriptions ?? [];
				this.loaded = true;
			} finally {
				this.#loading = null;
			}
		})();
		return this.#loading;
	}

	/** Subscribe to an external webcal/ICS URL. Throws with a message safe to
	 *  show verbatim (the gateway's SSRF-rejection copy is already generic). */
	async subscribe(url: string, name?: string): Promise<CalendarSubscription> {
		const created = await typedFetch<{ id: number; calendarId: string; url: string; status: string }>(
			'/api/calendar/subscriptions',
			{
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ url, name }),
				loginRedirect: null
			}
		);
		await this.load();
		return (
			this.forCalendar(created.calendarId) ?? {
				id: created.id,
				calendarId: created.calendarId,
				calendarName: name || 'Subscribed calendar',
				url: created.url,
				lastFetchAt: null,
				lastStatus: 'pending',
				lastError: null,
				refreshIntervalMinutes: 15
			}
		);
	}

	async unsubscribe(id: number): Promise<void> {
		const prev = this.subscriptions;
		this.subscriptions = this.subscriptions.filter((s) => s.id !== id);
		try {
			await httpRequest(`/api/calendar/subscriptions/${id}`, { method: 'DELETE', loginRedirect: null });
		} catch (e) {
			this.subscriptions = prev;
			throw e;
		}
	}

	reset(): void {
		this.subscriptions = [];
		this.loaded = false;
		this.#loading = null;
	}
}

/** Process-wide singleton — one list per session, shared by CalendarApp. */
export const calendarSubscriptions = new CalendarSubscriptionsStore();

/** "Updated Xh ago" / "Updated just now" copy for a subscription's last_fetch_at.
 *  Pure function so vitest can cover every bucket without mounting the component. */
export function formatSyncedAgo(lastFetchAt: string | null): string {
	if (!lastFetchAt) return 'Not synced yet';
	const ms = Date.now() - new Date(lastFetchAt).getTime();
	if (ms < 0) return 'Updated just now';
	const mins = Math.floor(ms / 60000);
	if (mins < 1) return 'Updated just now';
	if (mins < 60) return `Updated ${mins}m ago`;
	const hours = Math.floor(mins / 60);
	if (hours < 24) return `Updated ${hours}h ago`;
	const days = Math.floor(hours / 24);
	return `Updated ${days}d ago`;
}
