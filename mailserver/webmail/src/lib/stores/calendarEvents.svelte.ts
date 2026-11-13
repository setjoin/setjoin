// CalendarEventsStore — the calendar's reactive events bag (Svelte 5 $state rune class).
//
// Replaces the legacy `events` writable in stores/calendar.ts. Owns the loaded
// event window, the loading flag, and the mutation-support patches (optimistic
// drag preview/rollback + shared-calendar merge). Consumed by CalendarApp
// directly and by CalendarActionStore through its `CalendarActionHost` seam
// (mirroring how InboxStore backs EmailActionStore's ActionHost).

import { calendarEventQuery, calendarEventGet } from '$lib/jmap/client';
import type { CalendarEvent } from '$lib/types/jmap';

export class CalendarEventsStore {
	events = $state<CalendarEvent[]>([]);
	loading = $state(false);

	// Monotonic load token: concurrent loads (post-save refresh racing a push-triggered
	// one) can resolve OUT OF ORDER, letting a query that STARTED pre-commit land last
	// and overwrite the store with stale results. Only the newest load may write.
	#loadSeq = 0;
	#lastRange: { start: Date; end: Date } | null = null;

	/** Load the events overlapping [startDate, endDate). Session must be loaded by the caller. */
	async load(startDate: Date, endDate: Date): Promise<void> {
		this.#lastRange = { start: startDate, end: endDate };
		const seq = ++this.#loadSeq;
		this.loading = true;
		try {
			const filter = {
				after: startDate.toISOString(),
				before: endDate.toISOString()
			};
			const ids = await calendarEventQuery(filter, 500);
			const list = ids && ids.length > 0 ? (await calendarEventGet(ids)) || [] : [];
			if (seq !== this.#loadSeq) return; // superseded by a newer load
			this.events = list;
		} finally {
			this.loading = false;
		}
	}

	/** Re-run the last load range (post-mutation refresh; the view owns range changes). */
	async reload(): Promise<void> {
		if (this.#lastRange) await this.load(this.#lastRange.start, this.#lastRange.end);
	}

	/** Patch one event's times in the grid (optimistic drag preview + the drag rollback paths). */
	patchEventTimes(id: string, start: string, end: string): void {
		this.events = this.events.map((x) => (x.id === id ? { ...x, start, end } : x));
	}

	/** Merge another owner's shared events, deduped by id and tagged read-only. */
	mergeShared(shared: CalendarEvent[]): void {
		const existing = new Set(this.events.map((e) => e.id));
		const merged = shared
			.filter((e) => !existing.has(e.id))
			.map((e) => ({ ...e, isReadOnly: true }));
		if (merged.length > 0) this.events = [...this.events, ...merged];
	}

	reset(): void {
		this.#loadSeq++; // invalidate any in-flight load so it can't resurrect cleared events
		this.#lastRange = null;
		this.events = [];
	}
}

// Module singleton — shared by CalendarApp, calendar.ts's openSharedCalendar merge, and reset().
export const calendarEvents = new CalendarEventsStore();
