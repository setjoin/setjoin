import { writable, derived } from 'svelte/store';
import {
	calendarGet,
	calendarEventSet,
	calendarEventImport,
	calendarEventRsvp,
	calendarEventCounter,
	calendarEventQueryFreeSlots,
	identityGet,
	loadSession,
	calendarGetShared,
	calendarEventGetShared,
	calendarShareGet,
	calendarShareSet,
	calendarDelegateList,
	calendarEventSetOccurrence,
	calendarEventResourceList,
	calendarEventSendUpdate,
	calendarEventRsvpOnBehalf
} from '$lib/jmap/client';
import { calendarEvents } from '$lib/stores/calendarEvents.svelte';
import type {
	Calendar,
	CalendarEvent,
	FreeSlot,
	JmapMethodResponse,
	Identity,
	CalendarShare,
	CalendarResource,
	Delegation,
	CalendarShareLevel
} from '$lib/types/jmap';

export type ViewMode = 'month' | 'week' | 'workweek' | 'day' | 'agenda';

export const calendars = writable<Calendar[]>([]);
// The events bag lives in CalendarEventsStore (stores/calendarEvents.svelte.ts) —
// a $state rune class consumed directly by CalendarApp and, via the
// CalendarActionHost seam, by CalendarActionStore.
export const selectedDate = writable<Date>(new Date());
export const selectedCalendarIds = writable<string[]>([]);
export const viewMode = writable<ViewMode>('month');
export const identities = writable<Identity[]>([]);

export const visibleCalendars = derived(
	[calendars, selectedCalendarIds],
	([$calendars, $selectedCalendarIds]) => {
		if ($selectedCalendarIds.length === 0) return $calendars;
		return $calendars.filter((c) => $selectedCalendarIds.includes(c.id));
	}
);

export const visibleCalendarIds = derived(visibleCalendars, ($cals) => $cals.map((c) => c.id));

export async function loadCalendars(): Promise<void> {
	await loadSession();
	const list = await calendarGet();
	calendars.set(list || []);
	if (list && list.length > 0) {
		const stored =
			typeof localStorage !== 'undefined' ? localStorage.getItem('selected_calendar_ids') : null;
		if (stored) {
			selectedCalendarIds.set(JSON.parse(stored) as string[]);
		} else {
			selectedCalendarIds.set(list.map((c) => c.id));
		}
	}
}

export function reset() {
	calendars.set([]);
	calendarEvents.reset();
	selectedDate.set(new Date());
	selectedCalendarIds.set([]);
	viewMode.set('month');
	identities.set([]);
	sharedOwners.set([]);
}

export async function loadIdentities(): Promise<void> {
	await loadSession();
	try {
		const idents = await identityGet();
		identities.set(idents || []);
	} catch {
		identities.set([]);
	}
}

/** Throw when a CalendarEvent/set item-level failure comes back in an otherwise-200
 *  response. Without this the editor closed as if saved while the server had
 *  rejected the event (notCreated) — a silent data-loss path. */
function assertSetApplied(result: JmapMethodResponse, key: 'notCreated' | 'notUpdated' | 'notDestroyed'): JmapMethodResponse {
	const failures = result[key] as Record<string, { description?: string; type?: string }> | undefined;
	const first = failures && Object.values(failures)[0];
	if (first) throw new Error(first.description || first.type || 'The calendar rejected the change');
	return result;
}

export async function createEvent(
	eventData: Partial<CalendarEvent>
): Promise<JmapMethodResponse> {
	await loadSession();
	const result = await calendarEventSet({ k1: eventData as CalendarEvent }, null, null);
	return assertSetApplied(result, 'notCreated');
}

export async function updateEvent(
	id: string,
	patch: Partial<CalendarEvent>
): Promise<JmapMethodResponse> {
	await loadSession();
	const result = await calendarEventSet(null, { [id]: patch }, null);
	return assertSetApplied(result, 'notUpdated');
}

export async function deleteEvent(id: string): Promise<JmapMethodResponse> {
	await loadSession();
	const result = await calendarEventSet(null, null, [id]);
	return assertSetApplied(result, 'notDestroyed');
}

// Import a .ics file into one owned calendar. Ownership + conflict handling live in
// the calendar_import_ics reducer; the client only ships the raw file text.
export async function importEvents(
	calendarId: string,
	ics: string,
	strategy: 'skip' | 'overwrite' | 'rename'
): Promise<{ imported: number; skipped: number }> {
	await loadSession();
	return await calendarEventImport(calendarId, ics, strategy);
}

export async function rsvpEvent(id: string, status: string): Promise<JmapMethodResponse> {
	await loadSession();
	const result = await calendarEventRsvp(id, status);
	return result;
}

// Propose a new time to the organizer (iTIP COUNTER). start/end are ISO strings.
export async function proposeNewTime(
	id: string,
	start: string,
	end: string
): Promise<JmapMethodResponse> {
	await loadSession();
	return await calendarEventCounter(id, start, end);
}

export async function findFreeSlots(params: {
	userIds: string[];
	start: string;
	end: string;
	durationMinutes?: number;
	slotIntervalMinutes?: number;
	workingStartTime?: string;
	workingEndTime?: string;
	maxSlots?: number;
}): Promise<FreeSlot[]> {
	await loadSession();
	const result = await calendarEventQueryFreeSlots(params);
	return (result.list as FreeSlot[]) ?? [];
}

// ── A3: sharing, shared reads, occurrence edit, delegate, rooms, send update ──

// Tracks which owner emails the user has opened shared calendars for, so refreshes can
// re-merge their events alongside the user's own.
export const sharedOwners = writable<string[]>([]);

export async function shareCalendar(
	calendarId: string,
	userEmail: string,
	level: CalendarShareLevel
): Promise<void> {
	await loadSession();
	await calendarShareSet(calendarId, [{ userEmail, level }], []);
}

export async function revokeShare(calendarId: string, userEmail: string): Promise<void> {
	await loadSession();
	await calendarShareSet(calendarId, [], [{ userEmail }]);
}

export async function loadShares(calendarId: string): Promise<CalendarShare[]> {
	await loadSession();
	const res = await calendarShareGet(calendarId);
	return (res.list as CalendarShare[]) ?? [];
}

// openSharedCalendar fetches another user's calendars + events by OWNER EMAIL only — the
// viewer is always the authenticated user server-side; we never pass a viewer id. The
// returned calendars/events are merged into the stores tagged read-only.
export async function openSharedCalendar(ownerEmail: string): Promise<Calendar[]> {
	await loadSession();
	const sharedCals = await calendarGetShared(ownerEmail);
	const sharedEvents = await calendarEventGetShared(ownerEmail);

	if (sharedCals.length > 0) {
		calendars.update((cs) => {
			const existing = new Set(cs.map((c) => c.id));
			const merged = sharedCals
				.filter((c) => !existing.has(c.id))
				.map((c) => ({ ...c, isShared: true, isReadOnly: true }));
			return [...cs, ...merged];
		});
		calendarEvents.mergeShared(sharedEvents);
		sharedOwners.update((owners) =>
			owners.includes(ownerEmail) ? owners : [...owners, ownerEmail]
		);
	}
	return sharedCals;
}

export async function listDelegations(): Promise<Delegation[]> {
	await loadSession();
	const res = await calendarDelegateList();
	return (res.list as Delegation[]) ?? [];
}

export async function rsvpOnBehalf(
	eventId: string,
	status: string,
	onBehalfOf: string
): Promise<JmapMethodResponse> {
	await loadSession();
	return await calendarEventRsvpOnBehalf(eventId, status, onBehalfOf);
}

export async function updateOccurrence(
	masterId: string,
	recurrenceId: string,
	scope: 'this' | 'following' | 'series',
	patch: Record<string, unknown>
): Promise<JmapMethodResponse> {
	await loadSession();
	return await calendarEventSetOccurrence(masterId, recurrenceId, scope, patch);
}

export async function listResources(): Promise<CalendarResource[]> {
	await loadSession();
	const res = await calendarEventResourceList();
	return (res.list as CalendarResource[]) ?? [];
}

export async function sendMeetingUpdate(eventId: string): Promise<JmapMethodResponse> {
	await loadSession();
	return await calendarEventSendUpdate(eventId);
}

export function toggleCalendarVisibility(calendarId: string): void {
	selectedCalendarIds.update((ids) => {
		if (ids.includes(calendarId)) {
			ids = ids.filter((id) => id !== calendarId);
		} else {
			ids = [...ids, calendarId];
		}
		if (typeof localStorage !== 'undefined') {
			localStorage.setItem('selected_calendar_ids', JSON.stringify(ids));
		}
		return ids;
	});
}

export function getViewRange(date: Date, mode: ViewMode): { start: Date; end: Date } {
	const d = new Date(date);
	switch (mode) {
		case 'month': {
			const start = new Date(d.getFullYear(), d.getMonth(), 1);
			start.setDate(start.getDate() - start.getDay());
			const end = new Date(start);
			end.setDate(end.getDate() + 42);
			return { start, end };
		}
		case 'week': {
			const start = new Date(d);
			start.setDate(start.getDate() - start.getDay());
			start.setHours(0, 0, 0, 0);
			const end = new Date(start);
			end.setDate(end.getDate() + 7);
			return { start, end };
		}
		case 'workweek': {
			// Monday-start, Mon–Fri. (getDay()+6)%7 maps Sun→6 (prior Monday), Mon→0, …
			const start = new Date(d);
			start.setDate(start.getDate() - ((start.getDay() + 6) % 7));
			start.setHours(0, 0, 0, 0);
			const end = new Date(start);
			end.setDate(end.getDate() + 5);
			return { start, end };
		}
		case 'day': {
			const start = new Date(d);
			start.setHours(0, 0, 0, 0);
			const end = new Date(start);
			end.setDate(end.getDate() + 1);
			return { start, end };
		}
		case 'agenda': {
			const start = new Date(d);
			start.setHours(0, 0, 0, 0);
			const end = new Date(start);
			end.setDate(end.getDate() + 30);
			return { start, end };
		}
		default:
			return getViewRange(d, 'month');
	}
}
