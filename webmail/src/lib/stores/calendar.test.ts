import { describe, it, expect, vi, beforeEach } from 'vitest';
import { get } from 'svelte/store';

// Mock the JMAP client so the store actions can be asserted against the right helpers.
vi.mock('$lib/jmap/client', () => ({
	loadSession: vi.fn(async () => ({})),
	calendarGet: vi.fn(async () => []),
	calendarEventQuery: vi.fn(async () => []),
	calendarEventGet: vi.fn(async () => []),
	calendarEventSet: vi.fn(async () => ({})),
	calendarEventRsvp: vi.fn(async () => ({})),
	calendarEventCounter: vi.fn(async () => ({})),
	calendarEventQueryFreeSlots: vi.fn(async () => ({ list: [] })),
	identityGet: vi.fn(async () => []),
	// A3 helpers:
	calendarGetShared: vi.fn(async () => [{ id: 'c9', name: 'Alice', isShared: true, isReadOnly: true }]),
	calendarEventGetShared: vi.fn(async () => [{ id: 'e9', calendarId: 'c9', start: '2026-06-15T10:00:00Z', title: 'Busy' }]),
	calendarShareGet: vi.fn(async () => ({ list: [{ userEmail: 'bob@x.test', level: 'read' }] })),
	calendarShareSet: vi.fn(async () => ({ ok: true })),
	calendarDelegateList: vi.fn(async () => ({ list: [{ email: 'm@x.test', name: 'Manager', permission: 'full_access' }] })),
	calendarEventSetOccurrence: vi.fn(async () => ({ ok: true })),
	calendarEventResourceList: vi.fn(async () => ({ list: [{ id: 'r1', name: 'Room', resourceType: 'room', capacity: 8, bookingPolicy: 'auto-accept' }] })),
	calendarEventSendUpdate: vi.fn(async () => ({ sequence: 1 })),
	calendarEventRsvpOnBehalf: vi.fn(async () => ({}))
}));

import * as client from '$lib/jmap/client';
import {
	shareCalendar,
	revokeShare,
	loadShares,
	openSharedCalendar,
	listDelegations,
	rsvpOnBehalf,
	proposeNewTime,
	updateOccurrence,
	listResources,
	sendMeetingUpdate,
	calendars,
	reset
} from './calendar';
import { calendarEvents } from './calendarEvents.svelte';

describe('calendar store — A3 actions', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		reset();
	});

	it('shareCalendar calls calendarShareSet with a grant and no revokes', async () => {
		await shareCalendar('cal1', 'bob@x.test', 'write');
		expect(client.calendarShareSet).toHaveBeenCalledWith(
			'cal1',
			[{ userEmail: 'bob@x.test', level: 'write' }],
			[]
		);
	});

	it('revokeShare calls calendarShareSet with a revoke and no grants', async () => {
		await revokeShare('cal1', 'bob@x.test');
		expect(client.calendarShareSet).toHaveBeenCalledWith('cal1', [], [{ userEmail: 'bob@x.test' }]);
	});

	it('loadShares calls calendarShareGet and returns the list', async () => {
		const shares = await loadShares('cal1');
		expect(client.calendarShareGet).toHaveBeenCalledWith('cal1');
		expect(shares).toEqual([{ userEmail: 'bob@x.test', level: 'read' }]);
	});

	it('openSharedCalendar passes ownerEmail (never a viewer id) and merges read-only calendars', async () => {
		await openSharedCalendar('alice@x.test');
		expect(client.calendarGetShared).toHaveBeenCalledWith('alice@x.test');
		expect(client.calendarEventGetShared).toHaveBeenCalledWith('alice@x.test');
		// The returned shared calendar is merged into the store, tagged read-only.
		const cals = get(calendars);
		expect(cals.some((c) => c.id === 'c9' && c.isReadOnly)).toBe(true);
		expect(calendarEvents.events.some((e) => e.id === 'e9' && e.isReadOnly)).toBe(true);
	});

	it('listDelegations calls calendarDelegateList and returns the list', async () => {
		const dels = await listDelegations();
		expect(client.calendarDelegateList).toHaveBeenCalled();
		expect(dels[0].email).toBe('m@x.test');
	});

	it('rsvpOnBehalf passes onBehalfOf through to the client', async () => {
		await rsvpOnBehalf('evt1', 'accepted', 'm@x.test');
		expect(client.calendarEventRsvpOnBehalf).toHaveBeenCalledWith('evt1', 'accepted', 'm@x.test');
	});

	it('proposeNewTime passes the proposed start/end through to CalendarEvent/counter', async () => {
		await proposeNewTime('evt1', '2026-07-02T10:00:00Z', '2026-07-02T10:30:00Z');
		expect(client.calendarEventCounter).toHaveBeenCalledWith(
			'evt1',
			'2026-07-02T10:00:00Z',
			'2026-07-02T10:30:00Z'
		);
	});

	it('updateOccurrence passes the scope through', async () => {
		await updateOccurrence('master1', '2026-06-22T09:00:00Z', 'this', { title: 'Moved' });
		expect(client.calendarEventSetOccurrence).toHaveBeenCalledWith(
			'master1',
			'2026-06-22T09:00:00Z',
			'this',
			{ title: 'Moved' }
		);
	});

	it('listResources calls calendarEventResourceList and returns the rooms', async () => {
		const rooms = await listResources();
		expect(client.calendarEventResourceList).toHaveBeenCalled();
		expect(rooms[0].id).toBe('r1');
	});

	it('sendMeetingUpdate calls calendarEventSendUpdate with the eventId', async () => {
		await sendMeetingUpdate('evt1');
		expect(client.calendarEventSendUpdate).toHaveBeenCalledWith('evt1');
	});
});
