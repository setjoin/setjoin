import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { CalendarEvent } from '$lib/types/jmap';

// ── stores/calendar pass-through mocks (assertSetApplied's throwing contract is
//    tested in calendar.test.ts; here they are plain spies) ──
const createEvent = vi.fn();
const updateEvent = vi.fn();
const deleteEvent = vi.fn();
const rsvpEvent = vi.fn();
const updateOccurrence = vi.fn();

vi.mock('$lib/stores/calendar', () => ({
	createEvent: (...a: unknown[]) => createEvent(...a),
	updateEvent: (...a: unknown[]) => updateEvent(...a),
	deleteEvent: (...a: unknown[]) => deleteEvent(...a),
	rsvpEvent: (...a: unknown[]) => rsvpEvent(...a),
	updateOccurrence: (...a: unknown[]) => updateOccurrence(...a),
}));

import { CalendarActionStore, type DragSnapshot } from './calendarActionStore.svelte';

// ── Fixtures ──
function ev(id: string, overrides: Partial<CalendarEvent> = {}): CalendarEvent {
	return {
		id,
		calendarId: 'cal1',
		title: id,
		start: '2026-07-06T09:00:00.000Z',
		end: '2026-07-06T10:00:00.000Z',
		...overrides,
	};
}

/**
 * A minimal CalendarEventsStore-like host. CalendarActionStore reads/writes
 * through this seam so the view binds the real events store and the test binds
 * a plain object (mirrors emailActionStore's ActionHost testing shape).
 */
function makeHost() {
	return {
		reload: vi.fn().mockResolvedValue(undefined),
		patchEventTimes: vi.fn(),
	};
}

/** A snapshot of the PRE-drag times (T0) distinct from any moved instant. */
const SNAP: DragSnapshot = {
	id: 'e1',
	start: '2026-07-06T09:00:00.000Z',
	end: '2026-07-06T10:00:00.000Z',
};
/** The drag's moved times (T1) — must never be used as the recurrence-id. */
const MOVED = { start: '2026-07-07T14:00:00.000Z', end: '2026-07-07T15:00:00.000Z' };

beforeEach(() => {
	createEvent.mockReset().mockResolvedValue({});
	updateEvent.mockReset().mockResolvedValue({});
	deleteEvent.mockReset().mockResolvedValue({});
	rsvpEvent.mockReset().mockResolvedValue({});
	updateOccurrence.mockReset().mockResolvedValue({});
});

describe('CalendarActionStore.dispatch — create / update', () => {
	it('create passes eventData through and reloads', async () => {
		const host = makeHost();
		const store = new CalendarActionStore(host);

		const res = await store.dispatch({ type: 'create', eventData: { title: 'Standup' } });

		expect(res).toBeNull();
		expect(createEvent).toHaveBeenCalledWith({ title: 'Standup' });
		expect(host.reload).toHaveBeenCalled();
		expect(store.saving).toBe(false);
	});

	it("create returns the new event's id (calendar's own created.k1 wire shape, not {id}) — Meet B1 Task 16's calendar hook needs it", async () => {
		createEvent.mockResolvedValue({ created: { k1: '4242' } });
		const host = makeHost();
		const store = new CalendarActionStore(host);

		const res = await store.dispatch({ type: 'create', eventData: { title: 'Standup' } });

		expect(res).toBe('4242');
	});

	it('update passes id + eventData through and reloads', async () => {
		const host = makeHost();
		const store = new CalendarActionStore(host);

		await store.dispatch({ type: 'update', id: 'e1', eventData: { title: 'Moved' } });

		expect(updateEvent).toHaveBeenCalledWith('e1', { title: 'Moved' });
		expect(host.reload).toHaveBeenCalled();
	});

	it('Task 12: editing a detached-occurrence override row (no recurrenceRule) commits directly, no scope dialog', async () => {
		// Same 'update' dispatch a plain event uses — the store's update path
		// never inspects recurrenceRule (that decision is CalendarApp's saveEvent,
		// which only calls requestScope for editingEvent.recurrenceRule truthy;
		// an override row's recurrenceRule is always null/absent). Pinned here so
		// a future store change can't silently route override edits through the
		// scope dialog.
		const host = makeHost();
		const store = new CalendarActionStore(host);

		await store.dispatch({ type: 'update', id: 'ov1', eventData: { title: 'Moved just this once' } });

		expect(updateEvent).toHaveBeenCalledWith('ov1', { title: 'Moved just this once' });
		expect(updateOccurrence).not.toHaveBeenCalled();
		expect(store.scopePending).toBeNull();
	});

	it('a rejected create rethrows (the view owns the banner), skips reload, and resets saving', async () => {
		createEvent.mockRejectedValueOnce(new Error('notCreated: invalidArguments'));
		const host = makeHost();
		const store = new CalendarActionStore(host);

		await expect(store.dispatch({ type: 'create', eventData: {} })).rejects.toThrow('notCreated');
		expect(host.reload).not.toHaveBeenCalled();
		expect(store.saving).toBe(false);

		// The store is usable again after the failure.
		await store.dispatch({ type: 'create', eventData: { title: 'retry' } });
		expect(createEvent).toHaveBeenCalledTimes(2);
	});
});

describe('CalendarActionStore — re-entrancy (invariant d: one `saving` guard spans save AND applyScope)', () => {
	it('a second create dispatched while one is in flight is a no-op', async () => {
		let release!: () => void;
		createEvent.mockImplementationOnce(
			() => new Promise<void>((resolve) => { release = () => resolve(); }),
		);
		const host = makeHost();
		const store = new CalendarActionStore(host);

		const first = store.dispatch({ type: 'create', eventData: { title: 'a' } });
		expect(store.saving).toBe(true);
		const second = await store.dispatch({ type: 'create', eventData: { title: 'b' } });

		expect(second).toBeNull();
		expect(createEvent).toHaveBeenCalledTimes(1); // the no-op never reached the network
		release();
		await first;
		expect(store.saving).toBe(false);
	});

	it('applyScope while a save is in flight is a no-op (shared guard, not a second flag)', async () => {
		let release!: () => void;
		updateEvent.mockImplementationOnce(
			() => new Promise<void>((resolve) => { release = () => resolve(); }),
		);
		const host = makeHost();
		const store = new CalendarActionStore(host);
		store.requestScope(ev('e1', { recurrenceRule: 'FREQ=DAILY' }));

		const save = store.dispatch({ type: 'update', id: 'e2', eventData: {} });
		const scoped = await store.dispatch({ type: 'applyScope', scope: 'this', eventData: () => ({}) });

		expect(scoped).toBeNull();
		expect(updateOccurrence).not.toHaveBeenCalled();
		release();
		await save;
	});
});

describe('CalendarActionStore.dispatch — delete', () => {
	it('deletes and reloads; a second delete during flight is a no-op', async () => {
		let release!: () => void;
		deleteEvent.mockImplementationOnce(
			() => new Promise<void>((resolve) => { release = () => resolve(); }),
		);
		const host = makeHost();
		const store = new CalendarActionStore(host);

		const first = store.dispatch({ type: 'delete', event: ev('e1') });
		expect(store.deleting).toBe(true);
		await store.dispatch({ type: 'delete', event: ev('e1') });
		expect(deleteEvent).toHaveBeenCalledTimes(1);

		release();
		await first;
		expect(store.deleting).toBe(false);
		expect(host.reload).toHaveBeenCalledTimes(1);
	});

	it('deleting a non-recurring override row deletes just that row directly (Task 12 — no scope dialog)', async () => {
		const host = makeHost();
		const store = new CalendarActionStore(host);

		const res = await store.dispatch({ type: 'delete', event: ev('e1', { recurrenceRule: null }) });

		expect(res).toBeNull();
		expect(deleteEvent).toHaveBeenCalledWith('e1');
		expect(store.scopePending).toBeNull();
		expect(host.reload).toHaveBeenCalled();
	});

	it('delete of a recurring event requires scope (Task 11) instead of deleting directly', async () => {
		const host = makeHost();
		const store = new CalendarActionStore(host);
		const recurring = ev('rec1', { recurrenceRule: 'FREQ=WEEKLY' });

		const res = await store.dispatch({ type: 'delete', event: recurring });

		expect(res).toEqual({ scopeRequired: true });
		expect(deleteEvent).not.toHaveBeenCalled();
		expect(store.scopePending).toEqual({ event: recurring, intent: 'delete', dragPatch: null, snapshot: null });
	});

	it("applyScope('this') after a recurring delete excludes just that occurrence", async () => {
		const host = makeHost();
		const store = new CalendarActionStore(host);
		const recurring = ev('rec1', { recurrenceRule: 'FREQ=WEEKLY' });
		await store.dispatch({ type: 'delete', event: recurring });

		await store.dispatch({ type: 'applyScope', scope: 'this', eventData: () => ({}) });

		expect(updateOccurrence).toHaveBeenCalledWith(recurring.id, recurring.start, 'this', { excluded: true });
		expect(deleteEvent).not.toHaveBeenCalled();
		expect(store.scopePending).toBeNull();
		expect(host.reload).toHaveBeenCalled();
	});

	it("applyScope('following') after a recurring delete excludes this-and-following", async () => {
		const host = makeHost();
		const store = new CalendarActionStore(host);
		const recurring = ev('rec1', { recurrenceRule: 'FREQ=WEEKLY' });
		await store.dispatch({ type: 'delete', event: recurring });

		await store.dispatch({ type: 'applyScope', scope: 'following', eventData: () => ({}) });

		expect(updateOccurrence).toHaveBeenCalledWith(recurring.id, recurring.start, 'following', { excluded: true });
	});

	it("applyScope('series') after a recurring delete calls deleteEvent for the whole series", async () => {
		const host = makeHost();
		const store = new CalendarActionStore(host);
		const recurring = ev('rec1', { recurrenceRule: 'FREQ=WEEKLY' });
		await store.dispatch({ type: 'delete', event: recurring });

		await store.dispatch({ type: 'applyScope', scope: 'series', eventData: () => ({}) });

		expect(deleteEvent).toHaveBeenCalledWith('rec1');
		expect(updateOccurrence).not.toHaveBeenCalled();
	});
});

describe('CalendarActionStore.dispatch — rsvp', () => {
	it('holds the in-flight status for the busy button, RSVPs, and reloads', async () => {
		let release!: () => void;
		rsvpEvent.mockImplementationOnce(
			() => new Promise<void>((resolve) => { release = () => resolve(); }),
		);
		const host = makeHost();
		const store = new CalendarActionStore(host);

		const p = store.dispatch({ type: 'rsvp', id: 'e1', status: 'accepted' });
		expect(store.responding).toBe('accepted');
		// A second RSVP while one is in flight is a no-op.
		await store.dispatch({ type: 'rsvp', id: 'e1', status: 'declined' });
		expect(rsvpEvent).toHaveBeenCalledTimes(1);

		release();
		await p;
		expect(rsvpEvent).toHaveBeenCalledWith('e1', 'accepted');
		expect(store.responding).toBeNull();
		expect(host.reload).toHaveBeenCalled();
	});
});

describe('CalendarActionStore.dispatch — dragCommit', () => {
	it('commits a plain event drag without reloading (the optimistic move already matches)', async () => {
		const host = makeHost();
		const store = new CalendarActionStore(host);

		const res = await store.dispatch({
			type: 'dragCommit',
			event: ev('e1', MOVED),
			patch: { ...MOVED },
			snapshot: SNAP,
		});

		expect(res).toBeNull();
		expect(updateEvent).toHaveBeenCalledWith('e1', { ...MOVED });
		expect(host.reload).not.toHaveBeenCalled();
	});

	it('INVARIANT (a) rollback 1/3: a failed drag commit restores the pre-drag snapshot and rethrows', async () => {
		updateEvent.mockRejectedValueOnce(new Error('boom'));
		const host = makeHost();
		const store = new CalendarActionStore(host);

		await expect(
			store.dispatch({ type: 'dragCommit', event: ev('e1', MOVED), patch: { ...MOVED }, snapshot: SNAP }),
		).rejects.toThrow('boom');

		expect(host.patchEventTimes).toHaveBeenCalledWith(SNAP.id, SNAP.start, SNAP.end);
	});

	it('a recurring event is NOT committed: the drag is stashed and the view is told to ask scope', async () => {
		const host = makeHost();
		const store = new CalendarActionStore(host);
		const recurring = ev('e1', { ...MOVED, recurrenceRule: 'FREQ=WEEKLY' });

		const res = await store.dispatch({
			type: 'dragCommit',
			event: recurring,
			patch: { ...MOVED },
			snapshot: SNAP,
		});

		expect(res).toEqual({ scopeRequired: true });
		expect(updateEvent).not.toHaveBeenCalled();
		expect(store.scopePending).toEqual({ event: recurring, intent: 'edit', dragPatch: { ...MOVED }, snapshot: SNAP });
	});
});

describe('CalendarActionStore.dispatch — applyScope', () => {
	it('INVARIANT (b): dragging a recurring occurrence keys updateOccurrence by the PRE-DRAG start (snap.start), never the moved instant', async () => {
		const host = makeHost();
		const store = new CalendarActionStore(host);
		// The grid's event already carries the MOVED (optimistic) times.
		const recurring = ev('e1', { ...MOVED, recurrenceRule: 'FREQ=WEEKLY' });
		await store.dispatch({ type: 'dragCommit', event: recurring, patch: { ...MOVED }, snapshot: SNAP });

		await store.dispatch({ type: 'applyScope', scope: 'this', eventData: () => ({ title: 'form' }) });

		expect(updateOccurrence).toHaveBeenCalledWith(
			'e1',
			SNAP.start, // the pre-drag instant — NOT MOVED.start, NOT recurring.start
			'this',
			{ ...MOVED }, // and the payload is the drag patch, not the form data
		);
		expect(updateOccurrence.mock.calls[0][1]).not.toBe(MOVED.start);
		expect(store.scopePending).toBeNull();
		expect(host.reload).toHaveBeenCalled();
	});

	it("INVARIANT (c): the drag entry never evaluates the view's form builder (dragPatch ?? eventData())", async () => {
		const host = makeHost();
		const store = new CalendarActionStore(host);
		await store.dispatch({
			type: 'dragCommit',
			event: ev('e1', { recurrenceRule: 'FREQ=DAILY' }),
			patch: { ...MOVED },
			snapshot: SNAP,
		});
		const buildEventData = vi.fn(() => ({ title: 'form' }));

		await store.dispatch({ type: 'applyScope', scope: 'series', eventData: buildEventData });

		// On a fresh mount the editor form may never have been opened — building it
		// would throw on empty dates, so the thunk must be short-circuited by the patch.
		expect(buildEventData).not.toHaveBeenCalled();
		expect(updateEvent).toHaveBeenCalledWith('e1', { ...MOVED });
	});

	it("'series' from a drag updates the whole series with the drag patch", async () => {
		const host = makeHost();
		const store = new CalendarActionStore(host);
		await store.dispatch({
			type: 'dragCommit',
			event: ev('e1', { recurrenceRule: 'FREQ=DAILY' }),
			patch: { ...MOVED },
			snapshot: SNAP,
		});

		await store.dispatch({ type: 'applyScope', scope: 'series', eventData: () => ({}) });

		expect(updateEvent).toHaveBeenCalledWith('e1', { ...MOVED });
		expect(updateOccurrence).not.toHaveBeenCalled();
	});

	it("'following' passes the scope through to updateOccurrence", async () => {
		const host = makeHost();
		const store = new CalendarActionStore(host);
		await store.dispatch({
			type: 'dragCommit',
			event: ev('e1', { recurrenceRule: 'FREQ=DAILY' }),
			patch: { ...MOVED },
			snapshot: SNAP,
		});

		await store.dispatch({ type: 'applyScope', scope: 'following', eventData: () => ({}) });

		expect(updateOccurrence).toHaveBeenCalledWith('e1', SNAP.start, 'following', { ...MOVED });
	});

	it('the edit-form entry uses the form-built eventData and keys by the event start', async () => {
		const host = makeHost();
		const store = new CalendarActionStore(host);
		const recurring = ev('e1', { recurrenceRule: 'FREQ=DAILY' });
		store.requestScope(recurring); // recurring EDIT-FORM save — no drag context

		await store.dispatch({
			type: 'applyScope',
			scope: 'this',
			eventData: () => ({ title: 'Edited title' }),
		});

		expect(updateOccurrence).toHaveBeenCalledWith('e1', recurring.start, 'this', { title: 'Edited title' });
	});

	it('INVARIANT (a) rollback 2/3: a rejected scope-apply for a dragged occurrence restores the pre-drag times and rethrows', async () => {
		updateOccurrence.mockRejectedValueOnce(new Error('rejected'));
		const host = makeHost();
		const store = new CalendarActionStore(host);
		await store.dispatch({
			type: 'dragCommit',
			event: ev('e1', { ...MOVED, recurrenceRule: 'FREQ=WEEKLY' }),
			patch: { ...MOVED },
			snapshot: SNAP,
		});

		await expect(
			store.dispatch({ type: 'applyScope', scope: 'this', eventData: () => ({}) }),
		).rejects.toThrow('rejected');

		expect(host.patchEventTimes).toHaveBeenCalledWith(SNAP.id, SNAP.start, SNAP.end);
		expect(store.scopePending).toBeNull();
		expect(store.saving).toBe(false);
		expect(host.reload).not.toHaveBeenCalled();
	});

	it('a rejected scope-apply from the edit-form entry does NOT patch the grid (nothing was dragged)', async () => {
		updateOccurrence.mockRejectedValueOnce(new Error('rejected'));
		const host = makeHost();
		const store = new CalendarActionStore(host);
		store.requestScope(ev('e1', { recurrenceRule: 'FREQ=DAILY' }));

		await expect(
			store.dispatch({ type: 'applyScope', scope: 'this', eventData: () => ({ title: 'x' }) }),
		).rejects.toThrow('rejected');

		expect(host.patchEventTimes).not.toHaveBeenCalled();
	});

	it('applyScope without a pending scope is a no-op', async () => {
		const host = makeHost();
		const store = new CalendarActionStore(host);

		const res = await store.dispatch({ type: 'applyScope', scope: 'series', eventData: () => ({}) });

		expect(res).toBeNull();
		expect(updateEvent).not.toHaveBeenCalled();
		expect(updateOccurrence).not.toHaveBeenCalled();
	});
});

describe('CalendarActionStore.dispatch — cancelScope', () => {
	it('INVARIANT (a) rollback 3/3: dismissing the scope dialog after a drag restores the pre-drag times', async () => {
		const host = makeHost();
		const store = new CalendarActionStore(host);
		await store.dispatch({
			type: 'dragCommit',
			event: ev('e1', { ...MOVED, recurrenceRule: 'FREQ=WEEKLY' }),
			patch: { ...MOVED },
			snapshot: SNAP,
		});

		await store.dispatch({ type: 'cancelScope' });

		expect(host.patchEventTimes).toHaveBeenCalledWith(SNAP.id, SNAP.start, SNAP.end);
		expect(store.scopePending).toBeNull();
	});

	it('dismissing the scope dialog from the edit-form entry clears the pending scope without touching the grid', async () => {
		const host = makeHost();
		const store = new CalendarActionStore(host);
		store.requestScope(ev('e1', { recurrenceRule: 'FREQ=DAILY' }));

		await store.dispatch({ type: 'cancelScope' });

		expect(host.patchEventTimes).not.toHaveBeenCalled();
		expect(store.scopePending).toBeNull();
	});
});
