// CalendarActionStore — the calendar's mutation/intent seam (Svelte 5 $state rune class).
//
// Mirrors EmailActionStore (the inbox's proven mutation store): a typed
// `CalendarAction` union behind one async `dispatch(action)`. CalendarApp keeps
// presentation, drag geometry, modal/toast copy, and form state; every event
// mutation (create/update/delete, RSVP, drag-commit, occurrence-scope) routes
// through here. Errors are RETHROWN so the view owns the error banner.
//
// SCOPE: rollback-on-failure only — EmailActionStore's Snapshot/undo-toast
// contract is deliberately NOT copied (no undo surface for calendar mutations).
//
// Reactive event state lives in the CalendarEventsStore, reached through the
// small `CalendarActionHost` interface (mirroring ActionHost) so the two stores
// stay decoupled and this store is unit-testable against a plain host object.

import {
	createEvent,
	updateEvent,
	deleteEvent,
	rsvpEvent,
	updateOccurrence
} from '$lib/stores/calendar';
import type { CalendarEvent } from '$lib/types/jmap';

/** The slice of CalendarEventsStore this store needs (mirrors the inbox ActionHost). */
export interface CalendarActionHost {
	/** Re-run the current view-range load after a committed mutation. */
	reload(): Promise<void>;
	/** Patch one event's times in the visible grid (the three drag rollback paths). */
	patchEventTimes(id: string, start: string, end: string): void;
}

/** Pre-drag times captured at drag start — the rollback AND recurrence-id source. */
export interface DragSnapshot {
	id: string;
	start: string;
	end: string;
}

export type ApplyScope = 'this' | 'following' | 'series';

/**
 * The typed calendar mutation union.
 *
 * `applyScope.eventData` is a THUNK, not a value: the store resolves
 * `dragPatch ?? eventData()` lazily, exactly like the component's old
 * `dragPatch ?? buildEventData()` — on the drag entry path the editor form may
 * never have been opened (empty dates would throw in the builder), so the form
 * builder must only run on the edit-form entry path.
 */
export type CalendarAction =
	| { type: 'create'; eventData: Partial<CalendarEvent> }
	| { type: 'update'; id: string; eventData: Partial<CalendarEvent> }
	| { type: 'delete'; event: CalendarEvent }
	| { type: 'rsvp'; id: string; status: string }
	| { type: 'dragCommit'; event: CalendarEvent; patch: Partial<CalendarEvent>; snapshot: DragSnapshot }
	| { type: 'applyScope'; scope: ApplyScope; eventData: () => Partial<CalendarEvent> }
	| { type: 'cancelScope' };

/** `dragCommit`/`delete` on a recurring event answer this; the view opens the scope dialog.
 *  `create` answers with the new event's id (Meet B1 Task 16's calendar hook needs it to
 *  bind a just-created meeting via calendarEventId) — every OTHER action's return is
 *  unaffected (a plain string was never a valid result for them before). */
export type CalendarDispatchResult = { scopeRequired: true } | string | null;

/** Pending occurrence-vs-series context (a recurring drag, edit-form save, or delete). */
interface ScopePending {
	event: CalendarEvent;
	/** Which action the chosen scope finishes — drives the applyScope branch + dialog copy. */
	intent: 'edit' | 'delete';
	/** Set only on the drag entry path — wins over the form-built eventData. */
	dragPatch: Partial<CalendarEvent> | null;
	/** Pre-drag times; null on the edit-form entry path. */
	snapshot: DragSnapshot | null;
}

export class CalendarActionStore {
	#host: CalendarActionHost;

	// INVARIANT (d) — re-entrancy boundary: `saving` is the store-owned guard and
	// spans BOTH the editor save (create/update) AND applyScope, exactly like the
	// component's single `saving` flag did — a second dispatch while one is in
	// flight is a no-op (today's behavior; nothing is queued). `justDragged`
	// (click-suppression after a real drag) is deliberately NOT here: it belongs
	// to the view/drag boundary and stays in CalendarApp.svelte.
	saving = $state(false);
	deleting = $state(false);
	/** RSVP in flight — holds the status string so the view can label the busy button. */
	responding = $state<string | null>(null);

	/** Pending occurrence-vs-series context; non-null while the scope dialog is relevant. */
	scopePending = $state<ScopePending | null>(null);

	constructor(host: CalendarActionHost) {
		this.#host = host;
	}

	/**
	 * Perform a calendar mutation. `dragCommit` on a recurring event returns
	 * `{ scopeRequired: true }` (the view opens the occurrence-vs-series dialog);
	 * everything else resolves `null`. Errors are rethrown so the view owns the
	 * error banner.
	 */
	async dispatch(action: CalendarAction): Promise<CalendarDispatchResult> {
		switch (action.type) {
			case 'create':
				return this.create(action.eventData);
			case 'update':
				return this.update(action.id, action.eventData);
			case 'delete':
				return this.deleteAction(action.event);
			case 'rsvp':
				return this.rsvp(action.id, action.status);
			case 'dragCommit':
				return this.dragCommit(action.event, action.patch, action.snapshot);
			case 'applyScope':
				return this.applyScope(action.scope, action.eventData);
			case 'cancelScope':
				return this.cancelScope();
		}
	}

	/**
	 * Stash the event a recurring EDIT-FORM save must scope (no drag context).
	 * The view opens the occurrence-vs-series dialog and later dispatches
	 * `applyScope` (with its form-built eventData) or `cancelScope`.
	 */
	requestScope(event: CalendarEvent): void {
		this.scopePending = { event, intent: 'edit', dragPatch: null, snapshot: null };
	}

	// ── Individual mutations ──

	private async create(eventData: Partial<CalendarEvent>): Promise<string | null> {
		if (this.saving) return null; // re-entrancy no-op — INVARIANT (d)
		this.saving = true;
		try {
			// INVARIANT (e): createEvent/updateEvent/deleteEvent (stores/calendar.ts)
			// THROW on a notCreated/notUpdated/notDestroyed item-level failure inside
			// an otherwise-200 response (assertSetApplied). The throw propagates out
			// of dispatch so the view shows the banner and keeps the editor open —
			// never a silent close over rejected data.
			const res = await createEvent(eventData);
			await this.#host.reload();
			// jmap_calendar_event_set_create's own wire shape: `created.k1` is the
			// raw id STRING (unlike mail/contacts/tasks' `{id: string}` — this repo's
			// generic JmapMethodResponse.created type doesn't fit calendar exactly).
			return (res?.created as unknown as Record<string, string> | undefined)?.k1 ?? null;
		} finally {
			this.saving = false;
		}
	}

	private async update(id: string, eventData: Partial<CalendarEvent>): Promise<null> {
		if (this.saving) return null; // re-entrancy no-op — INVARIANT (d)
		this.saving = true;
		try {
			// INVARIANT (e): notUpdated → throw → banner + editor stays open (see create).
			await updateEvent(id, eventData);
			await this.#host.reload();
			return null;
		} finally {
			this.saving = false;
		}
	}

	/**
	 * Delete a non-recurring event directly. A recurring event's delete is NOT
	 * committed here: like a recurring drag, the choice is stashed
	 * (intent: 'delete') and the view is told to ask occurrence-vs-series —
	 * an override row (no recurrenceRule) deletes just that one row directly.
	 */
	private async deleteAction(event: CalendarEvent): Promise<CalendarDispatchResult> {
		if (event.recurrenceRule) {
			this.scopePending = { event, intent: 'delete', dragPatch: null, snapshot: null };
			return { scopeRequired: true };
		}
		if (this.deleting) return null;
		this.deleting = true;
		try {
			// INVARIANT (e): notDestroyed → throw → banner + dialog stays open (see create).
			await deleteEvent(event.id);
			await this.#host.reload();
			return null;
		} finally {
			this.deleting = false;
		}
	}

	private async rsvp(id: string, status: string): Promise<null> {
		if (this.responding) return null;
		this.responding = status;
		try {
			await rsvpEvent(id, status);
			await this.#host.reload();
			return null;
		} finally {
			this.responding = null;
		}
	}

	/**
	 * Commit a finished drag (move/resize). A recurring event is NOT committed
	 * here: its patch + pre-drag snapshot are stashed and the view is told to ask
	 * occurrence-vs-series. A plain event commits directly; success does NOT
	 * reload (the optimistic move already matches the server).
	 */
	private async dragCommit(
		event: CalendarEvent,
		patch: Partial<CalendarEvent>,
		snapshot: DragSnapshot
	): Promise<CalendarDispatchResult> {
		if (event.recurrenceRule) {
			this.scopePending = { event, intent: 'edit', dragPatch: patch, snapshot };
			return { scopeRequired: true };
		}
		try {
			await updateEvent(event.id, patch);
		} catch (e) {
			// INVARIANT (a) — drag rollback path 1 of 3: a failed drag commit restores
			// the pre-drag times (dragSnapshot) so the visible grid isn't silently
			// corrupted until the next refresh. Rethrown: the view owns the banner.
			this.#host.patchEventTimes(snapshot.id, snapshot.start, snapshot.end);
			throw e;
		}
		return null;
	}

	private async applyScope(scope: ApplyScope, eventData: () => Partial<CalendarEvent>): Promise<null> {
		const pending = this.scopePending;
		if (!pending || this.saving) return null; // shared `saving` guard — INVARIANT (d)
		this.saving = true;
		const dragPatch = pending.dragPatch;
		const snap = pending.snapshot;
		try {
			if (pending.intent === 'delete') {
				// Delete-intent: 'this'/'following' exclude the occurrence (no patch —
				// {excluded:true}); 'series' destroys the whole series (the same
				// orphan-free destroy jmap_calendar_event_set_destroy performs).
				if (scope === 'series') {
					await deleteEvent(pending.event.id);
				} else {
					await updateOccurrence(pending.event.id, pending.event.start, scope, { excluded: true });
				}
			} else {
				// INVARIANT (c) — dual scope-dialog entry: a drag commit stashed its
				// {start,end} patch and it wins; otherwise the eventData the VIEW built
				// from its form is evaluated (`dragPatch ?? buildEventData()` semantics —
				// the store takes eventData as a parameter and never reads the form).
				const data = dragPatch ?? eventData();
				if (scope === 'series') {
					await updateEvent(pending.event.id, data);
				} else {
					// INVARIANT (b) — recurrence-id semantics: 'this'/'following' edits key
					// the occurrence by its ORIGINAL start instant — for a drag that is the
					// PRE-DRAG start (snap.start), NEVER the moved instant already painted
					// into the grid's event.
					await updateOccurrence(
						pending.event.id,
						dragPatch && snap ? snap.start : pending.event.start,
						scope,
						data as Record<string, unknown>
					);
				}
			}
			this.scopePending = null;
			await this.#host.reload();
			return null;
		} catch (e) {
			// INVARIANT (a) — drag rollback path 2 of 3: a rejected scope-apply for a
			// dragged occurrence restores the pre-drag times. Rethrown for the banner.
			if (dragPatch && snap) {
				this.#host.patchEventTimes(snap.id, snap.start, snap.end);
			}
			this.scopePending = null;
			throw e;
		} finally {
			this.saving = false;
		}
	}

	private cancelScope(): null {
		const pending = this.scopePending;
		this.scopePending = null;
		if (pending?.dragPatch && pending.snapshot) {
			// INVARIANT (a) — drag rollback path 3 of 3: dismissing the recurring-scope
			// dialog cancels the drag, restoring the pre-drag times.
			const s = pending.snapshot;
			this.#host.patchEventTimes(s.id, s.start, s.end);
		}
		return null;
	}
}
