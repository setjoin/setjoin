<svelte:options runes={true} />

<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { goto } from '$app/navigation';

	import { user } from '$lib/stores/auth';
	import PimShell from '$lib/components/PimShell.svelte';
	import { Dialog, Button, IconButton, Input, Select, Textarea, Checkbox, Spinner, EmptyState } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import RecurrenceEditor from '$lib/components/calendar/RecurrenceEditor.svelte';
	import RoomFinder from '$lib/components/calendar/RoomFinder.svelte';
	import ShareCalendarDialog from '$lib/components/calendar/ShareCalendarDialog.svelte';
	import { buildRrule, parseRrule, type RecurrenceParts } from '$lib/calendar/rrule';
	import { safeColor, localDayKey } from '$lib/calendar/format';
	import { printAgenda } from '$lib/calendar/printAgenda';
	import { t, localeCode } from '$lib/i18n';
	import {
		calendars, selectedDate, selectedCalendarIds, viewMode,
		visibleCalendarIds, loadCalendars, toggleCalendarVisibility,
		getViewRange, findFreeSlots, identities, loadIdentities,
		openSharedCalendar, listDelegations, rsvpOnBehalf,
		sendMeetingUpdate, proposeNewTime, importEvents
	} from '$lib/stores/calendar';
	import { calendarEvents as eventsStore } from '$lib/stores/calendarEvents.svelte';
	import { CalendarActionStore } from '$lib/stores/calendarActionStore.svelte';
	import { PushHandlerStore } from '$lib/stores/pushHandler.svelte';
	import { calendarSubscriptions, formatSyncedAgo } from '$lib/stores/calendarSubscriptions.svelte';
	import { tasks as taskStore, loadTasks, priorityColor } from '$lib/stores/tasks';
	import { parseError } from '$lib/errors';
	import type { CalendarEvent, FreeSlot, EventAttendee, Delegation, EventAlarm, Task } from '$lib/types/jmap';
	import { effectiveCaps } from '$lib/stores/session';
	import * as meetApi from '$lib/meet/api';
	import { updateEvent } from '$lib/stores/calendar';

	// "Remind me" presets — minutes before start (or 'none'). buildValarm() turns the
	// selection into an ABSOLUTE trigger client-side so the server stores no relative rule.
	const REMINDER_OPTIONS = ['none', '0', '5', '15', '30', '60', '1440'];
	function reminderLabel(v: string): string {
		switch (v) {
			case 'none': return t('calendar.reminder_none');
			case '0': return t('calendar.reminder_start');
			case '5': return t('calendar.reminder_5m');
			case '15': return t('calendar.reminder_15m');
			case '30': return t('calendar.reminder_30m');
			case '60': return t('calendar.reminder_1h');
			case '1440': return t('calendar.reminder_1d');
			default: return v;
		}
	}
	// Absolute-trigger alerts from the selected offset. Empty array clears any reminder.
	function buildValarm(start: Date, reminder: string): EventAlarm[] {
		if (reminder === 'none') return [];
		const trigger = new Date(start.getTime() - Number(reminder) * 60000);
		return [{ trigger: trigger.toISOString(), action: 'DISPLAY' }];
	}
	// Reverse a stored valarm back to the nearest preset for the edit modal.
	function reminderFromValarm(event: CalendarEvent): string {
		const trig = event.valarm?.[0]?.trigger;
		if (!trig || !event.start) return 'none';
		const mins = Math.round((new Date(event.start).getTime() - new Date(trig).getTime()) / 60000);
		return REMINDER_OPTIONS.includes(String(mins)) ? String(mins) : 'none';
	}

	let error = $state('');
	// Mutation orchestration (create/update/delete, RSVP, drag-commit, occurrence
	// scope — with the saving/deleting/responding flags and the drag rollbacks)
	// lives in CalendarActionStore; this component keeps presentation, drag
	// geometry, dialog copy, and form state. eventsStore is the reactive events bag.
	const actionStore = new CalendarActionStore(eventsStore);
	// Propose-new-time (iTIP COUNTER) dialog
	let showProposeModal = $state(false);
	let proposing = $state(false);
	let proposeError = $state('');
	let proposeStart = $state('');
	let proposeEnd = $state('');
	let showModal = $state(false);
	let modalMode = $state<'create' | 'edit' | 'detail'>('create');
	let editingEvent = $state<CalendarEvent | null>(null);

	let form = $state({
		title: '',
		calendarId: '',
		startDate: '',
		startTime: '09:00',
		endDate: '',
		endTime: '10:00',
		allDay: false,
		location: '',
		description: '',
		recurrence: 'none',
		attendees: '',
		optionalAttendees: '',
		delegatedFrom: '',
		color: '', // '' = inherit the calendar's color
		freeBusyStatus: 'busy', // organizer's own busy status; orthogonal to attendee RSVP
		privacy: 'public', // 'private' hides details from shared viewers (server-side redacted)
		reminder: 'none', // "Remind me" offset (minutes before start, or 'none')
		addMeet: false // Meet B1 Task 16: "Add setjoin Meet" toggle (spec §3.2 calendar hook)
	});

	// Recurrence editor state (composed → form.recurrence on change).
	let recurrenceParts = $state<RecurrenceParts | null>(null);

	// Resource (room) attendees appended via the RoomFinder, kept apart from the
	// comma-separated people field so they round-trip with role:'resource'.
	let resourceAttendees = $state<EventAttendee[]>([]);

	// Working-hours shading + scheduling prefill (webmail-only, localStorage). Parsed to a
	// whole hour once; workEnd<=workStart disables shading (no inverted band).
	const storedWorkStart = localStorage.getItem('sj-cal-work-start') || '09:00';
	const storedWorkEnd = localStorage.getItem('sj-cal-work-end') || '17:00';
	let workStart = $state(storedWorkStart);
	let workEnd = $state(storedWorkEnd);
	function parseHour(hhmm: string, fallback: number): number {
		const m = /^(\d{1,2}):(\d{2})$/.exec(hhmm || '');
		if (!m) return fallback;
		const h = Number(m[1]);
		return h >= 0 && h <= 23 ? h : fallback;
	}
	let workStartHr = $derived(parseHour(workStart, 9));
	let workEndHr = $derived(parseHour(workEnd, 17));
	function isOffHours(h: number): boolean {
		if (workEndHr <= workStartHr) return false; // graceful: no shading on an inverted/empty range
		return h < workStartHr || h >= workEndHr;
	}
	function persistWorkHours() {
		localStorage.setItem('sj-cal-work-start', workStart);
		localStorage.setItem('sj-cal-work-end', workEnd);
	}

	// Second (display-only) time zone. Native IANA list; a bad stored value is dropped so
	// it can never blank the grid (toLocaleString throws on an invalid timeZone).
	const TIMEZONES: string[] = (() => {
		try { return (Intl as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf?.('timeZone') ?? []; }
		catch { return []; }
	})();
	function validTz(tz: string): boolean {
		if (!tz) return false;
		// ponytail: locale literal is fine here — output is discarded, this only probes tz validity.
		try { new Date().toLocaleString('en-US', { timeZone: tz }); return true; }
		catch { return false; }
	}
	let tz2 = $state((() => {
		const stored = localStorage.getItem('sj-cal-tz2') || '';
		return validTz(stored) ? stored : '';
	})());
	function persistTz2() {
		localStorage.setItem('sj-cal-tz2', tz2);
	}
	// Label for hour h of the anchor day in tz2, anchored to a real date so the DST offset
	// is correct. Guarded: an invalid tz yields '' rather than throwing.
	function formatHourTz(day: Date, h: number, tz: string): string {
		try {
			return new Date(day.getFullYear(), day.getMonth(), day.getDate(), h)
				.toLocaleString(localeCode(), { timeZone: tz, hour: 'numeric', hour12: true });
		} catch {
			return '';
		}
	}

	// A3 dialogs.
	let showRoomFinder = $state(false);
	let showShareDialog = $state(false);
	let shareCalendarId = $state('');
	let shareCalendarName = $state('');
	let showOpenSharedDialog = $state(false);
	let openSharedEmail = $state('');
	let openSharedError = $state('');

	// ICS import dialog.
	let showImportDialog = $state(false);
	let importCalendarId = $state('');
	let importStrategy = $state<'skip' | 'overwrite' | 'rename'>('skip');
	let importing = $state(false);
	let importError = $state('');
	let importResult = $state('');
	let importFileEl = $state<HTMLInputElement | null>(null);

	// Webcal/ICS subscribe dialog (WAVE-5 #10) — a live external URL, unlike
	// import's one-shot file upload.
	let showSubscribeDialog = $state(false);
	let subscribeUrl = $state('');
	let subscribeName = $state('');
	let subscribing = $state(false);
	let subscribeError = $state('');

	// Occurrence-vs-series prompt visibility (the pending event/drag context it
	// acts on is actionStore.scopePending).
	let showScopePrompt = $state(false);
	// Edit vs delete copy/styling for the scope dialog — mirrors the pending
	// action's intent (defaults to 'edit' so a stale read before scopePending is
	// set never renders the destructive delete copy).
	let scopeIntent = $derived(actionStore.scopePending?.intent ?? 'edit');

	// Drag-to-reschedule + resize-to-change-duration (timed events, week/day views).
	type DragState = {
		id: string;
		mode: 'move' | 'resize';
		evStart: Date;
		evEnd: Date;
		grabMinute: number;         // pointer's minute-from-midnight at grab
		colEl: HTMLElement;         // the .day-column the drag started in (vertical geometry source)
		captureEl: HTMLElement;     // the .timed-event holding pointer capture (for release)
		pointerId: number;
		moved: boolean;
		startX: number;
		startY: number;
	};
	let drag = $state<DragState | null>(null);
	// INVARIANT (d) — boundary: `justDragged` (swallow the click that trails a real
	// drag) is view/drag-boundary state and stays HERE; the re-entrancy `saving`
	// guard spanning saveEvent AND applyScope lives in CalendarActionStore. The
	// pre-drag dragSnapshot/dragPatch pair lives in actionStore.scopePending.
	let justDragged = false;

	// Delegations the user may respond on behalf of.
	let delegations = $state<Delegation[]>([]);

	const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
	const MONTHS = ['January','February','March','April','May','June','July','August','September','October','November','December'];
	const HOURS = Array.from({length: 24}, (_, i) => i);

	// Scheduling assistant state
	let showSchedulingModal = $state(false);
	let schedulingLoading = $state(false);
	let schedulingError = $state('');
	let schedulingAttendees = $state('');
	let schedulingDuration = $state(30);
	let schedulingWorkStart = $state(storedWorkStart);
	let schedulingWorkEnd = $state(storedWorkEnd);
	let freeSlots = $state<FreeSlot[]>([]);
	let schedulingStartDate = $state('');
	let schedulingEndDate = $state('');

	let mounted = $state(false);
	const push = new PushHandlerStore();

	onMount(async () => {
		try {
			await loadCalendars();
			await loadIdentities();
			calendarSubscriptions.load().catch(() => {}); // best-effort; sidebar just shows nothing subscribed on failure
			try {
				delegations = await listDelegations();
			} catch {
				delegations = [];
			}
			push.register(['Calendar', 'CalendarEvent'], (changes) => {
				const c = changes as Record<string, unknown>;
				if (c && (c.Calendar || c.CalendarEvent)) {
					refreshEvents();
					// Re-fetch subscription status too — a webcal sync (async first
					// fetch, or the worker's periodic tick) pushes on the same
					// calendar channel; this is how "Updated Xh ago" / the failure
					// dot settle without a manual reload (no per-subscription push).
					calendarSubscriptions.load().catch(() => {});
				}
			});
		} catch (e) {
			error = parseError(e).message;
		} finally {
			// Flip mounted last so the $effect performs the single initial
			// event load (and every subsequent date/view change reload).
			mounted = true;
		}
	});

	onDestroy(() => {
		push.teardown();
		// Drop any in-flight drag listeners if we unmount mid-gesture.
		window.removeEventListener('pointermove', onDragMove);
		window.removeEventListener('pointerup', onDragEnd);
	});

	async function refreshEvents() {
		try {
			const range = getViewRange($selectedDate, $viewMode);
			await eventsStore.load(range.start, range.end);
			// QoL #16 — surface task due dates on the calendar grid; reuses the
			// same view-range fetch pattern as events.
			await loadTasks({ afterDue: range.start.toISOString(), beforeDue: range.end.toISOString() });
		} catch (e) {
			error = parseError(e).message;
		}
	}

	$effect(() => {
		void $selectedDate; void $viewMode;
		if (!mounted) return;
		refreshEvents();
	});

	function prevPeriod() {
		const d = new Date($selectedDate);
		if ($viewMode === 'month') d.setMonth(d.getMonth() - 1);
		else if ($viewMode === 'week' || $viewMode === 'workweek') d.setDate(d.getDate() - 7);
		else if ($viewMode === 'day') d.setDate(d.getDate() - 1);
		else if ($viewMode === 'agenda') d.setDate(d.getDate() - 30);
		selectedDate.set(d);
	}

	function nextPeriod() {
		const d = new Date($selectedDate);
		if ($viewMode === 'month') d.setMonth(d.getMonth() + 1);
		else if ($viewMode === 'week' || $viewMode === 'workweek') d.setDate(d.getDate() + 7);
		else if ($viewMode === 'day') d.setDate(d.getDate() + 1);
		else if ($viewMode === 'agenda') d.setDate(d.getDate() + 30);
		selectedDate.set(d);
	}

	function goToday() {
		selectedDate.set(new Date());
	}

	function formatMonthYear(date: Date) {
		return `${MONTHS[date.getMonth()]} ${date.getFullYear()}`;
	}

	function formatDate(d: Date) {
		return d.toLocaleDateString(localeCode(), { month: 'short', day: 'numeric' });
	}

	function formatDateShort(iso: string | undefined) {
		if (!iso) return '';
		return new Date(iso).toLocaleDateString(localeCode(), { month: 'short', day: 'numeric' });
	}

	function formatTime(iso: string | undefined) {
		if (!iso) return '';
		return new Date(iso).toLocaleTimeString(localeCode(), { hour: 'numeric', minute: '2-digit', hour12: true });
	}

	function formatDateFull(iso: string | undefined) {
		if (!iso) return '';
		return new Date(iso).toLocaleDateString(localeCode(), { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' });
	}

	function getMonthGrid() {
		const d = new Date($selectedDate);
		const start = new Date(d.getFullYear(), d.getMonth(), 1);
		start.setDate(start.getDate() - start.getDay());
		const cells = [];
		const today = new Date();
		const month = d.getMonth();
		for (let week = 0; week < 6; week++) {
			for (let day = 0; day < 7; day++) {
				const date = new Date(start);
				date.setDate(start.getDate() + week * 7 + day);
				const dayEvents = eventsStore.events.filter((ev) => {
					if (!$visibleCalendarIds.includes(ev.calendarId)) return false;
					const evStart = new Date(ev.start);
					const evEnd = new Date(ev.end || ev.start);
					const dayStart = new Date(date); dayStart.setHours(0,0,0,0);
					const dayEnd = new Date(date); dayEnd.setHours(23,59,59,999);
					return evStart <= dayEnd && evEnd >= dayStart;
				});
				const dayKey = localDayKey(date);
				cells.push({
					date,
					dayNum: date.getDate(),
					isCurrentMonth: date.getMonth() === month,
					isToday: date.toDateString() === today.toDateString(),
					events: dayEvents,
					tasks: tasksByDay.get(dayKey) || []
				});
			}
		}
		return cells;
	}

	function getWeekDays() {
		const d = new Date($selectedDate);
		const start = new Date(d);
		const workweek = $viewMode === 'workweek';
		// Work Week starts Monday (Mon–Fri, 5 cols); Week starts Sunday (7 cols).
		start.setDate(start.getDate() - (workweek ? (start.getDay() + 6) % 7 : start.getDay()));
		const days = [];
		const today = new Date();
		const count = workweek ? 5 : 7;
		for (let i = 0; i < count; i++) {
			const date = new Date(start);
			date.setDate(start.getDate() + i);
			const dayEvents = eventsStore.events.filter((ev) => {
				if (!$visibleCalendarIds.includes(ev.calendarId)) return false;
				const evStart = new Date(ev.start);
				const evEnd = new Date(ev.end || ev.start);
				const dayStart = new Date(date); dayStart.setHours(0,0,0,0);
				const dayEnd = new Date(date); dayEnd.setHours(23,59,59,999);
				return evStart <= dayEnd && evEnd >= dayStart;
			});
			days.push({
				date,
				isToday: date.toDateString() === today.toDateString(),
				events: dayEvents
			});
		}
		return days;
	}

	const eventMap = $derived.by(() => {
		const map = new Map<string, any[]>();
		for (const evt of eventsStore.events) {
			if (!evt.start) continue;
			const day = localDayKey(new Date(evt.start));
			const list = map.get(day) || [];
			list.push(evt);
			map.set(day, list);
		}
		return map;
	});

	// QoL #16 — tasks bucketed by due-date day. Done/cancelled tasks are hidden
	// from the grid (matches Outlook/To-Do: completed items don't clutter the calendar).
	const tasksByDay = $derived.by(() => {
		const map = new Map<string, Task[]>();
		for (const task of $taskStore) {
			if (!task.dueAt) continue;
			if (task.status === 'completed' || task.status === 'cancelled') continue;
			const day = localDayKey(new Date(task.dueAt));
			const list = map.get(day) || [];
			list.push(task);
			map.set(day, list);
		}
		return map;
	});

	function getEventsForDay(date: Date) {
		const dateStr = localDayKey(date);
		return (eventMap.get(dateStr) || []).filter((ev) => $visibleCalendarIds.includes(ev.calendarId));
	}

	function eventTopMinutes(iso: string) {
		const d = new Date(iso);
		return d.getHours() * 60 + d.getMinutes();
	}

	function eventDuration(startIso: string, endIso: string | undefined) {
		const s = new Date(startIso);
		const e = new Date(endIso || startIso);
		return Math.max(30, (e.getTime() - s.getTime()) / 60000);
	}

	function getCalendarColor(calendarId: string) {
		const cal = $calendars.find((c) => c.id === calendarId);
		return safeColor(cal?.color);
	}

	// Per-event color when set (guarded — it's user/shared-calendar-controlled),
	// else the calendar's color. safeColor keeps only #hex, exactly like cal color.
	function eventColor(ev: CalendarEvent): string {
		return ev.color ? safeColor(ev.color) : getCalendarColor(ev.calendarId);
	}

	// Swatch the editor's <input type="color"> shows: the event's own color, else
	// the calendar's. The native input needs a valid #hex (it coerces anything
	// else to #000000), so fall back to a default when the cal color is a token.
	let editorColor = $derived.by(() => {
		if (form.color) return form.color;
		const c = getCalendarColor(form.calendarId);
		return c.startsWith('#') ? c : '#5b8def';
	});

	/**
	 * Return '#000' or '#fff' that achieves >= 4.5:1 contrast against the given
	 * calendar background. Accepts 3- or 6-digit hex ('#abc' / '#aabbcc') or any
	 * other value (falls back to '#fff' so pure CSS token refs stay white).
	 */
	function contrastColor(bg: string): '#000' | '#fff' {
		const hex = bg.replace('#', '');
		let r: number, g: number, b: number;
		if (hex.length === 3) {
			r = parseInt(hex[0] + hex[0], 16);
			g = parseInt(hex[1] + hex[1], 16);
			b = parseInt(hex[2] + hex[2], 16);
		} else if (hex.length === 6) {
			r = parseInt(hex.slice(0, 2), 16);
			g = parseInt(hex.slice(2, 4), 16);
			b = parseInt(hex.slice(4, 6), 16);
		} else {
			// CSS var() or unparseable — keep white (design-system palette colors are dark enough)
			return '#fff';
		}
		// Relative luminance per WCAG 2.1
		const toLinear = (c: number) => { const s = c / 255; return s <= 0.04045 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4); };
		const L = 0.2126 * toLinear(r) + 0.7152 * toLinear(g) + 0.0722 * toLinear(b);
		// White on bg: (1+0.05)/(L+0.05); Black on bg: (L+0.05)/(0+0.05)
		const onWhite = 1.05 / (L + 0.05);
		const onBlack = (L + 0.05) / 0.05;
		return onWhite >= onBlack ? '#fff' : '#000';
	}

	// Display label for an attendee's role in the detail list. 'required'/undefined is the
	// implicit default and gets no chip; optional/resource/organizer are surfaced.
	function attendeeRoleLabel(role: string | undefined): string {
		switch (role) {
			case 'optional': return t('calendar.role_optional');
			case 'resource': return t('calendar.role_resource');
			case 'organizer': return t('calendar.role_organizer');
			default: return '';
		}
	}

	function openCreateModal(date: Date | null, hour: number | null) {
		modalMode = 'create';
		editingEvent = null;
		const d = date ? new Date(date) : new Date($selectedDate);
		if (hour !== null && hour !== undefined) {
			d.setHours(hour, 0, 0, 0);
			const end = new Date(d);
			end.setHours(hour + 1, 0, 0, 0);
			form = {
				title: '',
				calendarId: $calendars[0]?.id || '',
				startDate: d.toISOString().slice(0, 10),
				startTime: d.toTimeString().slice(0, 5),
				endDate: end.toISOString().slice(0, 10),
				endTime: end.toTimeString().slice(0, 5),
				allDay: false,
				location: '',
				description: '',
				recurrence: 'none',
				attendees: '',
				optionalAttendees: '',
				delegatedFrom: '',
				color: '',
				freeBusyStatus: 'busy',
				privacy: 'public',
				reminder: 'none',
				addMeet: false
			};
		} else {
			form = {
				title: '',
				calendarId: $calendars[0]?.id || '',
				startDate: d.toISOString().slice(0, 10),
				startTime: '09:00',
				endDate: d.toISOString().slice(0, 10),
				endTime: '10:00',
				allDay: false,
				location: '',
				description: '',
				recurrence: 'none',
				attendees: '',
				optionalAttendees: '',
				delegatedFrom: '',
				color: '',
				freeBusyStatus: 'busy',
				privacy: 'public',
				reminder: 'none',
				addMeet: false
			};
		}
		recurrenceParts = null;
		resourceAttendees = [];
		showModal = true;
	}

	function openEditModal(event: CalendarEvent) {
		modalMode = 'edit';
		editingEvent = event;
		const start = new Date(event.start);
		const end = new Date(event.end || event.start);
		form = {
			title: event.title || '',
			calendarId: event.calendarId || '',
			startDate: start.toISOString().slice(0, 10),
			startTime: event.isAllDay ? '09:00' : start.toTimeString().slice(0, 5),
			endDate: end.toISOString().slice(0, 10),
			endTime: event.isAllDay ? '10:00' : end.toTimeString().slice(0, 5),
			allDay: event.isAllDay || false,
			location: event.location || '',
			description: event.description || '',
			recurrence: event.recurrenceRule || 'none',
			attendees: event.attendees?.filter((a) => a.role !== 'resource' && a.role !== 'optional').map((a) => a.email).join(', ') || '',
			optionalAttendees: event.attendees?.filter((a) => a.role === 'optional').map((a) => a.email).join(', ') || '',
			delegatedFrom: '',
			color: event.color || '',
			freeBusyStatus: event.freeBusyStatus || 'busy',
			privacy: event.privacy || 'public',
			reminder: reminderFromValarm(event),
			addMeet: event.isMeeting ?? false
		};
		recurrenceParts = parseRrule(event.recurrenceRule);
		resourceAttendees = (event.attendees || []).filter((a) => a.role === 'resource');
		showModal = true;
	}

	function openDetailModal(event: CalendarEvent) {
		modalMode = 'detail';
		editingEvent = event;
		showModal = true;
	}

	function closeModal() {
		showModal = false;
		editingEvent = null;
	}

	// ── Drag-to-reschedule + resize-to-change-duration ──────────────────────────
	// Timed events in the week/day grids move by dragging and change duration via a
	// bottom resize handle. All-day + read-only events (event or owning calendar) are
	// not draggable. Pointer→time maps with the same fraction-of-column-height ×1440
	// the render uses, so the drag tracks the paint. Move/up run on window listeners
	// (added on pointerdown) so a cross-column move that re-parents the DOM node — or a
	// column emptying mid-drag — never strands the gesture.

	function isEventReadOnly(ev: CalendarEvent): boolean {
		if (ev.isReadOnly) return true;
		return !!$calendars.find((c) => c.id === ev.calendarId)?.isReadOnly;
	}

	function colMinute(colEl: HTMLElement, clientY: number): number {
		const r = colEl.getBoundingClientRect();
		return ((clientY - r.top) / r.height) * 1440;
	}

	// Snap an instant to the nearest 15 minutes (minute-of-day overflow rolls the date).
	function snap15(ms: number): Date {
		const d = new Date(ms);
		const snapped = Math.round((d.getHours() * 60 + d.getMinutes()) / 15) * 15;
		d.setHours(0, snapped, 0, 0);
		return d;
	}

	function startDrag(e: PointerEvent, ev: CalendarEvent, mode: 'move' | 'resize') {
		if (ev.isAllDay || isEventReadOnly(ev)) return;
		const el = e.currentTarget as HTMLElement;
		const colEl = el.closest('.day-column') as HTMLElement | null;
		const btn = el.closest('.timed-event') as HTMLElement | null;
		if (!colEl || !btn) return;
		justDragged = false;
		try { btn.setPointerCapture(e.pointerId); } catch { /* touch/older browsers */ }
		drag = {
			id: ev.id, mode,
			evStart: new Date(ev.start),
			evEnd: new Date(ev.end || ev.start),
			grabMinute: colMinute(colEl, e.clientY),
			colEl, captureEl: btn, pointerId: e.pointerId,
			moved: false, startX: e.clientX, startY: e.clientY
		};
		window.addEventListener('pointermove', onDragMove, { passive: false });
		window.addEventListener('pointerup', onDragEnd);
	}

	function onDragMove(e: PointerEvent) {
		const d = drag;
		if (!d) return;
		if (!d.moved) {
			if (Math.hypot(e.clientX - d.startX, e.clientY - d.startY) < 4) return;
			d.moved = true;
		}
		e.preventDefault();
		// Columns are equal-height flex siblings, so d.colEl's rect gives the vertical
		// mapping for any column the pointer is over; only the day (X) can change.
		const pointerMinute = colMinute(d.colEl, e.clientY);
		let newStart: Date;
		let newEnd: Date;
		if (d.mode === 'resize') {
			newStart = d.evStart;
			const dayBase = new Date(d.evStart); dayBase.setHours(0, 0, 0, 0);
			newEnd = snap15(dayBase.getTime() + pointerMinute * 60000);
			const minEnd = d.evStart.getTime() + 15 * 60000;   // duration floor: 15 min
			if (newEnd.getTime() < minEnd) newEnd = new Date(minEnd);
		} else {
			newStart = snap15(d.evStart.getTime() + (pointerMinute - d.grabMinute) * 60000);
			// Week view: retarget the day to whichever column the pointer is over.
			const overCol = (document.elementFromPoint(e.clientX, e.clientY) as HTMLElement | null)
				?.closest('.day-column[data-day]') as HTMLElement | null;
			const key = overCol?.dataset.day;
			if (key) {
				const [y, mo, da] = key.split('-').map(Number);
				newStart = new Date(y, mo - 1, da, newStart.getHours(), newStart.getMinutes(), 0, 0);
			}
			newEnd = new Date(newStart.getTime() + (d.evEnd.getTime() - d.evStart.getTime()));
		}
		// Optimistic drag preview — the grid paints the move immediately.
		eventsStore.patchEventTimes(d.id, newStart.toISOString(), newEnd.toISOString());
	}

	function onDragEnd() {
		const d = drag;
		if (!d) return;
		window.removeEventListener('pointermove', onDragMove);
		window.removeEventListener('pointerup', onDragEnd);
		try { d.captureEl.releasePointerCapture(d.pointerId); } catch { /* already released/removed */ }
		drag = null;
		if (!d.moved) return;                        // a plain click → onEventClick opens the detail modal
		justDragged = true;
		const ev = eventsStore.events.find((x) => x.id === d.id);
		if (!ev) return;
		// Pre-drag times: the rollback + recurrence-id source for the commit/scope paths.
		const snapshot = { id: d.id, start: d.evStart.toISOString(), end: d.evEnd.toISOString() };
		commitDragPatch(ev, { start: ev.start, end: ev.end }, snapshot);
	}

	// Commit a finished drag through the action store. A recurring event is routed
	// through the occurrence-vs-series dialog instead (the store stashes the drag
	// patch + snapshot); a failed commit is rolled back to the pre-drag times by
	// the store — only the error banner copy is ours.
	async function commitDragPatch(
		ev: CalendarEvent,
		patch: Partial<CalendarEvent>,
		snapshot: { id: string; start: string; end: string }
	) {
		try {
			const res = await actionStore.dispatch({ type: 'dragCommit', event: ev, patch, snapshot });
			if (res && typeof res === 'object' && res.scopeRequired) showScopePrompt = true;
		} catch (e) {
			error = parseError(e).message;
		}
	}

	function onEventClick(ev: CalendarEvent) {
		if (justDragged) { justDragged = false; return; }
		openDetailModal(ev);
	}

	function cancelScope() {
		showScopePrompt = false;
		// Cancelling a recurring drag rolls the optimistic change back to the
		// pre-drag times (rollback owned by the action store).
		void actionStore.dispatch({ type: 'cancelScope' });
	}

	function buildEventData(): Partial<CalendarEvent> {
		const start = form.allDay
			? new Date(form.startDate)
			: new Date(`${form.startDate}T${form.startTime}`);
		const end = form.allDay
			? new Date(form.endDate)
			: new Date(`${form.endDate}T${form.endTime}`);
		const eventData: Partial<CalendarEvent> = {
			// The editor can open before $calendars loads, leaving the select empty —
			// an empty calendarId is server-rejected (notCreated: invalidArguments).
			calendarId: form.calendarId || $calendars[0]?.id || '',
			title: form.title,
			start: start.toISOString(),
			end: end.toISOString(),
			isAllDay: form.allDay,
			location: form.location,
			description: form.description,
			recurrenceRule: recurrenceParts ? buildRrule(recurrenceParts) : null,
			color: form.color || null, // '' → null clears it, inheriting the calendar color
			freeBusyStatus: form.freeBusyStatus,
			privacy: form.privacy as CalendarEvent['privacy'], // form field widens to string; narrow back to the union
			// Recompute the absolute trigger from the (possibly edited) start every save, so a
			// start-time change moves the reminder. Empty array clears it in the update path.
			valarm: buildValarm(start, form.reminder)
		};
		const people: EventAttendee[] = form.attendees
			? form.attendees.split(',').map((e) => ({ email: e.trim(), participationStatus: 'needs-action' }))
			: [];
		// Optional attendees round-trip with role:'optional' (the reducer defaults required people
		// to role:'required'); the three buckets stay disjoint so optional people don't leak into resources.
		const optionalPeople: EventAttendee[] = form.optionalAttendees
			? form.optionalAttendees.split(',').map((e) => ({ email: e.trim(), role: 'optional', participationStatus: 'needs-action' }))
			: [];
		const allAttendees = [...people, ...optionalPeople, ...resourceAttendees];
		if (allAttendees.length > 0) eventData.attendees = allAttendees;
		if (form.delegatedFrom) {
			(eventData as Record<string, unknown>).delegatedFrom = form.delegatedFrom;
		}
		return eventData;
	}

	async function saveEvent() {
		if (actionStore.saving) return;
		// Editing a recurring event must first ask occurrence-vs-series.
		if (modalMode === 'edit' && editingEvent?.recurrenceRule) {
			actionStore.requestScope(editingEvent);
			showScopePrompt = true;
			return;
		}
		error = '';
		try {
			const eventData = buildEventData();
			const wasCreate = modalMode === 'create';
			const res = await actionStore.dispatch(
				wasCreate
					? { type: 'create', eventData }
					: { type: 'update', id: editingEvent!.id, eventData }
			);
			// Meet B1 Task 16 calendar hook (spec §3.2) — fires only on the actual
			// TOGGLE edge, never re-creates/re-clears on every unrelated save:
			// create+checked → bind a fresh meeting to the just-created event;
			// update+checked-but-wasn't → same, bound to the existing event;
			// update+unchecked-but-was → the {isMeeting:false} clear-only patch
			// (design #15 — the meeting row itself survives, no delete route).
			if (wasCreate && form.addMeet && typeof res === 'string') {
				await meetApi.createMeeting({ title: form.title, scheduledStart: eventData.start, scheduledEnd: eventData.end, calendarEventId: Number(res) });
			} else if (!wasCreate && editingEvent) {
				if (form.addMeet && !editingEvent.isMeeting) {
					await meetApi.createMeeting({ title: form.title, scheduledStart: eventData.start, scheduledEnd: eventData.end, calendarEventId: Number(editingEvent.id) });
				} else if (!form.addMeet && editingEvent.isMeeting) {
					await updateEvent(editingEvent.id, { isMeeting: false } as Partial<CalendarEvent>);
				}
			}
			closeModal();
		} catch (e) {
			// INVARIANT (e): a notCreated/notUpdated item-level rejection throws in
			// stores/calendar.ts (assertSetApplied) and lands here — the banner shows
			// and the editor stays open. Never a silent close over rejected data.
			error = parseError(e).message;
		}
	}

	async function applyScope(scope: 'this' | 'following' | 'series') {
		if (!actionStore.scopePending || actionStore.saving) return;
		error = '';
		showScopePrompt = false;
		try {
			// The store resolves `dragPatch ?? eventData()`: a drag's stashed patch wins
			// and its recurrence-id is the PRE-drag start; the form builder only runs on
			// the edit-form entry path (invariants b + c live in CalendarActionStore).
			await actionStore.dispatch({ type: 'applyScope', scope, eventData: buildEventData });
			closeModal();
		} catch (e) {
			error = parseError(e).message;
		}
	}

	async function handleDelete() {
		if (!editingEvent || actionStore.deleting) return;
		error = '';
		try {
			const res = await actionStore.dispatch({ type: 'delete', event: editingEvent });
			if (res && typeof res === 'object' && res.scopeRequired) { showScopePrompt = true; return; }
			closeModal();
		} catch (e) {
			// INVARIANT (e): notDestroyed → throw → banner, dialog stays open.
			error = parseError(e).message;
		}
	}

	async function handleRsvp(status: string) {
		if (!editingEvent || actionStore.responding) return;
		error = '';
		try {
			await actionStore.dispatch({ type: 'rsvp', id: editingEvent.id, status });
			const updated = eventsStore.events.find((e) => e.id === editingEvent!.id);
			if (updated) editingEvent = updated;
		} catch (e) {
			error = parseError(e).message;
		}
	}

	// Prefill the proposed times from the event's current times (same datetime-local
	// convention as the scheduling modal: ISO → slice(0,16), submit → new Date().toISOString()).
	function openProposeModal() {
		if (!editingEvent) return;
		proposeError = '';
		proposeStart = editingEvent.start ? new Date(editingEvent.start).toISOString().slice(0, 16) : '';
		proposeEnd = editingEvent.end ? new Date(editingEvent.end).toISOString().slice(0, 16) : '';
		showProposeModal = true;
	}

	async function handlePropose() {
		if (!editingEvent || proposing) return;
		if (!proposeStart || !proposeEnd) {
			proposeError = t('calendar.propose.start');
			return;
		}
		proposeError = '';
		proposing = true;
		try {
			await proposeNewTime(
				editingEvent.id,
				new Date(proposeStart).toISOString(),
				new Date(proposeEnd).toISOString()
			);
			showProposeModal = false;
		} catch (e) {
			proposeError = parseError(e).message;
		} finally {
			proposing = false;
		}
	}

	function openSchedulingModal() {
		const range = getViewRange($selectedDate, $viewMode);
		schedulingStartDate = range.start.toISOString().slice(0, 16);
		schedulingEndDate = range.end.toISOString().slice(0, 16);
		schedulingAttendees = '';
		schedulingDuration = 30;
		schedulingWorkStart = workStart;
		schedulingWorkEnd = workEnd;
		freeSlots = [];
		schedulingError = '';
		showSchedulingModal = true;
	}

	// In-editor "Add Scheduling Assistant": reuse the existing scheduling dialog (does NOT
	// rebuild free/busy), prefilled from the open event's attendees + start.
	function openSchedulingFromEditor() {
		const startBase = form.startDate
			? new Date(`${form.startDate}T${form.allDay ? '00:00' : form.startTime}`)
			: new Date($selectedDate);
		const endBase = new Date(startBase);
		endBase.setDate(endBase.getDate() + 7);
		schedulingStartDate = startBase.toISOString().slice(0, 16);
		schedulingEndDate = endBase.toISOString().slice(0, 16);
		schedulingAttendees = form.attendees;
		schedulingDuration = 30;
		schedulingWorkStart = workStart;
		schedulingWorkEnd = workEnd;
		freeSlots = [];
		schedulingError = '';
		showSchedulingModal = true;
	}

	// A3: open another user's shared calendar by owner email (viewer is the auth user).
	async function handleOpenShared() {
		const email = openSharedEmail.trim();
		if (!email) return;
		openSharedError = '';
		try {
			const cals = await openSharedCalendar(email);
			if (cals.length === 0) {
				openSharedError = parseError(new Error('No shared calendar found')).message;
				return;
			}
			showOpenSharedDialog = false;
			openSharedEmail = '';
			await refreshEvents();
		} catch (e) {
			openSharedError = parseError(e).message;
		}
	}

	function openShareFor(calendarId: string, name: string) {
		shareCalendarId = calendarId;
		shareCalendarName = name;
		showShareDialog = true;
	}

	// Print the current view's agenda: the already-loaded events, filtered to the visible
	// calendars + the current view range, escaped in printAgenda. Pure client-side.
	function printCurrentView() {
		const range = getViewRange($selectedDate, $viewMode);
		const list = eventsStore.events
			.filter((ev) => $visibleCalendarIds.includes(ev.calendarId))
			.filter((ev) => {
				const s = new Date(ev.start).getTime();
				return s >= range.start.getTime() && s < range.end.getTime();
			});
		printAgenda(list, `${t('calendar.print')} — ${formatMonthYear($selectedDate)}`);
	}

	// Only writable calendars can receive an import.
	let writableCalendars = $derived($calendars.filter((c) => !c.isReadOnly));

	function openImportDialog() {
		importCalendarId = writableCalendars[0]?.id || '';
		importStrategy = 'skip';
		importError = '';
		importResult = '';
		showImportDialog = true;
	}

	async function runImport() {
		if (importing) return;
		const file = importFileEl?.files?.[0];
		if (!file) { importError = t('calendar.import.no_file'); return; }
		if (!importCalendarId) { importError = t('calendar.import.no_calendar'); return; }
		importError = '';
		importResult = '';
		importing = true;
		try {
			const text = await file.text();
			const res = await importEvents(importCalendarId, text, importStrategy);
			importResult = t('calendar.import.done', { imported: String(res.imported), skipped: String(res.skipped) });
			await refreshEvents();
		} catch (e) {
			importError = parseError(e).message;
		} finally {
			importing = false;
		}
	}

	function openSubscribeDialog() {
		subscribeUrl = '';
		subscribeName = '';
		subscribeError = '';
		showSubscribeDialog = true;
	}

	async function runSubscribe() {
		if (subscribing) return;
		const url = subscribeUrl.trim();
		if (!url) { subscribeError = t('calendar.subscribe.no_url'); return; }
		subscribeError = '';
		subscribing = true;
		try {
			await calendarSubscriptions.subscribe(url, subscribeName.trim() || undefined);
			await loadCalendars(); // the new read-only calendar itself
			showSubscribeDialog = false;
		} catch (e) {
			subscribeError = parseError(e).message;
		} finally {
			subscribing = false;
		}
	}

	async function unsubscribeCalendar(subscriptionId: number, calendarName: string) {
		if (typeof window !== 'undefined' && !window.confirm(t('calendar.subscribe.unsubscribe_confirm', { name: calendarName }))) return;
		try {
			await calendarSubscriptions.unsubscribe(subscriptionId);
			await loadCalendars();
		} catch (e) {
			error = parseError(e).message;
		}
	}

	function onRoomPicked(attendee: EventAttendee) {
		if (!resourceAttendees.some((a) => a.email === attendee.email)) {
			resourceAttendees = [...resourceAttendees, attendee];
		}
	}

	let sendingUpdate = $state(false);
	async function handleSendUpdate() {
		if (!editingEvent || sendingUpdate) return;
		error = '';
		sendingUpdate = true;
		try {
			await sendMeetingUpdate(editingEvent.id);
		} catch (e) {
			error = parseError(e).message;
		} finally {
			sendingUpdate = false;
		}
	}

	let respondingOnBehalf = $state(false);
	async function handleRespondOnBehalf(status: string, managerEmail: string) {
		if (!editingEvent || respondingOnBehalf) return;
		error = '';
		respondingOnBehalf = true;
		try {
			await rsvpOnBehalf(editingEvent.id, status, managerEmail);
			await refreshEvents();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			respondingOnBehalf = false;
		}
	}

	// The organizer the current user may respond for (delegate). Matches the open event's
	// organizer email against the user's delegations.
	let delegateForEvent = $derived(
		editingEvent?.organizer?.email
			? delegations.find((d) => d.email === editingEvent!.organizer!.email)
			: undefined
	);

	// A meeting (has attendees) the user organizes → eligible for "Send update".
	let isOrganizedMeeting = $derived(
		!!editingEvent &&
			(editingEvent.attendees?.length ?? 0) > 0 &&
			(!editingEvent.organizer || editingEvent.organizer.email === ($user?.email || ''))
	);

	// QoL #12 — organizer-only RSVP roster: accepted/declined/tentative/no-response
	// counts, computed client-side from the attendee data already on the wire.
	let rsvpCounts = $derived.by(() => {
		const counts = { accepted: 0, declined: 0, tentative: 0, noResponse: 0 };
		for (const a of editingEvent?.attendees ?? []) {
			if (a.participationStatus === 'accepted') counts.accepted++;
			else if (a.participationStatus === 'declined') counts.declined++;
			else if (a.participationStatus === 'tentative') counts.tentative++;
			else counts.noResponse++;
		}
		return counts;
	});

	// Non-responders sorted to the top so the organizer sees who to nudge first.
	let sortedAttendees = $derived.by(() => {
		const list = editingEvent?.attendees ?? [];
		const responded = (s?: string) => s === 'accepted' || s === 'declined' || s === 'tentative';
		return [...list].sort((a, b) => Number(responded(a.participationStatus)) - Number(responded(b.participationStatus)));
	});

	function closeSchedulingModal() {
		showSchedulingModal = false;
		schedulingError = '';
		freeSlots = [];
	}

	async function handleFindFreeSlots() {
		schedulingLoading = true;
		schedulingError = '';
		try {
			const attendeeIds = schedulingAttendees
				.split(',')
				.map((s) => s.trim())
				.filter(Boolean);
			if (attendeeIds.length === 0) {
				schedulingError = 'Enter at least one attendee email';
				freeSlots = [];
				return;
			}
			const result = await findFreeSlots({
				userIds: attendeeIds,
				start: new Date(schedulingStartDate).toISOString(),
				end: new Date(schedulingEndDate).toISOString(),
				durationMinutes: schedulingDuration,
				workingStartTime: schedulingWorkStart,
				workingEndTime: schedulingWorkEnd
			});
			freeSlots = result;
			if (result.length === 0) {
				schedulingError = 'No free slots found in this range';
			}
		} catch (e) {
			schedulingError = parseError(e).message;
		} finally {
			schedulingLoading = false;
		}
	}

	function createFromSlot(slot: FreeSlot) {
		closeSchedulingModal();
		const slotStart = new Date(slot.start);
		const slotEnd = new Date(slot.end);
		form = {
			title: '',
			calendarId: $visibleCalendarIds[0] || ($calendars[0]?.id || ''),
			startDate: slotStart.toISOString().slice(0, 10),
			startTime: slotStart.toTimeString().slice(0, 5),
			endDate: slotEnd.toISOString().slice(0, 10),
			endTime: slotEnd.toTimeString().slice(0, 5),
			allDay: false,
			location: '',
			description: '',
			recurrence: 'none',
			attendees: schedulingAttendees,
			optionalAttendees: '',
			delegatedFrom: '',
			color: '',
			freeBusyStatus: 'busy',
			privacy: 'public',
			reminder: 'none',
			addMeet: false
		};
		recurrenceParts = null;
		resourceAttendees = [];
		modalMode = 'create';
		editingEvent = null;
		showModal = true;
	}

	let agendaEvents = $derived(eventsStore.events
		.filter((ev) => $visibleCalendarIds.includes(ev.calendarId))
		.filter((ev) => new Date(ev.start) >= new Date($selectedDate))
		.sort((a, b) => new Date(a.start).getTime() - new Date(b.start).getTime()));

	// QoL #16 — tasks due on/after the agenda's start date, done/cancelled hidden.
	let agendaTasks = $derived($taskStore
		.filter((task) => task.dueAt && new Date(task.dueAt) >= new Date($selectedDate))
		.filter((task) => task.status !== 'completed' && task.status !== 'cancelled')
		.sort((a, b) => new Date(a.dueAt!).getTime() - new Date(b.dueAt!).getTime()));

	let userIsAttendee = $derived(editingEvent && (editingEvent.attendees || []).some(
		(a) => a.email === ($user?.email || '')
	));
</script>

{#if error}
	<div class="cal-error">{error}</div>
{/if}

<PimShell title="Calendar">
	{#snippet topbarActions()}
		<div class="toolbar">
			<div class="nav">
				<IconButton label="Previous period" variant="ghost" size="sm" onclick={prevPeriod}>
					<Icon name="ChevronLeft" size={16} />
				</IconButton>
				<Button variant="secondary" size="sm" onclick={goToday}>Today</Button>
				<IconButton label="Next period" variant="ghost" size="sm" onclick={nextPeriod}>
					<Icon name="ChevronRight" size={16} />
				</IconButton>
				<span class="nav-title">{formatMonthYear($selectedDate)}</span>
			</div>
			<div class="view-toggle">
				<Button variant={$viewMode === 'month' ? 'primary' : 'ghost'} size="sm" onclick={() => viewMode.set('month')}>Month</Button>
				<Button variant={$viewMode === 'week' ? 'primary' : 'ghost'} size="sm" onclick={() => viewMode.set('week')}>Week</Button>
				<Button variant={$viewMode === 'workweek' ? 'primary' : 'ghost'} size="sm" onclick={() => viewMode.set('workweek')}>Work Week</Button>
				<Button variant={$viewMode === 'day' ? 'primary' : 'ghost'} size="sm" onclick={() => viewMode.set('day')}>Day</Button>
				<Button variant={$viewMode === 'agenda' ? 'primary' : 'ghost'} size="sm" onclick={() => viewMode.set('agenda')}>Agenda</Button>
			</div>
			<Button variant="primary" size="md" onclick={() => openCreateModal(null, null)}>New event</Button>
			<Button variant="secondary" size="sm" onclick={openSchedulingModal}>Find a time</Button>
			<Button variant="secondary" size="sm" onclick={() => { openSharedError = ''; showOpenSharedDialog = true; }}>{t('calendar.open_shared.title')}</Button>
			<Button variant="secondary" size="sm" onclick={openImportDialog}>{t('calendar.import')}</Button>
			<Button variant="secondary" size="sm" onclick={openSubscribeDialog}>{t('calendar.subscribe.button')}</Button>
			<Button variant="secondary" size="sm" onclick={printCurrentView}>{t('calendar.print')}</Button>
		</div>
	{/snippet}

	{#snippet sidebar()}
		<h3 class="sidebar-title">Calendars</h3>
		<ul class="calendar-list">
			{#each $calendars as cal}
				{@const sub = calendarSubscriptions.forCalendar(cal.id)}
				<li>
					<div class="cal-item">
						<span class="cal-dot" style="background:{safeColor(cal.color)}"></span>
						<Checkbox
							checked={$selectedCalendarIds.includes(cal.id)}
							onchange={() => toggleCalendarVisibility(cal.id)}
							label={cal.name}
						/>
						{#if sub}
							<span class="cal-sub-icon" title={t('calendar.subscribe.subscribed_title')}>
								<Icon name="Globe" size={14} />
							</span>
							{#if sub.lastStatus === 'error'}
								<span class="cal-sub-dot cal-sub-dot--error" title={sub.lastError || t('calendar.subscribe.status_error')}></span>
							{:else if sub.lastStatus === 'partial'}
								<span class="cal-sub-dot cal-sub-dot--partial" title={sub.lastError || t('calendar.subscribe.status_partial')}></span>
							{/if}
							<span class="cal-sub-synced">{formatSyncedAgo(sub.lastFetchAt)}</span>
							<IconButton label={t('calendar.subscribe.unsubscribe')} variant="ghost" size="sm" onclick={() => unsubscribeCalendar(sub.id, cal.name)}>
								<Icon name="X" size={14} />
							</IconButton>
						{:else if cal.isShared || cal.isReadOnly}
							<span class="cal-badge" title={t('calendar.open_shared.readonly')}>{t('calendar.open_shared.shared_badge')}</span>
						{:else}
							<IconButton label={t('calendar.share.open')} variant="ghost" size="sm" onclick={() => openShareFor(cal.id, cal.name)}>
								<Icon name="Users" size={14} />
							</IconButton>
						{/if}
					</div>
				</li>
			{/each}
		</ul>

		<h3 class="sidebar-title">{t('calendar.view_options')}</h3>
		<div class="view-opts">
			<div class="opt-group">
				<span class="field-sublabel">{t('calendar.scheduling.working_hours')}</span>
				<div class="time-row">
					<Input type="time" bind:value={workStart} onchange={persistWorkHours} />
					<span class="time-sep">&ndash;</span>
					<Input type="time" bind:value={workEnd} onchange={persistWorkHours} />
				</div>
			</div>
			<div class="opt-group">
				<label class="field-sublabel" for="cal-tz2">{t('calendar.second_timezone')}</label>
				<select id="cal-tz2" class="tz2-select" bind:value={tz2} onchange={persistTz2}>
					<option value="">{t('calendar.second_timezone_none')}</option>
					{#each TIMEZONES as tz}
						<option value={tz}>{tz}</option>
					{/each}
				</select>
			</div>
		</div>
	{/snippet}

	{#snippet main()}
		<div class="calendar-app">
			{#if eventsStore.loading}
				<div class="cal-loading">
					<Spinner size={20} label="Loading calendar" />
				</div>
			{:else if $viewMode === 'month'}
				<div class="month-grid">
					{#each DAYS as day}
						<div class="day-header">{day}</div>
					{/each}
					{#each getMonthGrid() as cell}
						<div
							class="month-cell"
							class:other-month={!cell.isCurrentMonth}
							class:today={cell.isToday}
							role="button"
							tabindex="0"
							onclick={() => openCreateModal(cell.date, null)}
							onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openCreateModal(cell.date, null); } }}
						>
							<span class="day-num">{cell.dayNum}</span>
							{#each cell.events.slice(0, 3) as ev}
								<button
									type="button"
									class="event-pill"
									style="background:{eventColor(ev)};color:{contrastColor(eventColor(ev))}"
									onclick={(e) => { e.stopPropagation(); openDetailModal(ev); }}
								>
									{#if !ev.isAllDay}{formatTime(ev.start)}{/if} {ev.title}
								</button>
							{/each}
							{#each cell.tasks.slice(0, Math.max(0, 3 - cell.events.length)) as task}
								<button
									type="button"
									class="event-pill task-pill"
									style="color:{priorityColor(task.priority)}"
									onclick={(e) => { e.stopPropagation(); goto('/tasks'); }}
								>
									<Icon name="CheckSquare" size={12} />
									{task.title}
								</button>
							{/each}
							{#if cell.events.length + cell.tasks.length > 3}
								<span class="more-events">+{cell.events.length + cell.tasks.length - 3} more</span>
							{/if}
						</div>
					{/each}
				</div>
			{:else if $viewMode === 'week' || $viewMode === 'workweek'}
				<div class="time-grid week-grid">
					<div class="time-gutter">
						{#each HOURS as h}
							<div class="time-label">{h === 0 ? '' : new Date(0, 0, 0, h).toLocaleString(localeCode(), {hour:'numeric', hour12:true})}</div>
						{/each}
					</div>
					{#if tz2}
						<div class="time-gutter">
							{#each HOURS as h}
								<div class="time-label">{h === 0 ? '' : formatHourTz($selectedDate, h, tz2)}</div>
							{/each}
						</div>
					{/if}
					{#each getWeekDays() as day}
						<div class="day-column" class:today={day.isToday} data-day={localDayKey(day.date)}>
							<div class="day-column-header">
								<span class="day-name">{DAYS[day.date.getDay()]}</span>
								<span class="day-number" class:highlight={day.isToday}>{day.date.getDate()}</span>
							</div>
							{#each HOURS as h}
								<button
									type="button"
									class="hour-slot"
									class:off-hours={isOffHours(h)}
									aria-label="Create event at {h}:00"
									onclick={() => openCreateModal(day.date, h)}
								></button>
							{/each}
							{#each day.events as ev}
								{#if !ev.isAllDay}
									<button
										type="button"
										class="timed-event"
										class:draggable={!isEventReadOnly(ev)}
										class:dragging={drag?.id === ev.id && drag?.moved}
										style="top:{eventTopMinutes(ev.start) / 1440 * 100}%;height:{eventDuration(ev.start, ev.end) / 1440 * 100}%;background:{eventColor(ev)};color:{contrastColor(eventColor(ev))}"
										onpointerdown={(e) => startDrag(e, ev, 'move')}
										onclick={(e) => { e.stopPropagation(); onEventClick(ev); }}
									>
										<span class="ev-time">{formatTime(ev.start)}</span> {ev.title}
										{#if !isEventReadOnly(ev)}
											<div
												class="resize-handle"
												role="button"
												tabindex={-1}
												aria-label={t('calendar.drag.resize')}
												onpointerdown={(e) => { e.stopPropagation(); startDrag(e, ev, 'resize'); }}
											></div>
										{/if}
									</button>
								{:else}
									<button
										type="button"
										class="allday-event"
										style="background:{eventColor(ev)};color:{contrastColor(eventColor(ev))}"
										onclick={(e) => { e.stopPropagation(); openDetailModal(ev); }}
									>
										{ev.title}
									</button>
								{/if}
							{/each}
						</div>
					{/each}
				</div>
			{:else if $viewMode === 'day'}
				<div class="time-grid day-grid">
					<div class="time-gutter">
						{#each HOURS as h}
							<div class="time-label">{h === 0 ? '' : new Date(0, 0, 0, h).toLocaleString(localeCode(), {hour:'numeric', hour12:true})}</div>
						{/each}
					</div>
					{#if tz2}
						<div class="time-gutter">
							{#each HOURS as h}
								<div class="time-label">{h === 0 ? '' : formatHourTz($selectedDate, h, tz2)}</div>
							{/each}
						</div>
					{/if}
					<div class="day-column today" data-day={localDayKey($selectedDate)}>
						{#each HOURS as h}
							<button
								type="button"
								class="hour-slot"
								class:off-hours={isOffHours(h)}
								aria-label="Create event at {h}:00"
								onclick={() => openCreateModal($selectedDate, h)}
							></button>
						{/each}
						{#each getEventsForDay($selectedDate) as ev}
							{#if !ev.isAllDay}
								<button
									type="button"
									class="timed-event"
									class:draggable={!isEventReadOnly(ev)}
									class:dragging={drag?.id === ev.id && drag?.moved}
									style="top:{eventTopMinutes(ev.start) / 1440 * 100}%;height:{eventDuration(ev.start, ev.end) / 1440 * 100}%;background:{eventColor(ev)};color:{contrastColor(eventColor(ev))}"
									onpointerdown={(e) => startDrag(e, ev, 'move')}
									onclick={(e) => { e.stopPropagation(); onEventClick(ev); }}
								>
									<div class="ev-title">{ev.title}</div>
									<div class="ev-time">{formatTime(ev.start)} – {formatTime(ev.end)}</div>
									{#if ev.location}<div class="ev-loc">{ev.location}</div>{/if}
									{#if !isEventReadOnly(ev)}
										<div
											class="resize-handle"
											role="button"
											tabindex={-1}
											aria-label={t('calendar.drag.resize')}
											onpointerdown={(e) => { e.stopPropagation(); startDrag(e, ev, 'resize'); }}
										></div>
									{/if}
								</button>
							{:else}
								<button
									type="button"
									class="allday-event"
									style="background:{eventColor(ev)};color:{contrastColor(eventColor(ev))}"
									onclick={(e) => { e.stopPropagation(); openDetailModal(ev); }}
								>
									{ev.title}
								</button>
							{/if}
						{/each}
					</div>
				</div>
			{:else}
				<div class="agenda-view">
					{#if agendaEvents.length === 0 && agendaTasks.length === 0}
						<EmptyState title="No upcoming events" />
					{:else}
						{#each agendaEvents as ev}
							<button
								type="button"
								class="agenda-item"
								onclick={(e) => { e.stopPropagation(); openDetailModal(ev); }}
							>
								<span class="color-bar" style="background:{eventColor(ev)}"></span>
								<div class="agenda-info">
									<div class="agenda-title">{ev.title}</div>
									<div class="agenda-time">
										{#if ev.isAllDay}
											{formatDateShort(ev.start)} (All day)
										{:else}
											{formatDateShort(ev.start)}, {formatTime(ev.start)} – {formatTime(ev.end)}
										{/if}
									</div>
									{#if ev.location}<div class="agenda-loc">{ev.location}</div>{/if}
								</div>
							</button>
						{/each}
						{#each agendaTasks as task}
							<button
								type="button"
								class="agenda-item task-agenda-item"
								onclick={(e) => { e.stopPropagation(); goto('/tasks'); }}
							>
								<span class="color-bar" style="background:{priorityColor(task.priority)}"></span>
								<div class="agenda-info">
									<div class="agenda-title">{task.title}</div>
									<div class="agenda-time">{t('calendar.task_due')}: {formatDateShort(task.dueAt)}</div>
								</div>
							</button>
						{/each}
					{/if}
				</div>
			{/if}
		</div>
	{/snippet}
</PimShell>

<!-- Event create/edit dialog -->
<Dialog
	open={showModal && modalMode !== 'detail'}
	title={modalMode === 'create' ? 'New event' : 'Edit event'}
	onClose={closeModal}
	wide
>
	<form onsubmit={(e) => { e.preventDefault(); saveEvent(); }}>
		<div class="form-group">
			<Input label="Title" bind:value={form.title} placeholder="Event title" required />
		</div>
		<div class="form-group">
			<Select label="Calendar" bind:value={form.calendarId} options={$calendars.map((cal) => ({ value: cal.id, label: cal.name }))} />
		</div>
		<div class="form-row">
			<div class="form-group">
				<Input label="Start date" type="date" bind:value={form.startDate} required />
			</div>
			{#if !form.allDay}
				<div class="form-group">
					<Input label="Time" type="time" bind:value={form.startTime} />
				</div>
			{/if}
		</div>
		<div class="form-row">
			<div class="form-group">
				<Input label="End date" type="date" bind:value={form.endDate} required />
			</div>
			{#if !form.allDay}
				<div class="form-group">
					<Input label="Time" type="time" bind:value={form.endTime} />
				</div>
			{/if}
		</div>
		<div class="form-group">
			<Checkbox checked={form.allDay} onchange={(e) => form.allDay = e.currentTarget.checked} label="All day" />
		</div>
		<div class="form-group">
			<Input label="Location" bind:value={form.location} placeholder="Add location" />
		</div>
		<div class="form-group">
			<Textarea label="Description" bind:value={form.description} placeholder="Add notes" rows={3} />
		</div>
		<div class="form-group">
			<span class="field-sublabel">{t('calendar.event_color')}</span>
			<div class="event-color-controls">
				<input
					type="color"
					class="event-color-input"
					aria-label={t('calendar.event_color')}
					value={editorColor}
					oninput={(e) => (form.color = (e.currentTarget as HTMLInputElement).value)}
				/>
				{#if form.color}
					<Button type="button" variant="ghost" size="sm" onclick={() => (form.color = '')}>
						{t('calendar.event_color_inherit')}
					</Button>
				{/if}
			</div>
		</div>
		<div class="form-group">
			<Select label={t('calendar.show_as')} bind:value={form.freeBusyStatus} options={[
				{ value: 'free', label: t('calendar.show_as_free') },
				{ value: 'busy', label: t('calendar.show_as_busy') },
				{ value: 'tentative', label: t('calendar.show_as_tentative') }
			]} />
		</div>
		<div class="form-group">
			<Select label={t('calendar.reminder')} bind:value={form.reminder}
				options={REMINDER_OPTIONS.map((v) => ({ value: v, label: reminderLabel(v) }))} />
		</div>
		<div class="form-group">
			<Checkbox
				checked={form.privacy === 'private'}
				onchange={(e) => (form.privacy = e.currentTarget.checked ? 'private' : 'public')}
				label={t('calendar.private')}
			/>
		</div>
		<div class="form-group">
			<RecurrenceEditor value={recurrenceParts} onChange={(p) => (recurrenceParts = p)} />
		</div>
		{#if $effectiveCaps.enabledApps.includes('meet')}
			<div class="form-group">
				<Checkbox checked={form.addMeet} onchange={(e) => (form.addMeet = e.currentTarget.checked)} label={t('meet.calendar.addMeet')} />
			</div>
		{/if}
		<div class="form-group">
			<Input label="Attendees (comma-separated emails)" bind:value={form.attendees} placeholder="alice@example.com, bob@example.com" />
		</div>
		<div class="form-group">
			<Input label={t('calendar.optional_attendees')} bind:value={form.optionalAttendees} placeholder="alice@example.com, bob@example.com" />
		</div>
		<div class="form-group editor-actions">
			<Button type="button" variant="secondary" size="sm" onclick={() => (showRoomFinder = true)}>{t('calendar.rooms.add')}</Button>
			<Button type="button" variant="secondary" size="sm" onclick={openSchedulingFromEditor}>{t('calendar.scheduling.add')}</Button>
		</div>
		{#if resourceAttendees.length > 0}
			<div class="form-group">
				<span class="field-sublabel">{t('calendar.rooms.title')}</span>
				<ul class="resource-chips">
					{#each resourceAttendees as room (room.email)}
						<li class="resource-chip">
							<Icon name="DoorOpen" size={14} />
							<span>{room.name || room.email}</span>
							<button type="button" class="chip-remove" aria-label={t('calendar.share.revoke')}
								onclick={() => (resourceAttendees = resourceAttendees.filter((r) => r.email !== room.email))}>×</button>
						</li>
					{/each}
				</ul>
			</div>
		{/if}
		{#if $identities.length > 0}
			<div class="form-group">
				<Select label="Send on behalf of" bind:value={form.delegatedFrom} options={[
					{ value: '', label: 'Myself' },
					...$identities.map((ident) => ({ value: ident.email, label: `${ident.name} (${ident.email})` }))
				]} />
			</div>
		{/if}
	</form>

	{#snippet footer()}
			{#if modalMode === 'edit'}
				<Button type="button" variant="primary" size="md" disabled={actionStore.saving} onclick={saveEvent}>
					{actionStore.saving ? 'Saving...' : 'Save changes'}
				</Button>
				<Button type="button" variant="danger" size="md" disabled={actionStore.deleting} onclick={handleDelete}>
					{actionStore.deleting ? 'Deleting...' : 'Delete'}
				</Button>
				<Button type="button" variant="secondary" size="md" onclick={closeModal}>Cancel</Button>
			{:else}
				<Button type="button" variant="primary" size="md" disabled={actionStore.saving} onclick={saveEvent}>
					{actionStore.saving ? 'Saving...' : 'Create'}
				</Button>
				<Button type="button" variant="secondary" size="md" onclick={closeModal}>Cancel</Button>
			{/if}
		{/snippet}
</Dialog>

<!-- Event detail dialog -->
<Dialog
	open={showModal && modalMode === 'detail'}
	title={editingEvent?.title || 'Untitled'}
	onClose={closeModal}
	wide
>
	<div class="detail-content">
		<div class="detail-row">
			<span class="detail-label">When:</span>
			<span>{#if editingEvent?.isAllDay}{formatDateShort(editingEvent?.start)} (All day){:else}{formatDateShort(editingEvent?.start)}, {formatTime(editingEvent?.start)} – {formatTime(editingEvent?.end)}{/if}</span>
		</div>
		{#if editingEvent?.isMeeting && editingEvent?.meetingUrl && $effectiveCaps.enabledApps.includes('meet')}
			<div class="detail-row">
				<Button variant="primary" size="sm" onclick={() => goto(editingEvent!.meetingUrl!)}>
					<Icon name="Video" size={14} />
					{t('meet.calendar.joinMeeting')}
				</Button>
			</div>
		{/if}
		{#if editingEvent?.location}
			<div class="detail-row">
				<span class="detail-label">Where:</span>
				<span>{editingEvent.location}</span>
			</div>
		{/if}
		{#if editingEvent?.description}
			<div class="detail-row">
				<span class="detail-label">Notes:</span>
				<span class="detail-desc">{editingEvent.description}</span>
			</div>
		{/if}
		{#if editingEvent?.organizer}
			<div class="detail-row">
				<span class="detail-label">Organizer:</span>
				<span>{editingEvent.organizer.name || editingEvent.organizer.email}</span>
			</div>
		{/if}
		{#if editingEvent?.attendees?.length}
			<div class="detail-row">
				<span class="detail-label">Attendees:</span>
				{#if isOrganizedMeeting}
					<div class="rsvp-roster" data-testid="rsvp-roster">
						<span class="rsvp-count accepted">{t('calendar.roster.accepted')}: {rsvpCounts.accepted}</span>
						<span class="rsvp-count declined">{t('calendar.roster.declined')}: {rsvpCounts.declined}</span>
						<span class="rsvp-count tentative">{t('calendar.roster.tentative')}: {rsvpCounts.tentative}</span>
						<span class="rsvp-count no-response">{t('calendar.roster.no_response')}: {rsvpCounts.noResponse}</span>
					</div>
				{/if}
				<div class="attendee-list">
					{#each sortedAttendees as a}
						<div class="attendee">
							{a.name || a.email}
							<span class="attendee-meta">
								{#if attendeeRoleLabel(a.role)}<span class="attendee-role">{attendeeRoleLabel(a.role)}</span>{/if}
								<span class="rsvp-status {a.participationStatus}">{a.participationStatus}</span>
							</span>
						</div>
					{/each}
				</div>
			</div>
		{/if}
		{#if editingEvent?.recurrenceRule}
			<div class="detail-row">
				<span class="detail-label">Repeats:</span>
				<span>{editingEvent.recurrenceRule}</span>
			</div>
		{/if}
	</div>

	{#snippet footer()}
		{#if userIsAttendee}
			<Button variant="secondary" size="sm" disabled={actionStore.responding !== null} onclick={() => handleRsvp('accepted')}>
				{actionStore.responding === 'accepted' ? 'Responding...' : 'Accept'}
			</Button>
			<Button variant="secondary" size="sm" disabled={actionStore.responding !== null} onclick={() => handleRsvp('tentative')}>
				{actionStore.responding === 'tentative' ? 'Responding...' : 'Tentative'}
			</Button>
			<Button variant="secondary" size="sm" disabled={actionStore.responding !== null} onclick={() => handleRsvp('declined')}>
				{actionStore.responding === 'declined' ? 'Responding...' : 'Decline'}
			</Button>
			<Button variant="secondary" size="sm" disabled={actionStore.responding !== null} onclick={openProposeModal}>
				{t('calendar.propose_new_time')}
			</Button>
		{/if}
		{#if delegateForEvent}
			<Button variant="secondary" size="sm" disabled={respondingOnBehalf}
				onclick={() => handleRespondOnBehalf('accepted', delegateForEvent!.email)}>
				{t('calendar.delegate.respond_for', { name: delegateForEvent.name || delegateForEvent.email })}
			</Button>
		{/if}
		{#if isOrganizedMeeting}
			<Button variant="secondary" size="sm" disabled={sendingUpdate} onclick={handleSendUpdate}>
				{sendingUpdate ? '…' : t('calendar.send_update')}
			</Button>
		{/if}
		<Button variant="secondary" size="sm" disabled={actionStore.deleting} onclick={() => { modalMode = 'edit'; openEditModal(editingEvent!); }}>
			Edit
		</Button>
		<Button variant="danger" size="sm" disabled={actionStore.deleting} onclick={handleDelete}>
			{actionStore.deleting ? 'Deleting...' : 'Delete'}
		</Button>
	{/snippet}
</Dialog>

<!-- Scheduling assistant dialog -->
<Dialog
	open={showSchedulingModal}
	title="Find a meeting time"
	onClose={closeSchedulingModal}
	wide
>
	<form onsubmit={(e) => { e.preventDefault(); handleFindFreeSlots(); }}>
		<div class="form-group">
			<Input label="Attendees (emails)" bind:value={schedulingAttendees} placeholder="alice@example.com, bob@example.com" />
		</div>
		<div class="form-row">
			<div class="form-group">
				<Input label="From" type="datetime-local" bind:value={schedulingStartDate} />
			</div>
			<div class="form-group">
				<Input label="To" type="datetime-local" bind:value={schedulingEndDate} />
			</div>
		</div>
		<div class="form-row">
			<div class="form-group">
				<Select label="Duration (min)" value={String(schedulingDuration)} onchange={(e) => schedulingDuration = parseInt((e.currentTarget as HTMLSelectElement).value)} options={[
					{ value: '15', label: '15 min' },
					{ value: '30', label: '30 min' },
					{ value: '45', label: '45 min' },
					{ value: '60', label: '1 hour' },
					{ value: '90', label: '1.5 hours' }
				]} />
			</div>
			<div class="form-group">
				<span class="field-sublabel">Working hours</span>
				<div class="time-row">
					<Input type="time" bind:value={schedulingWorkStart} />
					<span class="time-sep">&ndash;</span>
					<Input type="time" bind:value={schedulingWorkEnd} />
				</div>
			</div>
		</div>
	</form>

	{#snippet footer()}
		<Button type="button" variant="primary" size="md" disabled={schedulingLoading} onclick={handleFindFreeSlots}>
			{schedulingLoading ? 'Searching...' : 'Find slots'}
		</Button>
		<Button type="button" variant="secondary" size="md" onclick={closeSchedulingModal}>Cancel</Button>
	{/snippet}

	{#if schedulingError}
		<div class="sched-error">{schedulingError}</div>
	{/if}
	{#if freeSlots.length > 0}
		<div class="slots-list">
			<h3>Available slots ({freeSlots.length})</h3>
			{#each freeSlots as slot}
				<button
					type="button"
					class="slot-item"
					onclick={() => createFromSlot(slot)}
				>
					<div class="slot-time">
						{new Date(slot.start).toLocaleDateString(localeCode(), { weekday: 'short', month: 'short', day: 'numeric' })}
						<br />
						{new Date(slot.start).toLocaleTimeString(localeCode(), { hour: 'numeric', minute: '2-digit' })}
						&ndash;
						{new Date(slot.end).toLocaleTimeString(localeCode(), { hour: 'numeric', minute: '2-digit' })}
					</div>
					<div class="slot-meta">
						<span class="slot-score" class:best={slot.score >= 90}>Score: {slot.score}</span>
						<span class="slot-free-block">{slot.contiguousFreeMinutes} min free block</span>
						{#if slot.conflictCount > 0}
							<span class="slot-conflict">{t('calendar.scheduling.conflicts', { n: String(slot.conflictCount) })}</span>
						{/if}
					</div>
				</button>
			{/each}
		</div>
	{/if}
</Dialog>

<!-- Propose-new-time dialog (iTIP COUNTER: an invitee proposes new times to the organizer) -->
<Dialog
	open={showProposeModal}
	title={t('calendar.propose.title')}
	onClose={() => (showProposeModal = false)}
>
	<form onsubmit={(e) => { e.preventDefault(); handlePropose(); }}>
		<p class="propose-help">{t('calendar.propose.help')}</p>
		<div class="form-row">
			<div class="form-group">
				<Input label={t('calendar.propose.start')} type="datetime-local" bind:value={proposeStart} required />
			</div>
			<div class="form-group">
				<Input label={t('calendar.propose.end')} type="datetime-local" bind:value={proposeEnd} required />
			</div>
		</div>
		{#if proposeError}
			<div class="sched-error">{proposeError}</div>
		{/if}
	</form>

	{#snippet footer()}
		<Button type="button" variant="primary" size="md" disabled={proposing} onclick={handlePropose}>
			{proposing ? '…' : t('calendar.propose.send')}
		</Button>
		<Button type="button" variant="secondary" size="md" onclick={() => (showProposeModal = false)}>Cancel</Button>
	{/snippet}
</Dialog>

<!-- A3: Room finder (invite a room/equipment resource) -->
<RoomFinder open={showRoomFinder} requiredCapacity={0} onPick={onRoomPicked} onClose={() => (showRoomFinder = false)} />

<!-- A3: Share calendar -->
<ShareCalendarDialog open={showShareDialog} calendarId={shareCalendarId} calendarName={shareCalendarName} onClose={() => (showShareDialog = false)} />

<!-- A3: Open shared calendar -->
<Dialog open={showOpenSharedDialog} title={t('calendar.open_shared.title')} onClose={() => (showOpenSharedDialog = false)}>
	<form onsubmit={(e) => { e.preventDefault(); handleOpenShared(); }}>
		<div class="form-group">
			<Input label={t('calendar.open_shared.email')} type="email" bind:value={openSharedEmail} placeholder="alice@example.com" />
		</div>
		{#if openSharedError}
			<div class="cal-error">{openSharedError}</div>
		{/if}
	</form>
	{#snippet footer()}
		<Button type="button" variant="primary" size="md" onclick={handleOpenShared}>{t('calendar.open_shared.open')}</Button>
		<Button type="button" variant="secondary" size="md" onclick={() => (showOpenSharedDialog = false)}>{t('common.close')}</Button>
	{/snippet}
</Dialog>

<!-- Import calendar (.ics file) -->
<Dialog open={showImportDialog} title={t('calendar.import.title')} onClose={() => (showImportDialog = false)}>
	<form onsubmit={(e) => { e.preventDefault(); runImport(); }}>
		<div class="form-group">
			<label class="field-sublabel" for="ics-import-file">{t('calendar.import.file')}</label>
			<input id="ics-import-file" type="file" accept=".ics" bind:this={importFileEl} />
		</div>
		{#if writableCalendars.length > 0}
			<div class="form-group">
				<Select label={t('calendar.import.into')} bind:value={importCalendarId}
					options={writableCalendars.map((c) => ({ value: c.id, label: c.name }))} />
			</div>
		{/if}
		<div class="form-group">
			<Select label={t('calendar.import.strategy')} bind:value={importStrategy} options={[
				{ value: 'skip', label: t('calendar.import.skip') },
				{ value: 'rename', label: t('calendar.import.rename') },
				{ value: 'overwrite', label: t('calendar.import.overwrite') }
			]} />
		</div>
		{#if importError}
			<div class="cal-error">{importError}</div>
		{/if}
		{#if importResult}
			<div class="import-result">{importResult}</div>
		{/if}
	</form>
	{#snippet footer()}
		<Button type="button" variant="primary" size="md" disabled={importing} onclick={runImport}>
			{importing ? '…' : t('calendar.import.run')}
		</Button>
		<Button type="button" variant="secondary" size="md" onclick={() => (showImportDialog = false)}>{t('common.close')}</Button>
	{/snippet}
</Dialog>

<!-- Subscribe to a webcal/ICS URL (WAVE-5 #10) — a live external calendar,
     mirrored read-only, synced on a background tick. -->
<Dialog open={showSubscribeDialog} title={t('calendar.subscribe.title')} onClose={() => (showSubscribeDialog = false)}>
	<form onsubmit={(e) => { e.preventDefault(); runSubscribe(); }}>
		<div class="form-group">
			<Input label={t('calendar.subscribe.url_label')} type="url" placeholder="webcal://example.com/feed.ics"
				bind:value={subscribeUrl} autofocus />
		</div>
		<div class="form-group">
			<Input label={t('calendar.subscribe.name_label')} bind:value={subscribeName} placeholder={t('calendar.subscribe.name_placeholder')} />
		</div>
		{#if subscribeError}
			<div class="cal-error">{subscribeError}</div>
		{/if}
	</form>
	{#snippet footer()}
		<Button type="button" variant="primary" size="md" disabled={subscribing} onclick={runSubscribe}>
			{subscribing ? '…' : t('calendar.subscribe.run')}
		</Button>
		<Button type="button" variant="secondary" size="md" onclick={() => (showSubscribeDialog = false)}>{t('common.close')}</Button>
	{/snippet}
</Dialog>

<!-- A3: Occurrence-vs-series prompt for recurring edits AND deletes (Task 11) -->
<Dialog
	open={showScopePrompt}
	title={t(scopeIntent === 'delete' ? 'calendar.scope.deleteTitle' : 'calendar.scope.title')}
	onClose={cancelScope}
>
	<p class="scope-prompt">{t(scopeIntent === 'delete' ? 'calendar.scope.deletePrompt' : 'calendar.scope.prompt')}</p>
	{#snippet footer()}
		<Button
			type="button"
			variant={scopeIntent === 'delete' ? 'danger' : 'primary'}
			size="md"
			onclick={() => applyScope('this')}
		>{t('calendar.scope.this')}</Button>
		<Button
			type="button"
			variant={scopeIntent === 'delete' ? 'danger' : 'secondary'}
			size="md"
			onclick={() => applyScope('following')}
		>{t('calendar.scope.following')}</Button>
		<Button
			type="button"
			variant={scopeIntent === 'delete' ? 'danger' : 'secondary'}
			size="md"
			onclick={() => applyScope('series')}
		>{t('calendar.scope.series')}</Button>
	{/snippet}
</Dialog>

<style>
	/* — Layout — */
	.calendar-app {
		display: flex;
		flex-direction: column;
		flex: 1;
		overflow: hidden;
		background: var(--surface-card);
	}

	/* — Sidebar — */
	.sidebar-title {
		font-size: var(--text-sm);
		font-weight: var(--weight-semibold);
		color: var(--text-secondary);
		padding: var(--space-3) var(--space-4) var(--space-2);
		margin: 0;
	}
	.calendar-list {
		list-style: none;
		padding: 0;
		margin: 0;
	}
	.calendar-list li {
		margin-bottom: 0;
	}
	.cal-item {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: 2px var(--space-4);
	}
	.cal-dot {
		width: 10px;
		height: 10px;
		border-radius: var(--radius-full);
		flex-shrink: 0;
	}
	.cal-sub-icon {
		display: flex;
		align-items: center;
		color: var(--text-secondary);
		flex-shrink: 0;
	}
	.cal-sub-dot {
		width: 6px;
		height: 6px;
		border-radius: var(--radius-full);
		flex-shrink: 0;
	}
	.cal-sub-dot--error {
		background: var(--danger-solid);
	}
	.cal-sub-dot--partial {
		background: var(--warning-solid);
	}
	.cal-sub-synced {
		margin-left: auto;
		font-size: var(--text-xs);
		color: var(--text-caption);
		white-space: nowrap;
	}

	/* — Sidebar view options (working hours + second time zone) — */
	.view-opts {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		padding: 0 var(--space-4) var(--space-3);
	}
	.opt-group {
		display: flex;
		flex-direction: column;
		gap: 4px;
	}
	.tz2-select {
		height: var(--control-height);
		padding: 0 8px;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-primary);
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		width: 100%;
	}

	/* — Toolbar — */
	.toolbar {
		display: flex;
		gap: var(--space-2);
		padding: 0;
		align-items: center;
		flex-wrap: wrap;
	}
	.nav {
		display: flex;
		gap: 4px;
		align-items: center;
	}
	.nav-title {
		font-weight: var(--weight-semibold);
		margin-left: var(--space-2);
		font-size: var(--text-md);
		color: var(--text-primary);
		white-space: nowrap;
	}
	.view-toggle {
		display: flex;
		gap: 4px;
		margin-left: auto;
	}

	/* — Error / Loading — */
	.cal-error {
		color: var(--danger-fg);
		font-size: var(--text-sm);
		padding: var(--space-2) var(--space-4);
		background: var(--danger-bg);
		margin: 0;
	}
	.cal-loading {
		display: flex;
		align-items: center;
		justify-content: center;
		padding: var(--space-8);
	}

	/* — Month view — */
	.month-grid {
		display: grid;
		grid-template-columns: repeat(7, 1fr);
		flex: 1;
		overflow: auto;
	}
	.day-header {
		padding: var(--space-2);
		text-align: center;
		font-size: var(--text-xs);
		font-weight: var(--weight-semibold);
		color: var(--text-tertiary);
		border-bottom: 1px solid var(--border-default);
	}
	.month-cell {
		border-right: 1px solid var(--border-default);
		border-bottom: 1px solid var(--border-default);
		padding: 6px;
		min-height: 80px;
		cursor: pointer;
	}
	.month-cell.other-month {
		background: var(--surface-sunken);
		color: var(--text-tertiary);
	}
	.month-cell.today {
		background: var(--surface-selected);
	}
	.day-num {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		display: block;
		margin-bottom: 4px;
	}
	.event-pill {
		display: block;
		width: 100%;
		padding: 2px 4px;
		margin-bottom: 2px;
		border-radius: var(--radius-xs);
		font-size: var(--text-2xs);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
		border: none;
		cursor: pointer;
		text-align: left;
	}
	.event-pill:hover {
		opacity: 0.85;
	}
	.task-pill {
		background: var(--surface-sunken);
		display: flex;
		align-items: center;
		gap: 3px;
	}
	.more-events {
		font-size: var(--text-2xs);
		color: var(--text-tertiary);
	}

	/* — Week / Day time grid — */
	.time-grid {
		display: flex;
		flex: 1;
		overflow: auto;
	}
	.time-gutter {
		width: 50px;
		flex-shrink: 0;
		border-right: 1px solid var(--border-default);
		padding-top: 40px;
	}
	.time-label {
		height: 40px;
		font-size: var(--text-2xs);
		color: var(--text-tertiary);
		text-align: right;
		padding-right: 6px;
		border-bottom: 1px solid var(--border-subtle);
	}
	.day-column {
		flex: 1;
		position: relative;
		border-right: 1px solid var(--border-default);
		min-width: 100px;
	}
	.day-column.today {
		background: var(--surface-selected);
	}
	.day-column-header {
		height: 40px;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		border-bottom: 1px solid var(--border-default);
		font-size: var(--text-xs);
	}
	.day-name {
		font-size: var(--text-2xs);
		color: var(--text-tertiary);
	}
	.day-number {
		font-weight: var(--weight-semibold);
	}
	.day-number.highlight {
		background: var(--accent);
		color: var(--text-inverse);
		width: 24px;
		height: 24px;
		border-radius: var(--radius-full);
		display: flex;
		align-items: center;
		justify-content: center;
	}
	.hour-slot {
		display: block;
		width: 100%;
		height: 40px;
		border: none;
		border-bottom: 1px solid var(--border-subtle);
		background: none;
		cursor: pointer;
		padding: 0;
	}
	.hour-slot.off-hours {
		/* Subtle non-working-hours tint. Declared before :hover so hover feedback still wins. */
		background: var(--surface-sunken);
	}
	.hour-slot:hover {
		background: var(--surface-hover);
	}
	.timed-event {
		position: absolute;
		left: 2px;
		right: 2px;
		padding: 2px 6px;
		border-radius: var(--radius-xs);
		font-size: var(--text-2xs);
		overflow: hidden;
		border: none;
		cursor: pointer;
		text-align: left;
	}
	.timed-event:hover {
		opacity: 0.85;
	}
	.timed-event.draggable {
		cursor: grab;
		touch-action: none;   /* pointer drag owns the gesture, not scroll, on touch */
	}
	.timed-event.dragging {
		cursor: grabbing;
		opacity: 0.85;
	}
	.resize-handle {
		position: absolute;
		bottom: 0;
		left: 0;
		right: 0;
		height: 6px;
		cursor: ns-resize;
		touch-action: none;
	}
	.allday-event {
		position: absolute;
		left: 2px;
		right: 2px;
		top: 42px;
		padding: 2px 6px;
		border-radius: var(--radius-xs);
		font-size: var(--text-2xs);
		border: none;
		cursor: pointer;
		text-align: left;
	}
	.allday-event:hover {
		opacity: 0.85;
	}
	.ev-time {
		font-size: var(--text-2xs);
		opacity: 0.9;
	}
	.ev-title {
		font-weight: var(--weight-semibold);
	}
	.ev-loc {
		font-size: var(--text-2xs);
		opacity: 0.8;
	}

	/* — Agenda — */
	.agenda-view {
		flex: 1;
		overflow: auto;
		padding: var(--space-4);
	}
	.agenda-item {
		display: flex;
		gap: var(--space-3);
		padding: var(--space-3);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		margin-bottom: var(--space-2);
		background: var(--surface-card);
		cursor: pointer;
		width: 100%;
		text-align: left;
	}
	.agenda-item:hover {
		background: var(--surface-hover);
	}
	.color-bar {
		width: 4px;
		border-radius: 2px;
		flex-shrink: 0;
	}
	.agenda-info {
		flex: 1;
	}
	.agenda-title {
		font-weight: var(--weight-medium);
		font-size: var(--text-md);
	}
	.agenda-time {
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.agenda-loc {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}

	/* — Dialog form inputs — */
	.detail-row {
		margin-bottom: var(--space-2);
		font-size: var(--text-sm);
	}
	.detail-label {
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		margin-right: var(--space-2);
	}
	.detail-desc {
		white-space: pre-wrap;
	}
	.rsvp-roster {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
		margin-top: 4px;
	}
	.rsvp-count {
		font-size: var(--text-xs);
		padding: 2px 6px;
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		color: var(--text-caption);
	}
	.rsvp-count.accepted { background: var(--success-bg); color: var(--success-fg); }
	.rsvp-count.tentative { background: var(--warning-bg); color: var(--warning-fg); }
	.rsvp-count.declined { background: var(--danger-bg); color: var(--danger-fg); }
	.attendee-list {
		margin-top: 4px;
	}
	.attendee {
		display: flex;
		justify-content: space-between;
		padding: 4px 0;
		border-bottom: 1px solid var(--border-subtle);
	}
	.attendee-meta {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.attendee-role {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		text-transform: capitalize;
	}
	.rsvp-status {
		font-size: var(--text-xs);
		padding: 2px 6px;
		border-radius: var(--radius-sm);
		text-transform: capitalize;
	}
	.rsvp-status.accepted { background: var(--success-bg); color: var(--success-fg); }
	.rsvp-status.tentative { background: var(--warning-bg); color: var(--warning-fg); }
	.rsvp-status.declined { background: var(--danger-bg); color: var(--danger-fg); }

	.form-group {
		margin-bottom: var(--space-3);
	}
	.field-sublabel {
		display: block;
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		margin-bottom: 4px;
	}
	.event-color-controls {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.event-color-input {
		width: 40px;
		height: 32px;
		padding: 0;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-xs);
		background: none;
		cursor: pointer;
	}
	.form-row {
		display: flex;
		gap: var(--space-2);
	}
	.form-row .form-group {
		flex: 1;
	}

	/* — A3: badges, editor actions, resource chips, scope prompt — */
	.cal-badge {
		margin-left: auto;
		font-size: var(--text-xs);
		color: var(--text-secondary);
		background: var(--surface-sunken, var(--surface-card));
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-sm);
		padding: 0 var(--space-1);
	}
	.editor-actions {
		display: flex;
		gap: var(--space-2);
	}
	.resource-chips {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-1);
	}
	.resource-chip {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		padding: 2px var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-pill, var(--radius-sm));
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.chip-remove {
		border: none;
		background: none;
		cursor: pointer;
		color: var(--text-secondary);
		font-size: var(--text-md);
		line-height: 1;
	}
	.scope-prompt {
		margin: 0;
		color: var(--text-primary);
	}
	.import-result {
		color: var(--success-fg);
		font-size: var(--text-sm);
		margin-top: var(--space-2);
	}

	/* — Scheduling assistant — */
	.time-row {
		display: flex;
		align-items: center;
		gap: 4px;
	}
	.time-sep {
		color: var(--text-tertiary);
		font-size: var(--text-sm);
	}
	.sched-error {
		color: var(--danger-fg);
		font-size: var(--text-xs);
		margin: var(--space-2) 0;
		padding: var(--space-2);
		background: var(--danger-bg);
		border-radius: var(--radius-sm);
	}
	.propose-help {
		color: var(--text-tertiary);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-3);
	}
	.slots-list {
		margin-top: var(--space-3);
		border-top: 1px solid var(--border-default);
		padding-top: var(--space-3);
		max-height: 350px;
		overflow-y: auto;
	}
	.slots-list h3 {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		margin: 0 0 var(--space-2) 0;
		font-weight: var(--weight-medium);
	}
	.slot-item {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3);
		width: 100%;
		padding: var(--space-2) var(--space-3);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		background: var(--surface-card);
		cursor: pointer;
		margin-bottom: 6px;
		text-align: left;
		font-size: var(--text-xs);
		transition: border-color var(--duration-fast);
	}
	.slot-item:hover {
		border-color: var(--success-solid);
		background: var(--success-bg);
	}
	.slot-time {
		font-weight: var(--weight-medium);
		line-height: var(--leading-snug);
		min-width: 0;
	}
	.slot-meta {
		display: flex;
		flex-direction: column;
		align-items: flex-end;
		gap: 2px;
		flex-shrink: 0;
	}
	.slot-score {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
	.slot-score.best {
		color: var(--success-fg);
		font-weight: var(--weight-semibold);
	}
	.slot-free-block {
		font-size: var(--text-2xs);
		color: var(--text-tertiary);
	}
	.slot-conflict {
		font-size: var(--text-2xs);
		color: var(--warning-fg);
		background: var(--warning-bg);
		border-radius: 3px;
		padding: 0 4px;
	}
</style>
