import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import CalendarApp from './CalendarApp.svelte';
import {
	createEvent,
	findFreeSlots,
	openSharedCalendar,
	sendMeetingUpdate,
	listResources,
	listDelegations,
	rsvpOnBehalf,
	updateOccurrence
} from '$lib/stores/calendar';
import { selectedDate, viewMode } from '$lib/stores/calendar';
import { calendarEvents } from '$lib/stores/calendarEvents.svelte';
import { createMeeting } from '$lib/meet/api';

vi.mock('$lib/meet/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/meet/api')>('$lib/meet/api');
	return { ...actual, createMeeting: vi.fn() };
});

function mockStore<T>(initial: T) {
	let val = initial;
	const subs = new Set<(v: T) => void>();
	return {
		subscribe: vi.fn((cb: (v: T) => void) => { cb(val); subs.add(cb); return () => subs.delete(cb); }),
		set: vi.fn((v: T) => { val = v; for (const cb of subs) cb(v); }),
		update: vi.fn(),
	};
}

vi.mock('$lib/stores/calendar', () => ({
	calendars: mockStore([{id:'cal1', name:'Personal', color:'#4A90D9'}]),
	selectedDate: mockStore(new Date('2026-06-15')),
	selectedCalendarIds: mockStore(['cal1']),
	viewMode: mockStore('month'),
	visibleCalendarIds: mockStore(['cal1']),
	identities: mockStore([]),
	sharedOwners: mockStore([]),
	loadCalendars: vi.fn(),
	createEvent: vi.fn(),
	updateEvent: vi.fn(),
	deleteEvent: vi.fn(),
	rsvpEvent: vi.fn(),
	proposeNewTime: vi.fn(async () => ({})),
	toggleCalendarVisibility: vi.fn(),
	getViewRange: vi.fn(() => ({ start: new Date('2026-06-01'), end: new Date('2026-07-01') })),
	findFreeSlots: vi.fn(async () => []),
	loadIdentities: vi.fn(),
	openSharedCalendar: vi.fn(async () => []),
	shareCalendar: vi.fn(async () => {}),
	revokeShare: vi.fn(async () => {}),
	loadShares: vi.fn(async () => []),
	listDelegations: vi.fn(async () => []),
	rsvpOnBehalf: vi.fn(async () => ({})),
	updateOccurrence: vi.fn(async () => ({ ok: true })),
	listResources: vi.fn(async () => []),
	sendMeetingUpdate: vi.fn(async () => ({ sequence: 1 })),
}));

// The events bag is a rune-class store (CalendarEventsStore); the mock is a plain
// object with the same surface — tests assign `calendarEvents.events` before render.
vi.mock('$lib/stores/calendarEvents.svelte', () => ({
	calendarEvents: {
		events: [],
		loading: false,
		load: vi.fn(async () => {}),
		reload: vi.fn(async () => {}),
		patchEventTimes: vi.fn(),
		mergeShared: vi.fn(),
		reset: vi.fn(),
	},
}));

// QoL #16 — task-due feed into the calendar grid. A minimal store literal (no
// external import — vi.hoisted runs before module imports resolve) with the
// same subscribe/set surface CalendarApp's `$taskStore` needs.
const tasksStoreMock = vi.hoisted(() => {
	let val: import('$lib/types/jmap').Task[] = [];
	const subs = new Set<(v: import('$lib/types/jmap').Task[]) => void>();
	return {
		subscribe: (cb: (v: import('$lib/types/jmap').Task[]) => void) => { cb(val); subs.add(cb); return () => subs.delete(cb); },
		set: (v: import('$lib/types/jmap').Task[]) => { val = v; for (const cb of subs) cb(v); },
	};
});
vi.mock('$lib/stores/tasks', () => ({
	tasks: tasksStoreMock,
	loadTasks: vi.fn(async () => {}),
	priorityColor: (p: number) => (p >= 9 ? 'var(--danger-fg)' : p >= 5 ? 'var(--warning-fg)' : 'var(--success-fg)'),
}));

vi.mock('$lib/jmap/websocket', () => ({
	connect: vi.fn(),
	disconnect: vi.fn(),
	subscribe: vi.fn(() => () => {}),
}));

// Webcal/ICS subscribe (WAVE-5 #10) — a real forCalendar() over a
// test-controlled `subscriptions` array (mirrors the real store's field), so
// each test can preset "this calendar is subscribed" without a network call.
// vi.hoisted: vi.mock factories are hoisted above all imports/consts, so the
// mock object referenced inside must be created through vi.hoisted (a plain
// top-level const would throw "Cannot access before initialization").
import type { CalendarSubscription } from '$lib/stores/calendarSubscriptions.svelte';
const calendarSubscriptionsMock = vi.hoisted(() => ({
	subscriptions: [] as CalendarSubscription[],
	loaded: false,
	forCalendar(this: { subscriptions: CalendarSubscription[] }, calendarId: string) {
		return this.subscriptions.find((s) => s.calendarId === calendarId);
	},
	load: vi.fn(async () => {}),
	subscribe: vi.fn(async (url: string, name?: string) => ({
		id: 99, calendarId: 'cal-new', calendarName: name ?? 'Subscribed calendar',
		url, lastFetchAt: null, lastStatus: 'pending' as const, lastError: null, refreshIntervalMinutes: 15
	})),
	unsubscribe: vi.fn(async () => {}),
	reset: vi.fn(),
}));
vi.mock('$lib/stores/calendarSubscriptions.svelte', () => ({
	calendarSubscriptions: calendarSubscriptionsMock,
	formatSyncedAgo: (v: string | null) => (v ? 'Updated 2h ago' : 'Not synced yet'),
}));

describe('CalendarApp', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		viewMode.set('month');
		selectedDate.set(new Date('2026-06-15'));
		calendarEvents.events = [];
		calendarSubscriptionsMock.subscriptions = [];
		tasksStoreMock.set([]);
	});

	it('renders the calendar-app root element', () => {
		const { container } = render(CalendarApp);
		const root = container.querySelector('.calendar-app');
		expect(root).toBeTruthy();
	});

	it('renders the pim topbar title "Calendar"', () => {
		render(CalendarApp);
		const title = screen.getByText('Calendar');
		expect(title).toBeTruthy();
		expect(title.classList.contains('pim-topbar__title')).toBe(true);
	});

	it('renders month grid with clickable cells', async () => {
		const { container } = render(CalendarApp);
		await vi.waitFor(() => {
			const cells = container.querySelectorAll('.month-cell');
			expect(cells.length).toBeGreaterThan(0);
		});
		// Month cells should be keyboard-accessible
		const firstCell = container.querySelector('.month-cell') as HTMLElement;
		expect(firstCell.getAttribute('role')).toBe('button');
		expect(firstCell.getAttribute('tabindex')).toBe('0');
	});

	// QoL #16 — task due dates surfaced on the month grid.
	it('renders a task-pill on the day the task is due, and only that day', async () => {
		tasksStoreMock.set([
			{
				id: 't1',
				title: 'File report',
				status: 'needs-action',
				priority: 9,
				dueAt: '2026-06-15T12:00:00Z'
			} as import('$lib/types/jmap').Task
		]);
		const { container } = render(CalendarApp);
		await vi.waitFor(() => {
			expect(container.querySelectorAll('.month-cell').length).toBeGreaterThan(0);
		});
		const pills = container.querySelectorAll('.task-pill');
		expect(pills.length).toBe(1);
		expect(pills[0].textContent).toContain('File report');
	});

	it('month cell responds to Space key (not only Enter)', async () => {
		const { container } = render(CalendarApp);
		await vi.waitFor(() => {
			expect(container.querySelectorAll('.month-cell').length).toBeGreaterThan(0);
		});
		const firstCell = container.querySelector('.month-cell') as HTMLElement;
		// A keydown handler (not deprecated keypress) must be present and handle Space.
		await fireEvent.keyDown(firstCell, { key: ' ' });
		await waitFor(() => {
			// The create dialog is open only when its Title input is rendered.
			expect(screen.getByLabelText('Title')).toBeTruthy();
		});
	});

	it('clicking Create in the event dialog calls createEvent', async () => {
		render(CalendarApp);
		// Open the create dialog via the New event button
		fireEvent.click(screen.getByText('New event').closest('button')!);
		await waitFor(() => {
			expect(screen.getByLabelText('Title')).toBeTruthy();
		});
		fireEvent.input(screen.getByLabelText('Title'), { target: { value: 'Test Event' } });
		// Click the primary Create button in the dialog footer
		const createBtn = screen.getByText('Create').closest('button')!;
		fireEvent.click(createBtn);
		await waitFor(() => {
			expect(createEvent).toHaveBeenCalled();
		});
	});

	it('Meet B1 Task 16: checking "Add setjoin Meet" on a new event creates a bound meeting after the event saves', async () => {
		vi.mocked(createEvent).mockResolvedValue({ created: { k1: '777' } } as unknown as Awaited<ReturnType<typeof createEvent>>);
		render(CalendarApp);
		fireEvent.click(screen.getByText('New event').closest('button')!);
		await waitFor(() => expect(screen.getByLabelText('Title')).toBeTruthy());
		fireEvent.input(screen.getByLabelText('Title'), { target: { value: 'Standup' } });
		fireEvent.click(screen.getByLabelText('Add setjoin Meet'));
		fireEvent.click(screen.getByText('Create').closest('button')!);
		await waitFor(() => expect(createEvent).toHaveBeenCalled());
		await waitFor(() =>
			expect(createMeeting).toHaveBeenCalledWith(expect.objectContaining({ title: 'Standup', calendarEventId: 777 })),
		);
	});

	it('clicking Find slots in the scheduling dialog calls findFreeSlots', async () => {
		render(CalendarApp);
		fireEvent.click(screen.getByText('Find a time').closest('button')!);
		await waitFor(() => {
			expect(screen.getByLabelText('Attendees (emails)')).toBeTruthy();
		});
		fireEvent.input(screen.getByLabelText('Attendees (emails)'), { target: { value: 'a@b.com' } });
		const findBtn = screen.getByText('Find slots').closest('button')!;
		fireEvent.click(findBtn);
		await waitFor(() => {
			expect(findFreeSlots).toHaveBeenCalled();
		});
	});

	// QoL #19 — scheduling assistant conflict ranking.
	it('renders a conflict badge when findFreeSlots returns a slot with conflictCount > 0', async () => {
		vi.mocked(findFreeSlots).mockResolvedValueOnce([
			{
				start: '2026-06-15T10:00:00Z',
				end: '2026-06-15T10:30:00Z',
				score: 42,
				contiguousFreeMinutes: 30,
				conflictCount: 1
			}
		]);
		render(CalendarApp);
		fireEvent.click(screen.getByText('Find a time').closest('button')!);
		await waitFor(() => {
			expect(screen.getByLabelText('Attendees (emails)')).toBeTruthy();
		});
		fireEvent.input(screen.getByLabelText('Attendees (emails)'), { target: { value: 'a@b.com' } });
		fireEvent.click(screen.getByText('Find slots').closest('button')!);
		await waitFor(() => {
			expect(document.querySelector('.slot-conflict')).toBeTruthy();
		});
	});

	// ── A3 wiring ──

	it('the event editor renders the RecurrenceEditor (interval/BYDAY/end), not a fixed Repeat select', async () => {
		render(CalendarApp);
		fireEvent.click(screen.getByText('New event').closest('button')!);
		await waitFor(() => expect(screen.getByLabelText('Title')).toBeTruthy());
		// RecurrenceEditor exposes a "Repeat" frequency select with a "does not repeat" option,
		// and (when weekly) interval + weekday toggles — none of which the old fixed select had.
		const repeat = screen.getByLabelText('Repeat') as HTMLSelectElement;
		expect(Array.from(repeat.options).some((o) => o.value === 'WEEKLY')).toBe(true);
		await fireEvent.change(repeat, { target: { value: 'WEEKLY' } });
		await waitFor(() => expect(screen.getByLabelText('Every')).toBeTruthy());
		expect(screen.getByRole('button', { name: 'Mo' })).toBeTruthy();
	});

	it('a toolbar "Open shared calendar" action calls openSharedCalendar with the owner email', async () => {
		render(CalendarApp);
		fireEvent.click(screen.getByText('Open shared calendar').closest('button')!);
		await waitFor(() => expect(screen.getByLabelText("Owner's email")).toBeTruthy());
		fireEvent.input(screen.getByLabelText("Owner's email"), { target: { value: 'alice@x.test' } });
		fireEvent.click(screen.getByText('Open').closest('button')!);
		await waitFor(() => {
			expect(openSharedCalendar).toHaveBeenCalledWith('alice@x.test');
		});
	});

	it('the editor "Add room" action opens the RoomFinder', async () => {
		render(CalendarApp);
		fireEvent.click(screen.getByText('New event').closest('button')!);
		await waitFor(() => expect(screen.getByLabelText('Title')).toBeTruthy());
		fireEvent.click(screen.getByText('Add room').closest('button')!);
		await waitFor(() => {
			expect(listResources).toHaveBeenCalled();
		});
	});

	it('the editor has an "Add Scheduling Assistant" affordance that opens the scheduling dialog prefilled', async () => {
		render(CalendarApp);
		fireEvent.click(screen.getByText('New event').closest('button')!);
		await waitFor(() => expect(screen.getByLabelText('Title')).toBeTruthy());
		fireEvent.input(screen.getByLabelText('Attendees (comma-separated emails)'), { target: { value: 'x@y.com' } });
		fireEvent.click(screen.getByText('Add Scheduling Assistant').closest('button')!);
		await waitFor(() => {
			// The scheduling dialog is open (its Attendees field is rendered), prefilled.
			const sched = screen.getByLabelText('Attendees (emails)') as HTMLInputElement;
			expect(sched.value).toContain('x@y.com');
		});
	});

	// ── per-event color ──

	function eventPill(container: HTMLElement, title: string): HTMLElement | undefined {
		return Array.from(container.querySelectorAll<HTMLElement>('.event-pill')).find((p) =>
			p.textContent?.includes(title)
		);
	}

	it('an event with its own color renders with that (safeColor-guarded) color', async () => {
		calendarEvents.events = [
			{ id: 'e1', calendarId: 'cal1', title: 'Colored', start: '2026-06-15T10:00:00Z', end: '2026-06-15T11:00:00Z', color: '#ff0000' }
		];
		const { container } = render(CalendarApp);
		await vi.waitFor(() => expect(eventPill(container, 'Colored')).toBeTruthy());
		// jsdom serializes the inline style's #hex to rgb().
		expect(eventPill(container, 'Colored')!.getAttribute('style')).toContain('rgb(255, 0, 0)');
	});

	it('an event without a color falls back to the calendar color', async () => {
		calendarEvents.events = [
			{ id: 'e2', calendarId: 'cal1', title: 'Plain', start: '2026-06-15T10:00:00Z', end: '2026-06-15T11:00:00Z' }
		];
		const { container } = render(CalendarApp);
		await vi.waitFor(() => expect(eventPill(container, 'Plain')).toBeTruthy());
		// cal1's color from the mocked store (#4A90D9 → rgb).
		expect(eventPill(container, 'Plain')!.getAttribute('style')).toContain('rgb(74, 144, 217)');
	});

	it('a malicious (non-hex) event color is dropped, not interpolated raw', async () => {
		calendarEvents.events = [
			{ id: 'e3', calendarId: 'cal1', title: 'Evil', start: '2026-06-15T10:00:00Z', end: '2026-06-15T11:00:00Z', color: 'red;position:fixed;inset:0' }
		];
		const { container } = render(CalendarApp);
		await vi.waitFor(() => expect(eventPill(container, 'Evil')).toBeTruthy());
		const style = eventPill(container, 'Evil')!.getAttribute('style') ?? '';
		expect(style).not.toContain('position:fixed');
		expect(style).toContain('var(--app-calendar)');
	});

	it('picking a color in the editor includes it in the created event patch', async () => {
		render(CalendarApp);
		fireEvent.click(screen.getByText('New event').closest('button')!);
		await waitFor(() => expect(screen.getByLabelText('Title')).toBeTruthy());
		fireEvent.input(screen.getByLabelText('Title'), { target: { value: 'Party' } });
		fireEvent.input(screen.getByLabelText('Color'), { target: { value: '#00ff00' } });
		fireEvent.click(screen.getByText('Create').closest('button')!);
		await waitFor(() => {
			expect(createEvent).toHaveBeenCalledWith(expect.objectContaining({ color: '#00ff00' }));
		});
	});

	// ── Show-as (organizer free/busy status) ──

	it('defaults freeBusyStatus to busy and includes the chosen value in the created event patch', async () => {
		render(CalendarApp);
		fireEvent.click(screen.getByText('New event').closest('button')!);
		await waitFor(() => expect(screen.getByLabelText('Title')).toBeTruthy());
		fireEvent.input(screen.getByLabelText('Title'), { target: { value: 'Focus' } });
		const showAs = screen.getByLabelText('Show as') as HTMLSelectElement;
		expect(showAs.value).toBe('busy');
		await fireEvent.change(showAs, { target: { value: 'free' } });
		fireEvent.click(screen.getByText('Create').closest('button')!);
		await waitFor(() => {
			expect(createEvent).toHaveBeenCalledWith(expect.objectContaining({ freeBusyStatus: 'free' }));
		});
	});

	it('editing an event pre-selects its freeBusyStatus in the Show-as select', async () => {
		calendarEvents.events = [
			{ id: 'e5', calendarId: 'cal1', title: 'Tentative one', start: '2026-06-15T10:00:00Z', end: '2026-06-15T11:00:00Z', freeBusyStatus: 'tentative' }
		];
		const { container } = render(CalendarApp);
		await vi.waitFor(() => expect(eventPill(container, 'Tentative one')).toBeTruthy());
		fireEvent.click(eventPill(container, 'Tentative one')!);
		// Detail dialog → Edit opens the editor.
		await waitFor(() => expect(screen.getByText('Edit').closest('button')).toBeTruthy());
		fireEvent.click(screen.getByText('Edit').closest('button')!);
		await waitFor(() => {
			const showAs = screen.getByLabelText('Show as') as HTMLSelectElement;
			expect(showAs.value).toBe('tentative');
		});
	});

	// ── Private (event privacy) ──

	it('checking the Private box sets privacy:private in the created event patch', async () => {
		render(CalendarApp);
		fireEvent.click(screen.getByText('New event').closest('button')!);
		await waitFor(() => expect(screen.getByLabelText('Title')).toBeTruthy());
		fireEvent.input(screen.getByLabelText('Title'), { target: { value: 'Secret' } });
		const priv = screen.getByLabelText('Private') as HTMLInputElement;
		expect(priv.checked).toBe(false); // defaults to public (unchecked)
		fireEvent.click(priv);
		fireEvent.click(screen.getByText('Create').closest('button')!);
		await waitFor(() => {
			expect(createEvent).toHaveBeenCalledWith(expect.objectContaining({ privacy: 'private' }));
		});
	});

	it('editing a private event pre-checks the Private box', async () => {
		calendarEvents.events = [
			{ id: 'e6', calendarId: 'cal1', title: 'Hidden', start: '2026-06-15T10:00:00Z', end: '2026-06-15T11:00:00Z', privacy: 'private' }
		];
		const { container } = render(CalendarApp);
		await vi.waitFor(() => expect(eventPill(container, 'Hidden')).toBeTruthy());
		fireEvent.click(eventPill(container, 'Hidden')!);
		await waitFor(() => expect(screen.getByText('Edit').closest('button')).toBeTruthy());
		fireEvent.click(screen.getByText('Edit').closest('button')!);
		await waitFor(() => {
			const priv = screen.getByLabelText('Private') as HTMLInputElement;
			expect(priv.checked).toBe(true);
		});
	});

	// ── Webcal/ICS subscribe (WAVE-5 #10) ──

	it('clicking "Subscribe to calendar" opens the subscribe dialog', async () => {
		render(CalendarApp);
		fireEvent.click(screen.getByText('Subscribe to calendar').closest('button')!);
		await waitFor(() => {
			expect(screen.getByLabelText('Calendar URL')).toBeTruthy();
		});
	});

	it('submitting the subscribe dialog calls calendarSubscriptions.subscribe with the URL and name', async () => {
		render(CalendarApp);
		fireEvent.click(screen.getByText('Subscribe to calendar').closest('button')!);
		await waitFor(() => expect(screen.getByLabelText('Calendar URL')).toBeTruthy());
		fireEvent.input(screen.getByLabelText('Calendar URL'), { target: { value: 'webcal://ex.test/feed.ics' } });
		fireEvent.input(screen.getByLabelText('Name'), { target: { value: 'Team Holidays' } });
		fireEvent.click(screen.getByText('Subscribe').closest('button')!);
		await waitFor(() => {
			expect(calendarSubscriptionsMock.subscribe).toHaveBeenCalledWith('webcal://ex.test/feed.ics', 'Team Holidays');
		});
	});

	it('submitting the subscribe dialog with an empty URL shows a validation error and does not call subscribe', async () => {
		render(CalendarApp);
		fireEvent.click(screen.getByText('Subscribe to calendar').closest('button')!);
		await waitFor(() => expect(screen.getByLabelText('Calendar URL')).toBeTruthy());
		fireEvent.click(screen.getByText('Subscribe').closest('button')!);
		await waitFor(() => {
			expect(screen.getByText('Enter a calendar URL first.')).toBeTruthy();
		});
		expect(calendarSubscriptionsMock.subscribe).not.toHaveBeenCalled();
	});

	it("a subscribed calendar's row renders a Globe icon and its synced-ago text", async () => {
		calendarSubscriptionsMock.subscriptions = [{
			id: 1, calendarId: 'cal1', calendarName: 'Personal', url: 'https://ex.test/a.ics',
			lastFetchAt: '2026-06-15T08:00:00Z', lastStatus: 'ok', lastError: null, refreshIntervalMinutes: 15
		}];
		const { container } = render(CalendarApp);
		await waitFor(() => {
			expect(container.querySelector('.cal-sub-icon')).toBeTruthy();
			expect(screen.getByText('Updated 2h ago')).toBeTruthy();
		});
	});

	it("a subscribed calendar's row shows a failure dot when the last sync errored", async () => {
		calendarSubscriptionsMock.subscriptions = [{
			id: 1, calendarId: 'cal1', calendarName: 'Personal', url: 'https://ex.test/a.ics',
			lastFetchAt: '2026-06-15T08:00:00Z', lastStatus: 'error', lastError: "Couldn't reach that URL", refreshIntervalMinutes: 15
		}];
		const { container } = render(CalendarApp);
		await waitFor(() => {
			expect(container.querySelector('.cal-sub-dot--error')).toBeTruthy();
		});
		expect(container.querySelector('.cal-sub-dot--partial')).toBeFalsy();
	});

	it('a non-subscribed calendar row shows the ordinary Share button, not the subscription controls', () => {
		const { container } = render(CalendarApp);
		expect(container.querySelector('.cal-sub-icon')).toBeFalsy();
		expect(screen.getByLabelText('Share')).toBeTruthy();
	});

	it('clicking Unsubscribe, after confirming, calls calendarSubscriptions.unsubscribe with the subscription id', async () => {
		calendarSubscriptionsMock.subscriptions = [{
			id: 42, calendarId: 'cal1', calendarName: 'Personal', url: 'https://ex.test/a.ics',
			lastFetchAt: null, lastStatus: 'pending', lastError: null, refreshIntervalMinutes: 15
		}];
		vi.spyOn(window, 'confirm').mockReturnValue(true);
		const { container } = render(CalendarApp);
		await waitFor(() => expect(container.querySelector('.cal-sub-icon')).toBeTruthy());
		fireEvent.click(screen.getByLabelText('Unsubscribe'));
		await waitFor(() => {
			expect(calendarSubscriptionsMock.unsubscribe).toHaveBeenCalledWith(42);
		});
	});

	it('declining the unsubscribe confirmation does not call unsubscribe', async () => {
		calendarSubscriptionsMock.subscriptions = [{
			id: 42, calendarId: 'cal1', calendarName: 'Personal', url: 'https://ex.test/a.ics',
			lastFetchAt: null, lastStatus: 'pending', lastError: null, refreshIntervalMinutes: 15
		}];
		vi.spyOn(window, 'confirm').mockReturnValue(false);
		const { container } = render(CalendarApp);
		await waitFor(() => expect(container.querySelector('.cal-sub-icon')).toBeTruthy());
		fireEvent.click(screen.getByLabelText('Unsubscribe'));
		await new Promise((r) => setTimeout(r, 0));
		expect(calendarSubscriptionsMock.unsubscribe).not.toHaveBeenCalled();
	});

	it('renders week, work-week, and day time grids and opens a time-specific editor', async () => {
		calendarEvents.events = [
			{ id: 'timed', calendarId: 'cal1', title: 'Design review', start: '2026-06-15T10:00:00', end: '2026-06-15T11:30:00', location: 'Room 4' },
			{ id: 'all-day', calendarId: 'cal1', title: 'Holiday', start: '2026-06-15T00:00:00', end: '2026-06-16T00:00:00', isAllDay: true },
		];
		const { container } = render(CalendarApp);
		await fireEvent.click(screen.getByRole('button', { name: 'Week' }));
		await waitFor(() => expect(container.querySelectorAll('.week-grid .day-column')).toHaveLength(7));
		expect(screen.getByText('Design review')).toBeInTheDocument();
		expect(screen.getAllByText('Holiday').length).toBeGreaterThan(0);
		expect(container.querySelectorAll('.off-hours').length).toBeGreaterThan(0);

		await fireEvent.click(screen.getByRole('button', { name: 'Work Week' }));
		await waitFor(() => expect(container.querySelectorAll('.week-grid .day-column')).toHaveLength(5));
		await fireEvent.click(screen.getByRole('button', { name: 'Day' }));
		await waitFor(() => expect(container.querySelector('.day-grid')).toBeInTheDocument());
		expect(screen.getByText('Room 4')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Create event at 14:00' }));
		await waitFor(() => expect(screen.getByLabelText('Title')).toBeInTheDocument());
		expect(screen.getAllByLabelText('Time')[0]).toHaveValue('14:00');
	});

	it('renders agenda event/task variants and follows empty agenda state', async () => {
		calendarEvents.events = [
			{ id: 'timed', calendarId: 'cal1', title: 'Customer call', start: '2026-06-15T10:00:00', end: '2026-06-15T11:00:00', location: 'Online' },
			{ id: 'all-day', calendarId: 'cal1', title: 'Offsite', start: '2026-06-16T00:00:00', end: '2026-06-17T00:00:00', isAllDay: true },
		];
		tasksStoreMock.set([{ id: 'task-1', title: 'Submit report', status: 'needs-action', priority: 5, dueAt: '2026-06-17T12:00:00' } as never]);
		const { container } = render(CalendarApp);
		await fireEvent.click(screen.getByRole('button', { name: 'Agenda' }));
		await waitFor(() => expect(container.querySelectorAll('.agenda-item')).toHaveLength(3));
		expect(screen.getByText('Customer call')).toBeInTheDocument();
		expect(screen.getByText(/All day/)).toBeInTheDocument();
		expect(screen.getByText('Submit report')).toBeInTheDocument();
	});

	it('renders complete event detail metadata and transitions to edit mode', async () => {
		calendarEvents.events = [{
			id: 'detail', calendarId: 'cal1', title: 'Planning', start: '2026-06-15T10:00:00', end: '2026-06-15T11:00:00',
			location: 'Board room', description: 'Quarterly plan', recurrenceRule: 'FREQ=WEEKLY',
			organizer: { email: 'owner@test', name: 'Owner' },
			attendees: [
				{ email: 'a@test', name: 'Alice', role: 'required', participationStatus: 'accepted' },
				{ email: 'b@test', name: 'Bob', role: 'optional', participationStatus: 'declined' },
			],
		} as never];
		const { container } = render(CalendarApp);
		await waitFor(() => expect(eventPill(container, 'Planning')).toBeTruthy());
		await fireEvent.click(eventPill(container, 'Planning')!);
		await waitFor(() => expect(screen.getByRole('dialog', { name: 'Planning' })).toBeInTheDocument());
		expect(screen.getByText('Board room')).toBeInTheDocument();
		expect(screen.getByText('Quarterly plan')).toBeInTheDocument();
		expect(screen.getByText('Owner')).toBeInTheDocument();
		expect(screen.getByText('Alice')).toBeInTheDocument();
		expect(screen.getByText('FREQ=WEEKLY')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
		await waitFor(() => expect(screen.getByRole('dialog', { name: 'Edit event' })).toBeInTheDocument());
		expect(screen.getByLabelText('Location')).toHaveValue('Board room');
	});
});
