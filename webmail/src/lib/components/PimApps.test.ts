import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render } from '@testing-library/svelte/svelte5';
import CalendarApp from './CalendarApp.svelte';
import ContactsApp from './ContactsApp.svelte';
import TasksApp from './TasksApp.svelte';

function mockStore<T>(initial: T) {
	let val = initial;
	const subs = new Set<(v: T) => void>();
	return {
		subscribe: vi.fn((cb: (v: T) => void) => { cb(val); return () => subs.delete(cb); }),
		set: vi.fn((v: T) => { val = v; for (const cb of subs) cb(v); }),
		update: vi.fn(),
	};
}

// ── Calendar mocks ──────────────────────────────────────────────
vi.mock('$lib/stores/calendar', () => ({
	calendars: mockStore([{id:'cal1', name:'Personal', color:'#4A90D9'}]),
	events: mockStore([]),
	selectedDate: mockStore(new Date('2026-06-15')),
	selectedCalendarIds: mockStore(['cal1']),
	viewMode: mockStore('month'),
	visibleCalendarIds: mockStore(['cal1']),
	identities: mockStore([]),
	loadCalendars: vi.fn(),
	loadEvents: vi.fn(),
	createEvent: vi.fn(),
	updateEvent: vi.fn(),
	deleteEvent: vi.fn(),
	rsvpEvent: vi.fn(),
	toggleCalendarVisibility: vi.fn(),
	getViewRange: vi.fn(() => ({ start: new Date('2026-06-01'), end: new Date('2026-07-01') })),
	findFreeSlots: vi.fn(),
	loadIdentities: vi.fn(),
}));

vi.mock('$lib/jmap/websocket', () => ({
	connect: vi.fn(),
	disconnect: vi.fn(),
}));

// ── Contacts mocks ───────────────────────────────────────────────
vi.mock('$lib/stores/contacts', () => ({
	addressBooks: mockStore([]),
	contacts: mockStore([]),
	selectedAddressBookId: mockStore(null),
	galResults: mockStore([]),
	viewMode: mockStore('list'),
	searchText: mockStore(''),
	isGAL: mockStore(false),
	loadAddressBooks: vi.fn(),
	loadContacts: vi.fn(),
	searchGAL: vi.fn(),
	createContact: vi.fn(),
	updateContact: vi.fn(),
	deleteContact: vi.fn(),
}));

vi.mock('$lib/stores/directory', () => ({
	setDirectoryAccountId: vi.fn(),
	directoryTree: vi.fn().mockResolvedValue([]),
	directoryMembers: vi.fn(),
}));

vi.mock('$lib/jmap/client', () => ({
	loadSession: vi.fn(),
	uploadBlob: vi.fn(),
	resetJmapAuthContext: vi.fn(),
}));

// ── Tasks mocks ─────────────────────────────────────────────────
vi.mock('$lib/stores/tasks', () => ({
	tasks: mockStore([]),
	viewMode: mockStore('kanban'),
	searchText: mockStore(''),
	statusFilter: mockStore(null),
	loadTasks: vi.fn(),
	createTask: vi.fn(),
	updateTask: vi.fn(),
	deleteTask: vi.fn(),
	groupByStatus: vi.fn(() => ({})),
	priorityLabel: vi.fn(() => 'Medium'),
	priorityColor: vi.fn(() => '#888'),
	statusLabel: vi.fn((s: string) => s),
	formatDateShort: vi.fn(() => ''),
	isOverdue: vi.fn(() => false),
}));

// ── Navigation mock (all apps) ──────────────────────────────────
vi.mock('$app/navigation', () => ({
	goto: vi.fn(),
}));

/**
 * Renders a component inside a 380px-wide container div, simulating
 * the split-view side-dock slot.
 */
function renderInSlot(

	Component: any,
	props?: Record<string, unknown>
) {
	const slot = document.createElement('div');
	slot.style.width = '380px';
	slot.style.height = '600px';
	document.body.appendChild(slot);


	const result = render(Component as any, {
		...props,
		target: slot,
	});

	return { ...result, slot };
}

describe('PIM apps — split-view slot mounting', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		document.body.innerHTML = '';
	});

	// ── CalendarApp ──────────────────────────────────────────────

	describe('CalendarApp', () => {
		it('renders inside a 380px-wide slot container', () => {
			const { slot } = renderInSlot(CalendarApp);
			expect(slot.style.width).toBe('380px');

			const root = slot.querySelector('[data-pim-shell]') as HTMLElement;
			expect(root).toBeTruthy();
		});

		it('root element has container-type: inline-size for container queries', () => {
			const { slot } = renderInSlot(CalendarApp);
			const root = slot.querySelector('[data-pim-shell]') as HTMLElement;
			expect(root).toBeTruthy();
			expect(root.style.containerType).toBe('inline-size');
		});

		it('renders the Calendar title in the topbar', () => {
			const { slot } = renderInSlot(CalendarApp);
			const title = slot.querySelector('.pim-topbar__title');
			expect(title).toBeTruthy();
			expect(title!.textContent).toBe('Calendar');
		});

		it('renders month grid when viewMode is month', async () => {
			const { slot } = renderInSlot(CalendarApp);
			await vi.waitFor(() => {
				const cells = slot.querySelectorAll('.month-cell');
				expect(cells.length).toBeGreaterThan(0);
			});
		});
	});

	// ── ContactsApp ──────────────────────────────────────────────

	describe('ContactsApp', () => {
		it('renders inside a 380px-wide slot container', () => {
			const { slot } = renderInSlot(ContactsApp);
			expect(slot.style.width).toBe('380px');

			const root = slot.querySelector('[data-pim-shell]') as HTMLElement;
			expect(root).toBeTruthy();
		});

		it('root element has container-type: inline-size for container queries', () => {
			const { slot } = renderInSlot(ContactsApp);
			const root = slot.querySelector('[data-pim-shell]') as HTMLElement;
			expect(root).toBeTruthy();
			expect(root.style.containerType).toBe('inline-size');
		});

		it('renders the Contacts title in the topbar', () => {
			const { slot } = renderInSlot(ContactsApp);
			const title = slot.querySelector('.pim-topbar__title');
			expect(title).toBeTruthy();
			expect(title!.textContent).toBe('Contacts');
		});
	});

	// ── TasksApp ─────────────────────────────────────────────────

	describe('TasksApp', () => {
		it('renders inside a 380px-wide slot container', () => {
			const { slot } = renderInSlot(TasksApp);
			expect(slot.style.width).toBe('380px');

			const root = slot.querySelector('[data-pim-shell]') as HTMLElement;
			expect(root).toBeTruthy();
		});

		it('root element has container-type: inline-size for container queries', () => {
			const { slot } = renderInSlot(TasksApp);
			const root = slot.querySelector('[data-pim-shell]') as HTMLElement;
			expect(root).toBeTruthy();
			expect(root.style.containerType).toBe('inline-size');
		});

		it('renders the Tasks title in the topbar', () => {
			const { slot } = renderInSlot(TasksApp);
			const title = slot.querySelector('.pim-topbar__title');
			expect(title).toBeTruthy();
			expect(title!.textContent).toBe('Tasks');
		});
	});
});
