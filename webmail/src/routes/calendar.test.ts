import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import CalendarPage from './calendar/+page.svelte';
import { reset as resetCalendar } from '$lib/stores/calendar';

vi.mock('$lib/jmap/websocket', () => ({
	connect: vi.fn(),
	disconnect: vi.fn(),
}));

vi.mock('$lib/logger', () => ({
	logger: { log: vi.fn(), error: vi.fn() },
}));

const today = new Date();
const todayStr = today.toISOString().slice(0, 10);

const mockCalendars = [{ id: 'cal1', name: 'Personal', color: '#4A90D9' }];

const mockEvents = [
	{
		id: 'ev1',
		calendarId: 'cal1',
		title: 'Meeting with Team',
		start: `${todayStr}T09:00:00`,
		end: `${todayStr}T10:00:00`,
		isAllDay: false,
		location: 'Office',
		description: 'Discuss project',
		attendees: [
			{ email: 'alice@test.local', name: 'Alice', participationStatus: 'needs-action' },
		],
		organizer: { email: 'bob@test.com', name: 'Bob' },
	},
];

interface CalendarTestHarness {
	mockFetch: ReturnType<typeof vi.fn>;
	eventSetRequests: { body: unknown }[];
	rsvpRequests: { body: unknown }[];
	resolveEventSet: (data?: Record<string, unknown>) => void;
	rejectEventSet: () => void;
	resolveRsvp: () => void;
	rejectRsvp: () => void;
}

function setupCalendarTest(): CalendarTestHarness {
	let eventSetResolve: (v: Response) => void = () => {};
	let eventSetReject: (e: Error) => void = () => {};
	let eventSetPromise: Promise<Response> = Promise.resolve(new Response());
	let rsvpResolve: (v: Response) => void = () => {};
	let rsvpReject: (e: Error) => void = () => {};
	let rsvpPromise: Promise<Response> = Promise.resolve(new Response());

	const eventSetRequests: { body: unknown }[] = [];
	const rsvpRequests: { body: unknown }[] = [];

	function createEventSetPromise() {
		eventSetPromise = new Promise<Response>((resolve, reject) => {
			eventSetResolve = resolve;
			eventSetReject = reject;
		});
	}
	createEventSetPromise();

	function createRsvpPromise() {
		rsvpPromise = new Promise<Response>((resolve, reject) => {
			rsvpResolve = resolve;
			rsvpReject = reject;
		});
	}
	createRsvpPromise();

	const mockFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input.toString();
		const reqBody = init?.body ? JSON.parse(init.body as string) : {};
		const methodCalls: string[][] = reqBody.methodCalls || [];

		const hasEventSet = methodCalls.some((mc: string[]) => mc[0] === 'CalendarEvent/set');
		const hasRsvp = methodCalls.some((mc: string[]) => mc[0] === 'CalendarEvent/rsvp');

		if (hasEventSet) {
			eventSetRequests.push({ body: reqBody });
			return eventSetPromise;
		}
		if (hasRsvp) {
			rsvpRequests.push({ body: reqBody });
			return rsvpPromise;
		}

		if (url.includes('/.well-known/jmap')) {
			return {
				ok: true,
				status: 200,
				json: async () => ({
					apiUrl: '/jmap',
					downloadUrl: '/blobs',
					uploadUrl: '/blobs',
					accounts: { a1: { name: 'alice@test.local', isPersonal: true, accountCapabilities: {} } },
					primaryAccounts: { 'urn:ietf:params:jmap:calendar': 'a1' },
					username: 'alice@test.local',
					capabilities: { 'urn:ietf:params:jmap:core': {} },
				}),
				text: async () => '',
			};
		}

		if (url.includes('/jmap') && !url.includes('/jmap/ws')) {
			const responses: unknown[] = [];
			for (const mc of methodCalls) {
				const [name, _args, callId] = mc;
				switch (name) {
					case 'Session':
						responses.push([
							name,
							{ accounts: { a1: { name: 'alice@test.local', isPrimary: true } }, primaryAccounts: {}, capabilities: {} },
							callId,
						]);
						break;
					case 'Calendar/get':
						responses.push([name, { list: mockCalendars, state: 's1' }, callId]);
						break;
					case 'Identity/get':
						responses.push([name, { list: [], state: 's1' }, callId]);
						break;
					case 'CalendarEvent/query':
						responses.push([
							name,
							{ ids: mockEvents.map((e: { id: string }) => e.id), total: mockEvents.length, position: mockEvents.length },
							callId,
						]);
						break;
					case 'CalendarEvent/get':
						responses.push([name, { list: mockEvents, state: 's1' }, callId]);
						break;
					default:
						responses.push([name, {}, callId]);
				}
			}
			return {
				ok: true,
				status: 200,
				json: async () => ({ methodResponses: responses }),
				text: async () => '',
			};
		}

		return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
	});

	vi.stubGlobal('fetch', mockFetch);

	return {
		mockFetch,
		eventSetRequests,
		rsvpRequests,
		resolveEventSet: (data?: Record<string, unknown>) => {
			eventSetResolve({
				ok: true,
				status: 200,
				json: async () => ({
					methodResponses: [
						[
							'CalendarEvent/set',
							{
								created: data?.created || { k1: { id: 'ev-new' } },
								updated: data?.updated || [],
								destroyed: data?.destroyed || [],
								notUpdated: {},
							},
							'0',
						],
					],
				}),
				text: async () => '',
			} as unknown as Response);
			createEventSetPromise();
		},
		rejectEventSet: () => {
			eventSetResolve({
				ok: false,
				status: 500,
				json: async () => { throw new Error('Server Error'); },
				text: async () => 'Server Error',
			} as unknown as Response);
			createEventSetPromise();
		},
		resolveRsvp: () => {
			rsvpResolve({
				ok: true,
				status: 200,
				json: async () => ({
					methodResponses: [['CalendarEvent/rsvp', { updated: mockEvents[0].id }, '0']],
				}),
				text: async () => '',
			} as unknown as Response);
			createRsvpPromise();
		},
		rejectRsvp: () => {
			rsvpResolve({
				ok: false,
				status: 500,
				json: async () => { throw new Error('Server Error'); },
				text: async () => 'Server Error',
			} as unknown as Response);
			createRsvpPromise();
		},
	};
}

describe('Calendar Page - Loading States', () => {
	beforeEach(() => {
		resetStores();
		resetCalendar();
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('mounts calendar page without crashing', async () => {
		setupCalendarTest();
		const { container } = await renderAsUser(CalendarPage);
		expect(container).toBeTruthy();
	});

	it('shows events after loading', async () => {
		setupCalendarTest();
		await renderAsUser(CalendarPage);
		await waitFor(() => {
			expect(screen.getByText((c) => c.includes('Meeting with Team'))).toBeTruthy();
		});
	});

	it('renders month view with cells and New event button', async () => {
		setupCalendarTest();
		await renderAsUser(CalendarPage);

		await waitFor(() => {
			const cells = document.querySelectorAll('.month-cell');
			expect(cells.length).toBeGreaterThan(0);
		});

		// New event button should be present
		expect(screen.getByText('New event')).toBeTruthy();

		// Month cells should be keyboard-accessible
		const firstCell = document.querySelector('.month-cell') as HTMLElement;
		expect(firstCell.getAttribute('role')).toBe('button');
		expect(firstCell.getAttribute('tabindex')).toBe('0');
	});

	it('shows Delete button in event detail dialog', async () => {
		setupCalendarTest();
		await renderAsUser(CalendarPage);

		// Wait for event to render
		await waitFor(() => {
			expect(screen.getByText((c) => c.includes('Meeting with Team'))).toBeTruthy();
		});

		// Click the event pill to open detail modal
		const eventBtn = screen.getByText((c) => c.includes('Meeting with Team')).closest('button')!;
		fireEvent.click(eventBtn);

		// Detail modal should appear with Delete button in footer
		await waitFor(() => {
			const deleteBtns = screen.getAllByText('Delete');
			expect(deleteBtns.length).toBeGreaterThan(0);
		});
	});

	it('disables RSVP Accept button during handleRsvp', async () => {
		const fetcher = setupCalendarTest();
		await renderAsUser(CalendarPage);

		await waitFor(() => {
			expect(screen.getByText((c) => c.includes('Meeting with Team'))).toBeTruthy();
		});

		const eventBtn = screen.getByText((c) => c.includes('Meeting with Team')).closest('button')!;
		fireEvent.click(eventBtn);

		// Detail modal should show Accept button (user is attendee)
		await waitFor(() => {
			expect(screen.getByText('Accept')).toBeTruthy();
		});

		const acceptBtn = screen.getByText('Accept').closest('button')!;
		fireEvent.click(acceptBtn);

		// Accept button should show loading text
		await waitFor(() => {
			expect(screen.getByText('Responding...')).toBeTruthy();
		});

		// Resolve the RSVP
		fetcher.resolveRsvp();

		// Button should re-enable
		await waitFor(() => {
			expect(screen.queryByText('Responding...')).toBeFalsy();
		});
	});

	it('disables RSVP Tentative button during handleRsvp', async () => {
		const fetcher = setupCalendarTest();
		await renderAsUser(CalendarPage);

		await waitFor(() => {
			expect(screen.getByText((c) => c.includes('Meeting with Team'))).toBeTruthy();
		});

		const eventBtn = screen.getByText((c) => c.includes('Meeting with Team')).closest('button')!;
		fireEvent.click(eventBtn);

		await waitFor(() => {
			expect(screen.getByText('Tentative')).toBeTruthy();
		});

		const tentativeBtn = screen.getByText('Tentative').closest('button')!;
		fireEvent.click(tentativeBtn);

		await waitFor(() => {
			expect(screen.getByText('Responding...')).toBeTruthy();
		});

		fetcher.resolveRsvp();

		await waitFor(() => {
			expect(screen.queryByText('Responding...')).toBeFalsy();
		});
	});

	it('disables RSVP Decline button during handleRsvp', async () => {
		const fetcher = setupCalendarTest();
		await renderAsUser(CalendarPage);

		await waitFor(() => {
			expect(screen.getByText((c) => c.includes('Meeting with Team'))).toBeTruthy();
		});

		const eventBtn = screen.getByText((c) => c.includes('Meeting with Team')).closest('button')!;
		fireEvent.click(eventBtn);

		await waitFor(() => {
			expect(screen.getByText('Decline')).toBeTruthy();
		});

		const declineBtn = screen.getByText('Decline').closest('button')!;
		fireEvent.click(declineBtn);

		await waitFor(() => {
			expect(screen.getByText('Responding...')).toBeTruthy();
		});

		fetcher.resolveRsvp();

		await waitFor(() => {
			expect(screen.queryByText('Responding...')).toBeFalsy();
		});
	});

});
