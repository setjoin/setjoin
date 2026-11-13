import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render } from '@testing-library/svelte';
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
	priorityLabel: vi.fn((p: number) => p === 9 ? 'High' : p === 5 ? 'Medium' : p === 1 ? 'Low' : 'None'),
	priorityColor: vi.fn((p: number) => p === 9 ? '#e94560' : p === 5 ? '#f4a261' : p === 1 ? '#2a9d8f' : '#888'),
	statusLabel: vi.fn((s: string) => {
		switch (s) {
			case 'needs-action': return 'To Do';
			case 'in-progress': return 'In Progress';
			case 'completed': return 'Done';
			case 'cancelled': return 'Cancelled';
			default: return s;
		}
	}),
	formatDateShort: vi.fn(() => ''),
	isOverdue: vi.fn(() => false),
	computeReorderSortOrder: vi.fn(() => 0),
}));

vi.mock('$lib/jmap/client', () => ({
	loadSession: vi.fn(),
	galSearch: vi.fn(() => Promise.resolve([])),
	taskActivityList: vi.fn(() => Promise.resolve([])),
	taskCommentCreate: vi.fn(() => Promise.resolve()),
}));

vi.mock('$app/navigation', () => ({
	goto: vi.fn(),
}));

describe('TasksApp', () => {
	beforeEach(() => {
		vi.clearAllMocks();
	});

	it('renders the pim-shell root element', () => {
		const { container } = render(TasksApp);
		const root = container.querySelector('[data-pim-shell]');
		expect(root).toBeTruthy();
	});

	it('renders the pim topbar title "Tasks"', () => {
		const { container } = render(TasksApp);
		const title = container.querySelector('.pim-topbar__title');
		expect(title).toBeTruthy();
		expect(title!.textContent).toBe('Tasks');
	});
});
