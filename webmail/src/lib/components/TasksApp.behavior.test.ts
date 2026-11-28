import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/svelte/svelte5';
import TasksApp from './TasksApp.svelte';

const h = vi.hoisted(() => {
	function store<T>(initial: T) {
		let value = initial;
		const subscribers = new Set<(next: T) => void>();
		return {
			subscribe(callback: (next: T) => void) { subscribers.add(callback); callback(value); return () => subscribers.delete(callback); },
			set(next: T) { value = next; for (const callback of subscribers) callback(next); },
			update(callback: (current: T) => T) { this.set(callback(value)); },
			get value() { return value; },
		};
	}
	return {
		tasks: store<unknown[]>([]), viewMode: store('list'), searchText: store(''), statusFilter: store<string | null>(null),
		taskLists: store<unknown[]>([]), activeView: store<unknown>({ kind: 'personal' }), assignedTasks: store<unknown[]>([]), listTasks: store<unknown[]>([]),
		loadSession: vi.fn(), loadTasks: vi.fn(), createTask: vi.fn(), updateTask: vi.fn(), deleteTask: vi.fn(),
		galSearch: vi.fn(), taskActivityList: vi.fn(), taskCommentCreate: vi.fn(), goto: vi.fn(), showToast: vi.fn(),
		loadLists: vi.fn(), setActiveView: vi.fn(), createTaskList: vi.fn(), renameTaskList: vi.fn(), deleteTaskList: vi.fn(),
		createListTask: vi.fn(), updateListTask: vi.fn(), deleteListTask: vi.fn(), refreshListTaskTarget: vi.fn(),
		setAssignedStatus: vi.fn(), onTaskListPush: vi.fn(),
		pushRegister: vi.fn(), pushTeardown: vi.fn(),
	};
});

vi.mock('$lib/stores/tasks', () => ({
	tasks: h.tasks, viewMode: h.viewMode, searchText: h.searchText, statusFilter: h.statusFilter,
	loadTasks: h.loadTasks, createTask: h.createTask, updateTask: h.updateTask, deleteTask: h.deleteTask,
	groupByStatus: (tasks: Array<{ status: string }>) => Object.groupBy(tasks, (task) => task.status),
	priorityLabel: (priority: number) => priority === 9 ? 'High' : priority === 5 ? 'Medium' : priority === 1 ? 'Low' : 'None',
	priorityColor: () => 'var(--text-primary)',
	statusLabel: (status: string) => ({ 'needs-action': 'To Do', 'in-progress': 'In Progress', completed: 'Done', cancelled: 'Cancelled' })[status] ?? status,
	formatDateShort: (date?: string) => date ? 'Jul 30' : '',
	isOverdue: () => false,
	computeReorderSortOrder: (before?: number, after?: number) => ((before ?? 0) + (after ?? 2)) / 2,
}));

vi.mock('$lib/stores/taskLists', () => ({
	taskLists: h.taskLists, activeView: h.activeView, assignedTasks: h.assignedTasks, listTasks: h.listTasks,
	loadLists: h.loadLists, setActiveView: h.setActiveView, createTaskList: h.createTaskList, renameTaskList: h.renameTaskList,
	deleteTaskList: h.deleteTaskList, createListTask: h.createListTask, updateListTask: h.updateListTask,
	deleteListTask: h.deleteListTask, refreshListTaskTarget: h.refreshListTaskTarget,
	setAssignedStatus: h.setAssignedStatus, onTaskListPush: h.onTaskListPush,
}));

vi.mock('$lib/jmap/client', () => ({
	loadSession: h.loadSession, galSearch: h.galSearch, taskActivityList: h.taskActivityList, taskCommentCreate: h.taskCommentCreate,
}));
vi.mock('$app/navigation', () => ({ goto: h.goto }));
vi.mock('$lib/stores/pushHandler.svelte', () => ({ PushHandlerStore: class { register = h.pushRegister; teardown = h.pushTeardown; } }));
vi.mock('$lib/components/ui', async () => ({ ...(await vi.importActual<typeof import('$lib/components/ui')>('$lib/components/ui')), showToast: h.showToast }));

const parent = {
	id: '11', title: 'Prepare launch', description: 'Coordinate the release checklist', status: 'needs-action', priority: 9,
	dueAt: '2026-07-30T09:00:00Z', sortOrder: 10, assigneeEmail: 'alice@example.test', assigneeName: 'Alice',
	recurrenceRule: 'FREQ=WEEKLY', linkedMessageId: 'm-7', categories: ['release'], checklist: [{ id: 'c1', text: 'Verify backup', done: true }],
};
const child = { id: '12', title: 'Notify support', status: 'completed', priority: 1, sortOrder: 20, parentId: '11', checklist: [] };

describe('TasksApp behavior', () => {
	beforeEach(() => {
		h.tasks.set([parent, child]); h.viewMode.set('list'); h.searchText.set(''); h.statusFilter.set(null);
		h.taskLists.set([]); h.activeView.set({ kind: 'personal' }); h.assignedTasks.set([]); h.listTasks.set([]);
		for (const mock of Object.values(h)) if (typeof mock === 'function' && 'mockReset' in mock) (mock as ReturnType<typeof vi.fn>).mockReset();
		h.loadSession.mockResolvedValue({ capabilities: {} }); h.loadTasks.mockResolvedValue(undefined); h.createTask.mockResolvedValue('13');
		h.updateTask.mockResolvedValue(undefined); h.deleteTask.mockResolvedValue(undefined); h.galSearch.mockResolvedValue([]);
		h.refreshListTaskTarget.mockResolvedValue(undefined);
		h.taskActivityList.mockResolvedValue([]); h.taskCommentCreate.mockResolvedValue(undefined);
	});

	it('creates a validated task with category and checklist data', async () => {
		render(TasksApp);
		await vi.waitFor(() => expect(h.loadTasks).toHaveBeenCalled());
		await fireEvent.click(screen.getByRole('button', { name: 'New task' }));
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		expect(screen.getByText('Title is required')).toBeTruthy();
		await fireEvent.input(screen.getByLabelText('Title'), { target: { value: 'Ship C3' } });
		await fireEvent.input(screen.getByLabelText('Description'), { target: { value: 'Exercise the core journey' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Add category' }));
		await fireEvent.input(screen.getByPlaceholderText('Category'), { target: { value: 'quality' } });
		await fireEvent.input(screen.getByPlaceholderText('Add an item'), { target: { value: 'Run tests' } });
		await fireEvent.click(screen.getByRole('button', { name: '+' }));
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		await vi.waitFor(() => expect(h.createTask).toHaveBeenCalledWith(expect.objectContaining({
			title: 'Ship C3', description: 'Exercise the core journey', categories: ['quality'],
			checklist: [expect.objectContaining({ text: 'Run tests', done: false })], assigneeEmail: '', recurrenceRule: '',
		})));
	});

	it('edits, completes, deletes, and offers a behavioral undo', async () => {
		render(TasksApp);
		await vi.waitFor(() => expect(screen.getByText('Prepare launch')).toBeTruthy());
		await fireEvent.click(screen.getAllByLabelText('Mark task done')[0]);
		await vi.waitFor(() => expect(h.updateTask).toHaveBeenCalledWith('11', { status: 'completed' }));

		const editButton = screen.getAllByRole('button', { name: 'Edit task' })[0];
		await vi.waitFor(() => expect(editButton).toBeEnabled());
		await fireEvent.click(editButton);
		await fireEvent.input(screen.getByLabelText('Title'), { target: { value: 'Prepare release' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Remove category' }));
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		await vi.waitFor(() => expect(h.updateTask).toHaveBeenCalledWith('11', expect.objectContaining({ title: 'Prepare release', categories: undefined })));
		await vi.waitFor(() => expect(screen.queryByRole('dialog', { name: 'Edit task' })).toBeNull());

		const deleteButton = screen.getAllByRole('button', { name: 'Delete task' })[0];
		await vi.waitFor(() => expect(deleteButton).toBeEnabled());
		await fireEvent.click(deleteButton);
		await vi.waitFor(() => expect(h.deleteTask).toHaveBeenCalledWith('11'));
		await vi.waitFor(() => expect(h.showToast).toHaveBeenCalledWith('Task deleted', expect.objectContaining({ actionLabel: 'Restore copy', onAction: expect.any(Function) })));
		await h.showToast.mock.calls.at(-1)?.[1].onAction();
		expect(h.createTask).toHaveBeenCalledWith({
			title: 'Prepare launch',
			description: 'Coordinate the release checklist',
			status: 'needs-action',
			priority: 9,
			dueAt: '2026-07-30T09:00:00Z',
			reminderAt: undefined,
			categories: ['release'],
		});
		expect(h.createTask.mock.calls.at(-1)?.[0]).not.toHaveProperty('recurrenceRule');
		expect(h.createTask.mock.calls.at(-1)?.[0]).not.toHaveProperty('linkedMessageId');
	});

	it('keeps a stale shared-list completion scoped to its captured target', async () => {
		let resolveCreate!: (value: string) => void;
		h.activeView.set({ kind: 'list', listId: 'list-a' });
		h.createListTask.mockReturnValue(new Promise<string>((resolve) => { resolveCreate = resolve; }));
		render(TasksApp);
		await fireEvent.click(screen.getByRole('button', { name: 'New task' }));
		await fireEvent.input(screen.getByLabelText('Title'), { target: { value: 'List work' } });
		h.activeView.set({ kind: 'personal' });
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		expect(screen.getByRole('button', { name: 'Saving...' })).toBeDisabled();
		resolveCreate('new-list-task');

		await vi.waitFor(() => expect(h.refreshListTaskTarget).toHaveBeenCalledTimes(1));
		expect(h.refreshListTaskTarget).toHaveBeenCalledWith('list-a');
		expect(h.createListTask).toHaveBeenCalledWith('list-a', expect.objectContaining({ title: 'List work' }), false);
		expect(screen.getByRole('dialog', { name: 'New task' })).toBeTruthy();
	});

	it('keeps a failed save in its dialog and announces the local error', async () => {
		h.createTask.mockRejectedValueOnce(new Error('task save denied'));
		render(TasksApp);
		await fireEvent.click(screen.getByRole('button', { name: 'New task' }));
		await fireEvent.input(screen.getByLabelText('Title'), { target: { value: 'Blocked task' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));

		const dialog = screen.getByRole('dialog', { name: 'New task' });
		await vi.waitFor(() => expect(dialog.querySelector('[role="alert"]')?.textContent).toContain('task save denied'));
		expect(dialog.querySelector('[role="alert"]')).toHaveFocus();
		expect(screen.getByLabelText('Title')).toHaveValue('Blocked task');
	});

	it('opens detail activity, submits a mention comment, and follows the linked email', async () => {
		h.taskActivityList.mockResolvedValue([
			{ id: 'a1', kind: 'status_change', authorEmail: 'admin@example.test', authorName: 'Admin', createdAt: '2026-07-20T10:00:00Z', meta: { old: 'needs-action', new: 'completed' } },
			{ id: 'a2', kind: 'comment', authorEmail: 'alice@example.test', authorName: 'Alice', createdAt: '2026-07-20T10:01:00Z', body: 'Ready' },
		]);
		h.galSearch.mockResolvedValue([{ id: 'u2', displayName: 'Bob', email: 'bob@example.test' }]);
		render(TasksApp);
		await vi.waitFor(() => expect(screen.getByText('Prepare launch')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: /Prepare launch/ }));
		await vi.waitFor(() => expect(screen.getByText('Alice commented')).toBeTruthy());
		await fireEvent.input(screen.getByLabelText('Comment'), { target: { value: 'Ask @Bo', selectionStart: 7 } });
		await new Promise((resolve) => setTimeout(resolve, 220));
		await vi.waitFor(() => expect(screen.getByRole('option', { name: /Bob/ })).toBeTruthy());
		await fireEvent.click(screen.getByRole('option', { name: /Bob/ }));
		await fireEvent.click(screen.getByRole('button', { name: 'Comment' }));
		await vi.waitFor(() => expect(h.taskCommentCreate).toHaveBeenCalledWith('11', 'Ask @Bob', ['bob@example.test']));
		await fireEvent.click(screen.getByRole('button', { name: 'Open email' }));
		expect(h.goto).toHaveBeenCalledWith('/inbox?t=m-7');
	});

	it('loads shared lists and enforces the assigned-to-me status-only surface', async () => {
		h.loadSession.mockResolvedValue({ capabilities: { 'urn:ietf:params:jmap:tasks': { sharedLists: true } } });
		h.activeView.set({ kind: 'assigned' });
		h.assignedTasks.set([{ id: '31', title: 'Review policy', status: 'needs-action', ownerEmail: 'owner@example.test', ownerName: 'Owner', listName: 'Governance', dueAt: '2026-07-30T09:00:00Z' }]);
		h.setAssignedStatus.mockResolvedValue(undefined);
		render(TasksApp);
		await vi.waitFor(() => expect(h.loadLists).toHaveBeenCalled());
		expect(screen.queryByRole('button', { name: 'New task' })).toBeNull();
		await fireEvent.change(screen.getByLabelText('Assigned to me: Review policy'), { target: { value: 'completed' } });
		await vi.waitFor(() => expect(h.setAssignedStatus).toHaveBeenCalledWith('31', 'completed'));
	});

	it('renders all kanban columns and moves cards through explicit actions', async () => {
		h.viewMode.set('kanban');
		render(TasksApp);
		await vi.waitFor(() => expect(screen.getByRole('list', { name: 'To Do' })).toBeTruthy());
		expect(screen.getByRole('list', { name: 'In Progress' })).toBeTruthy();
		expect(screen.getByRole('list', { name: 'Done' })).toBeTruthy();
		expect(screen.getByRole('list', { name: 'Cancelled' })).toBeTruthy();
		expect(screen.getByText('1/1')).toBeTruthy();
		await fireEvent.click(screen.getAllByRole('button', { name: 'Start' })[0]);
		await vi.waitFor(() => expect(h.updateTask).toHaveBeenCalledWith('11', { status: 'in-progress' }));
		const doneButton = screen.getAllByRole('button', { name: 'Done' })[0];
		await vi.waitFor(() => expect(doneButton).toBeEnabled());
		await fireEvent.click(doneButton);
		await vi.waitFor(() => expect(h.updateTask).toHaveBeenCalledWith('11', { status: 'completed' }));
	});

	it('creates, renames, selects, and deletes shared lists behind the capability gate', async () => {
		h.loadSession.mockResolvedValue({ capabilities: { 'urn:ietf:params:jmap:tasks': { sharedLists: true } } });
		h.taskLists.set([{ id: 'l1', name: 'Team Plan', role: 'owner', color: '#123456', openCount: 2, members: [] }]);
		h.createTaskList.mockResolvedValue('l2'); h.renameTaskList.mockResolvedValue(undefined); h.deleteTaskList.mockResolvedValue(undefined);
		vi.spyOn(window, 'confirm').mockReturnValue(true);
		render(TasksApp);
		await vi.waitFor(() => expect(screen.getByRole('button', { name: 'New list' })).toBeTruthy());
		expect(screen.getByText('Team Plan')).toBeTruthy();
		expect(screen.getByText('2')).toBeTruthy();
		await fireEvent.click(screen.getByText('Team Plan').closest('button')!);
		expect(h.setActiveView).toHaveBeenCalledWith({ kind: 'list', listId: 'l1' });

		await fireEvent.click(screen.getByRole('button', { name: 'New list' }));
		const newListInput = screen.getByRole('dialog', { name: 'New list' }).querySelector('input')!;
		await fireEvent.input(newListInput, { target: { value: ' Release ' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		await vi.waitFor(() => expect(h.createTaskList).toHaveBeenCalledWith('Release'));
		expect(h.setActiveView).toHaveBeenCalledWith({ kind: 'list', listId: 'l2' });

		await fireEvent.click(screen.getByRole('button', { name: 'Manage Team Plan' }));
		await fireEvent.click(screen.getByRole('menuitem', { name: 'Rename' }));
		const renameInput = screen.getByRole('dialog', { name: 'Rename' }).querySelector('input')!;
		await fireEvent.input(renameInput, { target: { value: 'Team Roadmap' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		await vi.waitFor(() => expect(h.renameTaskList).toHaveBeenCalledWith('l1', 'Team Roadmap'));

		await fireEvent.click(screen.getByRole('button', { name: 'Manage Team Plan' }));
		await fireEvent.click(screen.getByRole('menuitem', { name: 'Delete' }));
		expect(confirm).toHaveBeenCalled();
		await vi.waitFor(() => expect(h.deleteTaskList).toHaveBeenCalledWith('l1'));
	});

	it('surfaces initialization and assigned-status failures', async () => {
		h.loadSession.mockRejectedValueOnce(new Error('session unavailable'));
		const first = render(TasksApp);
		await vi.waitFor(() => expect(screen.getByText('session unavailable')).toBeTruthy());
		first.unmount();

		h.loadSession.mockResolvedValue({ capabilities: { 'urn:ietf:params:jmap:tasks': { sharedLists: true } } });
		h.activeView.set({ kind: 'assigned' });
		h.assignedTasks.set([{ id: '31', title: 'Review policy', status: 'needs-action', ownerEmail: 'owner@example.test', listName: '' }]);
		h.setAssignedStatus.mockRejectedValueOnce(new Error('status denied'));
		render(TasksApp);
		await vi.waitFor(() => expect(screen.getByLabelText('Assigned to me: Review policy')).toBeTruthy());
		await fireEvent.change(screen.getByLabelText('Assigned to me: Review policy'), { target: { value: 'completed' } });
		await vi.waitFor(() => expect(screen.getByText('status denied')).toBeTruthy());
	});
});
