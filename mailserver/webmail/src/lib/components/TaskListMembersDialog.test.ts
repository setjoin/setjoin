import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';
const mocks = vi.hoisted(() => {
	let value: any[] = [];
	const subscribers = new Set<(next: any[]) => void>();
	return {
		add: vi.fn(),
		remove: vi.fn(),
		loadSession: vi.fn(),
		taskLists: {
			subscribe(callback: (next: any[]) => void) {
				callback(value);
				subscribers.add(callback);
				return () => subscribers.delete(callback);
			},
			set(next: any[]) {
				value = next;
				for (const callback of subscribers) callback(value);
			},
		},
	};
});
vi.mock('$lib/stores/taskLists', () => ({ taskLists: mocks.taskLists, addTaskListMember: mocks.add, removeTaskListMember: mocks.remove }));
vi.mock('$lib/jmap/client', () => ({ loadSession: mocks.loadSession }));
import TaskListMembersDialog from './TaskListMembersDialog.svelte';

const list = { id: 'list-1', name: 'Project', role: 'owner', members: [
	{ userId: 'u1', email: 'owner@test', displayName: 'Owner', role: 'owner' },
	{ userId: 'u2', email: 'member@test', displayName: 'Member', role: 'member' }
] };

describe('TaskListMembersDialog', () => {
	beforeEach(() => { vi.clearAllMocks(); mocks.taskLists.set([list]); mocks.loadSession.mockResolvedValue({ username: 'owner@test' }); mocks.add.mockResolvedValue({}); mocks.remove.mockResolvedValue({}); });
	it('lets an owner add and remove members but never remove the owner', async () => {
		render(TaskListMembersDialog, { list: list as never, onClose: vi.fn() });
		expect(screen.getAllByText('Owner')).toHaveLength(2);
		expect(screen.getAllByText('Member')).toHaveLength(2);
		expect(screen.getAllByRole('button', { name: 'Remove' })).toHaveLength(1);
		await fireEvent.input(screen.getByLabelText('Add member'), { target: { value: ' new@test ' } });
		await fireEvent.submit(screen.getByLabelText('Add member').closest('form')!);
		await waitFor(() => expect(mocks.add).toHaveBeenCalledWith('list-1', 'new@test'));
		await fireEvent.click(screen.getByRole('button', { name: 'Remove' }));
		await waitFor(() => expect(mocks.remove).toHaveBeenCalledWith('list-1', 'u2'));
	});

	it('allows a non-owner to leave and reports reducer failures', async () => {
		const memberList = { ...list, role: 'member', members: [{ userId: 'u2', email: 'member@test', displayName: 'Member', role: 'member' }] };
		mocks.taskLists.set([memberList]); mocks.loadSession.mockResolvedValue({ username: 'member@test' }); mocks.remove.mockRejectedValueOnce(new Error('cannot leave'));
		render(TaskListMembersDialog, { list: memberList as never, onClose: vi.fn() });
		await waitFor(() => expect(screen.getByRole('button', { name: 'Leave' })).toBeInTheDocument());
		expect(screen.queryByLabelText('Add member')).not.toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Leave' }));
		await waitFor(() => expect(screen.getByText('cannot leave')).toBeInTheDocument());
	});
});
