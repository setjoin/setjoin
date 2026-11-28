import { describe, it, expect, vi, beforeEach } from 'vitest';
import { get } from 'svelte/store';
import type { AssignedTask, Task, TaskList } from '$lib/types/jmap';

const taskListGet = vi.fn();
const taskListSet = vi.fn();
const taskListMemberSet = vi.fn();
const taskListTasks = vi.fn();
const taskListTaskSet = vi.fn();
const taskAssignedGet = vi.fn();
const taskAssignedSetStatus = vi.fn();

vi.mock('$lib/jmap/client', () => ({
	taskListGet: (...a: unknown[]) => taskListGet(...a),
	taskListSet: (...a: unknown[]) => taskListSet(...a),
	taskListMemberSet: (...a: unknown[]) => taskListMemberSet(...a),
	taskListTasks: (...a: unknown[]) => taskListTasks(...a),
	taskListTaskSet: (...a: unknown[]) => taskListTaskSet(...a),
	taskAssignedGet: (...a: unknown[]) => taskAssignedGet(...a),
	taskAssignedSetStatus: (...a: unknown[]) => taskAssignedSetStatus(...a)
}));

import {
	taskLists,
	activeView,
	assignedTasks,
	listTasks,
	listState,
	reset,
	loadLists,
	loadActiveView,
	setActiveView,
	createListTask,
	updateListTask,
	deleteListTask,
	refreshListTaskTarget,
	setAssignedStatus,
	onTaskListPush
} from './taskLists';

function assignedRow(id: string, overrides: Partial<AssignedTask> = {}): AssignedTask {
	return {
		id,
		title: id,
		status: 'needs-action',
		priority: 0,
		listId: null,
		listName: null,
		ownerEmail: 'owner@example.com',
		ownerName: 'Owner',
		...overrides
	};
}

function listRow(id: string): TaskList {
	return { id, name: id, color: null, state: '0' };
}

function taskRow(id: string): Task {
	return { id, title: id, status: 'needs-action', priority: 0 };
}

beforeEach(() => {
	reset();
	taskListGet.mockReset().mockResolvedValue([]);
	taskListSet.mockReset();
	taskListMemberSet.mockReset();
	taskListTasks.mockReset().mockResolvedValue({ state: '1', list: [] });
	taskListTaskSet.mockReset();
	taskAssignedGet.mockReset().mockResolvedValue([]);
	taskAssignedSetStatus.mockReset().mockResolvedValue(undefined);
});

describe('view switching', () => {
	it('personal view is the default and loads nothing', async () => {
		expect(get(activeView)).toEqual({ kind: 'personal' });
		await loadActiveView();
		expect(taskAssignedGet).not.toHaveBeenCalled();
		expect(taskListTasks).not.toHaveBeenCalled();
	});

	it('switching to assigned loads TaskAssigned/get', async () => {
		taskAssignedGet.mockResolvedValue([assignedRow('a1')]);
		setActiveView({ kind: 'assigned' });
		await loadActiveView(); // setActiveView's own fire-and-forget load may still be in flight; await explicitly
		expect(get(activeView)).toEqual({ kind: 'assigned' });
		expect(get(assignedTasks).map((t) => t.id)).toEqual(['a1']);
	});

	it('switching to a list loads TaskList/tasks and resets on re-entry', async () => {
		taskListTasks.mockResolvedValue({ state: '5', list: [taskRow('t1')] });
		setActiveView({ kind: 'list', listId: 'L1' });
		await loadActiveView();
		expect(taskListTasks).toHaveBeenCalledWith('L1');
		expect(get(listTasks).map((t) => t.id)).toEqual(['t1']);
		expect(get(listState)).toBe('5');
	});
});

describe('monotonic load token (the tasks.ts pin, ported to taskLists)', () => {
	it('an older resolve after a newer one is discarded', async () => {
		let releaseFirst!: (v: { state: string; list: Task[] }) => void;
		taskListTasks
			.mockImplementationOnce(() => new Promise((res) => { releaseFirst = res; }))
			.mockResolvedValueOnce({ state: '2', list: [taskRow('fresh')] });

		activeView.set({ kind: 'list', listId: 'L1' });
		const first = loadActiveView(); // stale, held open
		const second = loadActiveView(); // newer
		await second;
		expect(get(listTasks).map((t) => t.id)).toEqual(['fresh']);

		releaseFirst({ state: '1', list: [taskRow('stale')] });
		await first;
		expect(get(listTasks).map((t) => t.id)).toEqual(['fresh']); // stale result dropped
	});
});

describe('captured-list action seam', () => {
	it('can mutate without an implicit current-view refresh', async () => {
		taskListTaskSet
			.mockResolvedValueOnce({ created: { k1: { id: 'new-id' } } })
			.mockResolvedValue(undefined);
		await expect(createListTask('L1', { title: 'A' }, false)).resolves.toBe('new-id');
		await updateListTask('L1', 'T1', { title: 'B' }, false);
		await deleteListTask('L1', 'T1', false);
		expect(taskListTasks).not.toHaveBeenCalled();
	});

	it('refreshes the captured list but does not overwrite a different current view', async () => {
		listTasks.set([taskRow('current')]);
		activeView.set({ kind: 'personal' });
		taskListTasks.mockResolvedValue({ state: '9', list: [taskRow('hidden-list')] });
		await refreshListTaskTarget('L1');
		expect(taskListTasks).toHaveBeenCalledWith('L1');
		expect(get(listTasks).map((task) => task.id)).toEqual(['current']);
	});

	it('applies a captured refresh when that list is still current', async () => {
		activeView.set({ kind: 'list', listId: 'L1' });
		taskListTasks.mockResolvedValue({ state: '9', list: [taskRow('fresh')] });
		await refreshListTaskTarget('L1');
		expect(get(listTasks).map((task) => task.id)).toEqual(['fresh']);
		expect(get(listState)).toBe('9');
	});
});

describe('onTaskListPush', () => {
	it('refetches the on-screen list when the pushed list matches', async () => {
		taskListTasks.mockResolvedValue({ state: '1', list: [] });
		activeView.set({ kind: 'list', listId: 'L1' });
		onTaskListPush('L1');
		await Promise.resolve();
		await Promise.resolve();
		expect(taskListTasks).toHaveBeenCalledWith('L1');
	});

	it('does NOT refetch a different list that is not on screen', async () => {
		activeView.set({ kind: 'list', listId: 'L1' });
		onTaskListPush('L2');
		await Promise.resolve();
		await Promise.resolve();
		expect(taskListTasks).not.toHaveBeenCalled();
	});

	it('a null listId (the real push granularity today) refetches the on-screen list unconditionally', async () => {
		taskListTasks.mockResolvedValue({ state: '1', list: [] });
		activeView.set({ kind: 'list', listId: 'L1' });
		onTaskListPush(null);
		await Promise.resolve();
		await Promise.resolve();
		expect(taskListTasks).toHaveBeenCalledWith('L1');
	});

	it('refetches the assigned view regardless of which list changed (it may reference any)', async () => {
		activeView.set({ kind: 'assigned' });
		onTaskListPush('L1');
		await Promise.resolve();
		await Promise.resolve();
		expect(taskAssignedGet).toHaveBeenCalled();
	});

	it('always refreshes the list summary (counts changed)', async () => {
		activeView.set({ kind: 'personal' });
		onTaskListPush(null);
		await Promise.resolve();
		expect(taskListGet).toHaveBeenCalled();
	});
});

describe('setAssignedStatus — optimistic update with rollback', () => {
	it('applies the status immediately, keeps it on success', async () => {
		assignedTasks.set([assignedRow('a1', { status: 'needs-action' })]);
		await setAssignedStatus('a1', 'in-progress');
		expect(get(assignedTasks)[0].status).toBe('in-progress');
	});

	it('rolls back to the prior state on failure', async () => {
		assignedTasks.set([assignedRow('a1', { status: 'needs-action' })]);
		taskAssignedSetStatus.mockRejectedValue(new Error('denied'));
		await expect(setAssignedStatus('a1', 'in-progress')).rejects.toThrow('denied');
		expect(get(assignedTasks)[0].status).toBe('needs-action');
	});
});

describe('loadLists', () => {
	it('populates taskLists from TaskList/get', async () => {
		taskListGet.mockResolvedValue([listRow('L1'), listRow('L2')]);
		await loadLists();
		expect(get(taskLists).map((l) => l.id)).toEqual(['L1', 'L2']);
	});
});
