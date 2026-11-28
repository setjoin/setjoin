import { describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Task } from '$lib/types/jmap';
import {
	TasksActionConflictError,
	TasksActionCoordinator,
	captureActionTarget,
	type ActionTarget,
	type TasksActionAdapter,
} from './actionCoordinator.svelte';

function deferred<T = void>() {
	let resolve!: (value: T | PromiseLike<T>) => void;
	let reject!: (reason?: unknown) => void;
	const promise = new Promise<T>((res, rej) => {
		resolve = res;
		reject = rej;
	});
	return { promise, resolve, reject };
}

function makeAdapter(): TasksActionAdapter & {
	create: ReturnType<typeof vi.fn>;
	update: ReturnType<typeof vi.fn>;
	remove: ReturnType<typeof vi.fn>;
	refresh: ReturnType<typeof vi.fn>;
} {
	return {
		create: vi.fn().mockResolvedValue('new-task-id'),
		update: vi.fn().mockResolvedValue(undefined),
		remove: vi.fn().mockResolvedValue(undefined),
		refresh: vi.fn().mockResolvedValue(undefined),
	};
}

const personal: ActionTarget = { kind: 'personal' };
const shared: ActionTarget = { kind: 'list', listId: 'list-a' };

describe('TasksActionCoordinator', () => {
	it('keeps legacy component routing, busy sets, and false Undo copy deleted', () => {
		const source = readFileSync(join(process.cwd(), 'src/lib/components/TasksApp.svelte'), 'utf8');
		for (const legacy of ['createInView', 'updateInView', 'deleteInView', 'refreshCurrentView']) {
			expect(source).not.toContain(legacy);
		}
		expect(source).not.toContain("actionLabel: 'Undo'");
	});

	it('captures an immutable mutation target from the active view', () => {
		expect(captureActionTarget({ kind: 'personal' })).toEqual(personal);
		expect(captureActionTarget({ kind: 'list', listId: 'list-a' })).toEqual(shared);
		expect(captureActionTarget({ kind: 'assigned' })).toBeNull();
	});

	it('coalesces the same action and refreshes its captured origin exactly once', async () => {
		const adapter = makeAdapter();
		const pending = deferred<void>();
		adapter.remove.mockReturnValue(pending.promise);
		const coordinator = new TasksActionCoordinator(adapter);
		const task = { id: 'task-a', title: 'Delete me' } as Task;

		const first = coordinator.remove(shared, task);
		const duplicate = coordinator.remove(shared, task);

		expect(duplicate).toBe(first);
		expect(coordinator.isTaskBusy(shared, task.id)).toBe(true);
		expect(adapter.remove).toHaveBeenCalledTimes(1);

		pending.resolve();
		await first;

		expect(adapter.refresh).toHaveBeenCalledTimes(1);
		expect(adapter.refresh).toHaveBeenCalledWith(shared);
		expect(coordinator.isTaskBusy(shared, task.id)).toBe(false);
	});

	it('rejects conflicting mutations of one task while allowing different tasks', async () => {
		const adapter = makeAdapter();
		const firstPending = deferred<void>();
		const secondPending = deferred<void>();
		adapter.update
			.mockReturnValueOnce(firstPending.promise)
			.mockReturnValueOnce(secondPending.promise);
		const coordinator = new TasksActionCoordinator(adapter);

		const first = coordinator.update(personal, 'task-a', { title: 'A' });
		const second = coordinator.update(personal, 'task-b', { title: 'B' });
		await expect(
			coordinator.remove(personal, { id: 'task-a', title: 'A' } as Task),
		).rejects.toBeInstanceOf(TasksActionConflictError);

		expect(adapter.update).toHaveBeenCalledTimes(2);
		expect(adapter.remove).not.toHaveBeenCalled();

		firstPending.resolve();
		secondPending.resolve();
		await Promise.all([first, second]);
		expect(adapter.refresh).toHaveBeenCalledTimes(2);
	});

	it('restores only the promised creatable fields as a new identity', async () => {
		const adapter = makeAdapter();
		adapter.create.mockResolvedValue('replacement-id');
		const coordinator = new TasksActionCoordinator(adapter);
		const deleted = {
			id: 'original-id',
			title: 'Original',
			description: 'Body',
			status: 'in-progress',
			priority: 7,
			dueAt: '2026-08-20T00:00:00Z',
			reminderAt: '2026-08-19T00:00:00Z',
			categories: ['alpha', 'beta'],
			startAt: '2026-08-18T00:00:00Z',
			assigneeId: 'user-a',
			recurrence: { frequency: 'weekly' },
			parentId: 'parent-a',
			checklist: [{ id: 'item-a', title: 'Nested' }],
		} as unknown as Task;

		const recipe = coordinator.restoreRecipe(shared, deleted);
		const completion = await coordinator.restoreCopy(recipe);

		expect(completion.value).toBe('replacement-id');
		expect(completion.target).toEqual(shared);
		expect(adapter.create).toHaveBeenCalledWith(shared, {
			title: 'Original',
			description: 'Body',
			status: 'in-progress',
			priority: 7,
			dueAt: '2026-08-20T00:00:00Z',
			reminderAt: '2026-08-19T00:00:00Z',
			categories: ['alpha', 'beta'],
		});
		expect(adapter.refresh).toHaveBeenCalledTimes(1);
		expect(adapter.refresh).toHaveBeenCalledWith(shared);
	});

	it('does not refresh on mutation failure and always releases the key', async () => {
		const adapter = makeAdapter();
		adapter.update.mockRejectedValue(new Error('offline'));
		const coordinator = new TasksActionCoordinator(adapter);

		await expect(coordinator.update(personal, 'task-a', { title: 'A' })).rejects.toThrow(
			'offline',
		);
		expect(adapter.refresh).not.toHaveBeenCalled();
		expect(coordinator.isTaskBusy(personal, 'task-a')).toBe(false);
	});

	it('does not claim create success when the adapter returns no new identity', async () => {
		const adapter = makeAdapter();
		adapter.create.mockResolvedValue(undefined);
		const coordinator = new TasksActionCoordinator(adapter);
		await expect(coordinator.create(personal, { title: 'A' })).rejects.toThrow(
			'Task creation was not confirmed',
		);
		expect(adapter.refresh).toHaveBeenCalledTimes(1);
	});

	it('reports a post-commit refresh failure without inviting a duplicate mutation', async () => {
		const adapter = makeAdapter();
		adapter.refresh.mockRejectedValue(new Error('refresh offline'));
		const coordinator = new TasksActionCoordinator(adapter);
		const completion = await coordinator.create(personal, { title: 'A' });
		expect(completion.value).toBe('new-task-id');
		expect(completion.refreshError).toEqual(new Error('refresh offline'));
		expect(adapter.create).toHaveBeenCalledTimes(1);
		expect(adapter.refresh).toHaveBeenCalledTimes(1);
	});
});
