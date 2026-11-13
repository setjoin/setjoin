import type { Task } from '$lib/types/jmap';
import type { TasksView } from '$lib/stores/taskLists';

export type ActionTarget = { kind: 'personal' } | { kind: 'list'; listId: string };
export type TaskAction = 'create' | 'update' | 'delete' | 'move' | 'reorder' | 'restore-copy';

export interface TasksActionAdapter {
	create(target: ActionTarget, data: Partial<Task>): Promise<string | undefined>;
	update(target: ActionTarget, taskId: string, patch: Partial<Task>): Promise<void>;
	remove(target: ActionTarget, taskId: string): Promise<void>;
	refresh(target: ActionTarget): Promise<void>;
}

export interface RestoreCopyRecipe {
	target: ActionTarget;
	originalTaskId: string;
	fields: Partial<Task>;
}

export interface ActionCompletion<T> {
	target: ActionTarget;
	value: T;
	refreshError?: unknown;
}

export class TasksActionConflictError extends Error {
	constructor() {
		super('A conflicting task action is already in progress');
		this.name = 'TasksActionConflictError';
	}
}

export class TasksActionNotConfirmedError extends Error {
	constructor(action: 'create' | 'restore-copy') {
		super(action === 'create' ? 'Task creation was not confirmed' : 'Task copy restoration was not confirmed');
		this.name = 'TasksActionNotConfirmedError';
	}
}

export function captureActionTarget(view: TasksView): ActionTarget | null {
	if (view.kind === 'personal') return { kind: 'personal' };
	if (view.kind === 'list') return { kind: 'list', listId: view.listId };
	return null;
}

export function actionTargetEquals(left: ActionTarget | null, right: ActionTarget | null): boolean {
	if (!left || !right || left.kind !== right.kind) return false;
	return left.kind === 'personal' || left.listId === (right as { kind: 'list'; listId: string }).listId;
}

function targetKey(target: ActionTarget): string {
	return target.kind === 'personal' ? 'personal' : `list:${target.listId}`;
}

function cloneTarget(target: ActionTarget): ActionTarget {
	return target.kind === 'personal' ? { kind: 'personal' } : { kind: 'list', listId: target.listId };
}

function copyRestorableFields(task: Task): Partial<Task> {
	return {
		title: task.title,
		description: task.description,
		status: task.status,
		priority: task.priority,
		dueAt: task.dueAt,
		reminderAt: task.reminderAt,
		categories: task.categories ? [...task.categories] : undefined,
	};
}

export class TasksActionCoordinator {
	#busyKeys = $state(new Set<string>());
	#inFlight = new Map<string, Promise<unknown>>();
	#resourceOwners = new Map<string, string>();

	constructor(private readonly adapter: TasksActionAdapter) {}

	isTaskBusy(target: ActionTarget, taskId: string): boolean {
		return this.#busyKeys.has(this.#resourceKey(target, taskId));
	}

	isActionBusy(target: ActionTarget, taskId: string, action: TaskAction): boolean {
		return this.#inFlight.has(this.#actionKey(target, taskId, action));
	}

	create(target: ActionTarget, data: Partial<Task>): Promise<ActionCompletion<string>> {
		return this.#run(target, 'new', 'create', async () => {
			const id = await this.adapter.create(target, data);
			const refreshError = await this.#refreshError(target);
			if (!id) throw new TasksActionNotConfirmedError('create');
			return { target: cloneTarget(target), value: id, refreshError };
		});
	}

	update(
		target: ActionTarget,
		taskId: string,
		patch: Partial<Task>,
		action: Extract<TaskAction, 'update' | 'move' | 'reorder'> = 'update',
	): Promise<ActionCompletion<void>> {
		return this.#run(target, taskId, action, async () => {
			await this.adapter.update(target, taskId, patch);
			const refreshError = await this.#refreshError(target);
			return { target: cloneTarget(target), value: undefined, refreshError };
		});
	}

	remove(target: ActionTarget, task: Task): Promise<ActionCompletion<RestoreCopyRecipe>> {
		const recipe = this.restoreRecipe(target, task);
		return this.#run(target, task.id, 'delete', async () => {
			await this.adapter.remove(target, task.id);
			const refreshError = await this.#refreshError(target);
			return { target: cloneTarget(target), value: recipe, refreshError };
		});
	}

	restoreRecipe(target: ActionTarget, task: Task): RestoreCopyRecipe {
		return {
			target: cloneTarget(target),
			originalTaskId: task.id,
			fields: copyRestorableFields(task),
		};
	}

	restoreCopy(recipe: RestoreCopyRecipe): Promise<ActionCompletion<string>> {
		return this.#run(recipe.target, recipe.originalTaskId, 'restore-copy', async () => {
			const id = await this.adapter.create(recipe.target, {
				...recipe.fields,
				categories: recipe.fields.categories ? [...recipe.fields.categories] : undefined,
			});
			const refreshError = await this.#refreshError(recipe.target);
			if (!id) throw new TasksActionNotConfirmedError('restore-copy');
			return { target: cloneTarget(recipe.target), value: id, refreshError };
		});
	}

	async #refreshError(target: ActionTarget): Promise<unknown | undefined> {
		try {
			await this.adapter.refresh(target);
			return undefined;
		} catch (error) {
			return error;
		}
	}

	#run<T>(
		target: ActionTarget,
		taskId: string,
		action: TaskAction,
		operation: () => Promise<T>,
	): Promise<T> {
		const actionKey = this.#actionKey(target, taskId, action);
		const existing = this.#inFlight.get(actionKey);
		if (existing) return existing as Promise<T>;

		const resourceKey = this.#resourceKey(target, taskId);
		if (this.#resourceOwners.has(resourceKey)) {
			return Promise.reject(new TasksActionConflictError());
		}

		this.#resourceOwners.set(resourceKey, actionKey);
		this.#busyKeys = new Set(this.#busyKeys).add(resourceKey);
		const promise = operation().finally(() => {
			this.#inFlight.delete(actionKey);
			this.#resourceOwners.delete(resourceKey);
			const nextBusy = new Set(this.#busyKeys);
			nextBusy.delete(resourceKey);
			this.#busyKeys = nextBusy;
		});
		this.#inFlight.set(actionKey, promise);
		return promise;
	}

	#actionKey(target: ActionTarget, taskId: string, action: TaskAction): string {
		return `${this.#resourceKey(target, taskId)}:${action}`;
	}

	#resourceKey(target: ActionTarget, taskId: string): string {
		return `${targetKey(target)}:${taskId}`;
	}
}
