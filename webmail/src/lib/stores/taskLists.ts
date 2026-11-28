import { writable, get } from 'svelte/store';
import {
	taskListGet,
	taskListSet,
	taskListMemberSet,
	taskListTasks,
	taskListTaskSet,
	taskAssignedGet,
	taskAssignedSetStatus
} from '$lib/jmap/client';
import type { Task, TaskList, AssignedTask } from '$lib/types/jmap';

// stores/taskLists.ts — shared/team task lists (Phase 1). Runes-adjacent
// writable-store idiom matching stores/tasks.ts (this app's other Svelte 4
// (non-.svelte.ts) stores); monotonic load token guards against an
// out-of-order response overwriting a newer one (the tasks.ts pin).

export type TasksView = { kind: 'personal' } | { kind: 'assigned' } | { kind: 'list'; listId: string };

export const taskLists = writable<TaskList[]>([]);
export const activeView = writable<TasksView>({ kind: 'personal' });
export const assignedTasks = writable<AssignedTask[]>([]);
export const listTasks = writable<Task[]>([]);
export const listState = writable<string>('0');

export function reset(): void {
	taskLists.set([]);
	activeView.set({ kind: 'personal' });
	assignedTasks.set([]);
	listTasks.set([]);
	listState.set('0');
}

let listsLoadSeq = 0;
export async function loadLists(): Promise<void> {
	const seq = ++listsLoadSeq;
	const lists = await taskListGet();
	if (seq === listsLoadSeq) taskLists.set(lists);
}

let viewLoadSeq = 0;
export async function loadActiveView(): Promise<void> {
	const seq = ++viewLoadSeq;
	const v = get(activeView);
	if (v.kind === 'assigned') {
		const rows = await taskAssignedGet();
		if (seq === viewLoadSeq) assignedTasks.set(rows);
	} else if (v.kind === 'list') {
		const r = await taskListTasks(v.listId);
		if (seq === viewLoadSeq) {
			listTasks.set(r.list);
			listState.set(r.state);
		}
	}
}

export function setActiveView(v: TasksView): void {
	activeView.set(v);
	void loadActiveView();
}

export async function createTaskList(name: string, color?: string | null): Promise<string | undefined> {
	const result = await taskListSet({ k1: { name, color } }, null, null);
	await loadLists();
	return (result.created as Record<string, { id: string }> | undefined)?.k1?.id;
}

export async function renameTaskList(listId: string, name: string): Promise<void> {
	await taskListSet(null, { [listId]: { name } }, null);
	await loadLists();
}

export async function deleteTaskList(listId: string): Promise<void> {
	await taskListSet(null, null, [listId]);
	const v = get(activeView);
	if (v.kind === 'list' && v.listId === listId) {
		setActiveView({ kind: 'personal' });
	}
	await loadLists();
}

export async function addTaskListMember(listId: string, email: string): Promise<void> {
	await taskListMemberSet(listId, [email], []);
	await loadLists();
}

export async function removeTaskListMember(listId: string, userId: string): Promise<void> {
	await taskListMemberSet(listId, [], [userId]);
	await loadLists();
}

export async function createListTask(listId: string, taskData: Partial<Task>, refresh = true): Promise<string | undefined> {
	const result = await taskListTaskSet(listId, { k1: taskData }, null, null);
	if (refresh) await loadActiveView();
	return (result.created as Record<string, { id: string }> | undefined)?.k1?.id;
}

export async function updateListTask(listId: string, id: string, patch: Partial<Task>, refresh = true): Promise<void> {
	await taskListTaskSet(listId, null, { [id]: patch }, null);
	if (refresh) await loadActiveView();
}

export async function deleteListTask(listId: string, id: string, refresh = true): Promise<void> {
	await taskListTaskSet(listId, null, null, [id]);
	if (refresh) await loadActiveView();
}

const targetLoadSeq = new Map<string, number>();

/** Refresh one captured list target without retargeting to the currently active view. */
export async function refreshListTaskTarget(listId: string): Promise<void> {
	const seq = (targetLoadSeq.get(listId) ?? 0) + 1;
	targetLoadSeq.set(listId, seq);
	const result = await taskListTasks(listId);
	if (targetLoadSeq.get(listId) !== seq) return;
	const view = get(activeView);
	if (view.kind === 'list' && view.listId === listId) {
		listTasks.set(result.list);
		listState.set(result.state);
	}
}

/** Optimistic status update with rollback on failure — the assigned-to-me
 *  view's only legal mutation. */
export async function setAssignedStatus(taskId: string, status: string): Promise<void> {
	const prev = get(assignedTasks);
	assignedTasks.set(
		prev.map((t) => (t.id === taskId ? { ...t, status: status as AssignedTask['status'] } : t))
	);
	try {
		await taskAssignedSetStatus(taskId, status);
	} catch (err) {
		assignedTasks.set(prev); // rollback
		throw err;
	}
}

/** Push handler: TasksApp forwards a push here on any Task-channel event.
 *  listId is the changed list when known; the webmail's push framework today
 *  abstracts the real signal down to "the Task datatype changed" with no
 *  per-list id, so callers pass null and this refetches whatever view is on
 *  screen (assigned or list) rather than risk missing an update. A non-null
 *  listId only refetches when it matches the on-screen list (kept for a
 *  future more-granular push). Counts (openCount/memberCount) always refresh. */
export function onTaskListPush(listId: string | null): void {
	const v = get(activeView);
	if (v.kind === 'assigned' || (v.kind === 'list' && (listId === null || v.listId === listId))) {
		void loadActiveView();
	}
	void loadLists();
}
