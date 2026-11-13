import { writable } from 'svelte/store';
import { taskGet, taskQuery, taskSet, loadSession } from '$lib/jmap/client';
import type { Task, JmapMethodResponse } from '$lib/types/jmap';

export const tasks = writable<Task[]>([]);
export const viewMode = writable<'kanban' | 'list'>('kanban');
export const searchText = writable<string>('');
export const statusFilter = writable<string | null>(null);

export function reset() {
	tasks.set([]);
	viewMode.set('kanban');
	searchText.set('');
	statusFilter.set(null);
}

// Monotonic load token — see CalendarEventsStore.load (stores/calendarEvents.svelte.ts): only the newest
// of concurrently racing loads may write the store, else a pre-commit query
// resolving last overwrites fresh results with stale ones.
let tasksLoadSeq = 0;

export async function loadTasks(filter?: Record<string, unknown>): Promise<void> {
	const seq = ++tasksLoadSeq;
	await loadSession();
	const f = filter || {};
	const ids = await taskQuery(f, 500);
	const list = ids && ids.length > 0 ? (await taskGet(ids)) || [] : [];
	if (seq !== tasksLoadSeq) return; // superseded by a newer load
	tasks.set(list);
}

export async function createTask(taskData: Partial<Task>): Promise<string | undefined> {
	await loadSession();
	const result = (await taskSet({ k1: taskData as Task }, null, null)) as JmapMethodResponse;
	return result.created?.k1?.id;
}

export async function updateTask(id: string, patch: Partial<Task>): Promise<void> {
	await loadSession();
	await taskSet(null, { [id]: patch }, null);
}

export async function deleteTask(id: string): Promise<void> {
	await loadSession();
	await taskSet(null, null, [id]);
}

/**
 * The fractional sort key for a task dropped BETWEEN two visible neighbours
 * (QoL #20). Pure so the reorder math is unit-testable without DragEvents:
 *   - both neighbours → midpoint
 *   - only a `next` (dropped at the top) → next - 1
 *   - only a `prev` (dropped at the bottom) → prev + 1
 *   - neither (empty list) → 0
 */
export function computeReorderSortOrder(prev?: number, next?: number): number {
	if (prev !== undefined && next !== undefined) return (prev + next) / 2;
	if (next !== undefined) return next - 1;
	if (prev !== undefined) return prev + 1;
	return 0;
}

export function groupByStatus(taskList: Task[]): Record<string, Task[]> {
	const groups: Record<string, Task[]> = {
		'needs-action': [],
		'in-progress': [],
		'completed': [],
		'cancelled': []
	};
	for (const t of taskList) {
		const s = t.status || 'needs-action';
		if (!groups[s]) groups[s] = [];
		groups[s].push(t);
	}
	return groups;
}

export function priorityLabel(p: number): string {
	switch (p) {
		case 9: return 'High';
		case 5: return 'Medium';
		case 1: return 'Low';
		default: return 'None';
	}
}

export function priorityColor(p: number): string {
	switch (p) {
		case 9: return 'var(--danger-fg)';
		case 5: return 'var(--warning-fg)';
		case 1: return 'var(--success-fg)';
		default: return 'var(--text-secondary)';
	}
}

export function statusLabel(s: string): string {
	switch (s) {
		case 'needs-action': return 'To Do';
		case 'in-progress': return 'In Progress';
		case 'completed': return 'Done';
		case 'cancelled': return 'Cancelled';
		default: return s;
	}
}

export function formatDateShort(d?: string): string {
	if (!d) return '';
	const date = new Date(d);
	if (isNaN(date.getTime())) return '';
	return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

export function isOverdue(d?: string): boolean {
	if (!d) return false;
	const date = new Date(d);
	if (isNaN(date.getTime())) return false;
	return date < new Date();
}
