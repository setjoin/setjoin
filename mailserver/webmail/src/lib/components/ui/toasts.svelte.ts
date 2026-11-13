// Toast service — module-level reactive store ($state) plus timer bookkeeping.
// Consumers call showToast(); <Toast /> (Toast.svelte) renders the `toasts` array.
// Do not mutate `toasts` from outside this module — use the exported functions.

export interface ToastOptions {
	actionLabel?: string;
	onAction?: () => void | Promise<void>;
	/** Zero disables automatic dismissal; the action and dismiss button remain available. */
	durationMs?: number;
	variant?: 'default' | 'success' | 'danger';
}

export interface ToastItem {
	id: number;
	message: string;
	actionLabel?: string;
	onAction?: () => void | Promise<void>;
	durationMs: number;
	variant: 'default' | 'success' | 'danger';
}

export interface ToastHandle {
	id: number;
	dismiss: () => void;
}

export const toasts: ToastItem[] = $state([]);

interface TimerState {
	timer: ReturnType<typeof setTimeout> | undefined;
	remaining: number;
	startedAt: number;
}

let nextId = 1;
const timers = new Map<number, TimerState>();

export function showToast(message: string, options: ToastOptions = {}): ToastHandle {
	const { actionLabel, onAction, durationMs = 6000, variant = 'default' } = options;
	if (onAction) {
		// Single action slot: a new actionable toast replaces the previous action.
		for (const t of [...toasts]) {
			if (t.onAction) dismissToast(t.id);
		}
	}
	const id = nextId++;
	toasts.push({ id, message, actionLabel, onAction, durationMs, variant });
	if (durationMs !== 0) {
		const state: TimerState = {
			timer: setTimeout(() => dismissToast(id), durationMs),
			remaining: durationMs,
			startedAt: Date.now()
		};
		timers.set(id, state);
	}
	return { id, dismiss: () => dismissToast(id) };
}

export function dismissToast(id: number): void {
	const state = timers.get(id);
	if (state?.timer !== undefined) clearTimeout(state.timer);
	timers.delete(id);
	const idx = toasts.findIndex((t) => t.id === id);
	if (idx !== -1) toasts.splice(idx, 1);
}

/** Pause the auto-dismiss countdown (called on toast mouseenter). */
export function pauseToast(id: number): void {
	const state = timers.get(id);
	if (!state || state.timer === undefined) return;
	clearTimeout(state.timer);
	state.timer = undefined;
	state.remaining = Math.max(0, state.remaining - (Date.now() - state.startedAt));
}

/** Resume a paused countdown with the remaining time (called on toast mouseleave). */
export function resumeToast(id: number): void {
	const state = timers.get(id);
	if (!state || state.timer !== undefined) return;
	state.startedAt = Date.now();
	state.timer = setTimeout(() => dismissToast(id), state.remaining);
}

export function clearToasts(): void {
	for (const t of [...toasts]) dismissToast(t.id);
}
