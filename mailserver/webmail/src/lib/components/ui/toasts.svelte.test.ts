import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
	toasts,
	showToast,
	dismissToast,
	clearToasts,
	pauseToast,
	resumeToast
} from './toasts.svelte';

describe('toast store', () => {
	beforeEach(() => {
		vi.useFakeTimers();
		clearToasts();
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	it('adds a toast with the default 6000ms duration', () => {
		showToast('Saved');
		expect(toasts.length).toBe(1);
		expect(toasts[0].message).toBe('Saved');
		expect(toasts[0].durationMs).toBe(6000);
	});

	it('auto-dismisses after durationMs', () => {
		showToast('Saved');
		vi.advanceTimersByTime(5999);
		expect(toasts.length).toBe(1);
		vi.advanceTimersByTime(1);
		expect(toasts.length).toBe(0);
	});

	it('honours a custom durationMs', () => {
		showToast('Quick', { durationMs: 1000 });
		vi.advanceTimersByTime(1000);
		expect(toasts.length).toBe(0);
	});

	it('durationMs zero stays actionable through hover/focus until explicitly dismissed', async () => {
		const action = vi.fn();
		const handle = showToast('Retry cleanup', { durationMs: 0, actionLabel: 'Retry', onAction: action });
		pauseToast(handle.id);
		resumeToast(handle.id);
		vi.advanceTimersByTime(60_000);
		expect(toasts).toHaveLength(1);
		expect(vi.getTimerCount()).toBe(0);
		await toasts[0].onAction?.();
		expect(action).toHaveBeenCalledOnce();
		handle.dismiss();
		expect(toasts).toHaveLength(0);
	});

	it('dismisses via the returned handle', () => {
		const handle = showToast('Saved');
		handle.dismiss();
		expect(toasts.length).toBe(0);
	});

	it('dismisses by id via dismissToast', () => {
		showToast('Saved');
		dismissToast(toasts[0].id);
		expect(toasts.length).toBe(0);
	});

	it('replaces the previous actionable toast (single action slot)', () => {
		showToast('plain');
		showToast('Moved to Archive', { actionLabel: 'Undo', onAction: vi.fn() });
		showToast('Moved to Trash', { actionLabel: 'Undo', onAction: vi.fn() });
		expect(toasts.map((t) => t.message)).toEqual(['plain', 'Moved to Trash']);
	});

	it('pause stops the clock and resume continues with remaining time', () => {
		showToast('Saved'); // 6000ms budget
		const id = toasts[0].id;
		vi.advanceTimersByTime(4000); // 2000ms remaining
		pauseToast(id);
		vi.advanceTimersByTime(60_000); // paused — must survive
		expect(toasts.length).toBe(1);
		resumeToast(id);
		vi.advanceTimersByTime(1999);
		expect(toasts.length).toBe(1);
		vi.advanceTimersByTime(1);
		expect(toasts.length).toBe(0);
	});

	it('clearToasts removes everything and cancels timers', () => {
		showToast('a');
		showToast('b');
		clearToasts();
		expect(toasts.length).toBe(0);
		vi.advanceTimersByTime(10_000);
		expect(toasts.length).toBe(0);
	});
});
