import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import { tick } from 'svelte';
import Toast from './Toast.svelte';
import { showToast, clearToasts } from './toasts.svelte';

describe('Toast renderer', () => {
	beforeEach(() => {
		clearToasts();
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	it('renders store toasts with status role', async () => {
		render(Toast);
		showToast('Saved');
		await tick();
		expect(screen.getByRole('status').textContent).toContain('Saved');
	});

	it('runs the action and dismisses the toast', async () => {
		const onAction = vi.fn();
		render(Toast);
		showToast('Message archived', { actionLabel: 'Undo', onAction });
		await tick();
		await fireEvent.click(screen.getByText('Undo'));
		expect(onAction).toHaveBeenCalledTimes(1);
		expect(screen.queryByText('Message archived')).toBeNull();
	});

	it('dismisses from the X button', async () => {
		render(Toast);
		showToast('Saved');
		await tick();
		await fireEvent.click(screen.getByLabelText('Dismiss'));
		expect(screen.queryByText('Saved')).toBeNull();
	});

	it('pauses auto-dismiss while hovered and resumes on leave', async () => {
		vi.useFakeTimers();
		render(Toast);
		showToast('Saved', { durationMs: 6000 });
		await tick();
		const toast = screen.getByRole('status');
		await fireEvent.mouseEnter(toast);
		vi.advanceTimersByTime(60_000);
		await tick();
		expect(screen.queryByText('Saved')).toBeTruthy();
		await fireEvent.mouseLeave(toast);
		vi.advanceTimersByTime(5999);
		await tick();
		expect(screen.queryByText('Saved')).toBeTruthy();
		vi.advanceTimersByTime(1);
		await tick();
		expect(screen.queryByText('Saved')).toBeNull();
	});

	it('pauses auto-dismiss while focused', async () => {
		vi.useFakeTimers();
		render(Toast);
		showToast('Task deleted', { actionLabel: 'Restore copy', onAction: vi.fn(), durationMs: 6000 });
		await tick();
		const action = screen.getByRole('button', { name: 'Restore copy' });
		await fireEvent.focusIn(action);
		vi.advanceTimersByTime(60_000);
		await tick();
		expect(screen.queryByText('Task deleted')).toBeTruthy();
		await fireEvent.focusOut(action);
		vi.advanceTimersByTime(6000);
		await tick();
		expect(screen.queryByText('Task deleted')).toBeNull();
	});

	it('keeps an async action visible and prevents duplicate activation until it settles', async () => {
		let resolve!: () => void;
		const onAction = vi.fn(() => new Promise<void>((done) => { resolve = done; }));
		render(Toast);
		showToast('Task deleted', { actionLabel: 'Restore copy', onAction });
		await tick();
		const action = screen.getByRole('button', { name: 'Restore copy' });
		await fireEvent.click(action);
		await fireEvent.click(action);
		expect(onAction).toHaveBeenCalledTimes(1);
		expect(action).toBeDisabled();
		expect(screen.queryByText('Task deleted')).toBeTruthy();
		resolve();
		await vi.waitFor(() => expect(screen.queryByText('Task deleted')).toBeNull());
	});

	it('keeps the action available when its promise rejects', async () => {
		const onAction = vi.fn().mockRejectedValue(new Error('restore failed'));
		render(Toast);
		showToast('Task deleted', { actionLabel: 'Restore copy', onAction });
		await tick();
		await fireEvent.click(screen.getByRole('button', { name: 'Restore copy' }));
		await vi.waitFor(() => expect(screen.getByRole('button', { name: 'Restore copy' })).toBeEnabled());
		expect(screen.queryByText('Task deleted')).toBeTruthy();
	});
});
