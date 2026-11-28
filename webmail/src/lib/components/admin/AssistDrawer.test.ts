import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';
const assistComplete = vi.hoisted(() => vi.fn());
vi.mock('$lib/admin/assist', async (importOriginal) => ({ ...(await importOriginal<object>()), assistComplete }));
import AssistDrawer from './AssistDrawer.svelte';

describe('AssistDrawer', () => {
	beforeEach(() => { vi.clearAllMocks(); assistComplete.mockResolvedValue({ content: 'Check **queue**\n`mailctl status`' }); });
	it('stays absent while closed and closes through Escape or the button', async () => {
		const onClose = vi.fn(); const { rerender } = render(AssistDrawer, { open: false, onClose });
		expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
		await rerender({ open: true, onClose });
		const dialog = screen.getByRole('dialog', { name: 'Assist' });
		await fireEvent.keyDown(dialog, { key: 'Escape' });
		expect(onClose).toHaveBeenCalledTimes(1);
		await fireEvent.click(screen.getByRole('button', { name: 'Close' }));
		expect(onClose).toHaveBeenCalledTimes(2);
	});

	it('sends sanitized history from Enter and renders rich assistant output', async () => {
		render(AssistDrawer, { open: true });
		const input = screen.getByPlaceholderText('Ask about alerts, queue, threats…');
		await fireEvent.input(input, { target: { value: '<unsafe> status' } });
		await fireEvent.keyDown(input, { key: 'Enter' });
		await waitFor(() => expect(assistComplete).toHaveBeenCalled());
		expect(screen.getByText('<unsafe> status')).toBeInTheDocument();
		expect(document.querySelector('script')).toBeNull();
		expect(screen.getByText('queue')).toBeInTheDocument();
		expect(screen.getByText('mailctl status')).toBeInTheDocument();
		const payload = assistComplete.mock.calls[0][0];
		expect(payload.messages.at(-1)).toEqual({ role: 'user', content: '<unsafe> status' });
	});

	it('runs a suggested question and surfaces a bounded service error', async () => {
		assistComplete.mockRejectedValueOnce(new Error('assistant unavailable'));
		render(AssistDrawer, { open: true });
		const suggestions = screen.getAllByRole('button').filter((b) => b.classList.contains('assist-suggested'));
		await fireEvent.click(suggestions[0]);
		await waitFor(() => expect(screen.getByText('assistant unavailable')).toBeInTheDocument());
	});
});
